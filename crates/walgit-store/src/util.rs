use bytes::{Bytes, BytesMut};
use futures::StreamExt;

use crate::{ByteStream, Result, StoreError};

/// Collect a byte stream. `size_hint` pre-allocates.
pub async fn collect(mut body: ByteStream, size_hint: usize) -> Result<Bytes> {
    let mut first: Option<Bytes> = None;
    let mut buf: Option<BytesMut> = None;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        match (&mut first, &mut buf) {
            (None, None) => first = Some(chunk),
            (Some(_), None) => {
                let f = first.take().unwrap();
                let mut b = BytesMut::with_capacity(size_hint.max(f.len() + chunk.len()));
                b.extend_from_slice(&f);
                b.extend_from_slice(&chunk);
                buf = Some(b);
            }
            (_, Some(b)) => b.extend_from_slice(&chunk),
        }
    }
    Ok(match (first, buf) {
        (Some(f), None) => f,
        (_, Some(b)) => b.freeze(),
        (None, None) => Bytes::new(),
    })
}

/// Collect a request body whose declared length is part of the storage
/// contract. Reject both early EOF and extra bytes.
pub async fn collect_exact(body: ByteStream, expected: u64) -> Result<Bytes> {
    let limit = expected.checked_add(1).ok_or_else(|| {
        StoreError::InvalidArgument(format!(
            "declared body length {expected} cannot be bounded in memory"
        ))
    })?;
    let capacity = usize::try_from(expected).map_err(|_| {
        StoreError::InvalidArgument(format!(
            "declared body length {expected} does not fit in memory"
        ))
    })?;
    let mut body = body;
    let mut bytes = BytesMut::with_capacity(capacity);
    let mut supplied = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        let remaining = limit - supplied;
        let copied = usize::try_from(remaining.min(chunk.len() as u64))
            .expect("copied byte count is bounded by a chunk length");
        bytes.extend_from_slice(&chunk[..copied]);
        supplied += copied as u64;
        if copied < chunk.len() || supplied == limit {
            return Err(StoreError::InvalidArgument(format!(
                "declared body length is {expected} bytes but the body supplied more data"
            )));
        }
    }
    if supplied != expected {
        return Err(StoreError::InvalidArgument(format!(
            "declared body length is {expected} bytes but the body supplied {} bytes",
            supplied
        )));
    }
    Ok(bytes.freeze())
}

/// Wrap a single `Bytes` as a stream.
pub fn once(b: Bytes) -> ByteStream {
    Box::pin(futures::stream::once(async move { Ok(b) }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn collect_exact_stops_after_expected_plus_one_across_chunks() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body: ByteStream =
            Box::pin(futures::stream::unfold(polls.clone(), |polls| async move {
                polls.fetch_add(1, Ordering::SeqCst);
                Some((Ok(Bytes::from_static(b"abcd")), polls))
            }));

        let error = collect_exact(body, 5)
            .await
            .expect_err("an unbounded overlong body must fail");
        assert!(matches!(error, StoreError::InvalidArgument(_)));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn collect_exact_accepts_multichunk_and_reports_early_eof() {
        let exact: ByteStream = Box::pin(futures::stream::iter([
            Ok(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cde")),
        ]));
        assert_eq!(
            collect_exact(exact, 5).await.expect("exact body"),
            Bytes::from_static(b"abcde")
        );

        let short: ByteStream = Box::pin(futures::stream::iter([
            Ok(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"c")),
        ]));
        let error = collect_exact(short, 5)
            .await
            .expect_err("early EOF must fail");
        assert!(error.to_string().contains("supplied 3 bytes"));
    }
}

/// Stream a local file in `chunk` sized pieces, optionally a byte range.
pub fn file_stream(
    path: std::path::PathBuf,
    range: Option<std::ops::Range<u64>>,
    chunk: usize,
) -> ByteStream {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    return async_stream_file(path, range, chunk)
        .map(|r| r.map_err(StoreError::other))
        .boxed();

    fn async_stream_file(
        path: std::path::PathBuf,
        range: Option<std::ops::Range<u64>>,
        chunk: usize,
    ) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send {
        futures::stream::unfold(State::Init { path, range, chunk }, |st| async move {
            match st {
                State::Init { path, range, chunk } => {
                    let mut f = match tokio::fs::File::open(&path).await {
                        Ok(f) => f,
                        Err(e) => return Some((Err(e), State::Done)),
                    };
                    let (start, remaining) = match range {
                        Some(r) => (r.start, r.end.saturating_sub(r.start)),
                        None => match f.metadata().await {
                            Ok(m) => (0, m.len()),
                            Err(e) => return Some((Err(e), State::Done)),
                        },
                    };
                    if start > 0 {
                        if let Err(e) = f.seek(std::io::SeekFrom::Start(start)).await {
                            return Some((Err(e), State::Done));
                        }
                    }
                    read_next(f, remaining, chunk).await
                }
                State::Reading {
                    f,
                    remaining,
                    chunk,
                } => read_next(f, remaining, chunk).await,
                State::Done => None,
            }
        })
    }
    async fn read_next(
        mut f: tokio::fs::File,
        remaining: u64,
        chunk: usize,
    ) -> Option<(std::io::Result<Bytes>, State)> {
        if remaining == 0 {
            return None;
        }
        let want = (chunk as u64).min(remaining) as usize;
        let mut buf = BytesMut::with_capacity(want);
        // read_buf reads at most capacity; loop until we get `want` or EOF.
        while buf.len() < want {
            match f.read_buf(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Some((Err(e), State::Done)),
            }
        }
        if buf.is_empty() {
            return None;
        }
        let n = buf.len() as u64;
        Some((
            Ok(buf.freeze()),
            State::Reading {
                f,
                remaining: remaining - n,
                chunk,
            },
        ))
    }
    enum State {
        Init {
            path: std::path::PathBuf,
            range: Option<std::ops::Range<u64>>,
            chunk: usize,
        },
        Reading {
            f: tokio::fs::File,
            remaining: u64,
            chunk: usize,
        },
        Done,
    }
}

/// Exponential backoff with full jitter. `attempt` starts at 0.
pub fn backoff(
    attempt: u32,
    base: std::time::Duration,
    max: std::time::Duration,
) -> std::time::Duration {
    use rand::Rng;
    let exp = base.saturating_mul(1u32 << attempt.min(16));
    let cap = exp.min(max);
    let jitter = rand::rng().random_range(0..=cap.as_millis() as u64);
    std::time::Duration::from_millis(jitter)
}

/// Retry `op` on `StoreError::Retryable` up to `max_attempts`.
pub async fn retry<T, F, Fut>(max_attempts: u32, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Err(e) if e.is_retryable() && attempt + 1 < max_attempts => {
                let d = backoff(
                    attempt,
                    std::time::Duration::from_millis(20),
                    std::time::Duration::from_secs(2),
                );
                tracing::debug!(attempt, ?d, error = %e, "retrying store op");
                tokio::time::sleep(d).await;
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// Upload a large local file as concurrent part uploads + server-side compose
/// (GCS). Falls back to a single streaming `put` when the backend cannot
/// compose natively (S3 does its own multipart PUT) or the file is small. Part objects live under `<key>.part/NNNN`
/// and are deleted afterwards (best effort). `opts.mode` applies to the final
/// object only; a `Create` precondition failure surfaces as such.
pub async fn put_file_parallel(
    store: &dyn crate::ObjectStore,
    key: &str,
    path: &std::path::Path,
    opts: crate::PutOptions,
    parallelism: usize,
) -> crate::Result<crate::ObjectMeta> {
    use crate::{PutBody, PutMode, PutOptions, StoreError};
    use futures::{StreamExt, TryStreamExt};

    const MIN_PART: u64 = 64 * 1024 * 1024;
    const MAX_PART: u64 = 1024 * 1024 * 1024;
    const MAX_PARTS: u64 = 32 * 32; // two compose levels
    let size = tokio::fs::metadata(path)
        .await
        .map_err(StoreError::other)?
        .len();
    if !store.compose_is_native() || size <= 2 * MIN_PART {
        return store
            .put(key, PutBody::File(path.to_path_buf()), opts)
            .await;
    }
    let part_size = (size.div_ceil(MAX_PARTS)).clamp(MIN_PART, MAX_PART);
    let parts: Vec<(u64, u64)> = (0..size)
        .step_by(part_size as usize)
        .map(|start| (start, (start + part_size).min(size)))
        .collect();
    let part_key = |i: usize| format!("{key}.part/{i:04}");
    let started = std::time::Instant::now();
    let uploaded = std::sync::atomic::AtomicU64::new(0);
    futures::stream::iter(parts.clone().into_iter().enumerate())
        .map(|(i, (start, end))| {
            let pk = part_key(i);
            let range = start..end;
            let uploaded = &uploaded;
            async move {
                let len = range.end - range.start;
                let body = PutBody::Stream {
                    len,
                    stream: file_stream(path.to_path_buf(), Some(range), 1024 * 1024),
                };
                // Parts are content of an immutable object: overwrite is safe.
                store
                    .put(&pk, body, PutOptions::from(PutMode::Overwrite))
                    .await?;
                let done = uploaded.fetch_add(len, std::sync::atomic::Ordering::Relaxed) + len;
                tracing::debug!(
                    key,
                    part = i,
                    done_bytes = done,
                    total_bytes = size,
                    mb_per_s = done as f64 / 1e6 / started.elapsed().as_secs_f64().max(0.001),
                    "part uploaded"
                );
                Ok::<(), StoreError>(())
            }
        })
        .buffer_unordered(parallelism.max(1))
        .try_collect::<Vec<()>>()
        .await?;

    // Level 1: groups of <= 32 parts -> intermediates (or directly the final).
    let part_keys: Vec<String> = (0..parts.len()).map(part_key).collect();
    let mut cleanup: Vec<String> = part_keys.clone();
    let result = if part_keys.len() <= 32 {
        store.compose(key, &part_keys, opts).await
    } else {
        let mut mids = Vec::new();
        for (g, chunk) in part_keys.chunks(32).enumerate() {
            let mk = format!("{key}.part/mid{g:04}");
            store
                .compose(&mk, chunk, PutOptions::from(PutMode::Overwrite))
                .await?;
            mids.push(mk);
        }
        cleanup.extend(mids.iter().cloned());
        store.compose(key, &mids, opts).await
    };
    for k in cleanup {
        let _ = store.delete(&k, None).await;
    }
    if result.is_ok() {
        tracing::info!(
            key,
            bytes = size,
            parts = part_keys.len(),
            secs = started.elapsed().as_secs_f64(),
            mb_per_s = size as f64 / 1e6 / started.elapsed().as_secs_f64().max(0.001),
            "striped upload done"
        );
    }
    result
}

/// Percent-encode an object key for use in a URL path: slashes stay slashes (they are
/// the key's own separators), every other byte outside the unreserved set is encoded.
pub fn encode_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for b in key.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

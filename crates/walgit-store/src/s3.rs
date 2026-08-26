//! S3-compatible backend (rustfs for local dev / CI).
//!
//! Uses `aws-sdk-s3` for all operations. GET responses are streamed via
//! presigned URLs + `reqwest` because the SDK's `GetObjectOutput::body()`
//! returns `&ByteStream` with no owned-body extractor. All other operations
//! (PUT, HEAD, DELETE, LIST) use the SDK directly.
//!
//! ## Version tokens
//!
//! S3 ETags are used as opaque `Version` strings. Quotes are stripped
//! consistently on read and never stored. For non-multipart uploads the
//! ETag is the MD5 of the content; for multipart uploads it is a compound
//! hash. Callers never parse the token — equality comparison suffices.
//!
//! ## Conditional PUT
//!
//! `PutMode::Create`    → `If-None-Match: *`  (object must not exist).
//! `PutMode::Update(v)` → `If-Match: <etag>`  (CAS on current ETag).
//! On failure the SDK returns a `PreconditionFailed` service error; we fill
//! `current` via a follow-up HEAD when the SDK doesn't include it.
//!
//! ## Conditional DELETE
//!
//! `DeleteObject` carries `If-Match` when a version is supplied. The
//! provider must enforce that condition atomically; walgit does not emulate
//! it with a racy HEAD-then-DELETE sequence.
//!
//! ## Multipart upload
//!
//! Objects above `cfg.multipart_threshold` use CreateMultipartUpload +
//! UploadPart + CompleteMultipartUpload. Conditions are attached to the
//! final CompleteMultipartUpload request. No destination object is visible
//! before that atomic operation. Providers that reject those S3 conditions
//! fail the request; walgit never substitutes a check-then-write sequence.
//!
//! ## rustfs compatibility (tested with rustfs/rustfs:latest)
//!
//! See the compatibility notes at the bottom of this file.

use std::io::Cursor;
use std::ops::Range;
use std::time::Duration;

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream as S3ByteStream;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;

use crate::{
    BoxStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode, PutOptions,
    Result, StoreError, Version,
};

/// S3-compatible object store.
pub struct S3Store {
    client: S3Client,
    bucket: String,
    /// reqwest client for streaming GETs via presigned URLs.
    http: reqwest::Client,
    multipart_threshold: u64,
    multipart_part_size: u64,
}

impl S3Store {
    /// Build a store from `walgit-config::StoreConfig`.
    ///
    /// The AWS SDK default chain supplies refreshable credentials. The env
    /// vars named in `cfg.s3.access_key_env` / `cfg.s3.secret_key_env`
    /// override it only when both resolve to non-empty values. A configured
    /// `session_token_env` is included for temporary explicit credentials.
    pub async fn new(cfg: &walgit_config::StoreConfig) -> anyhow::Result<Self> {
        let region = aws_sdk_s3::config::Region::new(cfg.s3.region.clone());
        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region.clone())
            .load()
            .await;
        let mut s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
            .region(region)
            .force_path_style(cfg.s3.force_path_style)
            .behavior_version_latest();

        if let Some((access_key, secret_key, session_token)) = explicit_credentials(
            &cfg.s3.access_key_env,
            &cfg.s3.secret_key_env,
            &cfg.s3.session_token_env,
            |name| std::env::var(name).ok(),
        )? {
            s3_config = s3_config.credentials_provider(Credentials::new(
                access_key,
                secret_key,
                session_token,
                None,
                "walgit-explicit-env",
            ));
        }

        if !cfg.s3.endpoint.is_empty() {
            s3_config = s3_config.endpoint_url(&cfg.s3.endpoint);
        }

        let client = S3Client::from_conf(s3_config.build());
        let http = reqwest::Client::builder().build()?;

        let multipart_part_size = multipart_part_size(1, cfg.multipart_part_size.as_u64())?;

        Ok(S3Store {
            client,
            bucket: cfg.bucket.clone(),
            http,
            multipart_threshold: cfg.multipart_threshold.as_u64(),
            multipart_part_size,
        })
    }

    /// `bytes=start-(end-1)` for a half-open range (S3 Range is inclusive).
    fn range_header(range: &Range<u64>) -> String {
        format!("bytes={}-{}", range.start, range.end.saturating_sub(1))
    }

    // ---- GET via presigned URL + reqwest (true streaming) ---------------

    async fn presigned_get(&self, key: &str, opts: &GetOptions) -> Result<reqwest::Response> {
        let presigning = PresigningConfig::expires_in(Duration::from_secs(60))
            .map_err(|e| StoreError::other(anyhow::anyhow!("presigning config: {e}")))?;

        let mut builder = self.client.get_object().bucket(&self.bucket).key(key);

        if let Some(v) = &opts.if_none_match {
            builder = builder.if_none_match(v.as_str());
        }
        if let Some(v) = &opts.if_match {
            builder = builder.if_match(v.as_str());
        }
        if let Some(r) = &opts.range {
            builder = builder.range(Self::range_header(r));
        }

        let presigned = builder
            .presigned(presigning)
            .await
            .map_err(|e| StoreError::other(anyhow::anyhow!("presigning get: {e}")))?;

        let mut req = self.http.get(presigned.uri());
        for (name, value) in presigned.headers() {
            req = req.header(name, value);
        }

        req.send()
            .await
            .map_err(|e| sanitized_reqwest_error("get request", e))
    }

    fn get_result_from_response(key: &str, resp: reqwest::Response) -> Result<GetResult> {
        let status = resp.status();
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_owned());
        let content_length = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // `ObjectMeta::size` is the size of the whole object (as on GCS/memory),
        // also for range reads: `Content-Range: bytes a-b/total` carries it.
        let total = resp
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit_once('/'))
            .and_then(|(_, t)| t.trim().parse::<u64>().ok());

        match status.as_u16() {
            200 | 206 => {
                let version = Version::new(etag.as_deref().unwrap_or(""));
                let meta = ObjectMeta {
                    key: key.into(),
                    size: total.or(content_length).unwrap_or(0),
                    version,
                };
                let body = resp
                    .bytes_stream()
                    .map(|r| r.map_err(|e| sanitized_reqwest_error("get body", e)))
                    .boxed();
                Ok(GetResult::Object { meta, body })
            }
            304 => Ok(GetResult::NotModified {
                version: Version::new(etag.as_deref().unwrap_or("")),
            }),
            404 => Err(StoreError::NotFound { key: key.into() }),
            412 => Err(StoreError::PreconditionFailed {
                key: key.into(),
                current: etag.map(Version::new),
            }),
            s if retryable_status(s) => {
                Err(StoreError::Retryable(anyhow::anyhow!("s3 get status {s}")))
            }
            s => Err(StoreError::Other(anyhow::anyhow!("s3 get status {s}"))),
        }
    }
}

const S3_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const S3_MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const S3_MAX_SINGLE_PUT_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const S3_MAX_PARTS: u64 = 10_000;
const S3_MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024 * 1024;
const S3_COMPOSE_COPY_TARGET: u64 = 1024 * 1024 * 1024;

type UploadReader = Box<dyn AsyncRead + Send + Unpin>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComposeRange {
    source: usize,
    start: u64,
    len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComposePartPlan {
    Copy(ComposeRange),
    Upload(Vec<ComposeRange>),
}

impl ComposePartPlan {
    fn len(&self) -> u64 {
        match self {
            Self::Copy(range) => range.len,
            Self::Upload(ranges) => ranges.iter().map(|range| range.len).sum(),
        }
    }
}

fn compose_part_plan(sizes: &[u64], part_target: u64) -> Result<Vec<ComposePartPlan>> {
    if !(S3_MIN_PART_SIZE..=S3_MAX_PART_SIZE).contains(&part_target) {
        return Err(StoreError::InvalidArgument(format!(
            "s3 compose part target must be between {S3_MIN_PART_SIZE} and {S3_MAX_PART_SIZE} bytes"
        )));
    }
    let total = sizes.iter().try_fold(0u64, |total, size| {
        total
            .checked_add(*size)
            .ok_or_else(|| StoreError::InvalidArgument("composed object size overflows u64".into()))
    })?;
    let expected_parts = total.div_ceil(part_target);
    if expected_parts > S3_MAX_PARTS {
        return Err(StoreError::InvalidArgument(format!(
            "s3 compose needs {expected_parts} parts, above the {S3_MAX_PARTS}-part limit"
        )));
    }

    let mut plans = Vec::with_capacity(expected_parts as usize);
    let mut source = 0usize;
    let mut source_offset = 0u64;
    let mut planned = 0u64;
    let copy_target = part_target
        .max(S3_COMPOSE_COPY_TARGET)
        .min(S3_MAX_PART_SIZE);
    while planned < total {
        while source < sizes.len() && source_offset == sizes[source] {
            source += 1;
            source_offset = 0;
        }
        if source == sizes.len() {
            return Err(StoreError::InvalidArgument(
                "s3 compose layout ended before the declared source sizes".into(),
            ));
        }

        let source_remaining = sizes[source] - source_offset;
        let total_remaining = total - planned;
        if source_remaining >= part_target || source_remaining == total_remaining {
            let len = source_remaining.min(copy_target);
            plans.push(ComposePartPlan::Copy(ComposeRange {
                source,
                start: source_offset,
                len,
            }));
            source_offset += len;
            planned += len;
            continue;
        }

        let part_len = part_target.min(total - planned);
        let mut remaining = part_len;
        let mut ranges = Vec::new();
        while remaining > 0 {
            while source < sizes.len() && source_offset == sizes[source] {
                source += 1;
                source_offset = 0;
            }
            if source == sizes.len() {
                return Err(StoreError::InvalidArgument(
                    "s3 compose layout ended before the declared source sizes".into(),
                ));
            }
            let take = remaining.min(sizes[source] - source_offset);
            ranges.push(ComposeRange {
                source,
                start: source_offset,
                len: take,
            });
            source_offset += take;
            remaining -= take;
        }
        planned += part_len;
        plans.push(ComposePartPlan::Upload(ranges));
    }

    if plans.len() as u64 > S3_MAX_PARTS
        || plans
            .iter()
            .enumerate()
            .any(|(index, plan)| index + 1 < plans.len() && plan.len() < S3_MIN_PART_SIZE)
        || plans.iter().any(|plan| plan.len() > S3_MAX_PART_SIZE)
    {
        return Err(StoreError::InvalidArgument(
            "s3 compose cannot produce a valid multipart layout".into(),
        ));
    }
    Ok(plans)
}

fn sanitized_reqwest_error(op: &str, error: reqwest::Error) -> StoreError {
    let category = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    };
    let retryable = error.is_timeout() || error.is_connect() || error.is_body();
    let error = error.without_url();
    let diagnostic = anyhow::anyhow!("s3 {op} {category}: {error}");
    if retryable {
        StoreError::retryable(diagnostic)
    } else {
        StoreError::other(diagnostic)
    }
}

fn explicit_credentials(
    access_name: &str,
    secret_name: &str,
    session_token_name: &str,
    read: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<(String, String, Option<String>)>> {
    if access_name.is_empty() != secret_name.is_empty() {
        anyhow::bail!(
            "s3: explicit credential override is partial; access_key_env and secret_key_env must both be configured or both be empty"
        );
    }
    if access_name.is_empty() {
        if !session_token_name.is_empty() {
            anyhow::bail!(
                "s3: session_token_env requires configured access_key_env and secret_key_env"
            );
        }
        return Ok(None);
    }

    let access = (!access_name.is_empty())
        .then(|| read(access_name))
        .flatten()
        .filter(|value| !value.is_empty());
    let secret = (!secret_name.is_empty())
        .then(|| read(secret_name))
        .flatten()
        .filter(|value| !value.is_empty());
    let session_token = (!session_token_name.is_empty())
        .then(|| read(session_token_name))
        .flatten()
        .filter(|value| !value.is_empty());
    match (access, secret, session_token) {
        (None, None, None) => Ok(None),
        (Some(access), Some(secret), session_token)
            if session_token_name.is_empty() || session_token.is_some() =>
        {
            Ok(Some((access, secret, session_token)))
        }
        (Some(_), Some(_), None) => anyhow::bail!(
            "s3: configured session token variable {} must resolve to a non-empty value",
            session_token_name
        ),
        _ => anyhow::bail!(
            "s3: explicit credential override is partial; {} and {} must both resolve to non-empty values",
            access_name,
            secret_name
        ),
    }
}

fn multipart_part_size(len: u64, configured: u64) -> Result<u64> {
    if len > S3_MAX_OBJECT_SIZE {
        return Err(StoreError::InvalidArgument(format!(
            "s3 object size {len} exceeds the {S3_MAX_OBJECT_SIZE}-byte service limit"
        )));
    }
    if !(S3_MIN_PART_SIZE..=S3_MAX_PART_SIZE).contains(&configured) {
        return Err(StoreError::InvalidArgument(format!(
            "s3 multipart part size must be between {S3_MIN_PART_SIZE} and {S3_MAX_PART_SIZE} bytes"
        )));
    }
    let required = len.div_ceil(S3_MAX_PARTS);
    let part_size = configured.max(required);
    if part_size > S3_MAX_PART_SIZE || len.div_ceil(part_size) > S3_MAX_PARTS {
        return Err(StoreError::InvalidArgument(format!(
            "s3 object of {len} bytes cannot fit within {S3_MAX_PARTS} parts of at most {S3_MAX_PART_SIZE} bytes"
        )));
    }
    Ok(part_size)
}

async fn body_to_reader(body: PutBody) -> Result<(UploadReader, u64)> {
    match body {
        PutBody::Bytes(bytes) => {
            let len = bytes.len() as u64;
            Ok((Box::new(Cursor::new(bytes)), len))
        }
        PutBody::Stream { len, stream } => {
            let stream = stream.map_err(std::io::Error::other);
            Ok((Box::new(StreamReader::new(stream)), len))
        }
        PutBody::File(path) => {
            let meta = tokio::fs::metadata(&path)
                .await
                .map_err(|e| StoreError::other(anyhow::anyhow!("stat {}: {e}", path.display())))?;
            let file = tokio::fs::File::open(&path)
                .await
                .map_err(|e| StoreError::other(anyhow::anyhow!("open {}: {e}", path.display())))?;
            Ok((Box::new(file), meta.len()))
        }
    }
}

async fn read_declared_body(reader: &mut UploadReader, len: u64) -> Result<Bytes> {
    let capacity = usize::try_from(len).map_err(|_| {
        StoreError::InvalidArgument(format!("declared body length {len} does not fit in memory"))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(len.saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| StoreError::other(anyhow::anyhow!("read request body: {e}")))?;
    if bytes.len() as u64 != len {
        return Err(StoreError::InvalidArgument(format!(
            "declared body length is {len} bytes but the body supplied {} bytes",
            bytes.len()
        )));
    }
    Ok(Bytes::from(bytes))
}

async fn read_multipart_part(
    reader: &mut UploadReader,
    part_len: u64,
    declared_len: u64,
    supplied_before: u64,
) -> Result<Bytes> {
    let part_len = usize::try_from(part_len).map_err(|_| {
        StoreError::InvalidArgument("s3 multipart part size does not fit in memory".into())
    })?;
    let mut bytes = vec![0u8; part_len];
    let mut read_total = 0usize;
    while read_total < part_len {
        let read = reader
            .read(&mut bytes[read_total..])
            .await
            .map_err(|error| StoreError::other(anyhow::anyhow!("multipart read: {error}")))?;
        if read == 0 {
            return Err(StoreError::InvalidArgument(format!(
                "declared body length is {declared_len} bytes but the body ended after {} bytes",
                supplied_before + read_total as u64
            )));
        }
        read_total += read;
    }
    Ok(Bytes::from(bytes))
}

async fn ensure_multipart_body_exhausted(
    reader: &mut UploadReader,
    declared_len: u64,
) -> Result<()> {
    let mut extra = [0u8; 1];
    match reader.read(&mut extra).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(StoreError::InvalidArgument(format!(
            "declared body length is {declared_len} bytes but the body supplied more data"
        ))),
        Err(error) => Err(StoreError::other(anyhow::anyhow!(
            "multipart trailing read: {error}"
        ))),
    }
}

async fn collect_compose_range(result: GetResult, key: &str, expected: u64) -> Result<Bytes> {
    match result {
        GetResult::Object { body, .. } => crate::util::collect_exact(body, expected).await,
        GetResult::NotModified { .. } => Err(StoreError::other(anyhow::anyhow!(
            "s3 compose range for {key} unexpectedly returned not modified"
        ))),
    }
}

fn apply_complete_condition(
    mut complete: aws_sdk_s3::operation::complete_multipart_upload::builders::CompleteMultipartUploadFluentBuilder,
    mode: &PutMode,
) -> aws_sdk_s3::operation::complete_multipart_upload::builders::CompleteMultipartUploadFluentBuilder
{
    match mode {
        PutMode::Overwrite => {}
        PutMode::Create => complete = complete.if_none_match("*"),
        PutMode::Update(version) => complete = complete.if_match(version.as_str()),
    }
    complete
}

// ---- error classification ----------------------------------------------

/// Extract the error code string from an SdkError's service error metadata.
fn err_code<E>(err: &aws_sdk_s3::error::SdkError<E>) -> Option<&str>
where
    E: aws_sdk_s3::error::ProvideErrorMetadata,
{
    err.as_service_error().and_then(|e| e.meta().code())
}

fn retryable_service_code(code: &str) -> bool {
    matches!(
        code,
        "ConditionalRequestConflict"
            | "InternalError"
            | "RequestTimeout"
            | "RequestTimeoutException"
            | "ServiceUnavailable"
            | "SlowDown"
            | "Throttling"
            | "ThrottlingException"
            | "TooManyRequestsException"
    )
}

fn retryable_status(status: u16) -> bool {
    status == 429 || status >= 500
}

fn classify_sdk_error<E>(op: &str, key: &str, err: aws_sdk_s3::error::SdkError<E>) -> StoreError
where
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    use aws_sdk_s3::error::SdkError;

    let code = err_code(&err).unwrap_or("");
    let status = err
        .raw_response()
        .map(|response| response.status().as_u16());
    if code == "PreconditionFailed" || status == Some(412) {
        return StoreError::PreconditionFailed {
            key: key.into(),
            current: None,
        };
    }
    if matches!(code, "NoSuchKey" | "NotFound") || status == Some(404) {
        return StoreError::NotFound { key: key.into() };
    }
    let retryable_status = status.is_some_and(retryable_status);
    let retryable_transport = matches!(
        err,
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_)
    );
    if retryable_transport || retryable_status || retryable_service_code(code) {
        StoreError::retryable(anyhow::anyhow!("s3 {op} error for {key}: {err}"))
    } else {
        StoreError::other(anyhow::anyhow!("s3 {op} error for {key}: {err}"))
    }
}

fn classify_put_error(
    key: &str,
    err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
) -> StoreError {
    classify_sdk_error("put", key, err)
}

fn classify_list_error(
    err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error>,
) -> StoreError {
    classify_sdk_error("list", "<prefix>", err)
}

#[async_trait::async_trait]
impl ObjectStore for S3Store {
    fn backend(&self) -> &'static str {
        "s3"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult> {
        let resp = self.presigned_get(key, &opts).await?;
        Self::get_result_from_response(key, resp)
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let resp = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;

        match resp {
            Ok(out) => {
                let etag = out.e_tag().map(|s| s.trim_matches('"').to_owned());
                let size = out.content_length().unwrap_or(0) as u64;
                Ok(Some(ObjectMeta {
                    key: key.into(),
                    size,
                    version: Version::new(etag.as_deref().unwrap_or("")),
                }))
            }
            Err(err) => {
                if let Some(aws_sdk_s3::operation::head_object::HeadObjectError::NotFound(_)) =
                    err.as_service_error()
                {
                    return Ok(None);
                }
                match classify_sdk_error("head", key, err) {
                    StoreError::NotFound { .. } => Ok(None),
                    other => Err(other),
                }
            }
        }
    }

    async fn put(&self, key: &str, body: PutBody, opts: PutOptions) -> Result<ObjectMeta> {
        let (mut reader, len) = body_to_reader(body).await?;

        if len > self.multipart_threshold || len > S3_MAX_SINGLE_PUT_SIZE {
            return self.multipart_put(key, &mut reader, len, &opts).await;
        }

        // Small mutable objects stay on the single atomic PUT path. Buffering
        // this bounded body lets us reject both early EOF and extra bytes
        // before the provider can make a shortened object visible.
        let bytes = read_declared_body(&mut reader, len).await?;

        let mut builder = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(S3ByteStream::from(bytes))
            .content_length(len as i64);

        match &opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => {
                builder = builder.if_none_match("*");
            }
            PutMode::Update(v) => {
                builder = builder.if_match(v.as_str());
            }
        }

        if let Some(ct) = opts.content_type {
            builder = builder.content_type(ct);
        }
        if opts.immutable {
            builder = builder.cache_control("public, max-age=31536000, immutable");
        }

        let result = builder.send().await;
        match result {
            Ok(resp) => {
                let etag = resp.e_tag().map(|s| s.trim_matches('"').to_owned());
                Ok(ObjectMeta {
                    key: key.into(),
                    size: len,
                    version: Version::new(etag.as_deref().unwrap_or("")),
                })
            }
            Err(e) => {
                let mut err = classify_put_error(key, e);
                // Fill `current` via HEAD if we got a PreconditionFailed.
                if let StoreError::PreconditionFailed { current: c, .. } = &mut err
                    && c.is_none()
                {
                    *c = self.head(key).await.ok().flatten().map(|m| m.version);
                }
                Err(err)
            }
        }
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<()> {
        let mut request = self.client.delete_object().bucket(&self.bucket).key(key);
        if let Some(want) = &if_version {
            request = request.if_match(want.as_str());
        }

        let resp = request.send().await;

        match resp {
            Ok(_) => Ok(()),
            Err(err) => {
                let mut mapped = classify_sdk_error("delete", key, err);
                if if_version.is_none() && mapped.is_not_found() {
                    return Ok(());
                }
                if if_version.is_some() && mapped.is_precondition_failed() {
                    match self.head(key).await? {
                        None => return Err(StoreError::NotFound { key: key.into() }),
                        Some(meta) => {
                            if let StoreError::PreconditionFailed { current, .. } = &mut mapped {
                                *current = Some(meta.version);
                            }
                        }
                    }
                }
                Err(mapped)
            }
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let prefix = prefix.to_owned();
        let start_after = start_after.map(|s| s.to_owned());

        Box::pin(futures::stream::unfold(
            ListState {
                client,
                bucket,
                prefix,
                start_after,
                continuation_token: None,
                started: false,
                buffer: Vec::new().into_iter(),
            },
            |mut state| async move {
                // Drain buffered items first.
                if let Some(item) = state.buffer.next() {
                    return Some((item, state));
                }

                if state.started && state.continuation_token.is_none() {
                    return None;
                }
                state.started = true;

                let mut builder = state
                    .client
                    .list_objects_v2()
                    .bucket(&state.bucket)
                    .prefix(&state.prefix)
                    .max_keys(1000);

                if let Some(sa) = &state.start_after {
                    builder = builder.start_after(sa);
                }
                if let Some(ct) = &state.continuation_token {
                    builder = builder.continuation_token(ct);
                }

                match builder.send().await {
                    Ok(resp) => {
                        let items: Vec<Result<ObjectMeta>> = resp
                            .contents()
                            .iter()
                            .map(|obj| {
                                let etag = obj.e_tag().map(|s| s.trim_matches('"').to_owned());
                                Ok(ObjectMeta {
                                    key: obj.key().unwrap_or("").to_owned(),
                                    size: obj.size().unwrap_or(0) as u64,
                                    version: Version::new(etag.as_deref().unwrap_or("")),
                                })
                            })
                            .collect();

                        state.continuation_token = resp
                            .is_truncated()
                            .unwrap_or(false)
                            .then(|| resp.next_continuation_token().map(|s| s.to_owned()))
                            .flatten();
                        state.buffer = items.into_iter();

                        let item = state.buffer.next();
                        item.map(|i| (i, state))
                    }
                    Err(err) => Some((Err(classify_list_error(err)), state)),
                }
            },
        ))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut continuation_token: Option<String> = None;
        loop {
            let mut builder = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .delimiter("/")
                .max_keys(1000);
            if let Some(ct) = &continuation_token {
                builder = builder.continuation_token(ct);
            }
            let resp = builder.send().await.map_err(classify_list_error)?;
            out.extend(
                resp.common_prefixes()
                    .iter()
                    .filter_map(|p| p.prefix().map(str::to_owned)),
            );
            continuation_token = resp
                .is_truncated()
                .unwrap_or(false)
                .then(|| resp.next_continuation_token().map(|s| s.to_owned()))
                .flatten();
            if continuation_token.is_none() {
                break;
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// A presigned GET (1 h): the edge needs no credentials and `Range` stays free (unsigned).
    async fn accel_target(&self, key: &str) -> Option<crate::AccelTarget> {
        let url = self
            .signed_get_url(key, Duration::from_secs(3600))
            .await
            .ok()
            .flatten()?;
        Some(crate::AccelTarget {
            url,
            cache_key: key.to_string(),
            authorization: None,
        })
    }

    fn supports_compose(&self) -> bool {
        true
    }

    /// Concatenate `sources` into `dest` with one multipart upload whose parts are
    /// `UploadPartCopy` byte ranges of the sources. Contiguous sources retain the
    /// approximately 1 GiB copy target (raised when the calculated multipart
    /// target requires it, capped at 5 GiB). Only fragmented parts stream through
    /// this process: small sources such as a bundle header are coalesced to the
    /// calculated target before upload.
    async fn compose(
        &self,
        dest: &str,
        sources: &[String],
        opts: PutOptions,
    ) -> Result<ObjectMeta> {
        if sources.is_empty() {
            return Err(StoreError::InvalidArgument(
                "compose needs at least one source".into(),
            ));
        }
        // Sizes first: the layout of parts depends on them.
        let mut sizes = Vec::with_capacity(sources.len());
        let mut versions = Vec::with_capacity(sources.len());
        for src in sources {
            let m = self
                .head(src)
                .await?
                .ok_or_else(|| StoreError::NotFound { key: src.clone() })?;
            sizes.push(m.size);
            versions.push(m.version);
        }
        let total = sizes.iter().try_fold(0u64, |total, size| {
            total.checked_add(*size).ok_or_else(|| {
                StoreError::InvalidArgument("composed object size overflows u64".into())
            })
        })?;
        if total > S3_MAX_OBJECT_SIZE {
            return Err(StoreError::InvalidArgument(format!(
                "s3 composed object size {total} exceeds the {S3_MAX_OBJECT_SIZE}-byte service limit"
            )));
        }
        if total == 0 {
            return self.put(dest, PutBody::Bytes(Bytes::new()), opts).await;
        }
        // Freeze a valid layout before CreateMultipartUpload. Fragmented
        // sources are coalesced into the calculated target so a provider never
        // sees a partially uploaded layout that later exceeds 10,000 parts.
        let part_target = multipart_part_size(total, self.multipart_part_size)?;
        let plans = compose_part_plan(&sizes, part_target)?;

        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(dest);
        if let Some(ct) = opts.content_type {
            create = create.content_type(ct);
        }
        if opts.immutable {
            create = create.cache_control("public, max-age=31536000, immutable");
        }
        let upload = create
            .send()
            .await
            .map_err(|e| classify_sdk_error("create multipart", dest, e))?;
        let upload_id = upload
            .upload_id()
            .ok_or_else(|| {
                StoreError::other(anyhow::anyhow!("no upload_id from CreateMultipartUpload"))
            })?
            .to_owned();
        let mut parts: Vec<aws_sdk_s3::types::CompletedPart> = Vec::new();
        let result: Result<()> = async {
            for (index, plan) in plans.into_iter().enumerate() {
                let part_number = i32::try_from(index + 1).map_err(|_| {
                    StoreError::InvalidArgument("s3 compose part number overflow".into())
                })?;
                match plan {
                    ComposePartPlan::Copy(range) => {
                        let source = &sources[range.source];
                        let range_end = range.start + range.len - 1;
                        let part = self
                            .client
                            .upload_part_copy()
                            .bucket(&self.bucket)
                            .key(dest)
                            .upload_id(&upload_id)
                            .part_number(part_number)
                            .copy_source(format!(
                                "{}/{}",
                                self.bucket,
                                crate::util::encode_path(source)
                            ))
                            .copy_source_range(format!("bytes={}-{}", range.start, range_end))
                            .copy_source_if_match(versions[range.source].as_str())
                            .send()
                            .await
                            .map_err(|e| classify_sdk_error("upload part copy", source, e))?;
                        let etag = part
                            .copy_part_result()
                            .and_then(|r| r.e_tag())
                            .unwrap_or("")
                            .to_owned();
                        parts.push(
                            aws_sdk_s3::types::CompletedPart::builder()
                                .e_tag(etag)
                                .part_number(part_number)
                                .build(),
                        );
                    }
                    ComposePartPlan::Upload(ranges) => {
                        let len: u64 = ranges.iter().map(|range| range.len).sum();
                        let capacity = usize::try_from(len).map_err(|_| {
                            StoreError::InvalidArgument(
                                "s3 compose upload part does not fit in memory".into(),
                            )
                        })?;
                        let mut buf = Vec::with_capacity(capacity);
                        for range in ranges {
                            let source = &sources[range.source];
                            let range_result = self
                                .get(
                                    source,
                                    GetOptions {
                                        if_match: Some(versions[range.source].clone()),
                                        range: Some(range.start..range.start + range.len),
                                        ..GetOptions::default()
                                    },
                                )
                                .await?;
                            let bytes =
                                collect_compose_range(range_result, source, range.len).await?;
                            buf.extend_from_slice(&bytes);
                        }
                        if buf.len() as u64 != len {
                            return Err(StoreError::InvalidArgument(
                                "s3 compose upload part length changed after planning".into(),
                            ));
                        }
                        let part = self
                            .client
                            .upload_part()
                            .bucket(&self.bucket)
                            .key(dest)
                            .upload_id(&upload_id)
                            .part_number(part_number)
                            .body(S3ByteStream::from(Bytes::from(buf)))
                            .content_length(len as i64)
                            .send()
                            .await
                            .map_err(|e| classify_sdk_error("upload part", dest, e))?;
                        parts.push(
                            aws_sdk_s3::types::CompletedPart::builder()
                                .e_tag(part.e_tag().unwrap_or("").to_owned())
                                .part_number(part_number)
                                .build(),
                        );
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.abort_multipart_after_failure(dest, &upload_id).await;
            return Err(e);
        }
        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        let complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(dest)
            .upload_id(&upload_id)
            .multipart_upload(completed);
        let complete = apply_complete_condition(complete, &opts.mode);
        let resp = match complete.send().await {
            Ok(r) => r,
            Err(e) => {
                self.abort_multipart_after_failure(dest, &upload_id).await;
                let mut error = classify_sdk_error("complete multipart", dest, e);
                if let StoreError::PreconditionFailed { current, .. } = &mut error
                    && current.is_none()
                {
                    *current = self
                        .head(dest)
                        .await
                        .ok()
                        .flatten()
                        .map(|meta| meta.version);
                }
                return Err(error);
            }
        };
        let etag = resp.e_tag().map(|s| s.trim_matches('"').to_owned());
        Ok(ObjectMeta {
            key: dest.into(),
            size: total,
            version: Version::new(etag.as_deref().unwrap_or("")),
        })
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>> {
        let presigning = PresigningConfig::expires_in(ttl)
            .map_err(|e| StoreError::other(anyhow::anyhow!("presigning config: {e}")))?;
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            // Client-facing signed URLs are bearer credentials. Override the object's public
            // immutable metadata so a shared cache cannot retain private repository bytes after
            // the URL expires. A private client cache is safe: the client already downloaded the
            // content-addressed object.
            .response_cache_control("private, max-age=31536000, immutable")
            .presigned(presigning)
            .await
            .map_err(|e| StoreError::other(anyhow::anyhow!("presigning: {e}")))?;
        Ok(Some(presigned.uri().to_owned()))
    }
}

/// State for the lazy list stream.
struct ListState {
    client: S3Client,
    bucket: String,
    prefix: String,
    start_after: Option<String>,
    continuation_token: Option<String>,
    started: bool,
    buffer: std::vec::IntoIter<Result<ObjectMeta>>,
}

// ---- multipart upload --------------------------------------------------

impl S3Store {
    async fn multipart_put(
        &self,
        key: &str,
        reader: &mut UploadReader,
        len: u64,
        opts: &PutOptions,
    ) -> Result<ObjectMeta> {
        let part_size = multipart_part_size(len, self.multipart_part_size)?;
        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key);

        if let Some(ct) = opts.content_type {
            create = create.content_type(ct);
        }
        if opts.immutable {
            create = create.cache_control("public, max-age=31536000, immutable");
        }

        let upload = create
            .send()
            .await
            .map_err(|e| classify_sdk_error("create multipart", key, e))?;

        let upload_id = upload
            .upload_id()
            .ok_or_else(|| {
                StoreError::other(anyhow::anyhow!("no upload_id from CreateMultipartUpload"))
            })?
            .to_owned();

        let mut part_number = 1i32;
        let mut uploaded_parts: Vec<aws_sdk_s3::types::CompletedPart> = Vec::new();
        let mut remaining = len;
        let mut supplied = 0u64;

        while remaining > 0 {
            let this_part = part_size.min(remaining);
            let buf = match read_multipart_part(reader, this_part, len, supplied).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.abort_multipart_after_failure(key, &upload_id).await;
                    return Err(error);
                }
            };
            let actual = buf.len() as u64;

            let part = match self
                .client
                .upload_part()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(S3ByteStream::from(buf))
                .content_length(actual as i64)
                .send()
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    self.abort_multipart_after_failure(key, &upload_id).await;
                    return Err(classify_sdk_error("upload part", key, e));
                }
            };

            let etag = part.e_tag().unwrap_or("").to_owned();
            uploaded_parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .e_tag(etag)
                    .part_number(part_number)
                    .build(),
            );

            remaining -= actual;
            supplied += actual;
            part_number += 1;
        }

        if let Err(error) = ensure_multipart_body_exhausted(reader, len).await {
            self.abort_multipart_after_failure(key, &upload_id).await;
            return Err(error);
        }

        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(uploaded_parts))
            .build();

        let complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed);
        let complete = apply_complete_condition(complete, &opts.mode);
        let resp = match complete.send().await {
            Ok(r) => r,
            Err(e) => {
                self.abort_multipart_after_failure(key, &upload_id).await;
                let mut error = classify_sdk_error("complete multipart", key, e);
                if let StoreError::PreconditionFailed { current, .. } = &mut error
                    && current.is_none()
                {
                    *current = self.head(key).await.ok().flatten().map(|meta| meta.version);
                }
                return Err(error);
            }
        };

        let etag = resp.e_tag().map(|s| s.trim_matches('"').to_owned());
        Ok(ObjectMeta {
            key: key.into(),
            size: len,
            version: Version::new(etag.as_deref().unwrap_or("")),
        })
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| classify_sdk_error("abort multipart", key, e))?;
        Ok(())
    }

    async fn abort_multipart_after_failure(&self, key: &str, upload_id: &str) {
        if let Err(error) = self.abort_multipart(key, upload_id).await {
            let category = match error {
                StoreError::NotFound { .. } => "not-found",
                StoreError::PreconditionFailed { .. } => "precondition",
                StoreError::Retryable(_) => "retryable",
                StoreError::InvalidArgument(_) => "invalid-argument",
                StoreError::Other(_) => "other",
            };
            tracing::warn!(
                key,
                error_category = category,
                "failed to abort multipart upload; bucket lifecycle cleanup is required"
            );
        }
    }
}

// ---- rustfs compatibility notes (integration testing) -------------------
//
// 1. Presigned URLs: rustfs honors SigV4 presigned GET URLs with conditional
//    headers (If-None-Match, If-Match, Range) in SignedHeaders.
// 2. If-None-Match: * on PUT: 412 "PreconditionFailed" when object exists.
// 3. If-Match: <etag> on PUT: 412 when ETag mismatch.
// 4. 304 Not Modified: HTTP 304 with ETag header, empty body.
// 5. ListObjectsV2: StartAfter, ContinuationToken, IsTruncated/NextToken OK.
// 6. DeleteObject: idempotent for absent keys (204).
// 7. Multipart: CreateMultipartUpload + UploadPart + CompleteMultipartUpload
//    are supported. The exact selected provider must separately prove the
//    conditional CompleteMultipartUpload headers required by this backend.
// 8. ETags: quoted, MD5 for single-PUT, compound for multipart. Quotes
//    stripped consistently in our Version.
// 9. force_path_style: required for rustfs local dev.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn explicit_credentials_fall_back_only_when_both_are_absent() {
        let empty = HashMap::<&str, &str>::new();
        assert!(
            explicit_credentials("ACCESS", "SECRET", "", |name| empty
                .get(name)
                .map(ToString::to_string))
            .expect("absent credentials use default chain")
            .is_none()
        );

        let both = HashMap::from([("ACCESS", "access-value"), ("SECRET", "secret-value")]);
        assert_eq!(
            explicit_credentials("ACCESS", "SECRET", "", |name| both
                .get(name)
                .map(ToString::to_string))
            .expect("complete explicit credentials"),
            Some(("access-value".into(), "secret-value".into(), None))
        );
    }

    #[test]
    fn default_chain_owns_standard_aws_environment() {
        let standard = HashMap::from([
            ("AWS_ACCESS_KEY_ID", "access-value"),
            ("AWS_SECRET_ACCESS_KEY", "secret-value"),
            ("AWS_SESSION_TOKEN", "token-value"),
        ]);
        assert!(
            explicit_credentials("", "", "", |name| standard
                .get(name)
                .map(ToString::to_string))
            .expect("empty override names select the SDK default chain")
            .is_none()
        );

        let defaults = walgit_config::S3Config::default();
        assert!(defaults.access_key_env.is_empty());
        assert!(defaults.secret_key_env.is_empty());
        assert!(defaults.session_token_env.is_empty());
    }

    #[test]
    fn explicit_temporary_credentials_include_session_token() {
        let values = HashMap::from([
            ("CUSTOM_ACCESS", "access-value"),
            ("CUSTOM_SECRET", "secret-value"),
            ("CUSTOM_TOKEN", "token-value"),
        ]);
        assert_eq!(
            explicit_credentials("CUSTOM_ACCESS", "CUSTOM_SECRET", "CUSTOM_TOKEN", |name| {
                values.get(name).map(ToString::to_string)
            },)
            .expect("complete temporary credentials"),
            Some((
                "access-value".into(),
                "secret-value".into(),
                Some("token-value".into())
            ))
        );
    }

    #[test]
    fn partial_explicit_credentials_fail_without_exposing_values() {
        let values = HashMap::from([("ACCESS", "must-not-appear")]);
        let error = explicit_credentials("ACCESS", "SECRET", "", |name| {
            values.get(name).map(ToString::to_string)
        })
        .expect_err("partial override must fail")
        .to_string();
        assert!(error.contains("ACCESS"));
        assert!(error.contains("SECRET"));
        assert!(!error.contains("must-not-appear"));

        let empty_secret = HashMap::from([("ACCESS", "must-not-appear"), ("SECRET", "")]);
        assert!(
            explicit_credentials("ACCESS", "SECRET", "", |name| empty_secret
                .get(name)
                .map(ToString::to_string))
            .is_err()
        );

        let missing_token = HashMap::from([
            ("ACCESS", "must-not-appear"),
            ("SECRET", "also-must-not-appear"),
        ]);
        let error = explicit_credentials("ACCESS", "SECRET", "TOKEN", |name| {
            missing_token.get(name).map(ToString::to_string)
        })
        .expect_err("a configured session-token variable must resolve")
        .to_string();
        assert!(!error.contains("must-not-appear"));
        assert!(!error.contains("also-must-not-appear"));
        assert!(explicit_credentials("ACCESS", "", "", |_| None).is_err());
        assert!(explicit_credentials("", "", "TOKEN", |_| None).is_err());
    }

    #[tokio::test]
    async fn client_signed_urls_override_public_object_cache_metadata() {
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "test-access",
                "test-secret",
                None,
                None,
                "unit-test",
            ))
            .endpoint_url("http://127.0.0.1:9000")
            .force_path_style(true)
            .build();
        let store = S3Store {
            client: S3Client::from_conf(config),
            bucket: "test-bucket".into(),
            http: reqwest::Client::new(),
            multipart_threshold: 8 * 1024 * 1024,
            multipart_part_size: S3_MIN_PART_SIZE,
        };

        let url = store
            .signed_get_url("lfs/private-object", Duration::from_secs(60))
            .await
            .expect("signing must succeed")
            .expect("S3 supports signed URLs");
        let cache_control = reqwest::Url::parse(&url)
            .expect("signed URL")
            .query_pairs()
            .find_map(|(name, value)| {
                (name == "response-cache-control").then(|| value.into_owned())
            });
        assert_eq!(
            cache_control.as_deref(),
            Some("private, max-age=31536000, immutable")
        );
    }

    #[tokio::test]
    async fn presigned_reqwest_errors_never_expose_url_credentials() {
        const SENTINEL: &str = "URL_SECRET_SENTINEL";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept request");
            drop(stream);
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("test client");
        let error = client
            .get(format!(
                "http://{address}/object?X-Amz-Credential={SENTINEL}&X-Amz-Signature={SENTINEL}"
            ))
            .send()
            .await
            .expect_err("closed loopback connection must reject the request");
        server.await.expect("loopback server task");
        assert!(
            error
                .url()
                .is_some_and(|url| url.as_str().contains(SENTINEL)),
            "the test error must initially own the sensitive URL"
        );
        let sanitized = sanitized_reqwest_error("get request", error).to_string();
        assert!(!sanitized.contains(SENTINEL));
        assert!(!sanitized.contains("X-Amz-"));
    }

    #[tokio::test]
    async fn only_transient_reqwest_categories_are_retryable() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("test client");
        let builder_error = client
            .get("http://[::1")
            .send()
            .await
            .expect_err("invalid URL must fail");
        assert!(matches!(
            sanitized_reqwest_error("get request", builder_error),
            StoreError::Other(_)
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        drop(listener);
        let connect_error = client
            .get(format!("http://{address}/object"))
            .send()
            .await
            .expect_err("closed loopback port must fail");
        assert!(matches!(
            sanitized_reqwest_error("get request", connect_error),
            StoreError::Retryable(_)
        ));
    }

    #[tokio::test]
    async fn declared_body_length_is_exact() {
        let mut exact: UploadReader = Box::new(Cursor::new(Bytes::from_static(b"abcd")));
        assert_eq!(
            read_declared_body(&mut exact, 4).await.expect("exact body"),
            Bytes::from_static(b"abcd")
        );

        let mut short: UploadReader = Box::new(Cursor::new(Bytes::from_static(b"abc")));
        let short_error = read_declared_body(&mut short, 4)
            .await
            .expect_err("early EOF must fail");
        assert!(matches!(short_error, StoreError::InvalidArgument(_)));

        let mut long: UploadReader = Box::new(Cursor::new(Bytes::from_static(b"abcde")));
        let long_error = read_declared_body(&mut long, 4)
            .await
            .expect_err("extra bytes must fail");
        assert!(matches!(long_error, StoreError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn multipart_part_reads_reject_early_eof_and_trailing_data() {
        let mut short: UploadReader = Box::new(Cursor::new(Bytes::from_static(b"abc")));
        let error = read_multipart_part(&mut short, 4, 8, 4)
            .await
            .expect_err("multipart early EOF must fail");
        assert!(error.to_string().contains("ended after 7 bytes"));

        let mut long: UploadReader = Box::new(Cursor::new(Bytes::from_static(b"abcde")));
        assert_eq!(
            read_multipart_part(&mut long, 4, 4, 0)
                .await
                .expect("declared multipart part"),
            Bytes::from_static(b"abcd")
        );
        let error = ensure_multipart_body_exhausted(&mut long, 4)
            .await
            .expect_err("multipart trailing data must fail");
        assert!(error.to_string().contains("supplied more data"));
    }

    #[tokio::test]
    async fn compose_range_collection_ignores_large_source_meta_and_is_exact() {
        let expected = 5 * 1024 * 1024u64;
        let result = GetResult::Object {
            meta: ObjectMeta {
                key: "large-pack".into(),
                size: 30 * 1024 * 1024 * 1024,
                version: Version::new("version"),
            },
            body: Box::pin(futures::stream::iter([
                Ok(Bytes::from(vec![b'a'; 2 * 1024 * 1024])),
                Ok(Bytes::from(vec![b'b'; 3 * 1024 * 1024])),
            ])),
        };
        let bytes = collect_compose_range(result, "large-pack", expected)
            .await
            .expect("bounded range");
        assert_eq!(bytes.len() as u64, expected);
        assert_eq!(bytes[0], b'a');
        assert_eq!(bytes[bytes.len() - 1], b'b');

        let truncated = GetResult::Object {
            meta: ObjectMeta {
                key: "large-pack".into(),
                size: 30 * 1024 * 1024 * 1024,
                version: Version::new("version"),
            },
            body: crate::util::once(Bytes::from_static(b"short")),
        };
        assert!(
            collect_compose_range(truncated, "large-pack", 6)
                .await
                .is_err()
        );
    }

    #[test]
    fn complete_multipart_conditions_are_attached_to_final_write() {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .build();
        let client = S3Client::from_conf(config);

        let create = apply_complete_condition(client.complete_multipart_upload(), &PutMode::Create);
        assert_eq!(create.get_if_none_match().as_deref(), Some("*"));
        assert!(create.get_if_match().is_none());

        let update_version = Version::new("etag");
        let update = apply_complete_condition(
            client.complete_multipart_upload(),
            &PutMode::Update(update_version),
        );
        assert_eq!(update.get_if_match().as_deref(), Some("etag"));
        assert!(update.get_if_none_match().is_none());
    }

    #[test]
    fn multipart_layout_stays_within_s3_limits() {
        assert_eq!(
            multipart_part_size(64 * 1024 * 1024 * 1024, 32 * 1024 * 1024).expect("64 GiB receive"),
            32 * 1024 * 1024
        );
        let five_tib = 5 * 1024 * 1024 * 1024 * 1024u64;
        let size = multipart_part_size(five_tib, S3_MIN_PART_SIZE).expect("S3 maximum object");
        assert!(five_tib.div_ceil(size) <= S3_MAX_PARTS);
        assert!(size <= S3_MAX_PART_SIZE);
        assert!(multipart_part_size(1, S3_MIN_PART_SIZE - 1).is_err());
        assert!(multipart_part_size(five_tib + 1, S3_MIN_PART_SIZE).is_err());
    }

    #[test]
    fn compose_layout_coalesces_fragmented_sources_before_upload() {
        let mib = 1024 * 1024u64;
        let sizes = vec![mib; 10_001];
        let total: u64 = sizes.iter().sum();
        let target = multipart_part_size(total, S3_MIN_PART_SIZE).expect("part target");
        let plans = compose_part_plan(&sizes, target).expect("fragmented layout");

        assert!(plans.len() as u64 <= S3_MAX_PARTS);
        assert_eq!(plans.iter().map(ComposePartPlan::len).sum::<u64>(), total);
        assert!(
            plans[..plans.len() - 1]
                .iter()
                .all(|plan| plan.len() >= S3_MIN_PART_SIZE)
        );
        assert!(plans.iter().any(|plan| matches!(
            plan,
            ComposePartPlan::Upload(ranges) if ranges.len() > 1
        )));
    }

    #[test]
    fn compose_layout_uses_copy_ranges_up_to_five_gib() {
        let gib = 1024 * 1024 * 1024u64;
        let target = multipart_part_size(11 * gib, S3_MAX_PART_SIZE).expect("part target");
        let plans = compose_part_plan(&[11 * gib], target).expect("copy layout");
        assert_eq!(plans.len(), 3);
        assert_eq!(plans[0].len(), S3_MAX_PART_SIZE);
        assert_eq!(plans[1].len(), S3_MAX_PART_SIZE);
        assert_eq!(plans[2].len(), gib);
        assert!(
            plans
                .iter()
                .all(|plan| matches!(plan, ComposePartPlan::Copy(_)))
        );
    }

    #[test]
    fn compose_layout_preserves_one_gib_copy_roundtrips() {
        let mib = 1024 * 1024u64;
        let gib = 1024 * mib;
        let total = 30 * gib;
        let target = multipart_part_size(total, 32 * mib).expect("part target");
        let plans = compose_part_plan(&[total], target).expect("copy layout");
        assert_eq!(plans.len(), 30);
        assert!(plans.iter().all(|plan| plan.len() == gib));
        assert!(
            plans
                .iter()
                .all(|plan| matches!(plan, ComposePartPlan::Copy(_)))
        );
    }

    #[test]
    fn compose_layout_coalesces_more_than_ten_thousand_near_minimum_sources() {
        let source_size = 6 * 1024 * 1024u64;
        let sizes = vec![source_size; 10_001];
        let total: u64 = sizes.iter().sum();
        let target = multipart_part_size(total, S3_MIN_PART_SIZE).expect("dynamic part target");
        assert!(target > source_size);

        let plans = compose_part_plan(&sizes, target).expect("bounded fragmented layout");
        assert!(plans.len() as u64 <= S3_MAX_PARTS);
        assert_eq!(plans.iter().map(ComposePartPlan::len).sum::<u64>(), total);
        assert!(plans.iter().any(|plan| matches!(
            plan,
            ComposePartPlan::Upload(ranges) if ranges.len() > 1
        )));
    }

    #[test]
    fn retryable_service_codes_are_bounded_and_explicit() {
        for code in [
            "InternalError",
            "ConditionalRequestConflict",
            "RequestTimeout",
            "ServiceUnavailable",
            "SlowDown",
            "Throttling",
            "TooManyRequestsException",
        ] {
            assert!(retryable_service_code(code), "{code}");
        }
        for code in ["NoSuchKey", "PreconditionFailed", "AccessDenied"] {
            assert!(!retryable_service_code(code), "{code}");
        }
        assert!(!retryable_status(409));
        assert!(!retryable_status(412));
    }
}

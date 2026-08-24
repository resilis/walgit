//! In-memory backend: reference semantics for tests. Versions are a global
//! monotonic counter so they are unique across keys and time, like generations.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use futures::StreamExt;
use parking_lot::Mutex;

use crate::{
    BoxStream, CasToken, ComposeSource, GetOptions, GetResult, MAX_VERSION_PAGE_SIZE, ObjectMeta,
    ObjectStore, ObjectVersion, ObjectVersionId, ObjectVersionKind, PutBody, PutMode, PutOptions,
    Result, StoreError, VersionCursor, VersionPage, util,
};

#[derive(Clone)]
struct MemoryVersion {
    cas_token: CasToken,
    object_version_id: ObjectVersionId,
    body: Option<Bytes>,
}

#[derive(Default)]
pub struct MemoryStore {
    objects: Mutex<BTreeMap<String, Vec<MemoryVersion>>>,
    counter: AtomicU64,
    /// Optional artificial latency per op (tests of races/batching).
    pub latency: Option<std::time::Duration>,
    /// Tests of edge offload (X-Accel-Redirect): when set, `accel_target` returns a
    /// URL + bearer pair like GCS would.
    pub fake_object_urls: std::sync::atomic::AtomicBool,
    /// Test switch: `signed_get_url` fails like a store whose signing permission
    /// is unavailable or denied.
    pub signing_fails: bool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
    fn next_version(&self) -> (CasToken, ObjectVersionId) {
        let value = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        (
            CasToken::new(format!("cas-{value}")),
            ObjectVersionId::new(format!("version-{value}")),
        )
    }
    async fn delay(&self) {
        if let Some(d) = self.latency {
            tokio::time::sleep(d).await;
        }
    }
    pub fn len(&self) -> usize {
        self.objects
            .lock()
            .values()
            .filter(|versions| {
                versions
                    .last()
                    .is_some_and(|version| version.body.is_some())
            })
            .count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

async fn body_bytes(body: PutBody) -> Result<Bytes> {
    Ok(match body {
        PutBody::Bytes(b) => b,
        PutBody::Stream { len, stream } => util::collect_exact(stream, len).await?,
        PutBody::File(p) => Bytes::from(tokio::fs::read(&p).await.map_err(StoreError::other)?),
    })
}

#[async_trait::async_trait]
impl ObjectStore for MemoryStore {
    async fn signed_get_url(&self, key: &str, _ttl: std::time::Duration) -> Result<Option<String>> {
        if self.signing_fails {
            return Err(StoreError::other(anyhow::anyhow!(
                "signBlob for {key}: PERMISSION_DENIED (VPC_SERVICE_CONTROLS) [test]"
            )));
        }
        Ok(None)
    }

    fn backend(&self) -> &'static str {
        "memory"
    }

    async fn accel_target(&self, key: &str) -> Option<crate::AccelTarget> {
        self.fake_object_urls
            .load(Ordering::Relaxed)
            .then(|| crate::AccelTarget {
                url: format!("https://storage.example.test/test-bucket/{key}"),
                authorization: Some("Bearer test-store-access-token".to_string()),
            })
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult> {
        self.delay().await;
        let selected = {
            let g = self.objects.lock();
            let versions = g
                .get(key)
                .ok_or_else(|| StoreError::NotFound { key: key.into() })?;
            match &opts.object_version_id {
                Some(version_id) => versions
                    .iter()
                    .find(|version| &version.object_version_id == version_id),
                None => versions.last(),
            }
            .cloned()
            .ok_or_else(|| StoreError::NotFound { key: key.into() })?
        };
        let data = selected
            .body
            .ok_or_else(|| StoreError::NotFound { key: key.into() })?;
        let version = selected.cas_token;
        if let Some(m) = &opts.if_match
            && *m != version
        {
            return Err(StoreError::PreconditionFailed {
                key: key.into(),
                current: Some(version),
            });
        }
        if opts.if_none_match.as_ref() == Some(&version) {
            return Ok(GetResult::NotModified { version });
        }
        let size = data.len() as u64;
        let slice = match &opts.range {
            Some(r) => {
                let start = r.start.min(size) as usize;
                let end = r.end.min(size) as usize;
                if start > end {
                    return Err(StoreError::InvalidArgument(format!(
                        "bad range {r:?} for size {size}"
                    )));
                }
                data.slice(start..end)
            }
            None => data,
        };
        Ok(GetResult::Object {
            meta: ObjectMeta {
                key: key.into(),
                size,
                version,
                object_version_id: Some(selected.object_version_id),
            },
            body: util::once(slice),
        })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        self.delay().await;
        Ok(self
            .objects
            .lock()
            .get(key)
            .and_then(|versions| versions.last())
            .and_then(|version| {
                version.body.as_ref().map(|body| ObjectMeta {
                    key: key.into(),
                    size: body.len() as u64,
                    version: version.cas_token.clone(),
                    object_version_id: Some(version.object_version_id.clone()),
                })
            }))
    }

    async fn put(&self, key: &str, body: PutBody, opts: PutOptions) -> Result<ObjectMeta> {
        let data = body_bytes(body).await?;
        self.delay().await;
        let mut g = self.objects.lock();
        let current = g.get(key).and_then(|versions| {
            versions
                .last()
                .and_then(|version| version.body.as_ref().map(|_| version.cas_token.clone()))
        });
        match (&opts.mode, &current) {
            (PutMode::Overwrite, _) => {}
            (PutMode::Create, None) => {}
            (PutMode::Create, Some(v)) => {
                return Err(StoreError::PreconditionFailed {
                    key: key.into(),
                    current: Some(v.clone()),
                });
            }
            (PutMode::Update(want), Some(v)) if want == v => {}
            (PutMode::Update(_), cur) => {
                return Err(StoreError::PreconditionFailed {
                    key: key.into(),
                    current: cur.clone(),
                });
            }
        }
        let (version, object_version_id) = self.next_version();
        let size = data.len() as u64;
        g.entry(key.to_owned()).or_default().push(MemoryVersion {
            cas_token: version.clone(),
            object_version_id: object_version_id.clone(),
            body: Some(data),
        });
        Ok(ObjectMeta {
            key: key.into(),
            size,
            version,
            object_version_id: Some(object_version_id),
        })
    }

    fn supports_compose(&self) -> bool {
        true
    }
    fn compose_is_native(&self) -> bool {
        true
    }

    async fn compose(
        &self,
        dest: &str,
        sources: &[ComposeSource],
        opts: PutOptions,
    ) -> Result<ObjectMeta> {
        if sources.is_empty() {
            return Err(StoreError::InvalidArgument(
                "compose needs at least one source".into(),
            ));
        }
        let mut buf = bytes::BytesMut::new();
        {
            let g = self.objects.lock();
            for source in sources {
                let version = g
                    .get(&source.key)
                    .and_then(|versions| {
                        versions
                            .iter()
                            .find(|version| version.object_version_id == source.object_version_id)
                    })
                    .ok_or_else(|| StoreError::NotFound {
                        key: source.key.clone(),
                    })?;
                let data = version.body.as_ref().ok_or_else(|| StoreError::NotFound {
                    key: source.key.clone(),
                })?;
                if version.cas_token != source.cas_token {
                    return Err(StoreError::PreconditionFailed {
                        key: source.key.clone(),
                        current: Some(version.cas_token.clone()),
                    });
                }
                if data.len() as u64 != source.size {
                    return Err(StoreError::InvalidArgument(format!(
                        "compose source {} size is {}, expected {}",
                        source.key,
                        data.len(),
                        source.size
                    )));
                }
                buf.extend_from_slice(data);
            }
        }
        self.put(dest, PutBody::Bytes(buf.freeze()), opts).await
    }

    async fn delete(&self, key: &str, if_version: Option<CasToken>) -> Result<()> {
        self.delay().await;
        let mut g = self.objects.lock();
        let current = g.get(key).and_then(|versions| versions.last());
        match (current, if_version) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(StoreError::NotFound { key: key.into() }),
            (Some(version), None) if version.body.is_none() => Ok(()),
            (Some(version), Some(_)) if version.body.is_none() => {
                Err(StoreError::NotFound { key: key.into() })
            }
            (Some(version), Some(want)) if version.cas_token != want => {
                Err(StoreError::PreconditionFailed {
                    key: key.into(),
                    current: Some(version.cas_token.clone()),
                })
            }
            _ => {
                let (cas_token, object_version_id) = self.next_version();
                g.entry(key.to_owned()).or_default().push(MemoryVersion {
                    cas_token,
                    object_version_id,
                    body: None,
                });
                Ok(())
            }
        }
    }

    async fn head_version(
        &self,
        key: &str,
        version_id: &ObjectVersionId,
    ) -> Result<Option<ObjectMeta>> {
        self.delay().await;
        Ok(self.objects.lock().get(key).and_then(|versions| {
            versions
                .iter()
                .find(|version| &version.object_version_id == version_id)
                .and_then(|version| {
                    version.body.as_ref().map(|body| ObjectMeta {
                        key: key.to_owned(),
                        size: body.len() as u64,
                        version: version.cas_token.clone(),
                        object_version_id: Some(version.object_version_id.clone()),
                    })
                })
        }))
    }

    async fn delete_version(&self, key: &str, version_id: &ObjectVersionId) -> Result<()> {
        self.delay().await;
        let mut objects = self.objects.lock();
        let versions = objects.get_mut(key).ok_or_else(|| StoreError::NotFound {
            key: key.to_owned(),
        })?;
        let index = versions
            .iter()
            .position(|version| &version.object_version_id == version_id)
            .ok_or_else(|| StoreError::NotFound {
                key: key.to_owned(),
            })?;
        versions.remove(index);
        if versions.is_empty() {
            objects.remove(key);
        }
        Ok(())
    }

    async fn list_versions(
        &self,
        prefix: &str,
        cursor: Option<&VersionCursor>,
        limit: usize,
    ) -> Result<VersionPage> {
        if !(1..=MAX_VERSION_PAGE_SIZE).contains(&limit) {
            return Err(StoreError::InvalidArgument(format!(
                "version page size must be in 1..={MAX_VERSION_PAGE_SIZE}"
            )));
        }
        self.delay().await;
        let start = match cursor.and_then(|cursor| cursor.page_token.as_deref()) {
            Some(token) => token
                .strip_prefix("memory:")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| {
                    StoreError::InvalidArgument("invalid memory version cursor".into())
                })?,
            None => 0,
        };
        let objects = self.objects.lock();
        let mut all = Vec::new();
        for (key, versions) in objects
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            for (index, version) in versions.iter().enumerate().rev() {
                all.push(ObjectVersion {
                    key: key.clone(),
                    object_version_id: version.object_version_id.clone(),
                    cas_token: version.body.as_ref().map(|_| version.cas_token.clone()),
                    size: version.body.as_ref().map_or(0, |body| body.len() as u64),
                    kind: if version.body.is_some() {
                        ObjectVersionKind::Object
                    } else {
                        ObjectVersionKind::DeleteMarker
                    },
                    is_latest: index + 1 == versions.len(),
                });
            }
        }
        if start > all.len() {
            return Err(StoreError::InvalidArgument(
                "memory version cursor is past the result set".into(),
            ));
        }
        let end = start.saturating_add(limit).min(all.len());
        let page = all[start..end].to_vec();
        let next = (end < all.len()).then(|| VersionCursor {
            key_marker: None,
            version_id_marker: None,
            page_token: Some(format!("memory:{end}")),
        });
        Ok(VersionPage {
            versions: page,
            next,
        })
    }

    async fn verify_versioning(&self) -> Result<()> {
        Ok(())
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        let g = self.objects.lock();
        let items: Vec<ObjectMeta> = g
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .filter(|(k, _)| start_after.is_none_or(|s| k.as_str() > s))
            .filter_map(|(key, versions)| {
                let version = versions.last()?;
                let body = version.body.as_ref()?;
                Some(ObjectMeta {
                    key: key.clone(),
                    size: body.len() as u64,
                    version: version.cas_token.clone(),
                    object_version_id: Some(version.object_version_id.clone()),
                })
            })
            .collect();
        futures::stream::iter(items.into_iter().map(Ok)).boxed()
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>> {
        let g = self.objects.lock();
        let mut out: Vec<String> = g
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .filter_map(|(k, versions)| {
                versions.last()?.body.as_ref()?;
                let rest = &k[prefix.len()..];
                rest.find('/').map(|i| format!("{prefix}{}/", &rest[..i]))
            })
            .collect();
        out.dedup();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectStoreExt, ObjectVersionKind};

    #[tokio::test]
    async fn cas_semantics() {
        let s = MemoryStore::new();
        let m1 = s.put_bytes("k", "a", PutMode::Create).await.unwrap();
        assert!(
            s.put_bytes("k", "b", PutMode::Create)
                .await
                .unwrap_err()
                .is_precondition_failed()
        );
        let m2 = s
            .put_bytes("k", "b", PutMode::Update(m1.version.clone()))
            .await
            .unwrap();
        assert!(
            s.put_bytes("k", "c", PutMode::Update(m1.version.clone()))
                .await
                .unwrap_err()
                .is_precondition_failed()
        );
        assert!(s.get_if_changed("k", &m2.version).await.unwrap().is_none());
        let (m3, b) = s.get_if_changed("k", &m1.version).await.unwrap().unwrap();
        assert_eq!(m3.version, m2.version);
        assert_eq!(&b[..], b"b");
        assert!(
            s.delete("k", Some(m1.version))
                .await
                .unwrap_err()
                .is_precondition_failed()
        );
        s.delete("k", Some(m2.version)).await.unwrap();
        assert!(s.get_bytes("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn historical_versions_are_exact_and_delete_markers_restore_history() {
        let s = MemoryStore::new();
        s.verify_versioning().await.unwrap();

        let first = s
            .put_bytes("history", "first", PutMode::Create)
            .await
            .unwrap();
        let second = s
            .put_bytes("history", "second", PutMode::Overwrite)
            .await
            .unwrap();
        let first_id = first.object_version_id.clone().unwrap();
        let second_id = second.object_version_id.clone().unwrap();
        assert_ne!(first_id, second_id);

        let (_, old) = s
            .get_version("history", &first_id, None)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&old[..], b"first");

        s.delete_version("history", &first_id).await.unwrap();
        assert_eq!(
            s.head("history").await.unwrap().unwrap().object_version_id,
            Some(second_id.clone())
        );

        s.delete("history", None).await.unwrap();
        assert!(s.head("history").await.unwrap().is_none());
        let page = s.list_versions("history", None, 1).await.unwrap();
        assert_eq!(page.versions.len(), 1);
        assert!(page.next.is_some());
        let next = s
            .list_versions("history", page.next.as_ref(), 1)
            .await
            .unwrap();
        let marker = page
            .versions
            .iter()
            .chain(&next.versions)
            .find(|version| version.kind == ObjectVersionKind::DeleteMarker)
            .expect("delete marker");
        s.delete_version("history", &marker.object_version_id)
            .await
            .unwrap();
        assert_eq!(
            s.head("history").await.unwrap().unwrap().object_version_id,
            Some(second_id)
        );
    }

    #[tokio::test]
    async fn identical_payloads_have_distinct_historical_ids() {
        let s = MemoryStore::new();
        let first = s
            .put_bytes("same", "payload", PutMode::Create)
            .await
            .unwrap();
        let second = s
            .put_bytes("same", "payload", PutMode::Overwrite)
            .await
            .unwrap();
        assert_ne!(first.object_version_id, second.object_version_id);
    }

    #[tokio::test]
    async fn compose_pins_an_exact_source_version() {
        let s = MemoryStore::new();
        let old = s.put_bytes("source", "old", PutMode::Create).await.unwrap();
        let source = ComposeSource::try_from(old).unwrap();
        s.put_bytes("source", "new", PutMode::Overwrite)
            .await
            .unwrap();

        s.compose("dest", &[source], PutOptions::from(PutMode::Create))
            .await
            .unwrap();
        let (_, body) = s.get_bytes("dest").await.unwrap().unwrap();
        assert_eq!(&body[..], b"old");
    }

    #[tokio::test]
    async fn list_prefixes_ignores_deleted_latest_versions() {
        let s = MemoryStore::new();
        s.put_bytes("root/deleted/item", "old", PutMode::Create)
            .await
            .unwrap();
        s.delete("root/deleted/item", None).await.unwrap();
        s.put_bytes("root/live/item", "live", PutMode::Create)
            .await
            .unwrap();

        assert_eq!(s.list_prefixes("root/").await.unwrap(), ["root/live/"]);
        s.delete("root/live/item", None).await.unwrap();
        assert!(s.list_prefixes("root/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn range_and_list() {
        let s = MemoryStore::new();
        s.put_bytes("p/a", "hello world", PutMode::Overwrite)
            .await
            .unwrap();
        s.put_bytes("p/b", "x", PutMode::Overwrite).await.unwrap();
        s.put_bytes("q/c", "y", PutMode::Overwrite).await.unwrap();
        let r = s
            .get(
                "p/a",
                GetOptions {
                    range: Some(6..11),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let (_, b) = r.bytes().await.unwrap().unwrap();
        assert_eq!(&b[..], b"world");
        let keys: Vec<_> = s.list("p/", None).map(|m| m.unwrap().key).collect().await;
        assert_eq!(keys, ["p/a", "p/b"]);
        let keys: Vec<_> = s
            .list("p/", Some("p/a"))
            .map(|m| m.unwrap().key)
            .collect()
            .await;
        assert_eq!(keys, ["p/b"]);
    }
}

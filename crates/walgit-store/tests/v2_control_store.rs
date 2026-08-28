use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, GrantRole, InlineGrants, InlinePackRoots, Lifecycle,
    ObjectFormat, QuotaState, ReclamationPhase, ReclamationState, RepoControl, RepositoryGrant,
    RepositoryIdentity, Visibility, WalState, WriterFence, decode_repo_control,
    encode_repo_control,
    keys::{CanonicalPathDigest, DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::{GrantRepresentation, PackRepresentation},
};
use walgit_store::{
    BoxStream, CasToken, DynStore, GetOptions, GetResult, ObjectMeta, ObjectStore, ObjectStoreExt,
    Prefixed, PutBody, PutMode, PutOptions, Result as StoreResult, StoreError,
    fault::{FaultPlan, FaultStore},
    memory::MemoryStore,
    v2_control::{
        CompareAndSwapOutcome, ControlStore, ControlStoreError, CreateOutcome, StoredRepoControl,
    },
};

const PREFIX: &str = "prod/";

#[tokio::test]
async fn create_load_and_cas_preserve_exact_bindings_and_apply_prefix_once() {
    let truth = MemoryStore::shared();
    let adapter = adapter(scoped(truth.clone()));
    let initial = sample_control();
    let full_key = control_key(&initial).to_owned();

    let first = committed_create(adapter.create(initial.clone()).await.unwrap());
    assert_eq!(first.binding().full_key(), full_key);
    let initial_bytes = encode_repo_control(&initial).unwrap();
    assert_eq!(first.binding().size(), initial_bytes.len() as u64);
    assert_eq!(
        first.binding().digest(),
        walgit_proto::v2::digests::ProtobufObjectDigest::of_exact_protobuf(&initial_bytes)
    );
    assert_ne!(
        first.binding().cas_token().as_str(),
        first.binding().object_version_id().as_str()
    );
    assert_eq!(
        adapter.load(&full_key).await.unwrap().unwrap().binding(),
        first.binding()
    );
    assert!(truth.get_bytes(&full_key).await.unwrap().is_some());
    assert!(
        truth
            .get_bytes(&format!("{PREFIX}{full_key}"))
            .await
            .unwrap()
            .is_none()
    );

    let unpublished = format!(
        "prod/v2/repositories/by-id/{}/g0000000000000001/catalogs/audit/{}.pb",
        "01890f4776447b8b9d7a876543210abd",
        "aa".repeat(32)
    );
    truth
        .put_bytes(
            &unpublished,
            b"unpublished candidate".to_vec(),
            PutMode::Create,
        )
        .await
        .unwrap();
    assert_eq!(
        adapter
            .load(&full_key)
            .await
            .unwrap()
            .unwrap()
            .control()
            .control_revision,
        1
    );

    let successor = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");
    let second = committed_cas(adapter.compare_and_swap(&first, successor).await.unwrap());
    assert_ne!(first.binding().cas_token(), second.binding().cas_token());
    assert_ne!(
        first.binding().object_version_id(),
        second.binding().object_version_id()
    );

    let historical = truth
        .get_version(&full_key, first.binding().object_version_id(), None)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(decode_repo_control(&historical).unwrap(), initial);
}

#[tokio::test]
async fn strict_load_rejects_noncanonical_control_bytes() {
    let truth = MemoryStore::shared();
    let adapter = adapter(scoped(truth.clone()));
    let control = sample_control();
    let full_key = control_key(&control);
    let mut encoded = encode_repo_control(&control).unwrap();
    encoded.extend_from_slice(&[0xf8, 0x07, 0x01]);
    truth
        .put_bytes(full_key, encoded, PutMode::Create)
        .await
        .unwrap();

    assert!(matches!(
        adapter.load(full_key).await,
        Err(ControlStoreError::Codec(_))
    ));
}

#[tokio::test]
async fn load_rejects_provider_size_above_the_control_bound() {
    let truth = MemoryStore::shared();
    let adapter = adapter(scoped(truth.clone()));
    let control = sample_control();
    let full_key = control_key(&control);
    truth
        .put_bytes(
            full_key,
            vec![0; walgit_proto::v2::MAX_REPO_CONTROL_BYTES + 1],
            PutMode::Create,
        )
        .await
        .unwrap();

    assert!(matches!(
        adapter.load(full_key).await,
        Err(ControlStoreError::Metadata(_))
    ));
}

#[tokio::test]
async fn missing_provider_version_identity_never_becomes_a_normal_binding() {
    let truth = MemoryStore::shared();
    let missing_versions = Arc::new(InterposingStore::without_version_ids(scoped(truth.clone())));
    let adapter = adapter(missing_versions);
    let control = sample_control();

    assert!(matches!(
        adapter.create(control.clone()).await.unwrap(),
        CreateOutcome::Indeterminate
    ));
    assert!(
        truth
            .get_bytes(control_key(&control))
            .await
            .unwrap()
            .is_some(),
        "the response is indeterminate because the bytes landed without usable version proof"
    );
}

#[tokio::test]
async fn absent_after_ambiguous_create_remains_indeterminate() {
    let truth = MemoryStore::shared();
    let error_before = Arc::new(InterposingStore::new(
        scoped(truth.clone()),
        InjectedWrite::ErrorBefore,
    ));
    let adapter = adapter(error_before);
    let control = sample_control();

    assert!(matches!(
        adapter.create(control.clone()).await.unwrap(),
        CreateOutcome::Indeterminate
    ));
    assert!(
        truth
            .get_bytes(control_key(&control))
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn adapter_rejects_wrong_or_repeated_store_prefixes() {
    let truth = MemoryStore::shared() as DynStore;
    let expected = DeploymentPrefix::parse(PREFIX).unwrap();
    let wrong: DynStore = Arc::new(Prefixed::new(truth.clone(), "other/"));
    assert!(matches!(
        ControlStore::new(wrong, expected.clone()),
        Err(ControlStoreError::Configuration(_))
    ));

    let once: DynStore = Arc::new(Prefixed::new(truth, PREFIX));
    let twice: DynStore = Arc::new(Prefixed::new(once, PREFIX));
    assert!(matches!(
        ControlStore::new(twice, expected),
        Err(ControlStoreError::Configuration(_))
    ));
}

#[tokio::test]
async fn create_is_idempotent_only_for_the_exact_immutable_binding() {
    let adapter = adapter(scoped(MemoryStore::shared()));
    let initial = sample_control();
    let first = committed_create(adapter.create(initial.clone()).await.unwrap());

    match adapter.create(initial.clone()).await.unwrap() {
        CreateOutcome::ExactReplay(current) => {
            assert_eq!(current.binding(), first.binding());
        }
        other => panic!("expected exact replay, got {other:?}"),
    }

    let mut different = initial;
    different.create_intent_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210ac0").unwrap());
    match adapter.create(different).await.unwrap() {
        CreateOutcome::Conflict(Some(current)) => {
            assert_eq!(current.binding(), first.binding());
        }
        other => panic!("expected create conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn stale_cas_returns_current_conflict_without_retry_or_rebase() {
    let truth = MemoryStore::shared();
    let fault = FaultStore::new(scoped(truth), "cas-conflict", 11);
    let adapter = adapter(fault.clone());
    let initial = sample_control();
    let first = committed_create(adapter.create(initial.clone()).await.unwrap());
    let winner = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");
    let winner = committed_cas(adapter.compare_and_swap(&first, winner).await.unwrap());

    let loser = successor(&initial, 2, "01890f4776447b8b9d7a876543210ac0");
    let before = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);
    match adapter.compare_and_swap(&first, loser).await.unwrap() {
        CompareAndSwapOutcome::Conflict(Some(current)) => {
            assert_eq!(current.binding(), winner.binding());
        }
        other => panic!("expected CAS conflict, got {other:?}"),
    }
    let after = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(after - before, 2, "one CAS plus one conflict read");
}

#[tokio::test]
async fn repeated_exact_cas_resolves_412_as_committed_with_one_get() {
    let truth = MemoryStore::shared();
    let fault = FaultStore::new(scoped(truth), "exact-cas-replay", 13);
    let adapter = adapter(fault.clone());
    let initial = sample_control();
    let first = committed_create(adapter.create(initial.clone()).await.unwrap());
    let successor = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");
    let landed = committed_cas(
        adapter
            .compare_and_swap(&first, successor.clone())
            .await
            .unwrap(),
    );

    let before = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);
    let replay = committed_cas(adapter.compare_and_swap(&first, successor).await.unwrap());
    let after = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);

    assert_eq!(replay, landed);
    assert_eq!(
        after - before,
        2,
        "the 412 path is exactly one failed CAS plus one strict GET; no retry, rebase, HEAD, or LIST"
    );
}

#[tokio::test]
async fn fault_store_lost_responses_are_resolved_with_one_fresh_read() {
    let truth = MemoryStore::shared();
    let fault = FaultStore::new(scoped(truth), "lost-response", 17);
    fault.set(FaultPlan {
        p_err_after: 1.0,
        only_keys: Some(vec!["repo_control.pb".to_owned()]),
        ..Default::default()
    });
    let adapter = adapter(fault.clone());
    let initial = sample_control();

    let first = match adapter.create(initial.clone()).await.unwrap() {
        CreateOutcome::ExactReplay(current) => current,
        other => panic!("expected resolved lost Create, got {other:?}"),
    };
    assert_eq!(
        fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    let next = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");
    let second = committed_cas(adapter.compare_and_swap(&first, next).await.unwrap());
    assert_eq!(second.control().control_revision, 2);
    assert_eq!(
        fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed),
        4
    );
    assert_eq!(
        fault
            .stats()
            .err_after
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[tokio::test]
async fn ambiguous_cas_distinguishes_unchanged_prior_from_a_later_successor() {
    let truth = MemoryStore::shared();
    let normal_scoped = scoped(truth);
    let normal = adapter(normal_scoped.clone());
    let initial = sample_control();
    let first = committed_create(normal.create(initial.clone()).await.unwrap());
    let second_control = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");

    let before_error = Arc::new(InterposingStore::new(
        normal_scoped.clone(),
        InjectedWrite::ErrorBefore,
    ));
    match adapter(before_error)
        .compare_and_swap(&first, second_control.clone())
        .await
        .unwrap()
    {
        CompareAndSwapOutcome::NotCommitted(current) => {
            assert_eq!(current.binding(), first.binding());
        }
        other => panic!("expected proved not-committed, got {other:?}"),
    }

    let third_control = successor(&second_control, 3, "01890f4776447b8b9d7a876543210ac1");
    let interleaved = Arc::new(InterposingStore::new(
        normal_scoped,
        InjectedWrite::ApplyThenSuccessor(Bytes::from(
            encode_repo_control(&third_control).unwrap(),
        )),
    ));
    assert!(matches!(
        adapter(interleaved)
            .compare_and_swap(&first, second_control)
            .await
            .unwrap(),
        CompareAndSwapOutcome::Indeterminate
    ));
    assert_eq!(
        normal
            .load(control_key(&initial))
            .await
            .unwrap()
            .unwrap()
            .control()
            .control_revision,
        3
    );
}

#[tokio::test]
async fn invalid_successors_are_rejected_before_any_store_operation() {
    let fault = FaultStore::new(scoped(MemoryStore::shared()), "validation", 23);
    let adapter = adapter(fault.clone());
    let initial = sample_control();
    let first = committed_create(adapter.create(initial.clone()).await.unwrap());
    let before = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);

    let mut changed_identity = successor(&initial, 2, "01890f4776447b8b9d7a876543210abf");
    changed_identity.identity.as_mut().unwrap().tenant_id = Bytes::from_static(b"other-tenant");
    assert!(matches!(
        adapter.compare_and_swap(&first, changed_identity).await,
        Err(ControlStoreError::InvalidSuccessor(_))
    ));

    let revision_gap = successor(&initial, 3, "01890f4776447b8b9d7a876543210ac0");
    assert!(matches!(
        adapter.compare_and_swap(&first, revision_gap).await,
        Err(ControlStoreError::InvalidSuccessor(_))
    ));
    assert_eq!(
        fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed),
        before,
        "validation must happen before the conditional PUT"
    );
}

#[tokio::test]
async fn create_rejects_non_active_initial_state_without_a_store_operation() {
    let fault = FaultStore::new(scoped(MemoryStore::shared()), "initial-state", 29);
    let adapter = adapter(fault.clone());
    let mut deleting = sample_control();
    deleting.lifecycle = Lifecycle::Deleting as i32;

    assert!(matches!(
        adapter.create(deleting).await,
        Err(ControlStoreError::InitialControl(_))
    ));
    assert_eq!(
        fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

fn adapter(store: DynStore) -> ControlStore {
    ControlStore::new(store, DeploymentPrefix::parse(PREFIX).unwrap()).unwrap()
}

fn scoped(truth: Arc<MemoryStore>) -> DynStore {
    Arc::new(Prefixed::new(truth as DynStore, PREFIX))
}

fn committed_create(outcome: CreateOutcome) -> StoredRepoControl {
    match outcome {
        CreateOutcome::Committed(stored) => stored,
        other => panic!("expected committed Create, got {other:?}"),
    }
}

fn committed_cas(outcome: CompareAndSwapOutcome) -> StoredRepoControl {
    match outcome {
        CompareAndSwapOutcome::Committed(stored) => stored,
        other => panic!("expected committed CAS, got {other:?}"),
    }
}

fn control_key(control: &RepoControl) -> &str {
    std::str::from_utf8(&control.repo_control_key).unwrap()
}

fn successor(control: &RepoControl, revision: u64, mutation_id: &str) -> RepoControl {
    let mut successor = control.clone();
    successor.control_revision = revision;
    successor.last_internal_mutation_id = Bytes::from(hex::decode(mutation_id).unwrap());
    successor
}

enum InjectedWrite {
    ErrorBefore,
    ApplyThenSuccessor(Bytes),
}

struct InterposingStore {
    inner: DynStore,
    write: Mutex<Option<InjectedWrite>>,
    strip_version_ids: bool,
}

impl InterposingStore {
    fn new(inner: DynStore, write: InjectedWrite) -> Self {
        Self {
            inner,
            write: Mutex::new(Some(write)),
            strip_version_ids: false,
        }
    }

    fn without_version_ids(inner: DynStore) -> Self {
        Self {
            inner,
            write: Mutex::new(None),
            strip_version_ids: true,
        }
    }

    fn strip_version_id(&self, mut meta: ObjectMeta) -> ObjectMeta {
        if self.strip_version_ids {
            meta.object_version_id = None;
        }
        meta
    }
}

#[async_trait::async_trait]
impl ObjectStore for InterposingStore {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    fn is_prefixed(&self) -> bool {
        self.inner.is_prefixed()
    }

    fn applied_prefix(&self) -> &str {
        self.inner.applied_prefix()
    }

    async fn get(&self, key: &str, opts: GetOptions) -> StoreResult<GetResult> {
        match self.inner.get(key, opts).await? {
            GetResult::Object { meta, body } => Ok(GetResult::Object {
                meta: self.strip_version_id(meta),
                body,
            }),
            unchanged @ GetResult::NotModified { .. } => Ok(unchanged),
        }
    }

    async fn head(&self, key: &str) -> StoreResult<Option<ObjectMeta>> {
        self.inner.head(key).await
    }

    async fn put(&self, key: &str, body: PutBody, opts: PutOptions) -> StoreResult<ObjectMeta> {
        let injected = self.write.lock().take();
        match injected {
            Some(InjectedWrite::ErrorBefore) => Err(StoreError::retryable(anyhow::anyhow!(
                "injected error before write"
            ))),
            Some(InjectedWrite::ApplyThenSuccessor(successor)) => {
                let applied = self.inner.put(key, body, opts).await?;
                self.inner
                    .put(
                        key,
                        PutBody::Bytes(successor),
                        PutMode::Update(applied.version).into(),
                    )
                    .await?;
                Err(StoreError::retryable(anyhow::anyhow!(
                    "injected lost response after a later CAS"
                )))
            }
            None => self
                .inner
                .put(key, body, opts)
                .await
                .map(|meta| self.strip_version_id(meta)),
        }
    }

    async fn delete(&self, key: &str, if_version: Option<CasToken>) -> StoreResult<()> {
        self.inner.delete(key, if_version).await
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, StoreResult<ObjectMeta>> {
        self.inner.list(prefix, start_after)
    }

    async fn list_prefixes(&self, prefix: &str) -> StoreResult<Vec<String>> {
        self.inner.list_prefixes(prefix).await
    }
}

fn sample_control() -> RepoControl {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let path = Bytes::from_static(b"tenant/project/repo");
    let canonical = CanonicalPathDigest::of(&path);
    let routing = RoutingDigest::of(&path).unwrap();
    RepoControl {
        schema_version: 2,
        identity: Some(RepositoryIdentity {
            tenant_id: Bytes::from_static(b"tenant-1"),
            project_id: Bytes::from_static(b"project-1"),
            repository_uuid: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abd").unwrap()),
            generation: 1,
            canonical_path: path,
            canonical_path_digest: Bytes::copy_from_slice(canonical.as_bytes()),
            routing_digest: Bytes::copy_from_slice(routing.as_bytes()),
        }),
        create_intent_id: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abc").unwrap()),
        create_intent_digest: Bytes::from(
            hex::decode("25c45a88b53645d3ce1bef07ee554a616c0ab425efbc7c95a8387914156912a6")
                .unwrap(),
        ),
        create_intent_cose: Bytes::from_static(b"cose"),
        repo_control_key: Bytes::from(repo_control_key(&prefix, routing).unwrap()),
        object_format: ObjectFormat::Sha1 as i32,
        lifecycle: Lifecycle::Active as i32,
        visibility: Visibility::Private as i32,
        control_revision: 1,
        cutover_generation: 1,
        writer: Some(WriterFence {
            holder: Bytes::from_static(b"writer-1"),
            epoch: 1,
        }),
        authorization_epoch: 1,
        quota: Some(QuotaState {
            logical_quota_bytes: 1_000_000,
            charged_git_bytes: 0,
            charged_lfs_bytes: 0,
        }),
        capacity: Some(CapacityBinding {
            allocation_epoch: 1,
            shard: 193,
            shard_key: Bytes::from_static(b"prod/v2/capacity/shards/c1/capacity_shard.pb"),
            shard_object_version_id: Bytes::from_static(b"capacity-version-1"),
            shard_budget_bytes: 2_000_000,
            tenant_slice_bytes: 1_000_000,
            shard_digest: Bytes::from(vec![0x34; 32]),
            shard_size: 4096,
        }),
        bucket_safety: Some(BucketSafetyBinding {
            epoch: 1,
            safety_digest: Bytes::from(vec![0x33; 32]),
        }),
        inline_settings: Bytes::new(),
        inline_policy: Bytes::new(),
        wal: Some(WalState::default()),
        reclamation: Some(ReclamationState {
            phase: ReclamationPhase::Idle as i32,
            cursor: Bytes::new(),
            pass_objects: 0,
            pass_bytes: 0,
        }),
        last_internal_mutation_id: Bytes::from(
            hex::decode("01890f4776447b8b9d7a876543210abe").unwrap(),
        ),
        receipt_catalog: None,
        event_catalog: None,
        pin_catalog: None,
        git_ownership_catalog: None,
        lfs_ownership_catalog: None,
        bundle_catalog: None,
        recovery_catalog: None,
        audit_catalog: None,
        reclamation_catalog: None,
        pack_representation: Some(PackRepresentation::InlinePacks(InlinePackRoots {
            roots: Vec::new(),
        })),
        grant_representation: Some(GrantRepresentation::InlineGrants(InlineGrants {
            grants: vec![RepositoryGrant {
                issuer: Bytes::from_static(b"cloud-core"),
                subject: Bytes::from_static(b"admin-1"),
                role: GrantRole::Administrator as i32,
            }],
        })),
    }
}

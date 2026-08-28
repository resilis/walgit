use std::sync::{Arc, atomic::Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    CapacityCommitBinding, CapacityControl, CapacityControlState, CapacityObjectRef,
    CapacityReservation, CapacityReservationState, CapacityShard, CapacityShardBudget,
    CapacityTenantAccount, CommittingCapacityReservation, MutationKind, PriorControlBinding,
    RepositoryIdentity, ReservedCapacityReservation, StableCapacityState, TenantCapacityAllocation,
    TenantCapacityCatalogPage, TenantShardSlice, WriterFence,
    capacity_commit_binding::Predecessor as CommitPredecessor,
    capacity_control::StatePayload as ControlPayload,
    capacity_reservation::StatePayload as ReservationPayload,
    digests::{ContentAddressDigest, ProtobufObjectDigest},
    encode_capacity_control, encode_capacity_shard, encode_tenant_capacity_catalog_page,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, RoutingDigest, capacity_control_key,
        capacity_shard_key, tenant_capacity_catalog_key,
    },
};
use walgit_store::{
    BoxStream, CasToken, DynStore, GetOptions, GetResult, ObjectMeta, ObjectStore, ObjectStoreExt,
    Prefixed, PutBody, PutMode, PutOptions, Result as StoreResult, StoreError,
    fault::{FaultPlan, FaultStore},
    memory::MemoryStore,
    v2_capacity::{CapacityStore, CapacityStoreError, ShardCompareAndSwapOutcome},
};

const PREFIX: &str = "prod/";

#[tokio::test]
async fn strict_current_and_exact_loads_apply_the_prefix_once() {
    let fixture = Fixture::new().await;
    let control = fixture
        .adapter
        .load_current_control()
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let shard = fixture
        .adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let exact = fixture
        .adapter
        .load_exact_shard(shard.binding().object())
        .await
        .unwrap();

    assert_eq!(page.page(), &fixture.page);
    assert_eq!(exact.shard(), shard.shard());
    assert!(
        fixture
            .truth
            .get_bytes(&capacity_control_key(&fixture.prefix).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .truth
            .get_bytes(&format!(
                "{PREFIX}{}",
                capacity_control_key(&fixture.prefix).unwrap()
            ))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn exact_catalog_load_rejects_wrong_version_and_never_falls_back_to_current() {
    let fixture = Fixture::new().await;
    let mut wrong = fixture.page_ref.clone();
    wrong.object_version_id = Bytes::from_static(b"missing-version");
    assert!(matches!(
        fixture.adapter.load_exact_tenant_catalog(&wrong).await,
        Err(CapacityStoreError::Store(_))
    ));
}

#[tokio::test]
async fn one_shard_cas_commits_and_a_stale_writer_conflicts_without_rebase() {
    let fixture = Fixture::new().await;
    let control = fixture
        .adapter
        .load_current_control()
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let first = fixture
        .adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let stale = first.clone();
    let first_candidate = reserved_successor(&first, &fixture.identity, 0xbd, 10, 100);
    assert!(matches!(
        fixture
            .adapter
            .reserve_cas(&control, &page, &first, first_candidate, 100)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));

    let second_candidate = reserved_successor(&stale, &fixture.identity, 0xbe, 10, 100);
    assert!(matches!(
        fixture
            .adapter
            .reserve_cas(&control, &page, &stale, second_candidate, 100)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Conflict(Some(_))
    ));
}

#[tokio::test]
async fn lost_success_response_uses_one_exact_current_get_and_returns_committed() {
    let fixture = Fixture::new().await;
    let fault = FaultStore::new(fixture.scoped.clone(), "lost-capacity-response", 7);
    fault.set(
        FaultPlan {
            p_err_after: 1.0,
            ..Default::default()
        }
        .with_only(&["capacity_shard.pb"]),
    );
    let adapter = CapacityStore::new(fault.clone(), fixture.prefix.clone()).unwrap();
    let control = adapter.load_current_control().await.unwrap().unwrap();
    let page = adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let previous = adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let baseline = fault.stats().ops.load(Ordering::Relaxed);
    let candidate = reserved_successor(&previous, &fixture.identity, 0xbf, 10, 100);

    assert!(matches!(
        adapter
            .reserve_cas(&control, &page, &previous, candidate, 100)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(fault.stats().ops.load(Ordering::Relaxed) - baseline, 2);
}

#[tokio::test]
async fn a_precondition_after_the_exact_candidate_landed_is_committed_replay() {
    let fixture = Fixture::new().await;
    let control = fixture
        .adapter
        .load_current_control()
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let previous = fixture
        .adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let candidate = reserved_successor(&previous, &fixture.identity, 0xbd, 10, 100);
    assert!(matches!(
        fixture
            .adapter
            .reserve_cas(&control, &page, &previous, candidate.clone(), 100,)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert!(matches!(
        fixture
            .adapter
            .reserve_cas(&control, &page, &previous, candidate, 100)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn ambiguous_error_before_and_later_successor_are_classified_without_retry() {
    let fixture = Fixture::new().await;
    let control = fixture
        .adapter
        .load_current_control()
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let previous = fixture
        .adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let candidate = reserved_successor(&previous, &fixture.identity, 0xbd, 10, 100);
    let before: DynStore = Arc::new(InterposingStore::new(
        fixture.scoped.clone(),
        InjectedWrite::ErrorBefore,
    ));
    let before = CapacityStore::new(before, fixture.prefix.clone()).unwrap();
    assert!(matches!(
        before
            .reserve_cas(&control, &page, &previous, candidate.clone(), 100,)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::NotCommitted(_)
    ));

    let mut later = candidate.clone();
    later.control_revision = 3;
    let later = Bytes::from(encode_capacity_shard(&later, &fixture.prefix).unwrap());
    let interleaved: DynStore = Arc::new(InterposingStore::new(
        fixture.scoped.clone(),
        InjectedWrite::ApplyThenSuccessor(later),
    ));
    let interleaved = CapacityStore::new(interleaved, fixture.prefix.clone()).unwrap();
    assert!(matches!(
        interleaved
            .reserve_cas(&control, &page, &previous, candidate, 100)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Indeterminate
    ));
}

#[tokio::test]
async fn current_load_rejects_missing_provider_object_version_id() {
    let fixture = Fixture::new().await;
    let stripped: DynStore = Arc::new(InterposingStore::without_version_ids(
        fixture.scoped.clone(),
    ));
    let adapter = CapacityStore::new(stripped, fixture.prefix.clone()).unwrap();
    assert!(matches!(
        adapter.load_current_control().await,
        Err(CapacityStoreError::Metadata(_))
    ));
}

#[tokio::test]
async fn purpose_specific_store_methods_reject_other_legal_successors_before_put() {
    let fixture = Fixture::new().await;
    let control = fixture
        .adapter
        .load_current_control()
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .adapter
        .load_exact_tenant_catalog(control.control().tenant_catalog.as_ref().unwrap())
        .await
        .unwrap();
    let empty = fixture
        .adapter
        .load_current_shard(fixture.shard)
        .await
        .unwrap()
        .unwrap();
    let reserved = reserved_successor(&empty, &fixture.identity, 0xbd, 10, 100);
    assert!(matches!(
        fixture
            .adapter
            .expire_reserved_cas(&control, &page, &empty, reserved.clone(), 100)
            .await,
        Err(CapacityStoreError::Operation(_))
    ));
    assert_eq!(
        fixture
            .adapter
            .load_current_shard(fixture.shard)
            .await
            .unwrap()
            .unwrap()
            .shard()
            .control_revision,
        1
    );

    let committed = match fixture
        .adapter
        .reserve_cas(&control, &page, &empty, reserved, 100)
        .await
        .unwrap()
    {
        ShardCompareAndSwapOutcome::Committed(stored) => stored,
        other => panic!("expected RESERVED insertion, got {other:?}"),
    };
    let mut committing = committed.shard().clone();
    committing.control_revision += 1;
    committing.reservations[0].state = CapacityReservationState::Committing as i32;
    committing.reservations[0].state_payload = Some(ReservationPayload::Committing(
        CommittingCapacityReservation {
            commit: Some(CapacityCommitBinding {
                writer_epoch: 1,
                mutation_id: Bytes::copy_from_slice(&reservation_uuid(0xcc)),
                kind: MutationKind::Settings as i32,
                predecessor: Some(CommitPredecessor::PriorControl(PriorControlBinding {
                    cas_token: Bytes::from_static(b"repo-cas-1"),
                    object_version_id: Bytes::from_static(b"repo-version-1"),
                })),
            }),
        },
    ));
    assert!(matches!(
        fixture
            .adapter
            .reserve_cas(&control, &page, &committed, committing, 100)
            .await,
        Err(CapacityStoreError::Operation(_))
    ));
    assert_eq!(
        fixture
            .adapter
            .load_current_shard(fixture.shard)
            .await
            .unwrap()
            .unwrap()
            .shard()
            .control_revision,
        2
    );
}

struct Fixture {
    truth: Arc<MemoryStore>,
    scoped: DynStore,
    adapter: CapacityStore,
    prefix: DeploymentPrefix,
    identity: RepositoryIdentity,
    page: TenantCapacityCatalogPage,
    page_ref: CapacityObjectRef,
    shard: u8,
}

impl Fixture {
    async fn new() -> Self {
        let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
        let truth = MemoryStore::shared();
        let scoped: DynStore = Arc::new(Prefixed::new(truth.clone() as DynStore, PREFIX));
        let adapter = CapacityStore::new(scoped.clone(), prefix.clone()).unwrap();
        let identity = identity();
        let shard = Sha256::digest(&identity.repository_uuid)[0];
        let page = tenant_page(&identity.tenant_id, 100);
        let page_bytes = encode_tenant_capacity_catalog_page(&page).unwrap();
        let page_digest: [u8; 32] = Sha256::digest(&page_bytes).into();
        let page_key =
            tenant_capacity_catalog_key(&prefix, ContentAddressDigest::from_bytes(page_digest))
                .unwrap();
        let page_meta = scoped
            .put_bytes(
                page_key.strip_prefix(PREFIX).unwrap(),
                page_bytes.clone(),
                PutMode::Create,
            )
            .await
            .unwrap();
        let page_ref = object_ref(&page_key, &page_bytes, &page_meta);

        let shard_value = CapacityShard {
            schema_version: 1,
            control_revision: 1,
            shard: u32::from(shard),
            allocation_epoch: 1,
            budget_bytes: 100,
            tenant_accounts: Vec::new(),
            reservations: Vec::new(),
        };
        let shard_bytes = encode_capacity_shard(&shard_value, &prefix).unwrap();
        let shard_key = capacity_shard_key(&prefix, shard).unwrap();
        let shard_meta = scoped
            .put_bytes(
                shard_key.strip_prefix(PREFIX).unwrap(),
                shard_bytes.clone(),
                PutMode::Create,
            )
            .await
            .unwrap();
        let exact_shard_ref = object_ref(&shard_key, &shard_bytes, &shard_meta);

        let control = CapacityControl {
            schema_version: 1,
            control_revision: 1,
            state: CapacityControlState::Stable as i32,
            writer: Some(WriterFence {
                holder: Bytes::from_static(b"capacity-writer"),
                epoch: 1,
            }),
            allocation_epoch: 1,
            global_allocatable_bytes: 25_600,
            tenant_catalog: Some(page_ref.clone()),
            shard_budgets: (0u16..256)
                .map(|number| CapacityShardBudget {
                    shard: u32::from(number),
                    budget_bytes: 100,
                    shard_object: Some(if number as u8 == shard {
                        exact_shard_ref.clone()
                    } else {
                        placeholder_shard_ref(&prefix, number as u8)
                    }),
                })
                .collect(),
            state_payload: Some(ControlPayload::Stable(StableCapacityState {})),
        };
        let control_bytes = encode_capacity_control(&control, &prefix).unwrap();
        scoped
            .put_bytes(
                capacity_control_key(&prefix)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                control_bytes,
                PutMode::Create,
            )
            .await
            .unwrap();

        Self {
            truth,
            scoped,
            adapter,
            prefix,
            identity,
            page,
            page_ref,
            shard,
        }
    }
}

fn object_ref(full_key: &str, body: &[u8], meta: &ObjectMeta) -> CapacityObjectRef {
    CapacityObjectRef {
        key: Bytes::copy_from_slice(full_key.as_bytes()),
        object_version_id: Bytes::copy_from_slice(
            meta.object_version_id.as_ref().unwrap().as_str().as_bytes(),
        ),
        digest: Bytes::copy_from_slice(ProtobufObjectDigest::of_exact_protobuf(body).as_bytes()),
        size: body.len() as u64,
    }
}

fn placeholder_shard_ref(prefix: &DeploymentPrefix, shard: u8) -> CapacityObjectRef {
    CapacityObjectRef {
        key: Bytes::from(capacity_shard_key(prefix, shard).unwrap()),
        object_version_id: Bytes::from(format!("version-{shard}")),
        digest: Bytes::from(vec![shard; 32]),
        size: 1,
    }
}

fn tenant_page(tenant_id: &Bytes, slice: u64) -> TenantCapacityCatalogPage {
    TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: vec![TenantCapacityAllocation {
            tenant_id: tenant_id.clone(),
            total_bytes: slice * 256,
            slices: (0u16..256)
                .map(|shard| TenantShardSlice {
                    shard: u32::from(shard),
                    byte_count: slice,
                })
                .collect(),
        }],
    }
}

fn reserved_successor(
    previous: &walgit_store::v2_capacity::StoredCapacityShard,
    identity: &RepositoryIdentity,
    id_suffix: u8,
    bytes: u64,
    now: u64,
) -> CapacityShard {
    let mut successor = previous.shard().clone();
    successor.control_revision += 1;
    let id = reservation_uuid(id_suffix);
    successor.tenant_accounts = vec![CapacityTenantAccount {
        tenant_id: identity.tenant_id.clone(),
        current_slice_bytes: 100,
    }];
    successor.reservations = vec![CapacityReservation {
        reservation_id: Bytes::copy_from_slice(&id),
        identity: Some(identity.clone()),
        tenant_id: identity.tenant_id.clone(),
        allocation_epoch: 1,
        byte_count: bytes,
        tenant_slice_bytes: 100,
        state: CapacityReservationState::Reserved as i32,
        state_payload: Some(ReservationPayload::Reserved(ReservedCapacityReservation {
            created_at_unix_seconds: now,
            expires_at_unix_seconds: now + 10,
        })),
    }];
    successor
}

fn reservation_uuid(suffix: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..15].copy_from_slice(&hex::decode("01890f4776447b8b9d7a876543210a").unwrap());
    id[15] = suffix;
    id
}

fn identity() -> RepositoryIdentity {
    let canonical_path = Bytes::from_static(b"tenant-a/project/repository");
    RepositoryIdentity {
        tenant_id: Bytes::from_static(b"tenant-a"),
        project_id: Bytes::from_static(b"project"),
        repository_uuid: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abc").unwrap()),
        generation: 1,
        canonical_path_digest: Bytes::copy_from_slice(
            CanonicalPathDigest::of(&canonical_path).as_bytes(),
        ),
        routing_digest: Bytes::copy_from_slice(
            RoutingDigest::of(&canonical_path).unwrap().as_bytes(),
        ),
        canonical_path,
    }
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
}

#[async_trait]
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
            GetResult::Object { mut meta, body } => {
                if self.strip_version_ids {
                    meta.object_version_id = None;
                }
                Ok(GetResult::Object { meta, body })
            }
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
                    "injected lost response after a later successor"
                )))
            }
            None => self.inner.put(key, body, opts).await,
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

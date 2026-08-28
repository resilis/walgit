use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, CapacityCommitBinding, CapacityControl,
    CapacityControlState, CapacityObjectRef, CapacityRedistribution, CapacityReservationState,
    CapacityShard, CapacityShardBaseline, CapacityShardBudget, CapacityShardBudgetProposal,
    CommittingCapacityReservation, GrantRole, InlineGrants, InlinePackRoots, Lifecycle,
    MutationKind, ObjectFormat, PriorControlBinding, QuotaState, ReclamationPhase,
    ReclamationState, RedistributionPhase, RepoControl, RepositoryGrant, RepositoryIdentity,
    StableCapacityState, TenantCapacityAllocation, TenantCapacityCatalogPage, TenantShardSlice,
    Visibility, WalState, WriterFence,
    aborted_capacity_reservation::Proof as AbortedProof,
    capacity_commit_binding::Predecessor as CommitPredecessor,
    capacity_control::StatePayload as ControlPayload,
    capacity_reservation::StatePayload as ReservationPayload,
    digests::{ContentAddressDigest, ProtobufObjectDigest},
    encode_capacity_control, encode_capacity_shard, encode_tenant_capacity_catalog_page,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, RoutingDigest, capacity_control_key,
        capacity_shard_key, repo_control_key, tenant_capacity_catalog_key,
    },
    repo_control::{GrantRepresentation, PackRepresentation},
};
use walgit_store::{
    DynStore, ObjectMeta, ObjectStoreExt, Prefixed, PutMode,
    fault::{FaultPlan, FaultStore},
    memory::MemoryStore,
    v2_capacity::{CapacityStore, ShardCompareAndSwapOutcome},
    v2_control::{
        CompareAndSwapOutcome as RepoCompareAndSwapOutcome, ControlStore, CreateOutcome,
        StoredRepoControl,
    },
};

use crate::capacity::{
    CapacityError, CapacityReservationPurpose, CapacityReservations, ExpireCapacityRequest,
    ReserveCapacityRequest,
};

const PREFIX: &str = "prod/";

#[tokio::test]
async fn reserve_derives_every_authority_field_and_accepts_both_closed_purposes() {
    for (purpose, suffix, ttl, expected_expiry) in [
        (CapacityReservationPurpose::GitWrite, 0xbd, 1, 101),
        (CapacityReservationPurpose::LfsFinalize, 0xbe, 900, 1_000),
    ] {
        let harness = Harness::new(false).await;
        let outcome = harness
            .reservations
            .reserve(
                &harness.repository,
                reserve_request(suffix, 100, ttl, 37, purpose),
            )
            .await
            .unwrap();
        let stored = committed(outcome);
        let row = &stored.shard().reservations[0];
        assert_eq!(row.identity.as_ref(), Some(&harness.identity));
        assert_eq!(row.tenant_id, harness.identity.tenant_id);
        assert_eq!(row.allocation_epoch, 1);
        assert_eq!(row.byte_count, 37);
        assert_eq!(row.tenant_slice_bytes, 100);
        assert_eq!(row.state, CapacityReservationState::Reserved as i32);
        let Some(ReservationPayload::Reserved(window)) = row.state_payload.as_ref() else {
            panic!("expected RESERVED payload")
        };
        assert_eq!(window.created_at_unix_seconds, 100);
        assert_eq!(window.expires_at_unix_seconds, expected_expiry);
    }
}

#[tokio::test]
async fn reserve_rejects_byte_and_time_bounds_without_a_write() {
    let cases = [
        reserve_request(0xbd, 10, 0, 1, CapacityReservationPurpose::GitWrite),
        reserve_request(0xbe, 10, 901, 1, CapacityReservationPurpose::GitWrite),
        reserve_request(0xbf, 10, 1, 0, CapacityReservationPurpose::GitWrite),
        reserve_request(0xc0, 10, 1, 101, CapacityReservationPurpose::GitWrite),
        reserve_request(0xc1, 10, 1, u64::MAX, CapacityReservationPurpose::GitWrite),
        reserve_request(0xc2, 0, 1, 1, CapacityReservationPurpose::GitWrite),
    ];
    for request in cases {
        let harness = Harness::new(false).await;
        assert!(matches!(
            harness
                .reservations
                .reserve(&harness.repository, request)
                .await,
            Err(CapacityError::InvalidRequest(_))
        ));
        assert_eq!(harness.current_shard().await.control_revision, 1);
    }

    let harness = Harness::new(false).await;
    let overflow = reserve_request(0xc3, u64::MAX, 1, 1, CapacityReservationPurpose::GitWrite);
    let overflow = ReserveCapacityRequest {
        observed_now_unix_seconds: u64::MAX,
        ..overflow
    };
    assert!(matches!(
        harness
            .reservations
            .reserve(&harness.repository, overflow)
            .await,
        Err(CapacityError::InvalidRequest(_))
    ));
    assert_eq!(harness.current_shard().await.control_revision, 1);

    for invalid_window in [
        ReserveCapacityRequest {
            reservation_id: uuid(0xc4),
            requested_bytes: 1,
            created_at_unix_seconds: 101,
            expires_at_unix_seconds: 102,
            observed_now_unix_seconds: 100,
            purpose: CapacityReservationPurpose::GitWrite,
        },
        ReserveCapacityRequest {
            reservation_id: uuid(0xc5),
            requested_bytes: 1,
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 101,
            observed_now_unix_seconds: 101,
            purpose: CapacityReservationPurpose::GitWrite,
        },
    ] {
        assert!(matches!(
            harness
                .reservations
                .reserve(&harness.repository, invalid_window)
                .await,
            Err(CapacityError::InvalidRequest(_))
        ));
    }
    assert_eq!(harness.current_shard().await.control_revision, 1);
}

#[tokio::test]
async fn reserve_exact_replay_is_idempotent_but_changed_binding_conflicts() {
    let harness = Harness::new(false).await;
    let request = ReserveCapacityRequest {
        reservation_id: uuid(0xbd),
        requested_bytes: 10,
        created_at_unix_seconds: 90,
        expires_at_unix_seconds: 110,
        observed_now_unix_seconds: 100,
        purpose: CapacityReservationPurpose::GitWrite,
    };
    committed(
        harness
            .reservations
            .reserve(&harness.repository, request)
            .await
            .unwrap(),
    );
    assert!(matches!(
        harness
            .reservations
            .reserve(&harness.repository, request)
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 2);

    let changed = ReserveCapacityRequest {
        requested_bytes: 11,
        purpose: CapacityReservationPurpose::LfsFinalize,
        ..request
    };
    assert!(matches!(
        harness
            .reservations
            .reserve(&harness.repository, changed)
            .await,
        Err(CapacityError::ReservationConflict)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 2);
}

#[tokio::test]
async fn control_state_fences_admission_and_limits_expiry_to_draining() {
    let draining = Harness::new(false).await;
    let request = reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite);
    committed(
        draining
            .reservations
            .reserve(&draining.repository, request)
            .await
            .unwrap(),
    );
    draining
        .set_redistribution_phase(RedistributionPhase::Draining)
        .await;

    assert!(matches!(
        draining
            .reservations
            .reserve(&draining.repository, request)
            .await,
        Err(CapacityError::InvalidRequest(_))
    ));
    assert!(matches!(
        draining
            .reservations
            .expire(
                &draining.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 110,
                },
            )
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));

    let applying = Harness::new(false).await;
    committed(
        applying
            .reservations
            .reserve(
                &applying.repository,
                reserve_request(0xbe, 100, 10, 10, CapacityReservationPurpose::GitWrite),
            )
            .await
            .unwrap(),
    );
    applying
        .set_redistribution_phase(RedistributionPhase::Applying)
        .await;
    assert!(
        applying
            .reservations
            .expire(
                &applying.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbe),
                    observed_now_unix_seconds: u64::MAX,
                },
            )
            .await
            .is_err()
    );
    assert_eq!(applying.current_shard().await.control_revision, 2);
}

#[tokio::test]
async fn committing_reservation_never_expires() {
    let harness = Harness::new(false).await;
    committed(
        harness
            .reservations
            .reserve(
                &harness.repository,
                reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite),
            )
            .await
            .unwrap(),
    );
    harness.set_reservation_committing().await;

    assert!(matches!(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: u64::MAX,
                },
            )
            .await,
        Err(CapacityError::ReservationConflict)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 3);
}

#[tokio::test]
async fn expired_replay_survives_applying_and_the_next_stable_epoch() {
    let harness = Harness::new(false).await;
    committed(
        harness
            .reservations
            .reserve(
                &harness.repository,
                reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite),
            )
            .await
            .unwrap(),
    );
    harness
        .set_redistribution_phase(RedistributionPhase::Draining)
        .await;
    let _lost_response = harness
        .reservations
        .expire(
            &harness.repository,
            ExpireCapacityRequest {
                reservation_id: uuid(0xbd),
                observed_now_unix_seconds: 110,
            },
        )
        .await
        .unwrap();
    harness
        .set_redistribution_phase(RedistributionPhase::Applying)
        .await;

    assert!(matches!(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 120,
                },
            )
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 3);

    harness.advance_shard_to_target_epoch().await;
    let advanced = harness
        .capacity_store
        .load_current_shard(harness.shard)
        .await
        .unwrap()
        .unwrap();
    let replayed = committed(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 130,
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        replayed, advanced,
        "replay must return the exact current binding"
    );
    assert_eq!(harness.current_shard().await.control_revision, 4);

    harness.finish_next_stable_epoch().await;
    assert!(matches!(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: u64::MAX,
                },
            )
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 4);
}

#[tokio::test]
async fn non_active_repository_denies_admission_but_allows_expiry_and_replay() {
    for lifecycle in [Lifecycle::Deleting, Lifecycle::Tombstoned] {
        let harness = Harness::new(false).await;
        committed(
            harness
                .reservations
                .reserve(
                    &harness.repository,
                    reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite),
                )
                .await
                .unwrap(),
        );
        let inactive = harness.repository_at_lifecycle(lifecycle).await;

        assert!(matches!(
            harness
                .reservations
                .reserve(
                    &inactive,
                    reserve_request(0xbe, 100, 10, 10, CapacityReservationPurpose::GitWrite),
                )
                .await,
            Err(CapacityError::RepositoryDenied)
        ));
        committed(
            harness
                .reservations
                .expire(
                    &inactive,
                    ExpireCapacityRequest {
                        reservation_id: uuid(0xbd),
                        observed_now_unix_seconds: 110,
                    },
                )
                .await
                .unwrap(),
        );
        assert!(matches!(
            harness
                .reservations
                .expire(
                    &inactive,
                    ExpireCapacityRequest {
                        reservation_id: uuid(0xbd),
                        observed_now_unix_seconds: 120,
                    },
                )
                .await
                .unwrap(),
            ShardCompareAndSwapOutcome::Committed(_)
        ));
        assert_eq!(harness.current_shard().await.control_revision, 3);
    }
}

#[tokio::test]
async fn expiry_repeats_the_exact_window_and_binds_caller_now() {
    let harness = Harness::new(false).await;
    committed(
        harness
            .reservations
            .reserve(
                &harness.repository,
                reserve_request(0xbd, 100, 10, 25, CapacityReservationPurpose::GitWrite),
            )
            .await
            .unwrap(),
    );
    assert!(matches!(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 109,
                },
            )
            .await,
        Err(CapacityError::InvalidRequest(_))
    ));

    let stored = committed(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 110,
                },
            )
            .await
            .unwrap(),
    );
    let row = &stored.shard().reservations[0];
    assert_eq!(row.state, CapacityReservationState::Aborted as i32);
    let Some(ReservationPayload::Aborted(aborted)) = row.state_payload.as_ref() else {
        panic!("expected ABORTED payload")
    };
    let Some(AbortedProof::Expired(proof)) = aborted.proof.as_ref() else {
        panic!("expected expiry proof")
    };
    assert_eq!(proof.created_at_unix_seconds, 100);
    assert_eq!(proof.expires_at_unix_seconds, 110);
    assert_eq!(proof.observed_now_unix_seconds, 110);
    assert!(stored.shard().tenant_accounts.is_empty());

    assert!(matches!(
        harness
            .reservations
            .expire(
                &harness.repository,
                ExpireCapacityRequest {
                    reservation_id: uuid(0xbd),
                    observed_now_unix_seconds: 120,
                },
            )
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(harness.current_shard().await.control_revision, 3);
}

#[tokio::test]
async fn concurrent_same_shard_reservations_have_one_winner_and_no_rebase() {
    let harness = Harness::new(true).await;
    let first = harness.reservations.clone();
    let second = harness.reservations.clone();
    let repository = harness.repository.clone();
    let other_repository = repository.clone();
    let (first, second) = tokio::join!(
        first.reserve(
            &repository,
            reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite,),
        ),
        second.reserve(
            &other_repository,
            reserve_request(0xbe, 100, 10, 10, CapacityReservationPurpose::LfsFinalize,),
        ),
    );
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ShardCompareAndSwapOutcome::Committed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ShardCompareAndSwapOutcome::Conflict(Some(_))))
            .count(),
        1
    );
    assert_eq!(harness.current_shard().await.control_revision, 2);
}

#[tokio::test]
async fn reserve_resolves_an_applied_but_lost_response_without_a_second_put() {
    let harness = Harness::new(false).await;
    let fault = FaultStore::new(harness.scoped.clone(), "capacity-lost-response", 17);
    fault.set(
        FaultPlan {
            p_err_after: 1.0,
            ..Default::default()
        }
        .with_only(&["capacity_shard.pb"]),
    );
    let reservations = CapacityReservations::new(
        CapacityStore::new(fault.clone(), harness.prefix.clone()).unwrap(),
    );
    let baseline = fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        reservations
            .reserve(
                &harness.repository,
                reserve_request(0xbd, 100, 10, 10, CapacityReservationPurpose::GitWrite,),
            )
            .await
            .unwrap(),
        ShardCompareAndSwapOutcome::Committed(_)
    ));
    assert_eq!(
        fault.stats().ops.load(std::sync::atomic::Ordering::Relaxed) - baseline,
        5,
        "control GET + parallel page/shard GETs + one PUT + one resolution GET"
    );
}

struct Harness {
    scoped: DynStore,
    prefix: DeploymentPrefix,
    capacity_store: CapacityStore,
    reservations: CapacityReservations,
    repository: StoredRepoControl,
    identity: RepositoryIdentity,
    shard: u8,
}

impl Harness {
    async fn new(with_latency: bool) -> Self {
        let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
        let mut memory = MemoryStore::new();
        if with_latency {
            memory.latency = Some(Duration::from_millis(5));
        }
        let truth = Arc::new(memory);
        let scoped: DynStore = Arc::new(Prefixed::new(truth.clone() as DynStore, PREFIX));
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

        let shard_body = CapacityShard {
            schema_version: 1,
            control_revision: 1,
            shard: u32::from(shard),
            allocation_epoch: 1,
            budget_bytes: 100,
            tenant_accounts: Vec::new(),
            reservations: Vec::new(),
        };
        let shard_bytes = encode_capacity_shard(&shard_body, &prefix).unwrap();
        let shard_key = capacity_shard_key(&prefix, shard).unwrap();
        let shard_meta = scoped
            .put_bytes(
                shard_key.strip_prefix(PREFIX).unwrap(),
                shard_bytes.clone(),
                PutMode::Create,
            )
            .await
            .unwrap();
        let shard_ref = object_ref(&shard_key, &shard_bytes, &shard_meta);

        let capacity_control = CapacityControl {
            schema_version: 1,
            control_revision: 1,
            state: CapacityControlState::Stable as i32,
            writer: Some(WriterFence {
                holder: Bytes::from_static(b"capacity-writer"),
                epoch: 1,
            }),
            allocation_epoch: 1,
            global_allocatable_bytes: 25_600,
            tenant_catalog: Some(page_ref),
            shard_budgets: (0u16..256)
                .map(|number| CapacityShardBudget {
                    shard: u32::from(number),
                    budget_bytes: 100,
                    shard_object: Some(if number as u8 == shard {
                        shard_ref.clone()
                    } else {
                        placeholder_shard_ref(&prefix, number as u8)
                    }),
                })
                .collect(),
            state_payload: Some(ControlPayload::Stable(StableCapacityState {})),
        };
        scoped
            .put_bytes(
                capacity_control_key(&prefix)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                encode_capacity_control(&capacity_control, &prefix).unwrap(),
                PutMode::Create,
            )
            .await
            .unwrap();

        let repository = match ControlStore::new(scoped.clone(), prefix.clone())
            .unwrap()
            .create(repo_control(identity.clone(), shard, &prefix))
            .await
            .unwrap()
        {
            CreateOutcome::Committed(stored) => stored,
            other => panic!("expected repository create, got {other:?}"),
        };
        let capacity_store = CapacityStore::new(scoped.clone(), prefix.clone()).unwrap();
        let reservations = CapacityReservations::new(capacity_store.clone());
        Self {
            scoped,
            prefix,
            capacity_store,
            reservations,
            repository,
            identity,
            shard,
        }
    }

    async fn current_shard(&self) -> CapacityShard {
        self.capacity_store
            .load_current_shard(self.shard)
            .await
            .unwrap()
            .unwrap()
            .shard()
            .clone()
    }

    async fn set_redistribution_phase(&self, phase: RedistributionPhase) {
        let current_shard = if phase == RedistributionPhase::Applying {
            self.capacity_store
                .load_current_shard(self.shard)
                .await
                .unwrap()
        } else {
            None
        };
        let stored = self
            .capacity_store
            .load_current_control()
            .await
            .unwrap()
            .unwrap();
        let mut control = stored.control().clone();
        control.control_revision += 1;
        control.state = CapacityControlState::Preparing as i32;
        let baselines = if phase == RedistributionPhase::Applying {
            control
                .shard_budgets
                .iter()
                .map(|budget| CapacityShardBaseline {
                    shard: budget.shard,
                    allocation_epoch: control.allocation_epoch,
                    budget_bytes: budget.budget_bytes,
                    shard_object: if budget.shard == u32::from(self.shard) {
                        Some(current_shard.as_ref().unwrap().binding().object().clone())
                    } else {
                        budget.shard_object.clone()
                    },
                })
                .collect()
        } else {
            Vec::new()
        };
        control.state_payload = Some(ControlPayload::Redistribution(Box::new(
            CapacityRedistribution {
                phase: phase as i32,
                target_epoch: control.allocation_epoch + 1,
                target_global_allocatable_bytes: control.global_allocatable_bytes,
                target_tenant_catalog: control.tenant_catalog.clone(),
                target_shard_budgets: control
                    .shard_budgets
                    .iter()
                    .map(|budget| CapacityShardBudgetProposal {
                        shard: budget.shard,
                        budget_bytes: budget.budget_bytes,
                    })
                    .collect(),
                admission_fence_id: Bytes::copy_from_slice(&uuid(0xdd)),
                baselines,
            },
        )));
        self.scoped
            .put_bytes(
                capacity_control_key(&self.prefix)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                encode_capacity_control(&control, &self.prefix).unwrap(),
                PutMode::Update(stored.binding().cas_token().clone()),
            )
            .await
            .unwrap();
    }

    async fn set_reservation_committing(&self) {
        let stored = self
            .capacity_store
            .load_current_shard(self.shard)
            .await
            .unwrap()
            .unwrap();
        let mut shard = stored.shard().clone();
        shard.control_revision += 1;
        shard.reservations[0].state = CapacityReservationState::Committing as i32;
        shard.reservations[0].state_payload = Some(ReservationPayload::Committing(
            CommittingCapacityReservation {
                commit: Some(CapacityCommitBinding {
                    writer_epoch: 1,
                    mutation_id: Bytes::copy_from_slice(&uuid(0xcc)),
                    kind: MutationKind::Settings as i32,
                    predecessor: Some(CommitPredecessor::PriorControl(PriorControlBinding {
                        cas_token: Bytes::from_static(b"repo-cas-1"),
                        object_version_id: Bytes::from_static(b"repo-version-1"),
                    })),
                }),
            },
        ));
        self.scoped
            .put_bytes(
                capacity_shard_key(&self.prefix, self.shard)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                encode_capacity_shard(&shard, &self.prefix).unwrap(),
                PutMode::Update(stored.binding().cas_token().clone()),
            )
            .await
            .unwrap();
    }

    async fn advance_shard_to_target_epoch(&self) {
        let stored_shard = self
            .capacity_store
            .load_current_shard(self.shard)
            .await
            .unwrap()
            .unwrap();
        let mut shard = stored_shard.shard().clone();
        shard.control_revision += 1;
        shard.allocation_epoch += 1;
        self.scoped
            .put_bytes(
                capacity_shard_key(&self.prefix, self.shard)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                encode_capacity_shard(&shard, &self.prefix).unwrap(),
                PutMode::Update(stored_shard.binding().cas_token().clone()),
            )
            .await
            .unwrap();
    }

    async fn finish_next_stable_epoch(&self) {
        let current_shard = self
            .capacity_store
            .load_current_shard(self.shard)
            .await
            .unwrap()
            .unwrap();
        let stored_control = self
            .capacity_store
            .load_current_control()
            .await
            .unwrap()
            .unwrap();
        let mut control = stored_control.control().clone();
        control.control_revision += 1;
        control.state = CapacityControlState::Stable as i32;
        control.allocation_epoch += 1;
        control.shard_budgets[usize::from(self.shard)].shard_object =
            Some(current_shard.binding().object().clone());
        control.state_payload = Some(ControlPayload::Stable(StableCapacityState {}));
        self.scoped
            .put_bytes(
                capacity_control_key(&self.prefix)
                    .unwrap()
                    .strip_prefix(PREFIX)
                    .unwrap(),
                encode_capacity_control(&control, &self.prefix).unwrap(),
                PutMode::Update(stored_control.binding().cas_token().clone()),
            )
            .await
            .unwrap();
    }

    async fn repository_at_lifecycle(&self, lifecycle: Lifecycle) -> StoredRepoControl {
        let store = ControlStore::new(self.scoped.clone(), self.prefix.clone()).unwrap();
        let mut current = self.repository.clone();
        let transitions: &[(Lifecycle, u8)] = match lifecycle {
            Lifecycle::Deleting => &[(Lifecycle::Deleting, 0xd1)],
            Lifecycle::Tombstoned => &[(Lifecycle::Deleting, 0xd1), (Lifecycle::Tombstoned, 0xd2)],
            Lifecycle::Active => return current,
            Lifecycle::Unspecified => panic!("UNSPECIFIED is not a repository lifecycle"),
        };
        for (next_lifecycle, mutation_suffix) in transitions {
            let mut successor = current.control().clone();
            successor.control_revision += 1;
            successor.lifecycle = *next_lifecycle as i32;
            successor.last_internal_mutation_id = Bytes::copy_from_slice(&uuid(*mutation_suffix));
            current = match store.compare_and_swap(&current, successor).await.unwrap() {
                RepoCompareAndSwapOutcome::Committed(stored) => stored,
                other => panic!("expected repository lifecycle CAS, got {other:?}"),
            };
        }
        current
    }
}

fn committed(
    outcome: ShardCompareAndSwapOutcome,
) -> walgit_store::v2_capacity::StoredCapacityShard {
    match outcome {
        ShardCompareAndSwapOutcome::Committed(stored) => stored,
        other => panic!("expected committed capacity CAS, got {other:?}"),
    }
}

fn reserve_request(
    suffix: u8,
    now: u64,
    ttl: u64,
    requested_bytes: u64,
    purpose: CapacityReservationPurpose,
) -> ReserveCapacityRequest {
    ReserveCapacityRequest {
        reservation_id: uuid(suffix),
        requested_bytes,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(ttl),
        observed_now_unix_seconds: now,
        purpose,
    }
}

fn uuid(suffix: u8) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..15].copy_from_slice(&hex::decode("01890f4776447b8b9d7a876543210a").unwrap());
    value[15] = suffix;
    value
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

fn repo_control(identity: RepositoryIdentity, shard: u8, prefix: &DeploymentPrefix) -> RepoControl {
    let create_intent_cose = Bytes::from_static(b"deterministic-cose-sign1");
    let routing = RoutingDigest::of(&identity.canonical_path).unwrap();
    RepoControl {
        schema_version: 2,
        identity: Some(identity),
        create_intent_id: Bytes::copy_from_slice(&uuid(0xaa)),
        create_intent_digest: Bytes::copy_from_slice(&Sha256::digest(&create_intent_cose)),
        create_intent_cose,
        repo_control_key: Bytes::from(repo_control_key(prefix, routing).unwrap()),
        object_format: ObjectFormat::Sha1 as i32,
        lifecycle: Lifecycle::Active as i32,
        visibility: Visibility::Private as i32,
        control_revision: 1,
        cutover_generation: 1,
        writer: Some(WriterFence {
            holder: Bytes::from_static(b"writer"),
            epoch: 1,
        }),
        authorization_epoch: 1,
        quota: Some(QuotaState {
            logical_quota_bytes: 1_000,
            charged_git_bytes: 0,
            charged_lfs_bytes: 0,
        }),
        capacity: Some(CapacityBinding {
            allocation_epoch: 1,
            shard: u32::from(shard),
            shard_key: Bytes::from(capacity_shard_key(prefix, shard).unwrap()),
            shard_object_version_id: Bytes::from_static(b"capacity-version"),
            shard_budget_bytes: 100,
            tenant_slice_bytes: 100,
            shard_digest: Bytes::from(vec![0x34; 32]),
            shard_size: 1,
        }),
        bucket_safety: Some(BucketSafetyBinding {
            epoch: 1,
            safety_digest: Bytes::from(vec![0x33; 32]),
        }),
        inline_settings: Bytes::new(),
        inline_policy: Bytes::new(),
        wal: Some(WalState {
            head_sequence: 0,
            minimum_sequence: 0,
            checkpoint: None,
            tail: Vec::new(),
        }),
        reclamation: Some(ReclamationState {
            phase: ReclamationPhase::Idle as i32,
            cursor: Bytes::new(),
            pass_objects: 0,
            pass_bytes: 0,
        }),
        last_internal_mutation_id: Bytes::copy_from_slice(&uuid(0xab)),
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
                issuer: Bytes::from_static(b"issuer"),
                subject: Bytes::from_static(b"subject"),
                role: GrantRole::Administrator as i32,
            }],
        })),
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

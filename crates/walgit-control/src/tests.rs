// Tests are kept with the domain crate so they can exercise the private
// authenticated-binding core without adding a forgeable capability constructor.

use std::sync::Arc;

use bytes::Bytes;
use prost::Message;
use sha2::{Digest, Sha256};
use walgit_identity::CapabilityPurpose;
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, CatalogRoot, GrantRole, InlineGrants, InlinePackRoots,
    Lifecycle, MutationKind, ObjectFormat, QuotaState, ReclamationPhase, ReclamationState,
    RepoControl, RepositoryGrant, RepositoryIdentity, Visibility, WalState, WriterFence,
    keys::{CanonicalPathDigest, DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::{GrantRepresentation, PackRepresentation},
};
use walgit_store::{
    DynStore, ObjectStoreExt, Prefixed, PutMode,
    fault::{FaultPlan, FaultStore},
    memory::MemoryStore,
    v2_control::{ControlStore, CreateOutcome, StoredRepoControl},
};

use super::*;

const PREFIX: &str = "prod/";

#[tokio::test]
async fn inline_authorization_checks_every_sealed_binding_and_exact_role_matrix() {
    let mut control = sample_control();
    let version = b"version-7";

    for visibility in [
        Visibility::Private,
        Visibility::Internal,
        Visibility::Public,
    ] {
        control.visibility = visibility as i32;
        for role in [
            GrantRole::Reader,
            GrantRole::Writer,
            GrantRole::Administrator,
        ] {
            inline_grants_mut(&mut control).grants[0].role = role as i32;
            for action in [
                RepositoryAction::CloneRead,
                RepositoryAction::GitRead,
                RepositoryAction::GitWrite,
                RepositoryAction::LfsRead,
                RepositoryAction::LfsFinalize,
                RepositoryAction::WebhookAdmin,
                RepositoryAction::ServiceBuild,
                RepositoryAction::RepositoryAdmin,
            ] {
                let allowed = match action {
                    RepositoryAction::CloneRead
                    | RepositoryAction::GitRead
                    | RepositoryAction::LfsRead
                    | RepositoryAction::ServiceBuild => true,
                    RepositoryAction::GitWrite | RepositoryAction::LfsFinalize => {
                        role != GrantRole::Reader
                    }
                    RepositoryAction::WebhookAdmin | RepositoryAction::RepositoryAdmin => {
                        role == GrantRole::Administrator
                    }
                };
                assert_eq!(
                    authorize_control(
                        &control,
                        version,
                        binding(&control, version, action.purpose()),
                        action,
                    )
                    .is_ok(),
                    allowed,
                    "visibility={visibility:?} role={role:?} action={action:?}"
                );
            }
        }
    }

    inline_grants_mut(&mut control).grants[0].role = GrantRole::Administrator as i32;
    let exact = binding(&control, version, CapabilityPurpose::RepositoryAdmin);
    assert_eq!(
        authorize_control(&control, version, exact, RepositoryAction::RepositoryAdmin).unwrap(),
        GrantRole::Administrator
    );

    macro_rules! denied {
        ($field:ident = $value:expr) => {{
            let mut changed = exact;
            changed.$field = $value;
            assert!(matches!(
                authorize_control(
                    &control,
                    version,
                    changed,
                    RepositoryAction::RepositoryAdmin
                ),
                Err(ControlError::Denied)
            ));
        }};
    }
    denied!(purpose = CapabilityPurpose::GitWrite);
    denied!(tenant_id = b"other-tenant");
    denied!(project_id = b"other-project");
    denied!(repository_uuid = &[0x11; 16]);
    denied!(generation = 2);
    denied!(canonical_path = b"other/path");
    denied!(canonical_path_digest = &[0x22; 32]);
    denied!(routing_digest = &[0x33; 32]);
    denied!(control_key = b"other-control-key");
    denied!(control_version_id = b"other-version");
    denied!(cutover_generation = 2);
    denied!(authorization_epoch = 2);
    denied!(grant = (b"other-issuer", b"admin-1"));
    denied!(grant = (b"cloud-core", b"other-subject"));

    let mut inactive = control.clone();
    inactive.lifecycle = Lifecycle::Deleting as i32;
    assert!(matches!(
        authorize_control(
            &inactive,
            version,
            binding(&inactive, version, CapabilityPurpose::RepositoryAdmin),
            RepositoryAction::RepositoryAdmin
        ),
        Err(ControlError::Denied)
    ));
    inactive.lifecycle = Lifecycle::Tombstoned as i32;
    assert!(matches!(
        authorize_control(
            &inactive,
            version,
            binding(&inactive, version, CapabilityPurpose::RepositoryAdmin),
            RepositoryAction::RepositoryAdmin
        ),
        Err(ControlError::Denied)
    ));

    let mut catalog_backed = control.clone();
    catalog_backed.grant_representation = Some(GrantRepresentation::GrantCatalog(Box::new(
        CatalogRoot::default(),
    )));
    assert!(matches!(
        authorize_control(
            &catalog_backed,
            version,
            binding(&catalog_backed, version, CapabilityPurpose::RepositoryAdmin),
            RepositoryAction::RepositoryAdmin
        ),
        Err(ControlError::GrantCatalogUnsupported)
    ));
}

#[tokio::test]
async fn receipt_result_and_settlement_survive_restart_and_gate_later_cas() {
    let (objects, prefix, initial) = fixture().await;
    let controller = RepositoryController::new(objects.clone(), prefix.clone()).unwrap();
    let mutation_id = uuid("01890f4776447b8b9d7a876543210ac0");
    let settlement_id = uuid("01890f4776447b8b9d7a876543210ac1");
    let later_id = uuid("01890f4776447b8b9d7a876543210ac2");
    let digest = MutationRequestDigest::of(MutationKind::Settings, b"settings-v2").unwrap();
    let mut successor = ordinary_successor(initial.control(), mutation_id).unwrap();
    successor.inline_settings = Bytes::from_static(b"settings-v2");

    let landed = committed(
        controller
            .publish(
                &initial,
                successor.clone(),
                MutationKind::Settings,
                mutation_id,
                digest,
            )
            .await
            .unwrap(),
    );
    let unresolved = controller
        .load_current_catalog(landed.control())
        .await
        .unwrap();
    let unresolved_root = landed.control().receipt_catalog.as_ref().unwrap();
    assert_eq!(unresolved_root.depth, 1);
    assert_eq!(unresolved_root.node_count, 1);
    assert_eq!(unresolved_root.item_count, 1);
    assert_eq!(
        unresolved_root.total_encoded_bytes,
        unresolved_root.object.as_ref().unwrap().size
    );
    assert_eq!(unresolved.rows.len(), 1);
    assert_eq!(unresolved.rows[0].state, ReceiptState::Unresolved as i32);
    assert!(unresolved.rows[0].result.is_none());
    let mut unsupported_obligation = unresolved.rows[0].receipt.clone().unwrap();
    unsupported_obligation.capacity_obligation = None;
    assert!(matches!(
        require_none_obligations(&unsupported_obligation),
        Err(ControlError::UnsupportedMutation)
    ));
    unsupported_obligation = unresolved.rows[0].receipt.clone().unwrap();
    unsupported_obligation.event_obligation = None;
    assert!(matches!(
        require_none_obligations(&unsupported_obligation),
        Err(ControlError::UnsupportedMutation)
    ));

    let mut wrong_last = landed.control().clone();
    wrong_last.last_internal_mutation_id = Bytes::copy_from_slice(&later_id);
    assert!(matches!(
        controller.load_current_catalog(&wrong_last).await,
        Err(ControlError::InvalidObject)
    ));
    let mut wrong_root = landed.control().clone();
    wrong_root.receipt_catalog.as_mut().unwrap().depth = 2;
    assert!(matches!(
        controller.load_current_catalog(&wrong_root).await,
        Err(ControlError::InvalidObject)
    ));
    let mut wrong_key_digest = landed.control().clone();
    let object = wrong_key_digest
        .receipt_catalog
        .as_mut()
        .unwrap()
        .object
        .as_mut()
        .unwrap();
    let key = std::str::from_utf8(&object.key).unwrap();
    let (parent, _) = key.rsplit_once('/').unwrap();
    object.key = Bytes::from(format!("{parent}/{}.pb", "00".repeat(32)));
    assert!(matches!(
        controller.load_current_catalog(&wrong_key_digest).await,
        Err(ControlError::InvalidObject)
    ));
    let mut multiple = unresolved.clone();
    let mut second = multiple.rows[0].clone();
    second.mutation_id = Bytes::copy_from_slice(&later_id);
    second.receipt.as_mut().unwrap().mutation_id = Bytes::copy_from_slice(&later_id);
    multiple.rows.push(second);
    multiple
        .rows
        .sort_by(|left, right| left.mutation_id.cmp(&right.mutation_id));
    let multiple_root = controller.persist_catalog(&multiple).await.unwrap();
    let mut multiple_control = landed.control().clone();
    multiple_control.receipt_catalog = Some(multiple_root);
    assert!(matches!(
        controller.load_current_catalog(&multiple_control).await,
        Err(ControlError::InvalidObject)
    ));

    assert!(matches!(
        controller
            .publish(
                &landed,
                successor,
                MutationKind::Settings,
                mutation_id,
                digest,
            )
            .await
            .unwrap(),
        MutationOutcome::RecoveryRequired(_)
    ));
    assert!(matches!(
        controller
            .publish(
                &landed,
                ordinary_successor(landed.control(), later_id).unwrap(),
                MutationKind::Settings,
                later_id,
                MutationRequestDigest::of(MutationKind::Settings, b"later").unwrap(),
            )
            .await,
        Err(ControlError::PendingSettlement)
    ));
    assert!(matches!(
        controller
            .publish(
                &landed,
                ordinary_successor(landed.control(), mutation_id).unwrap(),
                MutationKind::Settings,
                mutation_id,
                MutationRequestDigest::of(MutationKind::Settings, b"changed").unwrap(),
            )
            .await,
        Err(ControlError::ReplayConflict)
    ));

    // A new controller has no process-local record of the first invocation.
    let recovered = RepositoryController::new(objects.clone(), prefix.clone()).unwrap();
    let first_result = recovered
        .materialize_result(&landed, mutation_id)
        .await
        .unwrap();
    let replayed_result = recovered
        .materialize_result(&landed, mutation_id)
        .await
        .unwrap();
    assert_eq!(first_result, replayed_result);

    let writer = landed.control().writer.clone().unwrap();
    let settled = committed(
        recovered
            .settle(&landed, &writer, mutation_id, settlement_id)
            .await
            .unwrap(),
    );
    let restarted = RepositoryController::new(objects, prefix).unwrap();
    let catalog = restarted
        .load_current_catalog(settled.control())
        .await
        .unwrap();
    assert_eq!(catalog.rows.len(), 1);
    assert_eq!(catalog.rows[0].state, ReceiptState::Settled as i32);
    assert!(catalog.rows[0].result.is_some());
    assert_eq!(catalog.rows[0].receipt, unresolved.rows[0].receipt);

    let replayed_control = match restarted
        .publish(
            &settled,
            ordinary_successor(settled.control(), mutation_id).unwrap(),
            MutationKind::Settings,
            mutation_id,
            digest,
        )
        .await
        .unwrap()
    {
        MutationOutcome::ExactReplay(value) => value,
        other => panic!("unexpected settled replay outcome: {other:?}"),
    };
    let replayed_catalog = restarted
        .load_current_catalog(replayed_control.control())
        .await
        .unwrap();
    assert_eq!(replayed_catalog.rows[0].state, ReceiptState::Settled as i32);
    assert!(replayed_catalog.rows[0].result.is_some());

    assert!(matches!(
        restarted
            .settle(&settled, &writer, mutation_id, settlement_id)
            .await
            .unwrap(),
        MutationOutcome::ExactReplay(_)
    ));

    let later_digest =
        MutationRequestDigest::of(MutationKind::WriterTakeover, b"writer-2").unwrap();
    let mut later = ordinary_successor(settled.control(), later_id).unwrap();
    later.writer = Some(WriterFence {
        holder: Bytes::from_static(b"writer-2"),
        epoch: 2,
    });
    let takeover = committed(
        restarted
            .publish(
                &settled,
                later,
                MutationKind::WriterTakeover,
                later_id,
                later_digest,
            )
            .await
            .unwrap(),
    );
    let takeover_catalog = restarted
        .load_current_catalog(takeover.control())
        .await
        .unwrap();
    let takeover_row = takeover_catalog
        .rows
        .iter()
        .find(|row| row.mutation_id.as_ref() == later_id)
        .unwrap();
    assert_eq!(takeover_row.receipt.as_ref().unwrap().writer_epoch, 1);
    let result_target = restarted
        .materialize_result(&takeover, later_id)
        .await
        .unwrap();
    let (_, result_bytes) = restarted
        .load_exact(&result_target, V2KeyKind::ReceiptResult)
        .await
        .unwrap();
    let result = walgit_proto::v2::decode_mutation_result(&result_bytes).unwrap();
    assert_eq!(result.writer_epoch, 2);
}

#[tokio::test]
async fn immutable_writes_classify_lost_response_conflict_and_indeterminate() {
    let (objects, prefix, initial) = fixture().await;
    let fault = FaultStore::new(objects.clone(), "catalog-lost-response", 7);
    fault.set(FaultPlan {
        p_err_after: 1.0,
        only_keys: Some(vec!["catalogs/receipt/".to_owned()]),
        ..FaultPlan::default()
    });
    let controller = RepositoryController::new(fault.clone(), prefix.clone()).unwrap();
    let mutation_id = uuid("01890f4776447b8b9d7a876543210ac3");
    let digest = MutationRequestDigest::of(MutationKind::Settings, b"lost").unwrap();
    let mut successor = ordinary_successor(initial.control(), mutation_id).unwrap();
    successor.inline_settings = Bytes::from_static(b"lost");
    assert!(matches!(
        controller
            .publish(
                &initial,
                successor,
                MutationKind::Settings,
                mutation_id,
                digest,
            )
            .await
            .unwrap(),
        MutationOutcome::Committed(_)
    ));
    assert_eq!(
        fault
            .stats()
            .err_after
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    let (objects, prefix, initial) = fixture().await;
    let fault = FaultStore::new(objects.clone(), "catalog-indeterminate", 9);
    fault.set(FaultPlan {
        p_err_before: 1.0,
        only_keys: Some(vec!["catalogs/receipt/".to_owned()]),
        ..FaultPlan::default()
    });
    let controller = RepositoryController::new(fault, prefix.clone()).unwrap();
    let mutation_id = uuid("01890f4776447b8b9d7a876543210ac4");
    let mut successor = ordinary_successor(initial.control(), mutation_id).unwrap();
    successor.inline_settings = Bytes::from_static(b"indeterminate");
    assert!(matches!(
        controller
            .publish(
                &initial,
                successor,
                MutationKind::Settings,
                mutation_id,
                MutationRequestDigest::of(MutationKind::Settings, b"indeterminate").unwrap(),
            )
            .await,
        Err(ControlError::Indeterminate)
    ));
    let current = ControlStore::new(objects.clone(), prefix)
        .unwrap()
        .load(std::str::from_utf8(&initial.control().repo_control_key).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.control().control_revision, 1);

    let controller =
        RepositoryController::new(objects.clone(), DeploymentPrefix::parse(PREFIX).unwrap())
            .unwrap();
    let identity = initial.control().identity.as_ref().unwrap();
    let result_key = receipt_result_key(
        &DeploymentPrefix::parse(PREFIX).unwrap(),
        identity,
        &uuid("01890f4776447b8b9d7a876543210ac5"),
    )
    .unwrap();
    let relative = result_key.strip_prefix(PREFIX).unwrap();
    objects
        .put_bytes(relative, Bytes::from_static(b"different"), PutMode::Create)
        .await
        .unwrap();
    assert!(matches!(
        controller
            .persist_immutable(&result_key, b"expected", V2KeyKind::ReceiptResult)
            .await,
        Err(ControlError::ReplayConflict)
    ));
}

#[tokio::test]
async fn lost_result_and_settlement_responses_resume_from_persisted_state() {
    let (objects, prefix, initial) = fixture().await;
    let fault = FaultStore::new(objects, "result-and-settlement-loss", 11);
    let controller = RepositoryController::new(fault.clone(), prefix.clone()).unwrap();
    let mutation_id = uuid("01890f4776447b8b9d7a876543210ac7");
    let settlement_id = uuid("01890f4776447b8b9d7a876543210ac8");
    let digest = MutationRequestDigest::of(MutationKind::Settings, b"crash").unwrap();
    let mut successor = ordinary_successor(initial.control(), mutation_id).unwrap();
    successor.inline_settings = Bytes::from_static(b"crash");
    let landed = committed(
        controller
            .publish(
                &initial,
                successor,
                MutationKind::Settings,
                mutation_id,
                digest,
            )
            .await
            .unwrap(),
    );

    fault.set(FaultPlan {
        p_err_after: 1.0,
        only_keys: Some(vec!["receipts/results/".to_owned()]),
        ..FaultPlan::default()
    });
    let lost_result = controller
        .materialize_result(&landed, mutation_id)
        .await
        .unwrap();
    fault.heal();
    let restarted = RepositoryController::new(fault.clone(), prefix.clone()).unwrap();
    assert_eq!(
        restarted
            .materialize_result(&landed, mutation_id)
            .await
            .unwrap(),
        lost_result
    );

    fault.set(FaultPlan {
        p_err_after: 1.0,
        only_keys: Some(vec!["repo_control.pb".to_owned()]),
        ..FaultPlan::default()
    });
    let writer = landed.control().writer.clone().unwrap();
    let settled = committed(
        restarted
            .settle(&landed, &writer, mutation_id, settlement_id)
            .await
            .unwrap(),
    );
    assert_eq!(settled.control().control_revision, 3);
    fault.heal();
    let after_restart = RepositoryController::new(fault.clone(), prefix).unwrap();
    assert!(matches!(
        after_restart
            .settle(&settled, &writer, mutation_id, settlement_id)
            .await
            .unwrap(),
        MutationOutcome::ExactReplay(_)
    ));
    assert_eq!(
        settled.control().control_revision,
        3,
        "no duplicate settlement CAS"
    );
    let catalog = after_restart
        .load_current_catalog(settled.control())
        .await
        .unwrap();
    assert_eq!(catalog.rows.len(), 1);
    assert_eq!(catalog.rows[0].state, ReceiptState::Settled as i32);
    assert_eq!(catalog.rows[0].result.as_ref(), Some(&lost_result));
    assert_eq!(
        fault
            .stats()
            .err_after
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "one lost result PUT and one lost settlement CAS"
    );
}

#[test]
fn writer_fences_and_prefix_forms_are_exact() {
    let control = sample_control();
    let expected = control.writer.as_ref().unwrap();
    assert!(require_writer(&control, expected).is_ok());
    assert!(matches!(
        require_writer(
            &control,
            &WriterFence {
                holder: Bytes::from_static(b"other"),
                epoch: expected.epoch,
            }
        ),
        Err(ControlError::StaleWriterFence)
    ));
    assert!(matches!(
        require_writer(
            &control,
            &WriterFence {
                holder: expected.holder.clone(),
                epoch: expected.epoch + 1,
            }
        ),
        Err(ControlError::StaleWriterFence)
    ));

    let identity = control.identity.as_ref().unwrap();
    for prefix in [
        DeploymentPrefix::empty(),
        DeploymentPrefix::parse(PREFIX).unwrap(),
    ] {
        let result =
            receipt_result_key(&prefix, identity, &uuid("01890f4776447b8b9d7a876543210ac6"))
                .unwrap();
        let parsed = parse_key(&prefix, result.as_bytes()).unwrap();
        assert_eq!(parsed.kind, V2KeyKind::ReceiptResult);
        assert_eq!(parsed.repository.unwrap().generation, 1);
    }
}

#[test]
fn grant_requests_reject_invalid_fields_and_duplicates_but_bind_exact_order() {
    let grant = |issuer: &'static [u8], subject: &'static [u8], role: i32| RepositoryGrant {
        issuer: Bytes::from_static(issuer),
        subject: Bytes::from_static(subject),
        role,
    };
    let first = grant(b"issuer-b", b"subject-b", GrantRole::Reader as i32);
    let second = grant(b"issuer-a", b"subject-a", GrantRole::Writer as i32);
    let ordered = canonical_grant_request(&[first.clone(), second.clone()]).unwrap();
    let reversed = canonical_grant_request(&[second.clone(), first.clone()]).unwrap();
    assert_ne!(ordered, reversed, "the exact caller order is request-bound");
    assert!(matches!(
        canonical_grant_request(&[first.clone(), first]),
        Err(ControlError::InvalidRequest)
    ));
    assert!(matches!(
        canonical_grant_request(&[grant(b"", b"subject", GrantRole::Reader as i32)]),
        Err(ControlError::InvalidRequest)
    ));
    assert!(matches!(
        canonical_grant_request(&[grant(b"issuer", b"", GrantRole::Reader as i32)]),
        Err(ControlError::InvalidRequest)
    ));
    assert!(matches!(
        canonical_grant_request(&[grant(b"issuer", b"subject", 99)]),
        Err(ControlError::InvalidRequest)
    ));
    let error =
        canonical_grant_request(&[grant(b"sensitive-sentinel-must-not-leak", b"subject", 99)])
            .unwrap_err();
    assert!(!error.to_string().contains("sensitive-sentinel"));
    assert!(matches!(
        canonical_grant_request(&[RepositoryGrant {
            issuer: Bytes::from(vec![b'i'; 257]),
            subject: Bytes::from_static(b"subject"),
            role: GrantRole::Reader as i32,
        }]),
        Err(ControlError::InvalidRequest)
    ));
}

#[test]
fn unresolved_catalog_reserves_maximum_settlement_result_space() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let identity = sample_control().identity.unwrap();
    let settled_rows = (0..4_095)
        .map(|index| receipt_row(&prefix, &identity, index, true))
        .collect::<Vec<_>>();
    let candidate = |settled_count: usize| ReceiptCatalog {
        schema_version: 1,
        identity: Some(identity.clone()),
        rows: settled_rows[..settled_count]
            .iter()
            .cloned()
            .chain(std::iter::once(receipt_row(
                &prefix,
                &identity,
                settled_count as u32,
                false,
            )))
            .collect(),
    };

    let mut low = 0usize;
    let mut high = settled_rows.len();
    while low < high {
        let middle = (low + high).div_ceil(2);
        if candidate(middle).encoded_len() <= walgit_proto::v2::MAX_RECEIPT_CATALOG_BYTES {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let near_limit = candidate(low);
    let encoded = encode_catalog_with_backpressure(&near_limit).unwrap();
    assert!(encoded.len() <= walgit_proto::v2::MAX_RECEIPT_CATALOG_BYTES);
    let unresolved_id: [u8; 16] = near_limit
        .rows
        .last()
        .unwrap()
        .mutation_id
        .as_ref()
        .try_into()
        .unwrap();
    assert!(matches!(
        ensure_settlement_capacity(&near_limit, &prefix, &unresolved_id),
        Err(ControlError::ReceiptCatalogFull)
    ));
}

#[tokio::test]
async fn invalid_ids_and_unsupported_kinds_fail_before_writes() {
    let (objects, prefix, initial) = fixture().await;
    let controller = RepositoryController::new(objects, prefix).unwrap();
    let invalid = [0x11; 16];
    assert!(matches!(
        controller
            .publish(
                &initial,
                initial.control().clone(),
                MutationKind::Settings,
                invalid,
                MutationRequestDigest::of(MutationKind::Settings, b"x").unwrap(),
            )
            .await,
        Err(ControlError::InvalidRequest)
    ));
    for kind in [
        MutationKind::Settings,
        MutationKind::Grants,
        MutationKind::WriterTakeover,
    ] {
        assert!(SupportedMutationKind::try_from(kind).is_ok());
    }
    for kind in [
        MutationKind::Unspecified,
        MutationKind::Create,
        MutationKind::Push,
        MutationKind::RefUpdate,
        MutationKind::LfsFinalize,
        MutationKind::Policy,
        MutationKind::Lifecycle,
        MutationKind::Checkpoint,
        MutationKind::Compaction,
        MutationKind::Bundle,
        MutationKind::Follow,
        MutationKind::Import,
        MutationKind::Repair,
        MutationKind::Pin,
        MutationKind::Event,
        MutationKind::Reclamation,
        MutationKind::InternalSettlement,
    ] {
        assert!(matches!(
            SupportedMutationKind::try_from(kind),
            Err(ControlError::UnsupportedMutation)
        ));
    }
}

fn binding<'a>(
    control: &'a RepoControl,
    version: &'a [u8],
    purpose: CapabilityPurpose,
) -> CapabilityBinding<'a> {
    let identity = control.identity.as_ref().unwrap();
    CapabilityBinding {
        purpose,
        tenant_id: &identity.tenant_id,
        project_id: &identity.project_id,
        repository_uuid: identity.repository_uuid.as_ref().try_into().unwrap(),
        generation: identity.generation,
        canonical_path: &identity.canonical_path,
        canonical_path_digest: identity.canonical_path_digest.as_ref().try_into().unwrap(),
        routing_digest: identity.routing_digest.as_ref().try_into().unwrap(),
        control_key: &control.repo_control_key,
        control_version_id: version,
        cutover_generation: control.cutover_generation,
        authorization_epoch: control.authorization_epoch,
        grant: (b"cloud-core", b"admin-1"),
    }
}

fn inline_grants_mut(control: &mut RepoControl) -> &mut InlineGrants {
    let Some(GrantRepresentation::InlineGrants(inline)) = control.grant_representation.as_mut()
    else {
        panic!("fixture must use inline grants")
    };
    inline
}

async fn fixture() -> (DynStore, DeploymentPrefix, StoredRepoControl) {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let truth: DynStore = Arc::new(MemoryStore::new());
    let objects: DynStore = Arc::new(Prefixed::new(truth, PREFIX));
    let adapter = ControlStore::new(objects.clone(), prefix.clone()).unwrap();
    let stored = match adapter.create(sample_control()).await.unwrap() {
        CreateOutcome::Committed(value) => value,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    (objects, prefix, stored)
}

fn committed(outcome: MutationOutcome) -> StoredRepoControl {
    match outcome {
        MutationOutcome::Committed(value) => value,
        other => panic!("unexpected mutation outcome: {other:?}"),
    }
}

fn uuid(value: &str) -> [u8; 16] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn receipt_row(
    prefix: &DeploymentPrefix,
    identity: &RepositoryIdentity,
    index: u32,
    settled: bool,
) -> ReceiptCatalogRow {
    let mut mutation_id = uuid("01890f4776447b8b9d7a000000000000");
    mutation_id[12..].copy_from_slice(&index.to_be_bytes());
    let receipt = MutationReceipt {
        schema_version: 1,
        identity: Some(identity.clone()),
        mutation_id: Bytes::copy_from_slice(&mutation_id),
        kind: MutationKind::Settings as i32,
        writer_epoch: 1,
        wal_sequence: 0,
        request_digest: Bytes::from(vec![0x44; 32]),
        immutable_dependency_digests: Vec::new(),
        predecessor: Some(Predecessor::PriorControl(PriorControlBinding {
            cas_token: Bytes::from_static(b"cas"),
            object_version_id: Bytes::from_static(b"version"),
        })),
        capacity_obligation: Some(CapacityObligation::NoCapacity(NoCapacityObligation {})),
        event_obligation: Some(EventObligation::NoEvent(NoEventObligation {})),
    };
    ReceiptCatalogRow {
        mutation_id: Bytes::copy_from_slice(&mutation_id),
        state: if settled {
            ReceiptState::Settled as i32
        } else {
            ReceiptState::Unresolved as i32
        },
        receipt: Some(receipt),
        result: settled.then(|| TargetObjectRef {
            identity: Some(identity.clone()),
            key: Bytes::from(receipt_result_key(prefix, identity, &mutation_id).unwrap()),
            object_version_id: Bytes::from_static(b"v"),
            digest: Bytes::from(vec![0x55; 32]),
            size: 1,
        }),
    }
}

fn sample_control() -> RepoControl {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let canonical_path = Bytes::from_static(b"tenant/project/repo");
    let canonical = CanonicalPathDigest::of(&canonical_path);
    let routing = RoutingDigest::of(&canonical_path).unwrap();
    let identity = RepositoryIdentity {
        tenant_id: Bytes::from_static(b"tenant-1"),
        project_id: Bytes::from_static(b"project-1"),
        repository_uuid: Bytes::copy_from_slice(&uuid("01890f4776447b8b9d7a876543210abd")),
        generation: 1,
        canonical_path,
        canonical_path_digest: Bytes::copy_from_slice(canonical.as_bytes()),
        routing_digest: Bytes::copy_from_slice(routing.as_bytes()),
    };
    let create_intent_cose = Bytes::from_static(b"deterministic-cose-sign1");
    RepoControl {
        schema_version: 2,
        identity: Some(identity),
        create_intent_id: Bytes::copy_from_slice(&uuid("01890f4776447b8b9d7a876543210abc")),
        create_intent_digest: Bytes::copy_from_slice(&Sha256::digest(&create_intent_cose)),
        create_intent_cose,
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
        last_internal_mutation_id: Bytes::copy_from_slice(&uuid(
            "01890f4776447b8b9d7a876543210abe",
        )),
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

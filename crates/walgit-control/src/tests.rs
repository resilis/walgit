// Tests are kept with the domain crate so they can exercise the private
// authenticated-binding core without adding a forgeable capability constructor.

use std::{fs::File, io::Read, sync::Arc};

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use walgit_identity::{
    BoundRingObjects, CapabilityPurpose, CredentialAuthority, ExactRingObject, ExpectedCapability,
    ExpectedCommonClaims, PinnedRoot,
};
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, CatalogRoot, CredentialControl, GrantRole, InlineGrants,
    InlinePackRoots, Lifecycle, MutationKind, ObjectFormat, QuotaState, ReclamationPhase,
    ReclamationState, RepoControl, RepositoryGrant, RepositoryIdentity, VerificationRingRoot,
    Visibility, WalState, WriterFence,
    keys::{CanonicalPathDigest, DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::{GrantRepresentation, PackRepresentation},
};
use walgit_store::{
    CasToken, DynStore, ObjectMeta, ObjectStoreExt, ObjectVersionId, Prefixed, PutMode,
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
async fn real_verified_capability_authorizes_the_exact_stored_control() {
    let (_objects, prefix, stored) = fixture().await;
    let capability = verified_admin_capability(&stored, &prefix);
    assert_eq!(
        authorize_inline_grant(&stored, &capability, RepositoryAction::RepositoryAdmin,).unwrap(),
        GrantRole::Administrator
    );
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

    let replayed = match restarted
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
    assert_eq!(replayed.target, first_result);
    assert_eq!(replayed.result.mutation_id.as_ref(), mutation_id);

    let replayed_settlement = match restarted
        .settle(&settled, &writer, mutation_id, settlement_id)
        .await
        .unwrap()
    {
        MutationOutcome::ExactReplay(value) => value,
        other => panic!("unexpected settlement replay outcome: {other:?}"),
    };
    assert_eq!(replayed_settlement.target, first_result);
    assert_eq!(
        restarted
            .materialize_result(&settled, mutation_id)
            .await
            .unwrap(),
        first_result
    );

    let second_settlement_id = uuid("01890f4776447b8b9d7a876543210acf");
    let later_digest = MutationRequestDigest::of(MutationKind::Settings, b"later").unwrap();
    let mut later = ordinary_successor(settled.control(), later_id).unwrap();
    later.inline_settings = Bytes::from_static(b"later");
    let second_landed = committed(
        restarted
            .publish(
                &settled,
                later,
                MutationKind::Settings,
                later_id,
                later_digest,
            )
            .await
            .unwrap(),
    );
    let second_result = restarted
        .materialize_result(&second_landed, later_id)
        .await
        .unwrap();
    let second_settled = committed(
        restarted
            .settle(&second_landed, &writer, later_id, second_settlement_id)
            .await
            .unwrap(),
    );
    let catalog = restarted
        .load_current_catalog(second_settled.control())
        .await
        .unwrap();
    assert_eq!(catalog.rows.len(), 2);
    assert_eq!(
        catalog.rows[0].settlement_mutation_id.as_ref(),
        settlement_id
    );
    assert_eq!(
        catalog.rows[1].settlement_mutation_id.as_ref(),
        second_settlement_id
    );
    let first_exact = match restarted
        .settle(&second_settled, &writer, mutation_id, settlement_id)
        .await
        .unwrap()
    {
        MutationOutcome::ExactReplay(value) => value,
        other => panic!("unexpected A/S1 replay: {other:?}"),
    };
    let second_exact = match restarted
        .settle(&second_settled, &writer, later_id, second_settlement_id)
        .await
        .unwrap()
    {
        MutationOutcome::ExactReplay(value) => value,
        other => panic!("unexpected B/S2 replay: {other:?}"),
    };
    assert_eq!(first_exact.target, first_result);
    assert_eq!(second_exact.target, second_result);
    assert!(matches!(
        restarted
            .settle(&second_settled, &writer, mutation_id, second_settlement_id)
            .await,
        Err(ControlError::ReplayConflict)
    ));
    assert!(matches!(
        restarted
            .settle(&second_settled, &writer, later_id, settlement_id)
            .await,
        Err(ControlError::ReplayConflict)
    ));
    let reused_settlement_successor =
        ordinary_successor(second_settled.control(), settlement_id).unwrap();
    assert!(matches!(
        restarted
            .publish(
                &second_settled,
                reused_settlement_successor,
                MutationKind::Settings,
                settlement_id,
                MutationRequestDigest::of(MutationKind::Settings, b"reuse-s1").unwrap(),
            )
            .await,
        Err(ControlError::ReplayConflict)
    ));

    let third_id = uuid("01890f4776447b8b9d7a876543210ad4");
    let mut third_successor = ordinary_successor(second_settled.control(), third_id).unwrap();
    third_successor.inline_settings = Bytes::from_static(b"third");
    let third_landed = committed(
        restarted
            .publish(
                &second_settled,
                third_successor,
                MutationKind::Settings,
                third_id,
                MutationRequestDigest::of(MutationKind::Settings, b"third").unwrap(),
            )
            .await
            .unwrap(),
    );
    restarted
        .materialize_result(&third_landed, third_id)
        .await
        .unwrap();
    assert!(matches!(
        restarted
            .settle(&third_landed, &writer, third_id, settlement_id)
            .await,
        Err(ControlError::ReplayConflict)
    ));
    assert!(matches!(
        restarted
            .settle(&third_landed, &writer, third_id, third_id)
            .await,
        Err(ControlError::ReplayConflict)
    ));

    assert!(matches!(
        restarted
            .publish(
                &second_settled,
                ordinary_successor(
                    second_settled.control(),
                    uuid("01890f4776447b8b9d7a876543210ad0")
                )
                .unwrap(),
                MutationKind::WriterTakeover,
                uuid("01890f4776447b8b9d7a876543210ad0"),
                MutationRequestDigest::of(MutationKind::WriterTakeover, b"writer-2").unwrap(),
            )
            .await,
        Err(ControlError::UnsupportedMutation)
    ));
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

#[tokio::test]
async fn rooted_result_replay_rejects_target_and_receipt_binding_changes() {
    let (objects, prefix, initial) = fixture().await;
    let controller = RepositoryController::new(objects, prefix).unwrap();
    let mutation_id = uuid("01890f4776447b8b9d7a876543210ad1");
    let settlement_id = uuid("01890f4776447b8b9d7a876543210ad2");
    let mut successor = ordinary_successor(initial.control(), mutation_id).unwrap();
    successor.inline_settings = Bytes::from_static(b"rooted");
    let landed = committed(
        controller
            .publish(
                &initial,
                successor,
                MutationKind::Settings,
                mutation_id,
                MutationRequestDigest::of(MutationKind::Settings, b"rooted").unwrap(),
            )
            .await
            .unwrap(),
    );
    let target = controller
        .materialize_result(&landed, mutation_id)
        .await
        .unwrap();
    let writer = landed.control().writer.as_ref().unwrap();
    let settled = committed(
        controller
            .settle(&landed, writer, mutation_id, settlement_id)
            .await
            .unwrap(),
    );
    let catalog = controller
        .load_current_catalog(settled.control())
        .await
        .unwrap();
    let receipt = catalog.rows[0].receipt.as_ref().unwrap();
    let rooted = controller
        .load_rooted_result(&target, receipt)
        .await
        .unwrap();
    assert_eq!(rooted.target, target);

    let mut wrong = target.clone();
    wrong.object_version_id = Bytes::from_static(b"wrong-version");
    assert!(
        controller
            .load_rooted_result(&wrong, receipt)
            .await
            .is_err()
    );
    let mut wrong = target.clone();
    let mut digest = wrong.digest.to_vec();
    digest[0] ^= 1;
    wrong.digest = Bytes::from(digest);
    assert!(matches!(
        controller.load_rooted_result(&wrong, receipt).await,
        Err(ControlError::InvalidObject)
    ));
    let mut wrong = target.clone();
    wrong.size += 1;
    assert!(matches!(
        controller.load_rooted_result(&wrong, receipt).await,
        Err(ControlError::InvalidObject)
    ));
    let mut wrong = target;
    wrong.identity.as_mut().unwrap().generation += 1;
    assert!(matches!(
        controller.load_rooted_result(&wrong, receipt).await,
        Err(ControlError::InvalidObject)
    ));

    let exact = rooted.result;
    for changed in [
        MutationResult {
            mutation_id: Bytes::copy_from_slice(&uuid("01890f4776447b8b9d7a876543210ad3")),
            ..exact.clone()
        },
        MutationResult {
            kind: MutationKind::Grants as i32,
            ..exact.clone()
        },
        MutationResult {
            writer_epoch: exact.writer_epoch + 1,
            ..exact.clone()
        },
        MutationResult {
            wal_sequence: exact.wal_sequence + 1,
            ..exact.clone()
        },
    ] {
        assert!(matches!(
            verify_result_receipt_binding(&changed, receipt),
            Err(ControlError::InvalidObject)
        ));
    }

    let mut takeover_receipt = receipt.clone();
    takeover_receipt.kind = MutationKind::WriterTakeover as i32;
    takeover_receipt.writer_epoch = 7;
    let mut takeover_result = exact;
    takeover_result.kind = MutationKind::WriterTakeover as i32;
    takeover_result.writer_epoch = 8;
    assert!(verify_result_receipt_binding(&takeover_result, &takeover_receipt).is_ok());
    takeover_result.writer_epoch = 7;
    assert!(matches!(
        verify_result_receipt_binding(&takeover_result, &takeover_receipt),
        Err(ControlError::InvalidObject)
    ));
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
fn immutable_provider_version_metadata_has_exact_length_bounds() {
    let meta = |version: String| ObjectMeta {
        key: "object.pb".to_owned(),
        size: 4,
        version: CasToken::new("cas"),
        object_version_id: Some(ObjectVersionId::new(version)),
    };
    assert!(verify_written_meta("object.pb", b"body", meta("v".to_owned())).is_ok());
    assert!(verify_written_meta("object.pb", b"body", meta("v".repeat(1_024))).is_ok());
    assert!(matches!(
        verify_written_meta("object.pb", b"body", meta(String::new())),
        Err(ControlError::InvalidObject)
    ));
    assert!(matches!(
        verify_written_meta("object.pb", b"body", meta("v".repeat(1_025))),
        Err(ControlError::InvalidObject)
    ));
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
fn request_digest_forms_have_exact_golden_preimages_and_sha256() {
    let settings = b"settings-v2";
    let grants = canonical_grant_request(&[
        RepositoryGrant {
            issuer: Bytes::from_static(b"issuer-b"),
            subject: Bytes::from_static(b"subject-b"),
            role: GrantRole::Reader as i32,
        },
        RepositoryGrant {
            issuer: Bytes::from_static(b"issuer-a"),
            subject: Bytes::from_static(b"subject-a"),
            role: GrantRole::Writer as i32,
        },
    ])
    .unwrap();
    let takeover = b"writer-2";
    assert_eq!(hex::encode(settings), "73657474696e67732d7632");
    assert_eq!(
        hex::encode(&grants),
        "00000002000000086973737565722d62000000097375626a6563742d6200000001000000086973737565722d61000000097375626a6563742d6100000002"
    );
    assert_eq!(hex::encode(takeover), "7772697465722d32");

    for (kind, request, preimage_hex, digest_hex) in [
        (
            MutationKind::Settings,
            settings.as_slice(),
            "77616c6769742d7265706f7369746f72792d6d75746174696f6e2d726571756573742d763100000006000000000000000b73657474696e67732d7632",
            "03ff98f71a8866052391ad4001c8e1e3c17e24c76617ca7383892298c7f2ca29",
        ),
        (
            MutationKind::Grants,
            grants.as_slice(),
            "77616c6769742d7265706f7369746f72792d6d75746174696f6e2d726571756573742d763100000007000000000000003e00000002000000086973737565722d62000000097375626a6563742d6200000001000000086973737565722d61000000097375626a6563742d6100000002",
            "3e7ab792d3f3412aa8490041c9f5baa2897f1e5540bfca4a0ce1141a0f52b64c",
        ),
        (
            MutationKind::WriterTakeover,
            takeover.as_slice(),
            "77616c6769742d7265706f7369746f72792d6d75746174696f6e2d726571756573742d76310000001200000000000000087772697465722d32",
            "7606c7c4821fbe84308c822afff160edca0dc07d97bbb484d87e7b9d2574be83",
        ),
    ] {
        assert_eq!(
            hex::encode(mutation_request_preimage(kind, request).unwrap()),
            preimage_hex,
            "preimage changed for {kind:?}"
        );
        assert_eq!(
            hex::encode(MutationRequestDigest::of(kind, request).unwrap().as_bytes()),
            digest_hex,
            "digest changed for {kind:?}"
        );
    }
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
    for kind in [MutationKind::Settings, MutationKind::Grants] {
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
        MutationKind::WriterTakeover,
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
    let mut settlement_mutation_id = uuid("01890f4776447b8b9d7a100000000000");
    settlement_mutation_id[12..].copy_from_slice(&index.to_be_bytes());
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
        settlement_mutation_id: if settled {
            Bytes::copy_from_slice(&settlement_mutation_id)
        } else {
            Bytes::new()
        },
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

fn verified_admin_capability(
    stored: &StoredRepoControl,
    prefix: &DeploymentPrefix,
) -> walgit_identity::AuthenticatedCapability {
    const NOW: i64 = 1_800_000_000;
    const ROOT_KID_DOMAIN: &[u8] = b"walgit-ed25519-root-kid-v1";
    const RING_AAD: &[u8] = b"walgit-verification-key-ring-v1";
    const CAPABILITY_AAD: &[u8] = b"walgit-capability-v1";

    let root_signer = ephemeral_signing_key();
    let root_public = root_signer.verifying_key().to_bytes();
    let root_kid: [u8; 16] = Sha256::new()
        .chain_update(ROOT_KID_DOMAIN)
        .chain_update(root_public)
        .finalize()[..16]
        .try_into()
        .unwrap();
    let root = PinnedRoot::new(root_public, root_kid).unwrap();
    let data_signer = ephemeral_signing_key();
    let data_kid = [0x51; 16];

    let mut ring_payload = Vec::new();
    test_cbor_map(&mut ring_payload, 6);
    test_cbor_uint(&mut ring_payload, 1);
    test_cbor_uint(&mut ring_payload, 1);
    test_cbor_uint(&mut ring_payload, 2);
    test_cbor_bytes(&mut ring_payload, &time_uuid(NOW - 10, 0x52));
    test_cbor_uint(&mut ring_payload, 3);
    test_cbor_int(&mut ring_payload, NOW - 10);
    test_cbor_uint(&mut ring_payload, 4);
    test_cbor_bytes(&mut ring_payload, &[]);
    test_cbor_uint(&mut ring_payload, 5);
    test_cbor_array(&mut ring_payload, 1);
    test_cbor_map(&mut ring_payload, 7);
    test_cbor_uint(&mut ring_payload, 1);
    test_cbor_bytes(&mut ring_payload, &data_kid);
    test_cbor_uint(&mut ring_payload, 2);
    test_cbor_bytes(&mut ring_payload, &data_signer.verifying_key().to_bytes());
    test_cbor_uint(&mut ring_payload, 3);
    test_cbor_bytes(&mut ring_payload, b"cloud-core");
    test_cbor_uint(&mut ring_payload, 4);
    test_cbor_array(&mut ring_payload, 1);
    test_cbor_bytes(&mut ring_payload, b"walgit");
    test_cbor_uint(&mut ring_payload, 5);
    test_cbor_int(&mut ring_payload, NOW - 1_000);
    test_cbor_uint(&mut ring_payload, 6);
    test_cbor_int(&mut ring_payload, NOW + 1_000);
    test_cbor_uint(&mut ring_payload, 7);
    test_cbor_uint(&mut ring_payload, 2);
    test_cbor_uint(&mut ring_payload, 6);
    test_cbor_uint(&mut ring_payload, 1);
    let ring_body = test_sign1(&root_signer, &root_kid, RING_AAD, &ring_payload);
    let ring_digest: [u8; 32] = Sha256::digest(&ring_body).into();
    let ring_root = VerificationRingRoot {
        key: Bytes::from(format!(
            "{}v2/control/key-rings/{}.cose",
            prefix.as_str(),
            hex::encode(ring_digest)
        )),
        object_version_id: Bytes::from_static(b"ring-version-1"),
        digest: Bytes::copy_from_slice(&ring_digest),
        size: ring_body.len() as u64,
        ring_epoch: 1,
    };
    let credential_control = CredentialControl {
        schema_version: 2,
        control_revision: 1,
        issuer_epoch: 1,
        current: Some(ring_root.clone()),
        next: None,
        previous: None,
        previous_last_issue_unix_seconds: None,
        revoked_kids: Vec::new(),
        verifier_set_digest: Bytes::from(vec![0x61; 32]),
        acknowledgement_proof_digest: Bytes::from(vec![0x62; 32]),
    };
    let authority = CredentialAuthority::bind(
        &root,
        &credential_control,
        prefix,
        BoundRingObjects {
            current: ExactRingObject {
                key: &ring_root.key,
                object_version_id: &ring_root.object_version_id,
                body: &ring_body,
            },
            next: None,
            previous: None,
        },
    )
    .unwrap();

    let control = stored.control();
    let identity = control.identity.as_ref().unwrap();
    let token_id = time_uuid(NOW, 0x53);
    let mut payload = Vec::new();
    test_cbor_map(&mut payload, 24);
    for (key, value) in [(1, 1), (2, 2)] {
        test_cbor_uint(&mut payload, key);
        test_cbor_uint(&mut payload, value);
    }
    test_cbor_uint(&mut payload, 3);
    test_cbor_bytes(&mut payload, b"cloud-core");
    test_cbor_uint(&mut payload, 4);
    test_cbor_bytes(&mut payload, b"walgit");
    test_cbor_uint(&mut payload, 5);
    test_cbor_bytes(&mut payload, &token_id);
    for (key, value) in [(6, NOW), (7, NOW), (8, NOW + 900)] {
        test_cbor_uint(&mut payload, key);
        test_cbor_int(&mut payload, value);
    }
    test_cbor_uint(&mut payload, 9);
    test_cbor_bytes(&mut payload, &identity.tenant_id);
    test_cbor_uint(&mut payload, 10);
    test_cbor_bytes(&mut payload, &identity.project_id);
    test_cbor_uint(&mut payload, 11);
    test_cbor_bytes(&mut payload, &identity.repository_uuid);
    test_cbor_uint(&mut payload, 12);
    test_cbor_uint(&mut payload, identity.generation);
    test_cbor_uint(&mut payload, 13);
    test_cbor_bytes(&mut payload, &identity.canonical_path);
    test_cbor_uint(&mut payload, 14);
    test_cbor_bytes(&mut payload, &identity.canonical_path_digest);
    test_cbor_uint(&mut payload, 15);
    test_cbor_uint(&mut payload, 1);
    test_cbor_uint(&mut payload, 16);
    test_cbor_bytes(&mut payload, &ring_digest);
    test_cbor_uint(&mut payload, 17);
    test_cbor_bytes(&mut payload, &identity.routing_digest);
    test_cbor_uint(&mut payload, 30);
    test_cbor_uint(&mut payload, CapabilityPurpose::RepositoryAdmin as u64);
    test_cbor_uint(&mut payload, 31);
    test_cbor_uint(&mut payload, control.authorization_epoch);
    test_cbor_uint(&mut payload, 32);
    test_cbor_bytes(&mut payload, &control.repo_control_key);
    test_cbor_uint(&mut payload, 33);
    test_cbor_bytes(
        &mut payload,
        stored.binding().object_version_id().as_str().as_bytes(),
    );
    test_cbor_uint(&mut payload, 34);
    test_cbor_uint(&mut payload, control.cutover_generation);
    test_cbor_uint(&mut payload, 35);
    test_cbor_bytes(&mut payload, b"cloud-core");
    test_cbor_uint(&mut payload, 36);
    test_cbor_bytes(&mut payload, b"admin-1");
    let envelope = test_sign1(&data_signer, &data_kid, CAPABILITY_AAD, &payload);

    let repository_uuid: [u8; 16] = identity.repository_uuid.as_ref().try_into().unwrap();
    let ring_digest_expected = ring_digest;
    let routing_digest: [u8; 32] = identity.routing_digest.as_ref().try_into().unwrap();
    let expected = ExpectedCapability {
        common: ExpectedCommonClaims {
            issuer: b"cloud-core",
            audience: b"walgit",
            id: token_id,
            tenant_id: &identity.tenant_id,
            project_id: &identity.project_id,
            repository_uuid,
            canonical_path: &identity.canonical_path,
            ring_epoch: 1,
            ring_digest: ring_digest_expected,
            routing_digest,
        },
        purpose: CapabilityPurpose::RepositoryAdmin,
        authorization_epoch: control.authorization_epoch,
        control_key: &control.repo_control_key,
        control_version_id: stored.binding().object_version_id().as_str().as_bytes(),
        cutover_generation: control.cutover_generation,
        grant_issuer: b"cloud-core",
        grant_subject: b"admin-1",
    };
    authority
        .authenticate_capability(&envelope, NOW, &expected)
        .unwrap()
}

fn ephemeral_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    let key = SigningKey::from_bytes(&bytes);
    bytes.fill(0);
    key
}

fn time_uuid(timestamp: i64, tail: u8) -> [u8; 16] {
    let mut value = [tail; 16];
    let millis = (timestamp as u64) * 1_000;
    value[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    value[6] = (value[6] & 0x0f) | 0x70;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}

fn test_sign1(signing: &SigningKey, kid: &[u8; 16], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut protected = Vec::new();
    test_cbor_map(&mut protected, 2);
    test_cbor_uint(&mut protected, 1);
    test_cbor_int(&mut protected, -8);
    test_cbor_uint(&mut protected, 4);
    test_cbor_bytes(&mut protected, kid);

    let mut structure = Vec::new();
    test_cbor_array(&mut structure, 4);
    test_cbor_text(&mut structure, b"Signature1");
    test_cbor_bytes(&mut structure, &protected);
    test_cbor_bytes(&mut structure, aad);
    test_cbor_bytes(&mut structure, payload);
    let signature = signing.sign(&structure).to_bytes();

    let mut envelope = Vec::new();
    test_cbor_array(&mut envelope, 4);
    test_cbor_bytes(&mut envelope, &protected);
    test_cbor_map(&mut envelope, 0);
    test_cbor_bytes(&mut envelope, payload);
    test_cbor_bytes(&mut envelope, &signature);
    envelope
}

fn test_cbor_uint(out: &mut Vec<u8>, value: u64) {
    test_cbor_head(out, 0, value);
}

fn test_cbor_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        test_cbor_head(out, 0, value as u64);
    } else {
        test_cbor_head(out, 1, (-1i128 - value as i128) as u64);
    }
}

fn test_cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    test_cbor_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

fn test_cbor_text(out: &mut Vec<u8>, value: &[u8]) {
    test_cbor_head(out, 3, value.len() as u64);
    out.extend_from_slice(value);
}

fn test_cbor_array(out: &mut Vec<u8>, count: usize) {
    test_cbor_head(out, 4, count as u64);
}

fn test_cbor_map(out: &mut Vec<u8>, count: usize) {
    test_cbor_head(out, 5, count as u64);
}

fn test_cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => {
            out.push(prefix | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

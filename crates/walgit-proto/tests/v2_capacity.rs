use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use walgit_proto::v2::{
    capacity_commit_binding::Predecessor as CapacityCommitPredecessor,
    capacity_control::StatePayload as CapacityControlPayload,
    capacity_reservation::StatePayload as CapacityReservationPayload,
    digests::ContentAddressDigest,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, RoutingDigest, V2KeyKind, capacity_control_key,
        capacity_shard_key, parse_key, repo_control_key, tenant_capacity_catalog_key,
    },
};
use walgit_proto::{Message, v2::*};

const PREFIX: &str = "prod/";
const REPOSITORY_UUID: &str = "01890f4776447b8b9d7a876543210abc";
const RESERVATION_ID: &str = "01890f4776447b8b9d7a876543210abd";
const MUTATION_ID: &str = "01890f4776447b8b9d7a876543210abe";
const CONFLICTING_MUTATION_ID: &str = "01890f4776447b8b9d7a876543210abf";
const ADMISSION_FENCE_ID: &str = "01890f4776447b8b9d7a876543210ac0";

#[test]
fn capacity_enum_numbers_and_wire_bytes_are_frozen() {
    assert_eq!(CapacityControlState::Unspecified as i32, 0);
    assert_eq!(CapacityControlState::Stable as i32, 1);
    assert_eq!(CapacityControlState::Preparing as i32, 2);
    assert_eq!(RedistributionPhase::Unspecified as i32, 0);
    assert_eq!(RedistributionPhase::Draining as i32, 1);
    assert_eq!(RedistributionPhase::Applying as i32, 2);
    assert_eq!(CapacityReservationState::Unspecified as i32, 0);
    assert_eq!(CapacityReservationState::Reserved as i32, 1);
    assert_eq!(CapacityReservationState::Committing as i32, 2);
    assert_eq!(CapacityReservationState::Charged as i32, 3);
    assert_eq!(CapacityReservationState::Aborted as i32, 4);

    for (value, expected) in [(1, "1801"), (2, "1802")] {
        let control = CapacityControl {
            state: value,
            ..Default::default()
        };
        assert_eq!(hex::encode(control.encode_to_vec()), expected);
    }
    for (value, expected) in [(1, "0801"), (2, "0802")] {
        let redistribution = CapacityRedistribution {
            phase: value,
            ..Default::default()
        };
        assert_eq!(hex::encode(redistribution.encode_to_vec()), expected);
    }
    for (value, expected) in [(1, "3801"), (2, "3802"), (3, "3803"), (4, "3804")] {
        let reservation = CapacityReservation {
            state: value,
            ..Default::default()
        };
        assert_eq!(hex::encode(reservation.encode_to_vec()), expected);
    }

    let object = CapacityObjectRef {
        key: Bytes::from_static(b"k"),
        object_version_id: Bytes::from_static(b"v"),
        digest: Bytes::from(vec![0x11; 32]),
        size: 1,
    };
    assert_eq!(
        hex::encode(object.encode_to_vec()),
        "0a016b1201761a2011111111111111111111111111111111111111111111111111111111111111112001"
    );
    assert_eq!(
        hex::encode(commit_binding().encode_to_vec()),
        "0801121001890f4776447b8b9d7a876543210abe18062a100a056361732d3112077265706f2d7631"
    );
    let mut create = commit_binding();
    create.kind = MutationKind::Create as i32;
    create.predecessor = Some(CapacityCommitPredecessor::NoPriorControl(NoPriorControl {}));
    assert_eq!(
        hex::encode(create.encode_to_vec()),
        "0801121001890f4776447b8b9d7a876543210abe18012200"
    );
}

#[test]
fn persisted_capacity_roots_have_stable_exact_digests() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let values = [
        encode_tenant_capacity_catalog_page(&tenant_page()).unwrap(),
        encode_capacity_shard(&shard_with(vec![reserved_reservation()]), &prefix).unwrap(),
        encode_capacity_control(&stable_control(&prefix), &prefix).unwrap(),
        encode_capacity_control(
            &preparing_control(&prefix, RedistributionPhase::Applying),
            &prefix,
        )
        .unwrap(),
    ];
    let actual = values
        .iter()
        .map(|value| {
            (
                value.len(),
                hex::encode(<[u8; 32]>::from(Sha256::digest(value))),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (
                1_680,
                "ee19542f241d3ce3d8a5193196bd6d7693befe3de97b61c0bb0a0d7c4ac44df0".to_owned(),
            ),
            (
                208,
                "e4f4ffe964945231024f5a04153a9d053ea06a7ea72001d15e10818b241b5b2a".to_owned(),
            ),
            (
                26_577,
                "abb33ed78ae9a6ad7e3cd662078c2c111554824f319fa9a6a5590a1ea1e0656b".to_owned(),
            ),
            (
                55_833,
                "a68775ab3ecacc07c055d584719f3c21b2aad9eb68633ac9a913bc6f59656290".to_owned(),
            ),
        ]
    );
}

#[test]
fn every_capacity_key_is_exact_for_empty_and_nonempty_prefixes() {
    for prefix in [
        DeploymentPrefix::empty(),
        DeploymentPrefix::parse(PREFIX).unwrap(),
    ] {
        assert_eq!(
            parse_key(&prefix, capacity_control_key(&prefix).unwrap().as_bytes())
                .unwrap()
                .kind,
            V2KeyKind::CapacityControl
        );
        for shard in 0u8..=255 {
            let key = capacity_shard_key(&prefix, shard).unwrap();
            assert!(key.ends_with(&format!("v2/capacity/shards/{shard:02x}/capacity_shard.pb")));
            assert_eq!(
                parse_key(&prefix, key.as_bytes()).unwrap().kind,
                V2KeyKind::CapacityShard
            );
        }
        let digest = ContentAddressDigest::from_bytes([0x42; 32]);
        let key = tenant_capacity_catalog_key(&prefix, digest).unwrap();
        let parsed = parse_key(&prefix, key.as_bytes()).unwrap();
        assert_eq!(parsed.kind, V2KeyKind::TenantCapacityCatalog);
        assert_eq!(parsed.content_digest.unwrap().as_bytes(), &[0x42; 32]);
        validate_capacity_control(&stable_control(&prefix), &prefix).unwrap();
        validate_capacity_shard(&shard_with(vec![charged_reservation(&prefix)]), &prefix).unwrap();
    }
}

#[test]
fn tenant_catalog_is_flat_canonical_bounded_and_content_addressed() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let page = tenant_page();
    let encoded = encode_tenant_capacity_catalog_page(&page).unwrap();
    assert_eq!(decode_tenant_capacity_catalog_page(&encoded).unwrap(), page);
    let object = tenant_page_ref(&prefix, &page);
    validate_tenant_capacity_catalog_object(&page, &object, &prefix).unwrap();

    let mut wrong = object.clone();
    let mut wrong_digest = wrong.digest.to_vec();
    wrong_digest[0] ^= 1;
    wrong.digest = Bytes::from(wrong_digest);
    assert!(validate_tenant_capacity_catalog_object(&page, &wrong, &prefix).is_err());
    let mut wrong = object.clone();
    wrong.size += 1;
    assert!(validate_tenant_capacity_catalog_object(&page, &wrong, &prefix).is_err());
    let mut wrong = object.clone();
    wrong.key = Bytes::from_static(
        b"prod/v2/capacity/catalogs/tenant/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.pb",
    );
    assert!(validate_tenant_capacity_catalog_object(&page, &wrong, &prefix).is_err());

    let mut duplicate = page.clone();
    duplicate.allocations.push(duplicate.allocations[0].clone());
    assert!(encode_tenant_capacity_catalog_page(&duplicate).is_err());
    let mut unsorted = page.clone();
    unsorted.allocations.insert(0, allocation(b"tenant-z"));
    assert!(encode_tenant_capacity_catalog_page(&unsorted).is_err());

    let too_many = TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: vec![TenantCapacityAllocation::default(); 4_097],
    };
    assert!(validate_tenant_capacity_catalog_page(&too_many).is_err());
    assert_eq!(MAX_TENANT_CAPACITY_ALLOCATIONS, 4_096);

    let encoded_size_backpressure = TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: (0..500u32)
            .map(|index| allocation(&index.to_be_bytes()))
            .collect(),
    };
    assert!(encoded_size_backpressure.encoded_len() > MAX_TENANT_CAPACITY_CATALOG_BYTES);
    assert!(matches!(
        encode_tenant_capacity_catalog_page(&encoded_size_backpressure),
        Err(ControlCodecError::MessageTooLarge {
            maximum: 524_288,
            ..
        })
    ));
}

#[test]
fn tenant_allocations_require_all_256_nonzero_slices_and_checked_exact_sums() {
    let valid = tenant_page();
    validate_tenant_capacity_catalog_page(&valid).unwrap();

    let mut value = valid.clone();
    value.allocations[0].slices.pop();
    assert!(validate_tenant_capacity_catalog_page(&value).is_err());
    let mut value = valid.clone();
    value.allocations[0].slices[17].shard = 18;
    assert!(validate_tenant_capacity_catalog_page(&value).is_err());
    let mut value = valid.clone();
    value.allocations[0].slices[17].byte_count = 0;
    assert!(validate_tenant_capacity_catalog_page(&value).is_err());
    let mut value = valid.clone();
    value.allocations[0].total_bytes += 1;
    assert!(validate_tenant_capacity_catalog_page(&value).is_err());
    let mut value = valid;
    for slice in &mut value.allocations[0].slices {
        slice.byte_count = u64::MAX;
    }
    value.allocations[0].total_bytes = u64::MAX;
    assert!(validate_tenant_capacity_catalog_page(&value).is_err());
}

#[test]
fn all_reservation_state_cells_are_exact_and_ttl_is_explicit() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    for reservation in [
        reserved_reservation(),
        committing_reservation(),
        charged_reservation(&prefix),
        expired_reservation(),
        conflicting_reservation(&prefix),
    ] {
        let shard = shard_with(vec![reservation]);
        let encoded = encode_capacity_shard(&shard, &prefix).unwrap();
        assert_eq!(decode_capacity_shard(&encoded, &prefix).unwrap(), shard);
    }

    let mut value = reserved_reservation();
    let Some(capacity_reservation::StatePayload::Reserved(reserved)) = value.state_payload.as_mut()
    else {
        panic!("reserved payload")
    };
    reserved.expires_at_unix_seconds = reserved.created_at_unix_seconds + 901;
    assert!(validate_capacity_shard(&shard_with(vec![value]), &prefix).is_err());

    let mut value = reserved_reservation();
    let Some(capacity_reservation::StatePayload::Reserved(reserved)) = value.state_payload.as_mut()
    else {
        panic!("reserved payload")
    };
    reserved.created_at_unix_seconds = u64::MAX;
    reserved.expires_at_unix_seconds = 1;
    assert!(validate_capacity_shard(&shard_with(vec![value]), &prefix).is_err());

    let mut value = expired_reservation();
    let Some(capacity_reservation::StatePayload::Aborted(aborted)) = value.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::Expired(expired)) = aborted.proof.as_mut() else {
        panic!("expiry proof")
    };
    expired.observed_now_unix_seconds = expired.expires_at_unix_seconds - 1;
    assert!(validate_capacity_shard(&shard_with(vec![value]), &prefix).is_err());

    let mut value = conflicting_reservation(&prefix);
    let Some(capacity_reservation::StatePayload::Aborted(aborted)) = value.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(conflict)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    conflict.conflicting_mutation_id = conflict.commit.as_ref().unwrap().mutation_id.clone();
    assert!(validate_capacity_shard(&shard_with(vec![value]), &prefix).is_err());

    let mut mismatch = reserved_reservation();
    mismatch.state = CapacityReservationState::Committing as i32;
    assert!(validate_capacity_shard(&shard_with(vec![mismatch]), &prefix).is_err());
    let mut missing = expired_reservation();
    let Some(capacity_reservation::StatePayload::Aborted(aborted)) = missing.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    aborted.proof = None;
    assert!(validate_capacity_shard(&shard_with(vec![missing]), &prefix).is_err());
}

#[test]
fn capacity_commit_predecessor_is_explicit_for_create_and_existing_repositories() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let mut create = committing_reservation();
    let Some(capacity_reservation::StatePayload::Committing(payload)) =
        create.state_payload.as_mut()
    else {
        panic!("committing payload")
    };
    let commit = payload.commit.as_mut().unwrap();
    commit.kind = MutationKind::Create as i32;
    commit.predecessor = Some(CapacityCommitPredecessor::NoPriorControl(NoPriorControl {}));
    validate_capacity_shard(&shard_with(vec![create.clone()]), &prefix).unwrap();

    let mut create_with_prior = create.clone();
    let Some(capacity_reservation::StatePayload::Committing(payload)) =
        create_with_prior.state_payload.as_mut()
    else {
        panic!("committing payload")
    };
    payload.commit.as_mut().unwrap().predecessor = commit_binding().predecessor;
    assert!(validate_capacity_shard(&shard_with(vec![create_with_prior]), &prefix).is_err());

    let mut existing_with_none = committing_reservation();
    let Some(capacity_reservation::StatePayload::Committing(payload)) =
        existing_with_none.state_payload.as_mut()
    else {
        panic!("committing payload")
    };
    payload.commit.as_mut().unwrap().predecessor =
        Some(CapacityCommitPredecessor::NoPriorControl(NoPriorControl {}));
    assert!(validate_capacity_shard(&shard_with(vec![existing_with_none]), &prefix).is_err());

    let mut missing = committing_reservation();
    let Some(capacity_reservation::StatePayload::Committing(payload)) =
        missing.state_payload.as_mut()
    else {
        panic!("committing payload")
    };
    payload.commit.as_mut().unwrap().predecessor = None;
    assert!(validate_capacity_shard(&shard_with(vec![missing]), &prefix).is_err());
}

#[test]
fn shard_validation_closes_hash_activity_and_oversubscription_invariants() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let valid = shard_with(vec![reserved_reservation()]);
    validate_capacity_shard(&valid, &prefix).unwrap();

    let mut value = valid.clone();
    value.shard = (value.shard + 1) % 256;
    assert!(validate_capacity_shard(&value, &prefix).is_err());
    let mut value = valid.clone();
    value.reservations[0].reservation_id = Bytes::from_static(b"not-a-uuid-v7!!");
    assert!(validate_capacity_shard(&value, &prefix).is_err());

    let mut second = reserved_reservation();
    second.reservation_id = uuid("01890f4776447b8b9d7a876543210ac1");
    let active_twice = shard_with(vec![reserved_reservation(), second]);
    assert!(validate_capacity_shard(&active_twice, &prefix).is_err());

    let mut over_budget = shard_with(vec![reserved_reservation()]);
    over_budget.budget_bytes = 99;
    assert!(validate_capacity_shard(&over_budget, &prefix).is_err());
    let equal_budget = shard_with(vec![reserved_reservation()]);
    assert_eq!(
        equal_budget.tenant_accounts[0].current_slice_bytes,
        equal_budget.budget_bytes
    );
    validate_capacity_shard(&equal_budget, &prefix).unwrap();
    let mut account_over_budget = equal_budget;
    account_over_budget.tenant_accounts[0].current_slice_bytes =
        account_over_budget.budget_bytes + 1;
    assert!(validate_capacity_shard(&account_over_budget, &prefix).is_err());

    let mut first = charged_reservation(&prefix);
    first.byte_count = 60;
    first.tenant_slice_bytes = 100;
    let mut second = expired_reservation();
    second.state = CapacityReservationState::Charged as i32;
    second.reservation_id = uuid("01890f4776447b8b9d7a876543210ac1");
    second.byte_count = 60;
    second.tenant_slice_bytes = 100;
    second.state_payload = first.state_payload.clone();
    assert!(validate_capacity_shard(&shard_with(vec![first, second]), &prefix).is_err());

    let mut unsorted = reserved_reservation();
    unsorted.reservation_id = uuid("01890f4776447b8b9d7a876543210aaa");
    assert!(
        validate_capacity_shard(&shard_with(vec![reserved_reservation(), unsorted]), &prefix)
            .is_err()
    );
    let too_many = CapacityShard {
        reservations: vec![CapacityReservation::default(); 4_097],
        ..valid
    };
    assert!(validate_capacity_shard(&too_many, &prefix).is_err());
}

#[test]
fn commit_mutation_ids_are_unique_per_repository_not_globally() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let charged = charged_reservation(&prefix);
    let mut conflict = conflicting_reservation(&prefix);
    conflict.reservation_id = uuid("01890f4776447b8b9d7a876543210ac1");
    assert!(validate_capacity_shard(&shard_with(vec![charged, conflict]), &prefix).is_err());

    let first = committing_reservation();
    let mut second = committing_reservation();
    second.reservation_id = uuid("01890f4776447b8b9d7a876543210ac1");
    let other_identity = different_identity_same_shard();
    second.tenant_id = other_identity.tenant_id.clone();
    second.identity = Some(other_identity);
    validate_capacity_shard(&shard_with(vec![first, second]), &prefix).unwrap();
}

#[test]
fn redistribution_preserves_historical_rows_and_uses_current_tenant_accounts() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let mut older = charged_reservation(&prefix);
    older.allocation_epoch = 1;
    older.tenant_slice_bytes = 150;
    older.byte_count = 60;
    let mut newer = charged_reservation(&prefix);
    newer.reservation_id = uuid("01890f4776447b8b9d7a876543210ac1");
    let Some(capacity_reservation::StatePayload::Charged(charged)) = newer.state_payload.as_mut()
    else {
        panic!("charged payload")
    };
    charged.commit.as_mut().unwrap().mutation_id = uuid("01890f4776447b8b9d7a876543210ac2");
    newer.allocation_epoch = 2;
    newer.tenant_slice_bytes = 90;
    newer.byte_count = 40;
    let historical = vec![older, newer];
    let mut redistributed = shard_with(historical.clone());
    redistributed.allocation_epoch = 2;
    redistributed.tenant_accounts[0].current_slice_bytes = 100;
    validate_capacity_shard(&redistributed, &prefix).unwrap();
    assert_eq!(redistributed.reservations, historical);

    let mut insufficient = redistributed.clone();
    insufficient.tenant_accounts[0].current_slice_bytes = 99;
    assert!(validate_capacity_shard(&insufficient, &prefix).is_err());
    let mut missing = redistributed.clone();
    missing.tenant_accounts.clear();
    assert!(validate_capacity_shard(&missing, &prefix).is_err());
    let mut duplicate = redistributed.clone();
    duplicate
        .tenant_accounts
        .push(duplicate.tenant_accounts[0].clone());
    assert!(validate_capacity_shard(&duplicate, &prefix).is_err());
    let mut extraneous = redistributed.clone();
    extraneous.tenant_accounts.push(CapacityTenantAccount {
        tenant_id: Bytes::from_static(b"tenant-z"),
        current_slice_bytes: 1,
    });
    assert!(validate_capacity_shard(&extraneous, &prefix).is_err());

    let mut old_active = reserved_reservation();
    old_active.allocation_epoch = 1;
    assert!(validate_capacity_shard(&shard_at_epoch(vec![old_active], 2), &prefix).is_err());
    let mut future_active = reserved_reservation();
    future_active.allocation_epoch = 3;
    assert!(validate_capacity_shard(&shard_at_epoch(vec![future_active], 2), &prefix).is_err());
    let mut future_terminal = charged_reservation(&prefix);
    future_terminal.allocation_epoch = 3;
    assert!(validate_capacity_shard(&shard_at_epoch(vec![future_terminal], 2), &prefix).is_err());

    let aborted_only = shard_at_epoch(vec![expired_reservation()], 2);
    assert!(aborted_only.tenant_accounts.is_empty());
    validate_capacity_shard(&aborted_only, &prefix).unwrap();
}

#[test]
fn current_shard_view_binds_control_budget_epoch_and_exact_catalog_accounts() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let shard = shard_with(vec![reserved_reservation()]);
    let page = tenant_page_with_slice(shard.shard as usize, 1_000);
    let mut control = stable_control(&prefix);
    control.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    validate_capacity_shard_catalog(&shard, &page, &prefix).unwrap();
    validate_capacity_current_shard_view(&control, &page, &shard, &prefix).unwrap();
    validate_capacity_admission_view(&control, &page, &shard, &prefix).unwrap();

    let mut preparing = preparing_control(&prefix, RedistributionPhase::Draining);
    preparing.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    validate_capacity_current_shard_view(&preparing, &page, &shard, &prefix).unwrap();
    assert!(validate_capacity_admission_view(&preparing, &page, &shard, &prefix).is_err());

    for current_slice in [999, 1_001] {
        let wrong_page = tenant_page_with_slice(shard.shard as usize, current_slice);
        assert!(validate_capacity_shard_catalog(&shard, &wrong_page, &prefix).is_err());
    }
    let mut wrong_shard_slice = tenant_page_with_slice(shard.shard as usize, 999);
    let other = (shard.shard as usize + 1) % 256;
    let old_other = wrong_shard_slice.allocations[0].slices[other].byte_count;
    wrong_shard_slice.allocations[0].slices[other].byte_count = 1_000;
    wrong_shard_slice.allocations[0].total_bytes = wrong_shard_slice.allocations[0]
        .total_bytes
        .checked_add(1_000 - old_other)
        .unwrap();
    assert!(validate_capacity_shard_catalog(&shard, &wrong_shard_slice, &prefix).is_err());

    let empty_page = TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: Vec::new(),
    };
    assert!(validate_capacity_shard_catalog(&shard, &empty_page, &prefix).is_err());

    let mut wrong_epoch = shard.clone();
    wrong_epoch.allocation_epoch += 1;
    wrong_epoch.reservations[0].allocation_epoch += 1;
    assert!(validate_capacity_current_shard_view(&control, &page, &wrong_epoch, &prefix).is_err());
    let budget_page = tenant_page_with_slice(shard.shard as usize, 999);
    let mut budget_control = control.clone();
    budget_control.tenant_catalog = Some(tenant_page_ref(&prefix, &budget_page));
    let mut wrong_budget = shard.clone();
    wrong_budget.budget_bytes = 999;
    wrong_budget.tenant_accounts[0].current_slice_bytes = 999;
    assert!(
        validate_capacity_current_shard_view(&budget_control, &budget_page, &wrong_budget, &prefix)
            .is_err()
    );

    let mut historical = charged_reservation(&prefix);
    historical.allocation_epoch = 1;
    historical.tenant_slice_bytes = 150;
    historical.byte_count = 100;
    let mut redistributed = shard_at_epoch(vec![historical], 2);
    redistributed.tenant_accounts[0].current_slice_bytes = 100;
    let current_page = tenant_page_with_slice(redistributed.shard as usize, 100);
    validate_capacity_shard_catalog(&redistributed, &current_page, &prefix).unwrap();
}

#[test]
fn capacity_object_metadata_and_exact_shard_body_have_closed_bounds() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let shard = shard_with(vec![charged_reservation(&prefix)]);
    let encoded = encode_capacity_shard(&shard, &prefix).unwrap();
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    let key = capacity_shard_key(&prefix, shard.shard as u8).unwrap();
    let object = CapacityObjectRef {
        key: Bytes::from(key),
        object_version_id: Bytes::from(vec![b'v'; 1_024]),
        digest: Bytes::copy_from_slice(&digest),
        size: encoded.len() as u64,
    };
    validate_capacity_shard_object(&shard, &object, &prefix).unwrap();

    let mut wrong = object.clone();
    wrong.object_version_id.clear();
    assert!(validate_capacity_shard_object(&shard, &wrong, &prefix).is_err());
    let mut wrong = object.clone();
    wrong.object_version_id = Bytes::from(vec![b'v'; 1_025]);
    assert!(validate_capacity_shard_object(&shard, &wrong, &prefix).is_err());
    let mut wrong = object.clone();
    let mut wrong_digest = wrong.digest.to_vec();
    wrong_digest[0] ^= 1;
    wrong.digest = Bytes::from(wrong_digest);
    assert!(validate_capacity_shard_object(&shard, &wrong, &prefix).is_err());
    let mut wrong = object.clone();
    wrong.size = 0;
    assert!(validate_capacity_shard_object(&shard, &wrong, &prefix).is_err());
    let mut wrong = object;
    wrong.size = MAX_CAPACITY_SHARD_BYTES as u64 + 1;
    assert!(validate_capacity_shard_object(&shard, &wrong, &prefix).is_err());
}

#[test]
fn stable_and_both_preparing_phases_have_closed_recovery_proofs() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let stable = stable_control(&prefix);
    let encoded = encode_capacity_control(&stable, &prefix).unwrap();
    assert_eq!(decode_capacity_control(&encoded, &prefix).unwrap(), stable);

    let draining = preparing_control(&prefix, RedistributionPhase::Draining);
    validate_capacity_control(&draining, &prefix).unwrap();
    let applying = preparing_control(&prefix, RedistributionPhase::Applying);
    validate_capacity_control(&applying, &prefix).unwrap();
    let CapacityControlPayload::Redistribution(plan) = applying.state_payload.as_ref().unwrap()
    else {
        panic!("redistribution payload")
    };
    assert_ne!(
        plan.baselines[0]
            .shard_object
            .as_ref()
            .unwrap()
            .object_version_id,
        applying.shard_budgets[0]
            .shard_object
            .as_ref()
            .unwrap()
            .object_version_id
    );

    let mut wrong = draining.clone();
    wrong.state_payload = Some(CapacityControlPayload::Stable(StableCapacityState {}));
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = applying.clone();
    let Some(CapacityControlPayload::Redistribution(plan)) = wrong.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines.pop();
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = draining.clone();
    let Some(CapacityControlPayload::Redistribution(plan)) = wrong.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines = baselines(&prefix, &wrong.shard_budgets);
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = applying.clone();
    let Some(CapacityControlPayload::Redistribution(plan)) = wrong.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines[7].allocation_epoch += 1;
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = applying.clone();
    let Some(CapacityControlPayload::Redistribution(plan)) = wrong.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines[7].budget_bytes += 1;
    assert!(validate_capacity_control(&wrong, &prefix).is_err());

    let mut restored = stable;
    for budget in &mut restored.shard_budgets {
        budget.shard_object.as_mut().unwrap().object_version_id =
            Bytes::from(format!("restored-{}", budget.shard));
    }
    validate_capacity_control(&restored, &prefix).unwrap();
}

#[test]
fn applying_baseline_exact_binds_the_loaded_terminal_only_shard() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let terminal = shard_with(vec![charged_reservation(&prefix)]);
    let index = terminal.shard as usize;
    let mut applying = preparing_control(&prefix, RedistributionPhase::Applying);
    let Some(CapacityControlPayload::Redistribution(plan)) = applying.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines[index].shard_object = Some(exact_shard_ref(&terminal, &prefix));
    validate_capacity_applying_baseline(&applying, &terminal, &prefix).unwrap();

    let active = shard_with(vec![reserved_reservation()]);
    let Some(CapacityControlPayload::Redistribution(plan)) = applying.state_payload.as_mut() else {
        panic!("redistribution payload")
    };
    plan.baselines[index].shard_object = Some(exact_shard_ref(&active, &prefix));
    assert!(validate_capacity_applying_baseline(&applying, &active, &prefix).is_err());
}

#[test]
fn control_budget_rows_are_exact_complete_and_checked() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let valid = stable_control(&prefix);
    let mut wrong = valid.clone();
    wrong.shard_budgets.pop();
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = valid.clone();
    wrong.shard_budgets[17].shard = 18;
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = valid.clone();
    wrong.global_allocatable_bytes -= 1;
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = valid.clone();
    wrong.shard_budgets[0].budget_bytes = u64::MAX;
    wrong.global_allocatable_bytes = u64::MAX;
    assert!(validate_capacity_control(&wrong, &prefix).is_err());
    let mut wrong = valid.clone();
    wrong.shard_budgets[17].shard_object.as_mut().unwrap().key =
        Bytes::from(capacity_shard_key(&prefix, 18).unwrap());
    assert!(validate_capacity_control(&wrong, &prefix).is_err());

    let mut maximum = valid;
    maximum.shard_budgets[0].shard_object.as_mut().unwrap().size = MAX_CAPACITY_SHARD_BYTES as u64;
    validate_capacity_control(&maximum, &prefix).unwrap();
    maximum.shard_budgets[0].shard_object.as_mut().unwrap().size += 1;
    assert!(validate_capacity_control(&maximum, &prefix).is_err());
}

#[test]
fn control_catalog_cross_validation_binds_bodies_and_all_256_column_sums() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let current_page = tenant_page();
    let stable = stable_control(&prefix);
    validate_capacity_control_catalogs(&stable, &current_page, None, &prefix).unwrap();
    assert!(
        validate_capacity_control_catalogs(&stable, &current_page, Some(&current_page), &prefix)
            .is_err()
    );

    let preparing = preparing_control(&prefix, RedistributionPhase::Draining);
    validate_capacity_control_catalogs(&preparing, &current_page, Some(&current_page), &prefix)
        .unwrap();
    assert!(validate_capacity_control_catalogs(&preparing, &current_page, None, &prefix).is_err());

    let mut mismatched_page = current_page.clone();
    mismatched_page.allocations[0].tenant_id = Bytes::from_static(b"tenant-b");
    assert!(validate_capacity_control_catalogs(&stable, &mismatched_page, None, &prefix).is_err());

    let mut current_oversubscribed = current_page.clone();
    current_oversubscribed.allocations[0].slices[0].byte_count = 1_001;
    current_oversubscribed.allocations[0].total_bytes = 1_256;
    let mut current_control = stable.clone();
    current_control.tenant_catalog = Some(tenant_page_ref(&prefix, &current_oversubscribed));
    assert!(
        validate_capacity_control_catalogs(
            &current_control,
            &current_oversubscribed,
            None,
            &prefix
        )
        .is_err()
    );

    let mut target_oversubscribed = current_page.clone();
    target_oversubscribed.allocations[0].slices[0].byte_count = 1_001;
    target_oversubscribed.allocations[0].total_bytes = 1_256;
    let mut target_control = preparing;
    let Some(CapacityControlPayload::Redistribution(plan)) = target_control.state_payload.as_mut()
    else {
        panic!("redistribution payload")
    };
    plan.target_tenant_catalog = Some(tenant_page_ref(&prefix, &target_oversubscribed));
    assert!(
        validate_capacity_control_catalogs(
            &target_control,
            &current_page,
            Some(&target_oversubscribed),
            &prefix
        )
        .is_err()
    );

    let large_slice = u64::MAX / 2 + 1;
    let mut first = allocation(b"tenant-a");
    first.slices[0].byte_count = large_slice;
    first.total_bytes = large_slice + 255;
    let mut second = allocation(b"tenant-b");
    second.slices[0].byte_count = large_slice;
    second.total_bytes = large_slice + 255;
    let overflow_page = TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: vec![first, second],
    };
    let mut overflow_control = stable;
    overflow_control.global_allocatable_bytes = u64::MAX;
    overflow_control.shard_budgets[0].budget_bytes = u64::MAX - 255;
    for budget in &mut overflow_control.shard_budgets[1..] {
        budget.budget_bytes = 1;
    }
    overflow_control.tenant_catalog = Some(tenant_page_ref(&prefix, &overflow_page));
    validate_capacity_control(&overflow_control, &prefix).unwrap();
    assert!(
        validate_capacity_control_catalogs(&overflow_control, &overflow_page, None, &prefix)
            .is_err()
    );
}

#[test]
fn strict_capacity_roots_reject_unknown_duplicate_wrong_wire_and_corruption() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let page_bytes = encode_tenant_capacity_catalog_page(&tenant_page()).unwrap();
    let shard_bytes =
        encode_capacity_shard(&shard_with(vec![reserved_reservation()]), &prefix).unwrap();
    let control = stable_control(&prefix);
    let control_bytes = encode_capacity_control(&control, &prefix).unwrap();

    for (bytes, preflight) in [
        (
            page_bytes.as_slice(),
            preflight_tenant_capacity_catalog_page as fn(&[u8]) -> Result<(), ControlCodecError>,
        ),
        (shard_bytes.as_slice(), preflight_capacity_shard),
        (control_bytes.as_slice(), preflight_capacity_control),
    ] {
        let mut unknown = bytes.to_vec();
        unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
        assert!(preflight(&unknown).is_err());
        let mut duplicate = vec![0x08, 0x01];
        duplicate.extend_from_slice(bytes);
        assert!(preflight(&duplicate).is_err());
        let mut wrong_wire = bytes.to_vec();
        wrong_wire[0] = 0x0a;
        assert!(preflight(&wrong_wire).is_err());
        assert!(preflight(&bytes[..bytes.len() - 1]).is_err());
        let mut malformed_tail = bytes.to_vec();
        malformed_tail.push(0x80);
        assert!(preflight(&malformed_tail).is_err());
    }

    let mut unknown_enum = control;
    unknown_enum.state = 99;
    assert!(preflight_capacity_control(&unknown_enum.encode_to_vec()).is_err());

    let mut dual_oneof = control_bytes;
    dual_oneof.extend_from_slice(&[0x52, 0x00]);
    assert!(preflight_capacity_control(&dual_oneof).is_err());
}

fn stable_control(prefix: &DeploymentPrefix) -> CapacityControl {
    let page = tenant_page();
    CapacityControl {
        schema_version: 1,
        control_revision: 1,
        state: CapacityControlState::Stable as i32,
        writer: Some(WriterFence {
            holder: Bytes::from_static(b"capacity-writer"),
            epoch: 1,
        }),
        allocation_epoch: 1,
        global_allocatable_bytes: 256_000,
        tenant_catalog: Some(tenant_page_ref(prefix, &page)),
        shard_budgets: (0u16..256)
            .map(|shard| CapacityShardBudget {
                shard: u32::from(shard),
                budget_bytes: 1_000,
                shard_object: Some(shard_ref(prefix, shard as u8, false)),
            })
            .collect(),
        state_payload: Some(CapacityControlPayload::Stable(StableCapacityState {})),
    }
}

fn preparing_control(prefix: &DeploymentPrefix, phase: RedistributionPhase) -> CapacityControl {
    let mut control = stable_control(prefix);
    control.control_revision = 2;
    control.state = CapacityControlState::Preparing as i32;
    let baselines = if phase == RedistributionPhase::Applying {
        baselines(prefix, &control.shard_budgets)
    } else {
        Vec::new()
    };
    control.state_payload = Some(CapacityControlPayload::Redistribution(Box::new(
        CapacityRedistribution {
            phase: phase as i32,
            target_epoch: 2,
            target_global_allocatable_bytes: 256_000,
            target_tenant_catalog: control.tenant_catalog.clone(),
            target_shard_budgets: (0u16..256)
                .map(|shard| CapacityShardBudgetProposal {
                    shard: u32::from(shard),
                    budget_bytes: 1_000,
                })
                .collect(),
            admission_fence_id: uuid(ADMISSION_FENCE_ID),
            baselines,
        },
    )));
    control
}

fn baselines(
    prefix: &DeploymentPrefix,
    budgets: &[CapacityShardBudget],
) -> Vec<CapacityShardBaseline> {
    budgets
        .iter()
        .map(|budget| CapacityShardBaseline {
            shard: budget.shard,
            allocation_epoch: 1,
            budget_bytes: budget.budget_bytes,
            shard_object: Some(shard_ref(prefix, budget.shard as u8, true)),
        })
        .collect()
}

fn shard_ref(prefix: &DeploymentPrefix, shard: u8, drained: bool) -> CapacityObjectRef {
    CapacityObjectRef {
        key: Bytes::from(capacity_shard_key(prefix, shard).unwrap()),
        object_version_id: Bytes::from(if drained {
            format!("drained-{shard}")
        } else {
            format!("stable-{shard}")
        }),
        digest: Bytes::from(vec![shard.wrapping_add(u8::from(drained)); 32]),
        size: 100,
    }
}

fn exact_shard_ref(shard: &CapacityShard, prefix: &DeploymentPrefix) -> CapacityObjectRef {
    let encoded = encode_capacity_shard(shard, prefix).unwrap();
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    CapacityObjectRef {
        key: Bytes::from(capacity_shard_key(prefix, shard.shard as u8).unwrap()),
        object_version_id: Bytes::from_static(b"exact-shard-version"),
        digest: Bytes::copy_from_slice(&digest),
        size: encoded.len() as u64,
    }
}

fn tenant_page() -> TenantCapacityCatalogPage {
    TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: vec![allocation(b"tenant-a")],
    }
}

fn allocation(tenant_id: &[u8]) -> TenantCapacityAllocation {
    TenantCapacityAllocation {
        tenant_id: Bytes::copy_from_slice(tenant_id),
        total_bytes: 256,
        slices: (0u16..256)
            .map(|shard| TenantShardSlice {
                shard: u32::from(shard),
                byte_count: 1,
            })
            .collect(),
    }
}

fn tenant_page_with_slice(shard: usize, byte_count: u64) -> TenantCapacityCatalogPage {
    let mut page = tenant_page();
    page.allocations[0].slices[shard].byte_count = byte_count;
    page.allocations[0].total_bytes = byte_count + 255;
    page
}

fn tenant_page_ref(
    prefix: &DeploymentPrefix,
    page: &TenantCapacityCatalogPage,
) -> CapacityObjectRef {
    let encoded = encode_tenant_capacity_catalog_page(page).unwrap();
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    CapacityObjectRef {
        key: Bytes::from(
            tenant_capacity_catalog_key(prefix, ContentAddressDigest::from_bytes(digest)).unwrap(),
        ),
        object_version_id: Bytes::from_static(b"tenant-page-v1"),
        digest: Bytes::copy_from_slice(&digest),
        size: encoded.len() as u64,
    }
}

fn shard_with(reservations: Vec<CapacityReservation>) -> CapacityShard {
    shard_at_epoch(reservations, 1)
}

fn shard_at_epoch(reservations: Vec<CapacityReservation>, allocation_epoch: u64) -> CapacityShard {
    let shard = Sha256::digest(hex::decode(REPOSITORY_UUID).unwrap())[0];
    let mut accounts = BTreeMap::<Vec<u8>, (u64, u64)>::new();
    for reservation in &reservations {
        if reservation.state != CapacityReservationState::Aborted as i32 {
            let entry = accounts
                .entry(reservation.tenant_id.to_vec())
                .or_insert((reservation.tenant_slice_bytes, 0));
            entry.0 = entry.0.max(reservation.tenant_slice_bytes);
            entry.1 += reservation.byte_count;
        }
    }
    CapacityShard {
        schema_version: 1,
        control_revision: 1,
        shard: u32::from(shard),
        allocation_epoch,
        budget_bytes: 1_000,
        tenant_accounts: accounts
            .into_iter()
            .map(
                |(tenant_id, (historical_slice, used))| CapacityTenantAccount {
                    tenant_id: Bytes::from(tenant_id),
                    current_slice_bytes: historical_slice.max(used),
                },
            )
            .collect(),
        reservations,
    }
}

fn reserved_reservation() -> CapacityReservation {
    reservation(
        CapacityReservationState::Reserved,
        CapacityReservationPayload::Reserved(ReservedCapacityReservation {
            created_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 1_900,
        }),
    )
}

fn committing_reservation() -> CapacityReservation {
    reservation(
        CapacityReservationState::Committing,
        CapacityReservationPayload::Committing(CommittingCapacityReservation {
            commit: Some(commit_binding()),
        }),
    )
}

fn charged_reservation(prefix: &DeploymentPrefix) -> CapacityReservation {
    reservation(
        CapacityReservationState::Charged,
        CapacityReservationPayload::Charged(ChargedCapacityReservation {
            commit: Some(commit_binding()),
            landed_control: Some(landed_control(prefix)),
        }),
    )
}

fn expired_reservation() -> CapacityReservation {
    reservation(
        CapacityReservationState::Aborted,
        CapacityReservationPayload::Aborted(AbortedCapacityReservation {
            proof: Some(aborted_capacity_reservation::Proof::Expired(
                ExpiredCapacityReservation {
                    created_at_unix_seconds: 1_000,
                    expires_at_unix_seconds: 1_900,
                    observed_now_unix_seconds: 1_900,
                },
            )),
        }),
    )
}

fn conflicting_reservation(prefix: &DeploymentPrefix) -> CapacityReservation {
    reservation(
        CapacityReservationState::Aborted,
        CapacityReservationPayload::Aborted(AbortedCapacityReservation {
            proof: Some(aborted_capacity_reservation::Proof::ConflictingCommit(
                Box::new(ConflictingCapacityCommit {
                    commit: Some(commit_binding()),
                    conflicting_control: Some(landed_control(prefix)),
                    conflicting_mutation_id: uuid(CONFLICTING_MUTATION_ID),
                }),
            )),
        }),
    )
}

fn reservation(
    state: CapacityReservationState,
    payload: CapacityReservationPayload,
) -> CapacityReservation {
    let identity = identity();
    CapacityReservation {
        reservation_id: uuid(RESERVATION_ID),
        tenant_id: identity.tenant_id.clone(),
        identity: Some(identity),
        allocation_epoch: 1,
        byte_count: 100,
        tenant_slice_bytes: 1_000,
        state: state as i32,
        state_payload: Some(payload),
    }
}

fn commit_binding() -> CapacityCommitBinding {
    CapacityCommitBinding {
        writer_epoch: 1,
        mutation_id: uuid(MUTATION_ID),
        kind: MutationKind::Settings as i32,
        predecessor: Some(CapacityCommitPredecessor::PriorControl(
            PriorControlBinding {
                cas_token: Bytes::from_static(b"cas-1"),
                object_version_id: Bytes::from_static(b"repo-v1"),
            },
        )),
    }
}

fn landed_control(prefix: &DeploymentPrefix) -> LandedControlRef {
    let identity = identity();
    let routing = RoutingDigest::of(&identity.canonical_path).unwrap();
    LandedControlRef {
        repo_control_key: Bytes::from(repo_control_key(prefix, routing).unwrap()),
        object_version_id: Bytes::from_static(b"repo-v2"),
        digest: Bytes::from(vec![0x55; 32]),
        size: 100,
    }
}

fn identity() -> RepositoryIdentity {
    let canonical_path = Bytes::from_static(b"tenant/project/repo");
    RepositoryIdentity {
        tenant_id: Bytes::from_static(b"tenant-a"),
        project_id: Bytes::from_static(b"project-a"),
        repository_uuid: uuid(REPOSITORY_UUID),
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

fn different_identity_same_shard() -> RepositoryIdentity {
    let original = hex::decode(REPOSITORY_UUID).unwrap();
    let wanted = Sha256::digest(&original)[0];
    let mut candidate = original.clone();
    for suffix in 0u16..=u16::MAX {
        candidate[14..].copy_from_slice(&suffix.to_be_bytes());
        if candidate != original && Sha256::digest(&candidate)[0] == wanted {
            let canonical_path = Bytes::from_static(b"tenant/project/repo-two");
            return RepositoryIdentity {
                tenant_id: Bytes::from_static(b"tenant-a"),
                project_id: Bytes::from_static(b"project-a"),
                repository_uuid: Bytes::from(candidate),
                generation: 1,
                canonical_path_digest: Bytes::copy_from_slice(
                    CanonicalPathDigest::of(&canonical_path).as_bytes(),
                ),
                routing_digest: Bytes::copy_from_slice(
                    RoutingDigest::of(&canonical_path).unwrap().as_bytes(),
                ),
                canonical_path,
            };
        }
    }
    panic!("a second UUID must share one of 256 shard values")
}

fn uuid(value: &str) -> Bytes {
    Bytes::from(hex::decode(value).unwrap())
}

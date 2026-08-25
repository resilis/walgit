mod support;

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
const SETTLEMENT_ID: &str = "01890f4776447b8b9d7a876543210ac1";

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
    assert_eq!(CapacityConflictClass::Unspecified as i32, 0);
    assert_eq!(CapacityConflictClass::CreateControlExists as i32, 1);
    assert_eq!(CapacityConflictClass::SameWriterVersionAdvanced as i32, 2);
    assert_eq!(CapacityConflictClass::WriterEpochAdvanced as i32, 3);

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
    for (value, expected) in [(1, "2001"), (2, "2002"), (3, "2003")] {
        let conflict = ConflictingCapacityCommit {
            conflict_class: value,
            ..Default::default()
        };
        assert_eq!(hex::encode(conflict.encode_to_vec()), expected);
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
        (
            "tenant-page",
            encode_tenant_capacity_catalog_page(&tenant_page()).unwrap(),
        ),
        (
            "reserved",
            encode_capacity_shard(&shard_with(vec![reserved_reservation()]), &prefix).unwrap(),
        ),
        (
            "committing",
            encode_capacity_shard(&shard_with(vec![committing_reservation()]), &prefix).unwrap(),
        ),
        (
            "charged",
            encode_capacity_shard(&shard_with(vec![charged_reservation(&prefix)]), &prefix)
                .unwrap(),
        ),
        (
            "expired",
            encode_capacity_shard(&shard_with(vec![expired_reservation()]), &prefix).unwrap(),
        ),
        (
            "conflicting",
            encode_capacity_shard(&shard_with(vec![conflicting_reservation(&prefix)]), &prefix)
                .unwrap(),
        ),
        (
            "stable",
            encode_capacity_control(&stable_control(&prefix), &prefix).unwrap(),
        ),
        (
            "draining",
            encode_capacity_control(
                &preparing_control(&prefix, RedistributionPhase::Draining),
                &prefix,
            )
            .unwrap(),
        ),
        (
            "applying",
            encode_capacity_control(
                &preparing_control(&prefix, RedistributionPhase::Applying),
                &prefix,
            )
            .unwrap(),
        ),
    ];
    let actual = values
        .iter()
        .map(|(name, value)| {
            (
                *name,
                value.len(),
                hex::encode(<[u8; 32]>::from(Sha256::digest(value))),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (
                "tenant-page",
                1_680,
                "ee19542f241d3ce3d8a5193196bd6d7693befe3de97b61c0bb0a0d7c4ac44df0".to_owned(),
            ),
            (
                "reserved",
                208,
                "e4f4ffe964945231024f5a04153a9d053ea06a7ea72001d15e10818b241b5b2a".to_owned(),
            ),
            (
                "committing",
                244,
                "5be3f35b96e3661e260e324e4677646d3b307b9875788fbcde878456c0b8cc6c".to_owned(),
            ),
            (
                "charged",
                404,
                "ba7f6424bd29a877b2c6340bec025a9fa4104a2fa714bcc659c706a98216052b".to_owned(),
            ),
            (
                "expired",
                198,
                "13e321bf6f8e5a6f4269c8357895d4a8fcad85fa6bf9774d5cb33b408edcd002".to_owned(),
            ),
            (
                "conflicting",
                412,
                "ea40f7df40cf1536761d094c7de8b74da145524cac25b687ade8ff33328bd1ab".to_owned(),
            ),
            (
                "stable",
                26_577,
                "abb33ed78ae9a6ad7e3cd662078c2c111554824f319fa9a6a5590a1ea1e0656b".to_owned(),
            ),
            (
                "draining",
                28_680,
                "8c8d64774be91cf4d08ed090ace156f5c0d92628b29c6b491f3072e1d8cc9d28".to_owned(),
            ),
            (
                "applying",
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

    let mut value = conflicting_reservation(&prefix);
    set_conflicting_class_raw(&mut value, 99);
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
    let shard_object = exact_shard_ref(&shard, &prefix);
    let page = tenant_page_with_slice(shard.shard as usize, 1_000);
    let mut control = stable_control(&prefix);
    control.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    validate_capacity_shard_catalog(&shard, &page, &prefix).unwrap();
    validate_capacity_current_shard_view(&control, &page, &shard, &shard_object, &prefix).unwrap();
    validate_capacity_admission_view(&control, &page, &shard, &shard_object, &prefix).unwrap();

    let mut preparing = preparing_control(&prefix, RedistributionPhase::Draining);
    preparing.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    validate_capacity_current_shard_view(&preparing, &page, &shard, &shard_object, &prefix)
        .unwrap();
    assert!(
        validate_capacity_admission_view(&preparing, &page, &shard, &shard_object, &prefix)
            .is_err()
    );

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
    let wrong_epoch_object = exact_shard_ref(&wrong_epoch, &prefix);
    assert!(
        validate_capacity_current_shard_view(
            &control,
            &page,
            &wrong_epoch,
            &wrong_epoch_object,
            &prefix,
        )
        .is_err()
    );
    let budget_page = tenant_page_with_slice(shard.shard as usize, 999);
    let mut budget_control = control.clone();
    budget_control.tenant_catalog = Some(tenant_page_ref(&prefix, &budget_page));
    let mut wrong_budget = shard.clone();
    wrong_budget.budget_bytes = 999;
    wrong_budget.tenant_accounts[0].current_slice_bytes = 999;
    let wrong_budget_object = exact_shard_ref(&wrong_budget, &prefix);
    assert!(
        validate_capacity_current_shard_view(
            &budget_control,
            &budget_page,
            &wrong_budget,
            &wrong_budget_object,
            &prefix,
        )
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
fn retained_and_mutable_shard_object_gates_keep_provider_proofs_distinct() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let historical = shard_at_epoch(Vec::new(), 1);
    let historical_object = exact_shard_ref(&historical, &prefix);
    for mut control in [
        stable_control(&prefix),
        preparing_control(&prefix, RedistributionPhase::Draining),
        preparing_control(&prefix, RedistributionPhase::Applying),
    ] {
        control.shard_budgets[historical.shard as usize].shard_object =
            Some(historical_object.clone());
        validate_capacity_retained_shard_budget_object(&control, &historical, &prefix).unwrap();

        let mut current = historical.clone();
        current.control_revision += 1;
        let mut current_object = exact_shard_ref(&current, &prefix);
        current_object.object_version_id = Bytes::from_static(b"newer-current-version");
        assert_ne!(
            current_object.object_version_id,
            historical_object.object_version_id
        );
        validate_capacity_current_shard_object(&control, &current, &current_object, &prefix)
            .unwrap();
        assert!(
            validate_capacity_retained_shard_budget_object(&control, &current, &prefix).is_err()
        );

        let mut wrong_body_ref = current_object.clone();
        let mut wrong_digest = wrong_body_ref.digest.to_vec();
        wrong_digest[0] ^= 1;
        wrong_body_ref.digest = Bytes::from(wrong_digest);
        assert!(
            validate_capacity_current_shard_object(&control, &current, &wrong_body_ref, &prefix)
                .is_err()
        );
    }
}

#[test]
fn current_epoch_reservations_must_repeat_the_exact_account_and_page_slice() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    for reservation in [reserved_reservation(), committing_reservation()] {
        let mut shard = shard_with(vec![reservation]);
        shard.tenant_accounts[0].current_slice_bytes = 999;
        let page = tenant_page_with_slice(shard.shard as usize, 999);
        let mut control = stable_control(&prefix);
        control.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
        let object = exact_shard_ref(&shard, &prefix);
        assert!(validate_capacity_shard(&shard, &prefix).is_ok());
        assert!(validate_capacity_shard_catalog(&shard, &page, &prefix).is_err());
        assert!(
            validate_capacity_current_shard_view(&control, &page, &shard, &object, &prefix)
                .is_err()
        );
    }

    let mut historical = charged_reservation(&prefix);
    historical.allocation_epoch = 1;
    historical.tenant_slice_bytes = 1_000;
    let mut current = shard_at_epoch(vec![historical], 2);
    current.tenant_accounts[0].current_slice_bytes = 999;
    let page = tenant_page_with_slice(current.shard as usize, 999);
    validate_capacity_shard_catalog(&current, &page, &prefix).unwrap();
}

#[test]
fn composed_pre_cas_gates_close_admission_and_preparing_drainage() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let previous = shard_at_epoch(Vec::new(), 1);
    let previous_object = exact_shard_ref(&previous, &prefix);
    let page = tenant_page_with_slice(previous.shard as usize, 1_000);
    let mut stable = stable_control(&prefix);
    stable.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    let mut reserved = shard_with(vec![reserved_reservation()]);
    reserved.control_revision = previous.control_revision + 1;
    validate_capacity_stable_admission_successor(
        &stable,
        &page,
        &previous,
        &previous_object,
        &reserved,
        1_000,
        &prefix,
    )
    .unwrap();

    let empty_page = TenantCapacityCatalogPage {
        schema_version: 1,
        allocations: Vec::new(),
    };
    let mut absent_tenant = stable.clone();
    absent_tenant.tenant_catalog = Some(tenant_page_ref(&prefix, &empty_page));
    assert!(
        validate_capacity_stable_admission_successor(
            &absent_tenant,
            &empty_page,
            &previous,
            &previous_object,
            &reserved,
            1_000,
            &prefix,
        )
        .is_err()
    );
    for slice in [999, 1_001] {
        let wrong_page = tenant_page_with_slice(previous.shard as usize, slice);
        let mut wrong_control = stable.clone();
        wrong_control.tenant_catalog = Some(tenant_page_ref(&prefix, &wrong_page));
        assert!(
            validate_capacity_stable_admission_successor(
                &wrong_control,
                &wrong_page,
                &previous,
                &previous_object,
                &reserved,
                1_000,
                &prefix,
            )
            .is_err()
        );
    }

    let mut preparing = preparing_control(&prefix, RedistributionPhase::Draining);
    preparing.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    let reserved_object = exact_shard_ref(&reserved, &prefix);
    let mut expired = shard_with(vec![expired_reservation()]);
    expired.control_revision = reserved.control_revision + 1;
    validate_capacity_preparing_drainage_successor(
        &preparing,
        &page,
        &reserved,
        &reserved_object,
        &expired,
        1_900,
        &prefix,
    )
    .unwrap();

    let mut committing = reserved.clone();
    committing.control_revision += 1;
    committing.reservations[0] = committing_reservation();
    assert!(
        validate_capacity_preparing_drainage_successor(
            &preparing,
            &page,
            &reserved,
            &reserved_object,
            &committing,
            1_100,
            &prefix,
        )
        .is_err()
    );
    assert!(
        validate_capacity_preparing_drainage_successor(
            &preparing,
            &page,
            &previous,
            &previous_object,
            &reserved,
            1_000,
            &prefix,
        )
        .is_err()
    );
    let mut applying = preparing_control(&prefix, RedistributionPhase::Applying);
    applying.tenant_catalog = Some(tenant_page_ref(&prefix, &page));
    assert!(
        validate_capacity_preparing_drainage_successor(
            &applying,
            &page,
            &reserved,
            &reserved_object,
            &expired,
            1_900,
            &prefix,
        )
        .is_err()
    );
}

#[test]
fn shard_successor_closes_time_revision_and_state_transitions() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let empty = shard_at_epoch(Vec::new(), 1);
    validate_capacity_shard_successor(&empty, &empty, 1_000, &prefix).unwrap();

    let mut reserved = shard_with(vec![reserved_reservation()]);
    reserved.control_revision = 2;
    validate_capacity_shard_successor(&empty, &reserved, 1_000, &prefix).unwrap();
    assert!(validate_capacity_shard_successor(&empty, &reserved, 999, &prefix).is_err());
    assert!(validate_capacity_shard_successor(&empty, &reserved, 1_900, &prefix).is_err());

    let mut committing = reserved.clone();
    committing.control_revision = 3;
    committing.reservations[0] = committing_reservation();
    for now in [1_000, 1_100, 1_899] {
        validate_capacity_shard_successor(&reserved, &committing, now, &prefix).unwrap();
    }
    for now in [999, 1_900, 1_901] {
        assert!(validate_capacity_shard_successor(&reserved, &committing, now, &prefix).is_err());
    }

    let mut charged = committing.clone();
    charged.control_revision = 4;
    charged.reservations[0] = charged_reservation(&prefix);
    validate_capacity_shard_successor(&committing, &charged, 1_100, &prefix).unwrap();

    let mut conflicting = shard_with(vec![conflicting_reservation(&prefix)]);
    conflicting.control_revision = 4;
    validate_capacity_shard_successor(&committing, &conflicting, 1_100, &prefix).unwrap();

    let mut expired = shard_with(vec![expired_reservation()]);
    expired.control_revision = 3;
    validate_capacity_shard_successor(&reserved, &expired, 1_900, &prefix).unwrap();

    let mut wrong_window = expired.clone();
    let Some(CapacityReservationPayload::Aborted(aborted)) =
        wrong_window.reservations[0].state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::Expired(proof)) = aborted.proof.as_mut() else {
        panic!("expired proof")
    };
    proof.observed_now_unix_seconds = 1_901;
    assert!(validate_capacity_shard_successor(&reserved, &wrong_window, 1_900, &prefix).is_err());

    let mut changed_commit = charged.clone();
    let Some(CapacityReservationPayload::Charged(payload)) =
        changed_commit.reservations[0].state_payload.as_mut()
    else {
        panic!("charged payload")
    };
    payload.commit.as_mut().unwrap().mutation_id = uuid(CONFLICTING_MUTATION_ID);
    assert!(
        validate_capacity_shard_successor(&committing, &changed_commit, 1_100, &prefix).is_err()
    );

    let mut terminal_changed = charged.clone();
    terminal_changed.control_revision += 1;
    let Some(CapacityReservationPayload::Charged(payload)) =
        terminal_changed.reservations[0].state_payload.as_mut()
    else {
        panic!("charged payload")
    };
    payload.landed_control.as_mut().unwrap().object_version_id =
        Bytes::from_static(b"different-version");
    assert!(
        validate_capacity_shard_successor(&charged, &terminal_changed, 1_100, &prefix).is_err()
    );

    let mut revision_gap = committing;
    revision_gap.control_revision += 1;
    assert!(validate_capacity_shard_successor(&reserved, &revision_gap, 1_100, &prefix).is_err());
}

#[test]
fn terminal_repo_control_proofs_bind_exact_body_provider_mutation_and_writer() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();

    let mut charged = charged_reservation(&prefix);
    let (mut landed, observed, catalog, committing_shard, committing_object) =
        charged_proof_inputs(&mut charged, 1, &prefix);
    validate_capacity_charged_repo_control(
        &charged,
        &landed,
        &observed,
        &catalog,
        &committing_shard,
        &committing_object,
        &prefix,
    )
    .unwrap();

    landed.last_internal_mutation_id = uuid(CONFLICTING_MUTATION_ID);
    assert!(
        validate_capacity_charged_repo_control(
            &charged,
            &landed,
            &observed,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );
    landed.last_internal_mutation_id = uuid(MUTATION_ID);
    landed.writer.as_mut().unwrap().epoch = 2;
    assert!(
        validate_capacity_charged_repo_control(
            &charged,
            &landed,
            &observed,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );
    landed.writer.as_mut().unwrap().epoch = 1;
    landed.inline_settings = Bytes::from_static(b"body-changed");
    assert!(
        validate_capacity_charged_repo_control(
            &charged,
            &landed,
            &observed,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );

    let (landed, observed, catalog, committing_shard, committing_object) =
        charged_proof_inputs(&mut charged, 1, &prefix);
    let mut wrong_identity = landed.clone();
    wrong_identity.identity.as_mut().unwrap().project_id = Bytes::from_static(b"other-project");
    assert!(
        validate_capacity_charged_repo_control(
            &charged,
            &wrong_identity,
            &observed,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );
    let mut wrong_provider = observed.clone();
    wrong_provider.object_version_id = Bytes::from_static(b"wrong-provider-version");
    assert!(
        validate_capacity_charged_repo_control(
            &charged,
            &landed,
            &wrong_provider,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );
    let mut wrong_digest = observed.clone();
    let mut digest = wrong_digest.digest.to_vec();
    digest[0] ^= 1;
    wrong_digest.digest = Bytes::from(digest);
    let mut wrong_digest_reservation = charged.clone();
    let Some(CapacityReservationPayload::Charged(payload)) =
        wrong_digest_reservation.state_payload.as_mut()
    else {
        panic!("charged payload")
    };
    payload.landed_control = Some(wrong_digest.clone());
    assert!(
        validate_capacity_charged_repo_control(
            &wrong_digest_reservation,
            &landed,
            &wrong_digest,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );
    let mut wrong_size = observed.clone();
    wrong_size.size += 1;
    let mut wrong_size_reservation = charged.clone();
    let Some(CapacityReservationPayload::Charged(payload)) =
        wrong_size_reservation.state_payload.as_mut()
    else {
        panic!("charged payload")
    };
    payload.landed_control = Some(wrong_size.clone());
    assert!(
        validate_capacity_charged_repo_control(
            &wrong_size_reservation,
            &landed,
            &wrong_size,
            &catalog,
            &committing_shard,
            &committing_object,
            &prefix,
        )
        .is_err()
    );

    let mut takeover = charged.clone();
    {
        let Some(CapacityReservationPayload::Charged(payload)) = takeover.state_payload.as_mut()
        else {
            panic!("charged payload")
        };
        payload.commit.as_mut().unwrap().kind = MutationKind::WriterTakeover as i32;
    }
    let (takeover_control, takeover_ref, takeover_catalog, takeover_shard, takeover_shard_ref) =
        charged_proof_inputs(&mut takeover, 2, &prefix);
    validate_capacity_charged_repo_control(
        &takeover,
        &takeover_control,
        &takeover_ref,
        &takeover_catalog,
        &takeover_shard,
        &takeover_shard_ref,
        &prefix,
    )
    .unwrap();

    let mut conflict = conflicting_reservation(&prefix);
    let raw = repo_control_for_reservation(&conflict, CONFLICTING_MUTATION_ID, 1, &prefix);
    let (
        conflicting_control,
        conflicting_ref,
        conflicting_catalog,
        expected_receipt,
        conflict_shard,
        conflict_shard_ref,
    ) = conflict_proof_inputs(&mut conflict, raw, b"conflict-v1", &prefix);
    validate_capacity_conflicting_repo_control(
        &conflict,
        &conflicting_control,
        &conflicting_ref,
        &conflicting_catalog,
        &expected_receipt,
        &conflict_shard,
        &conflict_shard_ref,
        &prefix,
    )
    .unwrap();

    let mut same_prior_conflict = conflicting_reservation(&prefix);
    let raw =
        repo_control_for_reservation(&same_prior_conflict, CONFLICTING_MUTATION_ID, 1, &prefix);
    let (same_prior_control, same_prior_ref, same_prior_catalog, expected, shard, shard_ref) =
        conflict_proof_inputs(&mut same_prior_conflict, raw, b"repo-v1", &prefix);
    assert!(
        validate_capacity_conflicting_repo_control(
            &same_prior_conflict,
            &same_prior_control,
            &same_prior_ref,
            &same_prior_catalog,
            &expected,
            &shard,
            &shard_ref,
            &prefix,
        )
        .is_err()
    );

    let mut create_conflict = conflict.clone();
    set_conflicting_predecessor(
        &mut create_conflict,
        MutationKind::Create,
        CapacityCommitPredecessor::NoPriorControl(NoPriorControl {}),
        CapacityConflictClass::CreateControlExists,
    );
    let raw = repo_control_for_reservation(&create_conflict, CONFLICTING_MUTATION_ID, 1, &prefix);
    let (create_control, create_ref, create_catalog, expected, shard, shard_ref) =
        conflict_proof_inputs(&mut create_conflict, raw, b"create-conflict-v1", &prefix);
    validate_capacity_conflicting_repo_control(
        &create_conflict,
        &create_control,
        &create_ref,
        &create_catalog,
        &expected,
        &shard,
        &shard_ref,
        &prefix,
    )
    .unwrap();

    let mut create_collision = conflicting_reservation(&prefix);
    set_conflicting_predecessor(
        &mut create_collision,
        MutationKind::Create,
        CapacityCommitPredecessor::NoPriorControl(NoPriorControl {}),
        CapacityConflictClass::CreateControlExists,
    );
    let raw = repo_control_for_reservation(&create_collision, CONFLICTING_MUTATION_ID, 1, &prefix);
    let raw = different_identity_control_same_path(&raw, &prefix);
    let (
        different_identity_control,
        different_identity_ref,
        collision_catalog,
        collision_expected,
        collision_shard,
        collision_shard_ref,
    ) = conflict_proof_inputs(&mut create_collision, raw, b"create-collision-v1", &prefix);
    validate_capacity_conflicting_repo_control(
        &create_collision,
        &different_identity_control,
        &different_identity_ref,
        &collision_catalog,
        &collision_expected,
        &collision_shard,
        &collision_shard_ref,
        &prefix,
    )
    .unwrap();

    let mut wrong_epoch_conflict = conflicting_reservation(&prefix);
    let raw =
        repo_control_for_reservation(&wrong_epoch_conflict, CONFLICTING_MUTATION_ID, 2, &prefix);
    let (wrong_epoch, wrong_epoch_ref, wrong_catalog, expected, shard, shard_ref) =
        conflict_proof_inputs(&mut wrong_epoch_conflict, raw, b"conflict-v2", &prefix);
    assert!(
        validate_capacity_conflicting_repo_control(
            &wrong_epoch_conflict,
            &wrong_epoch,
            &wrong_epoch_ref,
            &wrong_catalog,
            &expected,
            &shard,
            &shard_ref,
            &prefix,
        )
        .is_err()
    );

    let mut writer_advanced = conflicting_reservation(&prefix);
    set_conflicting_class(
        &mut writer_advanced,
        CapacityConflictClass::WriterEpochAdvanced,
    );
    let raw = repo_control_for_reservation(&writer_advanced, CONFLICTING_MUTATION_ID, 2, &prefix);
    let (writer_advanced_control, writer_advanced_ref, writer_catalog, expected, shard, shard_ref) =
        conflict_proof_inputs(&mut writer_advanced, raw, b"writer-advanced-v1", &prefix);
    validate_capacity_conflicting_repo_control(
        &writer_advanced,
        &writer_advanced_control,
        &writer_advanced_ref,
        &writer_catalog,
        &expected,
        &shard,
        &shard_ref,
        &prefix,
    )
    .unwrap();
    let mut wrong_writer_advanced = conflicting_reservation(&prefix);
    set_conflicting_class(
        &mut wrong_writer_advanced,
        CapacityConflictClass::WriterEpochAdvanced,
    );
    let raw =
        repo_control_for_reservation(&wrong_writer_advanced, CONFLICTING_MUTATION_ID, 1, &prefix);
    let (same_writer_control, same_writer_ref, catalog, expected, shard, shard_ref) =
        conflict_proof_inputs(&mut wrong_writer_advanced, raw, b"same-writer-v1", &prefix);
    assert!(
        validate_capacity_conflicting_repo_control(
            &wrong_writer_advanced,
            &same_writer_control,
            &same_writer_ref,
            &catalog,
            &expected,
            &shard,
            &shard_ref,
            &prefix,
        )
        .is_err()
    );
}

#[test]
fn receipt_catalog_and_capacity_obligation_are_exact_composition_gates() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    let mut charged = charged_reservation(&prefix);
    let (landed, observed, catalog, committing_shard, committing_object) =
        charged_proof_inputs(&mut charged, 1, &prefix);
    validate_repo_control_receipt_catalog(&landed, &catalog, &prefix).unwrap();
    let committing = &committing_shard.reservations[0];
    let receipt = catalog.rows[0].receipt.as_ref().unwrap();
    validate_capacity_receipt_obligation(
        committing,
        &committing_shard,
        &committing_object,
        receipt,
        &prefix,
    )
    .unwrap();

    let mut wrong_count = landed.clone();
    wrong_count.receipt_catalog.as_mut().unwrap().item_count += 1;
    assert!(validate_repo_control_receipt_catalog(&wrong_count, &catalog, &prefix).is_err());
    let mut wrong_body = catalog.clone();
    wrong_body.rows[0].receipt.as_mut().unwrap().request_digest = Bytes::from(vec![0x45; 32]);
    assert!(validate_repo_control_receipt_catalog(&landed, &wrong_body, &prefix).is_err());
    let mut two_unresolved = catalog.clone();
    let mut second_receipt = no_capacity_receipt(&landed);
    second_receipt.mutation_id = uuid(CONFLICTING_MUTATION_ID);
    two_unresolved.rows.push(ReceiptCatalogRow {
        mutation_id: second_receipt.mutation_id.clone(),
        state: ReceiptState::Unresolved as i32,
        receipt: Some(second_receipt),
        result: None,
        settlement_mutation_id: Bytes::new(),
    });
    let mut two_unresolved_control = landed.clone();
    attach_receipt_catalog(&mut two_unresolved_control, &two_unresolved, &prefix);
    assert!(
        validate_repo_control_receipt_catalog(&two_unresolved_control, &two_unresolved, &prefix,)
            .is_err()
    );

    let mut settled_catalog = catalog.clone();
    settle_catalog_row(&mut settled_catalog.rows[0], &prefix);
    let mut settled_control = landed.clone();
    settled_control.last_internal_mutation_id = uuid(SETTLEMENT_ID);
    attach_receipt_catalog(&mut settled_control, &settled_catalog, &prefix);
    validate_repo_control_receipt_catalog(&settled_control, &settled_catalog, &prefix).unwrap();
    let mut wrong_obligation = receipt.clone();
    let Some(mutation_receipt::CapacityObligation::Capacity(value)) =
        wrong_obligation.capacity_obligation.as_mut()
    else {
        panic!("capacity obligation")
    };
    value.shard_object_version_id = Bytes::from_static(b"another-shard-version");
    assert!(
        validate_capacity_receipt_obligation(
            committing,
            &committing_shard,
            &committing_object,
            &wrong_obligation,
            &prefix,
        )
        .is_err()
    );

    let mut conflict = conflicting_reservation(&prefix);
    let prior_committing = prior_committing_reservation(&conflict);
    let prior_shard = shard_with(vec![prior_committing.clone()]);
    let prior_shard_object =
        exact_capacity_shard_ref(&prior_shard, b"capacity-committing-v1", &prefix);
    let expected_receipt = capacity_receipt_for(&prior_committing, &prior_shard_object);
    let mut current = repo_control_for_reservation(&conflict, CONFLICTING_MUTATION_ID, 1, &prefix);
    let conflicting_receipt = no_capacity_receipt(&current);
    let mut current_catalog = unresolved_catalog(expected_receipt.clone());
    settle_catalog_row(&mut current_catalog.rows[0], &prefix);
    current_catalog.rows.push(ReceiptCatalogRow {
        mutation_id: conflicting_receipt.mutation_id.clone(),
        state: ReceiptState::Unresolved as i32,
        receipt: Some(conflicting_receipt),
        result: None,
        settlement_mutation_id: Bytes::new(),
    });
    current_catalog
        .rows
        .sort_by(|left, right| left.mutation_id.cmp(&right.mutation_id));
    attach_receipt_catalog(&mut current, &current_catalog, &prefix);
    let current_object = exact_landed_control_ref(&current, b"conflict-after-success-v1");
    set_conflicting_control(&mut conflict, current_object.clone());
    assert!(
        validate_capacity_conflicting_repo_control(
            &conflict,
            &current,
            &current_object,
            &current_catalog,
            &expected_receipt,
            &prior_shard,
            &prior_shard_object,
            &prefix,
        )
        .is_err(),
        "a later current version cannot conceal an already-rooted expected mutation"
    );

    let mut unrepresented = current.clone();
    unrepresented.last_internal_mutation_id = uuid(ADMISSION_FENCE_ID);
    let unrepresented_object = exact_landed_control_ref(&unrepresented, b"unrepresented-v1");
    set_conflicting_control(&mut conflict, unrepresented_object.clone());
    assert!(
        validate_capacity_conflicting_repo_control(
            &conflict,
            &unrepresented,
            &unrepresented_object,
            &current_catalog,
            &expected_receipt,
            &prior_shard,
            &prior_shard_object,
            &prefix,
        )
        .is_err()
    );

    let mut settlement_conflict = conflicting_reservation(&prefix);
    set_conflicting_mutation_id(&mut settlement_conflict, SETTLEMENT_ID);
    let committing = prior_committing_reservation(&settlement_conflict);
    let committing_shard = shard_with(vec![committing.clone()]);
    let committing_object =
        exact_capacity_shard_ref(&committing_shard, b"settled-conflict-shard-v1", &prefix);
    let expected_receipt = capacity_receipt_for(&committing, &committing_object);
    let mut settled_current =
        repo_control_for_reservation(&settlement_conflict, CONFLICTING_MUTATION_ID, 1, &prefix);
    let mut settled_current_catalog = unresolved_catalog(no_capacity_receipt(&settled_current));
    settle_catalog_row(&mut settled_current_catalog.rows[0], &prefix);
    settled_current.last_internal_mutation_id = uuid(SETTLEMENT_ID);
    attach_receipt_catalog(&mut settled_current, &settled_current_catalog, &prefix);
    let settled_current_object = exact_landed_control_ref(&settled_current, b"settled-current-v1");
    set_conflicting_control(&mut settlement_conflict, settled_current_object.clone());
    validate_capacity_conflicting_repo_control(
        &settlement_conflict,
        &settled_current,
        &settled_current_object,
        &settled_current_catalog,
        &expected_receipt,
        &committing_shard,
        &committing_object,
        &prefix,
    )
    .unwrap();

    let _ = observed;
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

#[test]
fn capacity_raw_preflight_freezes_oneof_arms_root_sizes_and_repeated_counts() {
    let prefix = DeploymentPrefix::parse(PREFIX).unwrap();
    for reservation in [
        reserved_reservation(),
        committing_reservation(),
        charged_reservation(&prefix),
        expired_reservation(),
        conflicting_reservation(&prefix),
    ] {
        preflight_capacity_shard(&shard_with(vec![reservation]).encode_to_vec()).unwrap();
    }
    for control in [
        stable_control(&prefix),
        preparing_control(&prefix, RedistributionPhase::Draining),
        preparing_control(&prefix, RedistributionPhase::Applying),
    ] {
        preflight_capacity_control(&control.encode_to_vec()).unwrap();
    }

    for (maximum, preflight) in [
        (
            MAX_TENANT_CAPACITY_CATALOG_BYTES,
            preflight_tenant_capacity_catalog_page as fn(&[u8]) -> Result<(), ControlCodecError>,
        ),
        (MAX_CAPACITY_SHARD_BYTES, preflight_capacity_shard),
        (MAX_CAPACITY_CONTROL_BYTES, preflight_capacity_control),
    ] {
        assert!(!matches!(
            preflight(&vec![0; maximum]),
            Err(ControlCodecError::MessageTooLarge { .. })
        ));
        assert!(matches!(
            preflight(&vec![0; maximum + 1]),
            Err(ControlCodecError::MessageTooLarge {
                maximum: actual,
                ..
            }) if actual == maximum
        ));
    }

    let allocation = raw_repeated_message(3, &[], 256);
    let page = raw_repeated_message(2, &allocation, 1);
    preflight_tenant_capacity_catalog_page(&page).unwrap();
    assert!(
        preflight_tenant_capacity_catalog_page(&raw_repeated_message(
            2,
            &raw_repeated_message(3, &[], 255),
            1,
        ))
        .is_err()
    );
    assert!(
        preflight_tenant_capacity_catalog_page(&raw_repeated_message(
            2,
            &raw_repeated_message(3, &[], 257),
            1,
        ))
        .is_err()
    );
    let maximum_allocation_count = raw_repeated_message(2, &allocation, 4_096);
    assert!(maximum_allocation_count.len() > MAX_TENANT_CAPACITY_CATALOG_BYTES);
    assert!(matches!(
        preflight_tenant_capacity_catalog_page(&maximum_allocation_count),
        Err(ControlCodecError::MessageTooLarge {
            maximum: MAX_TENANT_CAPACITY_CATALOG_BYTES,
            ..
        })
    ));

    preflight_capacity_shard(&raw_repeated_message(6, &[], 4_096)).unwrap();
    assert!(preflight_capacity_shard(&raw_repeated_message(6, &[], 4_097)).is_err());
    preflight_capacity_shard(&raw_repeated_message(7, &[], 4_096)).unwrap();
    assert!(preflight_capacity_shard(&raw_repeated_message(7, &[], 4_097)).is_err());

    let control_budgets = raw_repeated_message(8, &[], 256);
    preflight_capacity_control(&control_budgets).unwrap();
    assert!(preflight_capacity_control(&raw_repeated_message(8, &[], 255)).is_err());
    assert!(preflight_capacity_control(&raw_repeated_message(8, &[], 257)).is_err());

    let mut redistribution = raw_repeated_message(5, &[], 256);
    redistribution.extend(raw_repeated_message(7, &[], 256));
    let mut applying = control_budgets.clone();
    push_length_delimited(&mut applying, 10, &redistribution);
    preflight_capacity_control(&applying).unwrap();
    let mut too_many_baselines = raw_repeated_message(5, &[], 256);
    too_many_baselines.extend(raw_repeated_message(7, &[], 257));
    let mut applying = control_budgets.clone();
    push_length_delimited(&mut applying, 10, &too_many_baselines);
    assert!(preflight_capacity_control(&applying).is_err());

    let mut dual_reservation = reserved_reservation().encode_to_vec();
    push_length_delimited(&mut dual_reservation, 9, &[]);
    assert!(preflight_capacity_shard(&raw_repeated_message(7, &dual_reservation, 1)).is_err());

    let mut dual_aborted = AbortedCapacityReservation {
        proof: Some(aborted_capacity_reservation::Proof::Expired(
            ExpiredCapacityReservation {
                created_at_unix_seconds: 1_000,
                expires_at_unix_seconds: 1_900,
                observed_now_unix_seconds: 1_900,
            },
        )),
    }
    .encode_to_vec();
    push_length_delimited(&mut dual_aborted, 2, &[]);
    let mut raw_aborted_reservation = expired_reservation();
    raw_aborted_reservation.state_payload = None;
    let mut raw_aborted_reservation = raw_aborted_reservation.encode_to_vec();
    push_length_delimited(&mut raw_aborted_reservation, 11, &dual_aborted);
    assert!(
        preflight_capacity_shard(&raw_repeated_message(7, &raw_aborted_reservation, 1)).is_err()
    );

    let mut dual_commit = commit_binding();
    dual_commit.predecessor = None;
    let mut dual_commit = dual_commit.encode_to_vec();
    push_length_delimited(&mut dual_commit, 4, &[]);
    push_length_delimited(
        &mut dual_commit,
        5,
        &PriorControlBinding {
            cas_token: Bytes::from_static(b"cas-1"),
            object_version_id: Bytes::from_static(b"repo-v1"),
        }
        .encode_to_vec(),
    );
    let mut committing_payload = Vec::new();
    push_length_delimited(&mut committing_payload, 1, &dual_commit);
    let mut raw_committing_reservation = committing_reservation();
    raw_committing_reservation.state_payload = None;
    let mut raw_committing_reservation = raw_committing_reservation.encode_to_vec();
    push_length_delimited(&mut raw_committing_reservation, 9, &committing_payload);
    assert!(
        preflight_capacity_shard(&raw_repeated_message(7, &raw_committing_reservation, 1)).is_err()
    );

    let mut dual_control = control_budgets;
    push_length_delimited(&mut dual_control, 9, &[]);
    push_length_delimited(&mut dual_control, 10, &redistribution);
    assert!(preflight_capacity_control(&dual_control).is_err());
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
                    conflict_class: CapacityConflictClass::SameWriterVersionAdvanced as i32,
                }),
            )),
        }),
    )
}

fn set_conflicting_control(reservation: &mut CapacityReservation, control: LandedControlRef) {
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(proof)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    proof.conflicting_control = Some(control);
}

fn set_conflicting_predecessor(
    reservation: &mut CapacityReservation,
    kind: MutationKind,
    predecessor: CapacityCommitPredecessor,
    conflict_class: CapacityConflictClass,
) {
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(proof)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    let commit = proof.commit.as_mut().unwrap();
    commit.kind = kind as i32;
    commit.predecessor = Some(predecessor);
    proof.conflict_class = conflict_class as i32;
}

fn set_conflicting_class(
    reservation: &mut CapacityReservation,
    conflict_class: CapacityConflictClass,
) {
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(proof)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    proof.conflict_class = conflict_class as i32;
}

fn set_conflicting_class_raw(reservation: &mut CapacityReservation, conflict_class: i32) {
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(proof)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    proof.conflict_class = conflict_class;
}

fn set_conflicting_mutation_id(reservation: &mut CapacityReservation, mutation_id: &str) {
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_mut()
    else {
        panic!("aborted payload")
    };
    let Some(aborted_capacity_reservation::Proof::ConflictingCommit(proof)) =
        aborted.proof.as_mut()
    else {
        panic!("conflict proof")
    };
    proof.conflicting_mutation_id = uuid(mutation_id);
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

fn repo_control_for_reservation(
    reservation: &CapacityReservation,
    mutation_id: &str,
    writer_epoch: u64,
    prefix: &DeploymentPrefix,
) -> RepoControl {
    let mut control = support::sample_control();
    let identity = reservation.identity.clone().unwrap();
    let routing = RoutingDigest::of(&identity.canonical_path).unwrap();
    let shard = Sha256::digest(&identity.repository_uuid)[0];
    control.identity = Some(identity);
    control.repo_control_key = Bytes::from(repo_control_key(prefix, routing).unwrap());
    control.last_internal_mutation_id = uuid(mutation_id);
    control.writer.as_mut().unwrap().epoch = writer_epoch;
    let capacity = control.capacity.as_mut().unwrap();
    capacity.allocation_epoch = reservation.allocation_epoch;
    capacity.shard = u32::from(shard);
    capacity.shard_key = Bytes::from(capacity_shard_key(prefix, shard).unwrap());
    capacity.shard_budget_bytes = 1_000;
    capacity.tenant_slice_bytes = reservation.tenant_slice_bytes;
    control
}

fn exact_landed_control_ref(control: &RepoControl, object_version_id: &[u8]) -> LandedControlRef {
    let encoded = encode_repo_control(control).unwrap();
    LandedControlRef {
        repo_control_key: control.repo_control_key.clone(),
        object_version_id: Bytes::copy_from_slice(object_version_id),
        digest: Bytes::copy_from_slice(&Sha256::digest(&encoded)),
        size: encoded.len() as u64,
    }
}

fn validate_capacity_charged_repo_control(
    reservation: &CapacityReservation,
    control: &RepoControl,
    observed_control: &LandedControlRef,
    catalog: &ReceiptCatalog,
    committing_shard: &CapacityShard,
    observed_shard: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    walgit_proto::v2::validate_capacity_charged_repo_control(
        reservation,
        LoadedRepoControlReceiptView {
            control,
            observed_object: observed_control,
            receipt_catalog: catalog,
        },
        LoadedCommittingCapacityView {
            shard: committing_shard,
            observed_object: observed_shard,
        },
        prefix,
    )
}

#[allow(clippy::too_many_arguments)] // Keeps each proof component explicit in the negative matrix.
fn validate_capacity_conflicting_repo_control(
    reservation: &CapacityReservation,
    control: &RepoControl,
    observed_control: &LandedControlRef,
    catalog: &ReceiptCatalog,
    expected_receipt: &MutationReceipt,
    committing_shard: &CapacityShard,
    observed_shard: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    walgit_proto::v2::validate_capacity_conflicting_repo_control(
        reservation,
        LoadedRepoControlReceiptView {
            control,
            observed_object: observed_control,
            receipt_catalog: catalog,
        },
        expected_receipt,
        LoadedCommittingCapacityView {
            shard: committing_shard,
            observed_object: observed_shard,
        },
        prefix,
    )
}

fn prior_committing_reservation(terminal: &CapacityReservation) -> CapacityReservation {
    let commit = match terminal.state_payload.as_ref().unwrap() {
        CapacityReservationPayload::Charged(value) => value.commit.clone(),
        CapacityReservationPayload::Aborted(value) => match value.proof.as_ref().unwrap() {
            aborted_capacity_reservation::Proof::ConflictingCommit(value) => value.commit.clone(),
            aborted_capacity_reservation::Proof::Expired(_) => panic!("expiry has no commit"),
        },
        _ => panic!("terminal reservation required"),
    };
    let mut reservation = terminal.clone();
    reservation.state = CapacityReservationState::Committing as i32;
    reservation.state_payload = Some(CapacityReservationPayload::Committing(
        CommittingCapacityReservation { commit },
    ));
    reservation
}

fn exact_capacity_shard_ref(
    shard: &CapacityShard,
    object_version_id: &[u8],
    prefix: &DeploymentPrefix,
) -> CapacityObjectRef {
    let encoded = encode_capacity_shard(shard, prefix).unwrap();
    CapacityObjectRef {
        key: Bytes::from(capacity_shard_key(prefix, shard.shard as u8).unwrap()),
        object_version_id: Bytes::copy_from_slice(object_version_id),
        digest: Bytes::copy_from_slice(&Sha256::digest(&encoded)),
        size: encoded.len() as u64,
    }
}

fn capacity_receipt_for(
    reservation: &CapacityReservation,
    shard_object: &CapacityObjectRef,
) -> MutationReceipt {
    let Some(CapacityReservationPayload::Committing(value)) = reservation.state_payload.as_ref()
    else {
        panic!("committing reservation")
    };
    let commit = value.commit.as_ref().unwrap();
    let predecessor = match commit.predecessor.as_ref().unwrap() {
        CapacityCommitPredecessor::NoPriorControl(_) => {
            mutation_receipt::Predecessor::NoPriorControl(NoPriorControl {})
        }
        CapacityCommitPredecessor::PriorControl(value) => {
            mutation_receipt::Predecessor::PriorControl(value.clone())
        }
    };
    MutationReceipt {
        schema_version: 1,
        identity: reservation.identity.clone(),
        mutation_id: commit.mutation_id.clone(),
        kind: commit.kind,
        writer_epoch: commit.writer_epoch,
        wal_sequence: 0,
        request_digest: Bytes::from(vec![0x44; 32]),
        immutable_dependency_digests: Vec::new(),
        predecessor: Some(predecessor),
        capacity_obligation: Some(mutation_receipt::CapacityObligation::Capacity(
            CapacityObligation {
                allocation_epoch: reservation.allocation_epoch,
                shard_key: shard_object.key.clone(),
                shard_object_version_id: shard_object.object_version_id.clone(),
                reservation_id: reservation.reservation_id.clone(),
                tenant_slice_bytes: reservation.tenant_slice_bytes,
                mutation_id: commit.mutation_id.clone(),
                byte_count: reservation.byte_count,
            },
        )),
        event_obligation: Some(mutation_receipt::EventObligation::NoEvent(
            NoEventObligation {},
        )),
    }
}

fn no_capacity_receipt(control: &RepoControl) -> MutationReceipt {
    MutationReceipt {
        schema_version: 1,
        identity: control.identity.clone(),
        mutation_id: control.last_internal_mutation_id.clone(),
        kind: MutationKind::Settings as i32,
        writer_epoch: control.writer.as_ref().unwrap().epoch,
        wal_sequence: 0,
        request_digest: Bytes::from(vec![0x66; 32]),
        immutable_dependency_digests: Vec::new(),
        predecessor: Some(mutation_receipt::Predecessor::PriorControl(
            PriorControlBinding {
                cas_token: Bytes::from_static(b"other-cas"),
                object_version_id: Bytes::from_static(b"other-prior"),
            },
        )),
        capacity_obligation: Some(mutation_receipt::CapacityObligation::NoCapacity(
            NoCapacityObligation {},
        )),
        event_obligation: Some(mutation_receipt::EventObligation::NoEvent(
            NoEventObligation {},
        )),
    }
}

fn unresolved_catalog(receipt: MutationReceipt) -> ReceiptCatalog {
    ReceiptCatalog {
        schema_version: 1,
        identity: receipt.identity.clone(),
        rows: vec![ReceiptCatalogRow {
            mutation_id: receipt.mutation_id.clone(),
            state: ReceiptState::Unresolved as i32,
            receipt: Some(receipt),
            result: None,
            settlement_mutation_id: Bytes::new(),
        }],
    }
}

fn settle_catalog_row(row: &mut ReceiptCatalogRow, prefix: &DeploymentPrefix) {
    let receipt = row.receipt.as_ref().unwrap();
    let identity = receipt.identity.clone().unwrap();
    row.state = ReceiptState::Settled as i32;
    row.settlement_mutation_id = uuid(SETTLEMENT_ID);
    row.result = Some(TargetObjectRef {
        identity: Some(identity.clone()),
        key: Bytes::from(format!(
            "{}v2/repositories/by-id/{}/g{:016x}/receipts/results/{}.pb",
            prefix.as_str(),
            hex::encode(&identity.repository_uuid),
            identity.generation,
            hex::encode(&receipt.mutation_id)
        )),
        object_version_id: Bytes::from_static(b"result-v1"),
        digest: Bytes::from(vec![0x77; 32]),
        size: 1,
    });
}

fn receipt_catalog_root(catalog: &ReceiptCatalog, prefix: &DeploymentPrefix) -> CatalogRoot {
    let encoded = encode_receipt_catalog(catalog).unwrap();
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    let identity = catalog.identity.clone().unwrap();
    CatalogRoot {
        kind: CatalogKind::Receipt as i32,
        object: Some(TargetObjectRef {
            identity: Some(identity.clone()),
            key: Bytes::from(format!(
                "{}v2/repositories/by-id/{}/g{:016x}/catalogs/receipt/{}.pb",
                prefix.as_str(),
                hex::encode(&identity.repository_uuid),
                identity.generation,
                hex::encode(digest)
            )),
            object_version_id: Bytes::from_static(b"receipt-catalog-v1"),
            digest: Bytes::copy_from_slice(&digest),
            size: encoded.len() as u64,
        }),
        depth: 1,
        node_count: 1,
        item_count: catalog.rows.len() as u64,
        total_encoded_bytes: encoded.len() as u64,
    }
}

fn attach_receipt_catalog(
    control: &mut RepoControl,
    catalog: &ReceiptCatalog,
    prefix: &DeploymentPrefix,
) {
    control.receipt_catalog = Some(receipt_catalog_root(catalog, prefix));
}

fn charged_proof_inputs(
    charged: &mut CapacityReservation,
    writer_epoch: u64,
    prefix: &DeploymentPrefix,
) -> (
    RepoControl,
    LandedControlRef,
    ReceiptCatalog,
    CapacityShard,
    CapacityObjectRef,
) {
    let committing = prior_committing_reservation(charged);
    let shard = shard_with(vec![committing.clone()]);
    let shard_object = exact_capacity_shard_ref(&shard, b"capacity-committing-v1", prefix);
    let catalog = unresolved_catalog(capacity_receipt_for(&committing, &shard_object));
    let mut control = repo_control_for_reservation(charged, MUTATION_ID, writer_epoch, prefix);
    attach_receipt_catalog(&mut control, &catalog, prefix);
    let control_object = exact_landed_control_ref(&control, b"landed-v1");
    let Some(CapacityReservationPayload::Charged(payload)) = charged.state_payload.as_mut() else {
        panic!("charged payload")
    };
    payload.landed_control = Some(control_object.clone());
    (control, control_object, catalog, shard, shard_object)
}

fn conflict_proof_inputs(
    conflict: &mut CapacityReservation,
    mut control: RepoControl,
    provider_version: &[u8],
    prefix: &DeploymentPrefix,
) -> (
    RepoControl,
    LandedControlRef,
    ReceiptCatalog,
    MutationReceipt,
    CapacityShard,
    CapacityObjectRef,
) {
    let committing = prior_committing_reservation(conflict);
    let shard = shard_with(vec![committing.clone()]);
    let shard_object = exact_capacity_shard_ref(&shard, b"capacity-committing-v1", prefix);
    let expected_receipt = capacity_receipt_for(&committing, &shard_object);
    let catalog = unresolved_catalog(no_capacity_receipt(&control));
    attach_receipt_catalog(&mut control, &catalog, prefix);
    let control_object = exact_landed_control_ref(&control, provider_version);
    set_conflicting_control(conflict, control_object.clone());
    (
        control,
        control_object,
        catalog,
        expected_receipt,
        shard,
        shard_object,
    )
}

fn different_identity_control_same_path(
    control: &RepoControl,
    prefix: &DeploymentPrefix,
) -> RepoControl {
    let mut control = control.clone();
    let identity = control.identity.as_mut().unwrap();
    identity.tenant_id = Bytes::from_static(b"different-tenant");
    identity.project_id = Bytes::from_static(b"different-project");
    identity.repository_uuid = uuid("01890f4776447b8b9d7a876543210ad0");
    let shard = Sha256::digest(&identity.repository_uuid)[0];
    let capacity = control.capacity.as_mut().unwrap();
    capacity.shard = u32::from(shard);
    capacity.shard_key = Bytes::from(capacity_shard_key(prefix, shard).unwrap());
    control
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

fn raw_repeated_message(field_number: u32, payload: &[u8], count: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..count {
        push_length_delimited(&mut bytes, field_number, payload);
    }
    bytes
}

fn push_length_delimited(bytes: &mut Vec<u8>, field_number: u32, payload: &[u8]) {
    push_varint(bytes, u64::from(field_number) << 3 | 2);
    push_varint(bytes, payload.len() as u64);
    bytes.extend_from_slice(payload);
}

fn push_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

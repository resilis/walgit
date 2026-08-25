use bytes::Bytes;
use walgit_proto::v2::{
    ControlCodecError, CredentialControl, CredentialTransitionKind, VerificationRingRoot,
    decode_credential_control, encode_credential_control, keys::DeploymentPrefix,
    preflight_credential_control, validate_credential_control,
    validate_credential_control_transition_structure,
};

#[test]
fn bootstrap_has_an_exact_canonical_golden_encoding() {
    let prefix = prefix();
    let control = bootstrap(&prefix);
    let bytes = encode_credential_control(&control, &prefix).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "0802100118012293010a5f70726f642f76322f636f6e74726f6c2f6b65792d72696e67732f313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131312e636f7365120976657273696f6e2d311a20111111111111111111111111111111111111111111111111111111111111111120802028014a20222222222222222222222222222222222222222222222222222222222222222252203333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(decode_credential_control(&bytes, &prefix).unwrap(), control);
}

#[test]
fn optional_signed_timestamp_preserves_absent_zero_and_negative() {
    let prefix = prefix();
    let installed = installed(&prefix);
    for timestamp in [0, -1, i64::MIN] {
        let mut promoted = promoted(&installed, timestamp);
        promoted.acknowledgement_proof_digest = Bytes::from(vec![0x45; 32]);
        let bytes = encode_credential_control(&promoted, &prefix).unwrap();
        assert_eq!(
            decode_credential_control(&bytes, &prefix)
                .unwrap()
                .previous_last_issue_unix_seconds,
            Some(timestamp)
        );
    }
    assert_eq!(bootstrap(&prefix).previous_last_issue_unix_seconds, None);

    preflight_credential_control(&[0x38, 0x00]).unwrap();
    preflight_credential_control(&[
        0x38, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ])
    .unwrap();
}

#[test]
fn preflight_rejects_unknown_duplicate_reordered_and_noncanonical_fields() {
    let prefix = prefix();
    let bytes = encode_credential_control(&bootstrap(&prefix), &prefix).unwrap();

    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[0x58, 0x01]);
    assert!(matches!(
        preflight_credential_control(&unknown),
        Err(ControlCodecError::UnknownField { number: 11, .. })
    ));

    let mut duplicate = vec![0x08, 0x02];
    duplicate.extend_from_slice(&bytes);
    assert!(matches!(
        preflight_credential_control(&duplicate),
        Err(ControlCodecError::NonCanonical(_))
    ));
    assert!(matches!(
        preflight_credential_control(&[0x38, 0x00, 0x38, 0x00]),
        Err(ControlCodecError::NonCanonical(_))
    ));
    assert!(matches!(
        preflight_credential_control(&[0x10, 0x01, 0x08, 0x02]),
        Err(ControlCodecError::NonCanonical(_))
    ));
    assert!(matches!(
        preflight_credential_control(&[0x08, 0x82, 0x00]),
        Err(ControlCodecError::NonCanonical(_))
    ));
    assert!(matches!(
        preflight_credential_control(&[0x0a, 0x01, 0x02]),
        Err(ControlCodecError::WrongWireType { .. })
    ));
    assert!(matches!(
        preflight_credential_control(&[0x22, 0x02, 0x30, 0x01]),
        Err(ControlCodecError::UnknownField { number: 6, .. })
    ));
    assert!(matches!(
        preflight_credential_control(&[0x22, 0x00, 0x22, 0x00]),
        Err(ControlCodecError::NonCanonical(_))
    ));
}

#[test]
fn preflight_enforces_credential_and_repeated_kid_bounds() {
    assert!(matches!(
        preflight_credential_control(&vec![0; 65_537]),
        Err(ControlCodecError::MessageTooLarge {
            maximum: 65_536,
            ..
        })
    ));
    let mut wrong_kid = vec![0x42, 0x0f];
    wrong_kid.extend_from_slice(&[0x11; 15]);
    assert!(matches!(
        preflight_credential_control(&wrong_kid),
        Err(ControlCodecError::BytesOutsideBounds {
            minimum: 16,
            maximum: 16,
            ..
        })
    ));
    let mut too_many = Vec::new();
    for byte in 0..65 {
        too_many.extend_from_slice(&[0x42, 0x10]);
        too_many.extend_from_slice(&[byte; 16]);
    }
    assert!(matches!(
        preflight_credential_control(&too_many),
        Err(ControlCodecError::CountExceeded { maximum: 64, .. })
    ));
}

#[test]
fn semantic_validation_binds_root_prefix_key_digest_slots_and_bootstrap() {
    let prefix = prefix();
    let control = bootstrap(&prefix);
    validate_credential_control(&control, &prefix).unwrap();

    let wrong_prefix = DeploymentPrefix::parse("staging/").unwrap();
    assert!(validate_credential_control(&control, &wrong_prefix).is_err());

    let mut invalid = control.clone();
    invalid.current.as_mut().unwrap().digest = Bytes::from(vec![0x12; 32]);
    assert!(validate_credential_control(&invalid, &prefix).is_err());

    let mut invalid = control.clone();
    invalid.current.as_mut().unwrap().size = 65_537;
    assert!(validate_credential_control(&invalid, &prefix).is_err());

    let mut invalid = control.clone();
    invalid.next = Some(ring(&prefix, 0x11, 2));
    assert!(validate_credential_control(&invalid, &prefix).is_err());

    let mut invalid = control.clone();
    invalid.control_revision = 1;
    invalid.issuer_epoch = 2;
    assert!(validate_credential_control(&invalid, &prefix).is_err());

    let mut invalid = control.clone();
    invalid.control_revision = 2;
    invalid.previous = Some(ring(&prefix, 0x44, 0));
    invalid.previous_last_issue_unix_seconds = None;
    assert!(validate_credential_control(&invalid, &prefix).is_err());
}

#[test]
fn semantic_validation_enforces_deny_set_order_uniqueness_and_cardinality() {
    let prefix = prefix();
    let mut control = bootstrap(&prefix);
    control.control_revision = 2;
    control.revoked_kids = vec![kid(1), kid(2)];
    validate_credential_control(&control, &prefix).unwrap();

    for values in [vec![kid(2), kid(1)], vec![kid(1), kid(1)]] {
        control.revoked_kids = values;
        assert!(validate_credential_control(&control, &prefix).is_err());
    }
    control.revoked_kids = (0..65).map(kid).collect();
    assert!(validate_credential_control(&control, &prefix).is_err());
}

#[test]
fn all_locally_visible_transition_shapes_are_exact() {
    let prefix = prefix();
    let bootstrap = bootstrap(&prefix);

    let installed = installed(&prefix);
    validate_credential_control_transition_structure(
        &bootstrap,
        &installed,
        CredentialTransitionKind::InstallNext,
        &prefix,
    )
    .unwrap();

    let promoted = promoted(&installed, 0);
    validate_credential_control_transition_structure(
        &installed,
        &promoted,
        CredentialTransitionKind::PromoteNext,
        &prefix,
    )
    .unwrap();

    let mut retired = promoted.clone();
    retired.control_revision += 1;
    retired.previous = None;
    retired.previous_last_issue_unix_seconds = None;
    retired.revoked_kids = vec![kid(1), kid(2)];
    retired.issuer_epoch += 1;
    retired.acknowledgement_proof_digest = Bytes::from(vec![0x46; 32]);
    validate_credential_control_transition_structure(
        &promoted,
        &retired,
        CredentialTransitionKind::RetirePrevious,
        &prefix,
    )
    .unwrap();

    let mut revoked = retired.clone();
    revoked.control_revision += 1;
    revoked.revoked_kids.push(kid(3));
    revoked.issuer_epoch += 1;
    revoked.acknowledgement_proof_digest = Bytes::from(vec![0x47; 32]);
    validate_credential_control_transition_structure(
        &retired,
        &revoked,
        CredentialTransitionKind::RevokeKid,
        &prefix,
    )
    .unwrap();

    let mut verifier = revoked.clone();
    verifier.control_revision += 1;
    verifier.verifier_set_digest = Bytes::from(vec![0x48; 32]);
    verifier.acknowledgement_proof_digest = Bytes::from(vec![0x49; 32]);
    validate_credential_control_transition_structure(
        &revoked,
        &verifier,
        CredentialTransitionKind::VerifierSetUpdate,
        &prefix,
    )
    .unwrap();

    let mut acknowledged = verifier.clone();
    acknowledged.control_revision += 1;
    acknowledged.acknowledgement_proof_digest = Bytes::from(vec![0x4a; 32]);
    validate_credential_control_transition_structure(
        &verifier,
        &acknowledged,
        CredentialTransitionKind::AcknowledgementUpdate,
        &prefix,
    )
    .unwrap();
}

#[test]
fn structural_transition_validation_rejects_skip_wrap_rollback_and_combined_changes() {
    let prefix = prefix();
    let bootstrap = bootstrap(&prefix);
    let installed = installed(&prefix);

    let mut skipped_revision = installed.clone();
    skipped_revision.control_revision += 1;
    assert!(
        validate_credential_control_transition_structure(
            &bootstrap,
            &skipped_revision,
            CredentialTransitionKind::InstallNext,
            &prefix,
        )
        .is_err()
    );

    let mut skipped_ring = installed.clone();
    skipped_ring.next = Some(ring(&prefix, 0x44, 3));
    assert!(validate_credential_control(&skipped_ring, &prefix).is_err());

    let mut rollback = installed.clone();
    rollback.next = Some(ring(&prefix, 0x44, 1));
    assert!(validate_credential_control(&rollback, &prefix).is_err());

    let mut combined = installed.clone();
    combined.issuer_epoch += 1;
    assert!(
        validate_credential_control_transition_structure(
            &bootstrap,
            &combined,
            CredentialTransitionKind::InstallNext,
            &prefix,
        )
        .is_err()
    );

    let mut ring_overflow = bootstrap.clone();
    ring_overflow.control_revision = 2;
    ring_overflow.current = Some(ring(&prefix, 0x11, u64::MAX));
    ring_overflow.next = Some(ring(&prefix, 0x44, 1));
    assert!(validate_credential_control(&ring_overflow, &prefix).is_err());

    let mut issuer_overflow_from = installed.clone();
    issuer_overflow_from.issuer_epoch = u64::MAX;
    let mut issuer_overflow_to = promoted(&installed, 0);
    issuer_overflow_to.issuer_epoch = u64::MAX;
    assert!(
        validate_credential_control_transition_structure(
            &issuer_overflow_from,
            &issuer_overflow_to,
            CredentialTransitionKind::PromoteNext,
            &prefix,
        )
        .is_err()
    );

    let mut max_revision = bootstrap.clone();
    max_revision.control_revision = u64::MAX;
    let mut successor = max_revision.clone();
    successor.acknowledgement_proof_digest = Bytes::from(vec![0x77; 32]);
    assert!(
        validate_credential_control_transition_structure(
            &max_revision,
            &successor,
            CredentialTransitionKind::AcknowledgementUpdate,
            &prefix,
        )
        .is_err()
    );

    let mut deny_rollback_from = bootstrap.clone();
    deny_rollback_from.control_revision = 2;
    deny_rollback_from.revoked_kids = vec![kid(1)];
    let mut deny_rollback_to = deny_rollback_from.clone();
    deny_rollback_to.control_revision = 3;
    deny_rollback_to.revoked_kids.clear();
    deny_rollback_to.acknowledgement_proof_digest = Bytes::from(vec![0x78; 32]);
    assert!(
        validate_credential_control_transition_structure(
            &deny_rollback_from,
            &deny_rollback_to,
            CredentialTransitionKind::AcknowledgementUpdate,
            &prefix,
        )
        .is_err()
    );
}

fn prefix() -> DeploymentPrefix {
    DeploymentPrefix::parse("prod/").unwrap()
}

fn bootstrap(prefix: &DeploymentPrefix) -> CredentialControl {
    CredentialControl {
        schema_version: 2,
        control_revision: 1,
        issuer_epoch: 1,
        current: Some(ring(prefix, 0x11, 1)),
        next: None,
        previous: None,
        previous_last_issue_unix_seconds: None,
        revoked_kids: Vec::new(),
        verifier_set_digest: Bytes::from(vec![0x22; 32]),
        acknowledgement_proof_digest: Bytes::from(vec![0x33; 32]),
    }
}

fn installed(prefix: &DeploymentPrefix) -> CredentialControl {
    let mut control = bootstrap(prefix);
    control.control_revision = 2;
    control.next = Some(ring(prefix, 0x44, 2));
    control.acknowledgement_proof_digest = Bytes::from(vec![0x44; 32]);
    control
}

fn promoted(installed: &CredentialControl, timestamp: i64) -> CredentialControl {
    CredentialControl {
        schema_version: 2,
        control_revision: installed.control_revision + 1,
        issuer_epoch: installed.issuer_epoch + 1,
        current: installed.next.clone(),
        next: None,
        previous: installed.current.clone(),
        previous_last_issue_unix_seconds: Some(timestamp),
        revoked_kids: installed.revoked_kids.clone(),
        verifier_set_digest: installed.verifier_set_digest.clone(),
        acknowledgement_proof_digest: Bytes::from(vec![0x45; 32]),
    }
}

fn ring(prefix: &DeploymentPrefix, digest: u8, ring_epoch: u64) -> VerificationRingRoot {
    let digest = [digest; 32];
    VerificationRingRoot {
        key: Bytes::from(format!(
            "{}v2/control/key-rings/{}.cose",
            prefix.as_str(),
            hex::encode(digest)
        )),
        object_version_id: Bytes::from(format!("version-{ring_epoch}")),
        digest: Bytes::copy_from_slice(&digest),
        size: 4_096,
        ring_epoch,
    }
}

fn kid(value: u8) -> Bytes {
    Bytes::from(vec![value; 16])
}

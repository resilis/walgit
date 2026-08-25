use std::{fs::File, io::Read};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    CredentialControl, VerificationRingRoot, encode_credential_control, keys::DeploymentPrefix,
};

use super::*;
use crate::transition::Binding;

const NOW: i64 = 1_800_000_000;

#[test]
fn strict_cbor_and_cose_reject_malleable_or_detached_forms() {
    for bytes in [
        vec![0x9f, 0xff],                         // indefinite array
        vec![0xd2, 0x80],                         // tag
        vec![0x84, 0x40, 0xa0, 0xf6, 0x40],       // detached/null payload
        vec![0x84, 0x40, 0xa0, 0x40, 0x40],       // empty attached payload/signature
        vec![0x98, 0x04, 0x40, 0xa0, 0x40, 0x40], // non-minimal array length
    ] {
        assert!(cose::Sign1::parse(&bytes, 8_192, 7_680).is_err());
    }

    let mut cursor = cbor::Cursor::new(&[0x18, 0x01], 2).unwrap();
    assert!(cursor.uint().is_err());
    let mut cursor = cbor::Cursor::new(&[0x5a, 0xff, 0xff, 0xff, 0xff], 5).unwrap();
    assert!(cursor.bytes(0, 1024).is_err());
}

#[test]
fn committed_public_vector_manifest_and_root_signatures_are_exact() {
    let vector = include_bytes!("../testdata/bootstrap-v1.hex");
    assert_eq!(
        hex::encode(Sha256::digest(vector)),
        "6c8a2a551e122c7282ca61d1b84e2adc59cee6bb82e3264039fdb6c973aa3c61"
    );
    assert_eq!(
        include_str!("../testdata/SHA256SUMS"),
        "6c8a2a551e122c7282ca61d1b84e2adc59cee6bb82e3264039fdb6c973aa3c61  bootstrap-v1.hex\n"
    );
    let text = std::str::from_utf8(vector).unwrap();
    let public_key: [u8; 32] = hex_value(text, "root_public_key").try_into().unwrap();
    let root_kid: [u8; 16] = hex_value(text, "root_kid").try_into().unwrap();
    let root = PinnedRoot::new(public_key, root_kid).unwrap();
    for (name, aad, maximum_payload) in [
        (
            "verifier_set_cose",
            b"walgit-credential-verifier-set-v1".as_slice(),
            65_024,
        ),
        (
            "transition_proof_cose",
            b"walgit-credential-transition-proof-v1".as_slice(),
            7_680,
        ),
    ] {
        let envelope = hex_value(text, name);
        let sign1 = cose::Sign1::parse(&envelope, 65_536, maximum_payload).unwrap();
        assert_eq!(sign1.kid, root_kid);
        sign1.verify(root.public_key(), aad).unwrap();
    }
    assert_eq!(
        Sha256::digest(hex_value(text, "transition_proof_cose")).as_slice(),
        hex_value(text, "transition_proof_digest")
    );
}

fn hex_value(text: &str, name: &str) -> Vec<u8> {
    let prefix = format!("{name}=");
    hex::decode(
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .expect("vector key exists"),
    )
    .unwrap()
}

#[test]
fn create_and_capability_are_exactly_authenticated_but_not_authorized() {
    let root_signer = ephemeral_key();
    let root = pinned(&root_signer);
    let data_signer = ephemeral_key();
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let ring = ring_fixture(&root_signer, &root, &data_signer, 1, &[], 2, 0x10);
    let control = bootstrap_control(&ring.root, [0x22; 32], [0x33; 32]);
    let authority = authority(&root, &prefix, &control, &ring, None, None);

    let create_payload = create_payload(&ring, 600);
    let create = sign1(&data_signer, &ring.data_kid, CREATE_AAD, &create_payload);
    let expected = expected_create(&ring);
    assert!(
        authority
            .verify_create_intent(&create, NOW, &expected)
            .is_ok()
    );

    let mut wrong = expected;
    wrong.quota += 1;
    assert!(
        authority
            .verify_create_intent(&create, NOW, &wrong)
            .is_err()
    );

    let capability_payload = capability_payload(&ring, 900, CapabilityPurpose::GitWrite);
    let capability = sign1(
        &data_signer,
        &ring.data_kid,
        CAPABILITY_AAD,
        &capability_payload,
    );
    let expected_capability = expected_capability(&ring, CapabilityPurpose::GitWrite);
    let authenticated = authority
        .authenticate_capability(&capability, NOW, &expected_capability)
        .unwrap();
    assert_eq!(authenticated.purpose(), CapabilityPurpose::GitWrite);
    assert_eq!(
        authenticated.grant(),
        (b"grant-issuer".as_slice(), b"grant-subject".as_slice())
    );

    assert!(
        authority
            .authenticate_capability(
                &sign1(
                    &data_signer,
                    &ring.data_kid,
                    b"wrong-aad",
                    &capability_payload
                ),
                NOW,
                &expected_capability
            )
            .is_err()
    );
    let mut wrong_ring = expected_capability;
    wrong_ring.common.ring_digest[0] ^= 1;
    assert!(
        authority
            .authenticate_capability(&capability, NOW, &wrong_ring)
            .is_err()
    );
}

#[test]
fn verifier_enforces_slot_state_deny_and_ring_claim_binding() {
    for state in 1..=4 {
        let root_signer = ephemeral_key();
        let root = pinned(&root_signer);
        let data_signer = ephemeral_key();
        let prefix = DeploymentPrefix::parse("prod/").unwrap();
        let ring = ring_fixture(
            &root_signer,
            &root,
            &data_signer,
            2,
            &[0x99; 32],
            state,
            state as u8,
        );
        let mut control = bootstrap_control(&ring.root, [0x22; 32], [0x33; 32]);
        control.control_revision = 2;
        let authority = authority(&root, &prefix, &control, &ring, None, None);
        let payload = capability_payload(&ring, 900, CapabilityPurpose::CloneRead);
        let envelope = sign1(&data_signer, &ring.data_kid, CAPABILITY_AAD, &payload);
        let expected = expected_capability(&ring, CapabilityPurpose::CloneRead);
        assert_eq!(
            authority
                .authenticate_capability(&envelope, NOW, &expected)
                .is_ok(),
            matches!(state, 2 | 3)
        );
    }

    for state in 1..=4 {
        let root_signer = ephemeral_key();
        let root = pinned(&root_signer);
        let current_signer = ephemeral_key();
        let candidate_signer = ephemeral_key();
        let prefix = DeploymentPrefix::parse("prod/").unwrap();
        let current = ring_fixture(&root_signer, &root, &current_signer, 1, &[], 2, 0x11);
        let candidate = ring_fixture(
            &root_signer,
            &root,
            &candidate_signer,
            2,
            &current.root.digest,
            state,
            0x12,
        );
        let mut control = bootstrap_control(&current.root, [0x22; 32], [0x33; 32]);
        control.control_revision = 2;
        control.next = Some(candidate.root.clone());
        let authority = authority(&root, &prefix, &control, &current, Some(&candidate), None);
        let payload = capability_payload(&candidate, 900, CapabilityPurpose::CloneRead);
        let envelope = sign1(
            &candidate_signer,
            &candidate.data_kid,
            CAPABILITY_AAD,
            &payload,
        );
        assert_eq!(
            authority
                .authenticate_capability(
                    &envelope,
                    NOW,
                    &expected_capability(&candidate, CapabilityPurpose::CloneRead),
                )
                .is_ok(),
            state == 2
        );
    }

    for state in 1..=4 {
        let root_signer = ephemeral_key();
        let root = pinned(&root_signer);
        let previous_signer = ephemeral_key();
        let current_signer = ephemeral_key();
        let prefix = DeploymentPrefix::parse("prod/").unwrap();
        let previous = ring_fixture(&root_signer, &root, &previous_signer, 1, &[], state, 0x13);
        let current = ring_fixture(
            &root_signer,
            &root,
            &current_signer,
            2,
            &previous.root.digest,
            2,
            0x14,
        );
        let mut control = bootstrap_control(&current.root, [0x22; 32], [0x33; 32]);
        control.control_revision = 3;
        control.issuer_epoch = 2;
        control.previous = Some(previous.root.clone());
        control.previous_last_issue_unix_seconds = Some(NOW);
        let authority = authority(&root, &prefix, &control, &current, None, Some(&previous));
        let payload = capability_payload(&previous, 900, CapabilityPurpose::CloneRead);
        let envelope = sign1(
            &previous_signer,
            &previous.data_kid,
            CAPABILITY_AAD,
            &payload,
        );
        assert_eq!(
            authority
                .authenticate_capability(
                    &envelope,
                    NOW,
                    &expected_capability(&previous, CapabilityPurpose::CloneRead),
                )
                .is_ok(),
            matches!(state, 2 | 3)
        );
    }

    let root_signer = ephemeral_key();
    let root = pinned(&root_signer);
    let current_signer = ephemeral_key();
    let next_signer = ephemeral_key();
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let current = ring_fixture(&root_signer, &root, &current_signer, 1, &[], 2, 0x20);
    let next = ring_fixture(
        &root_signer,
        &root,
        &next_signer,
        2,
        &current.root.digest,
        2,
        0x21,
    );
    let mut control = bootstrap_control(&current.root, [0x22; 32], [0x33; 32]);
    control.control_revision = 2;
    control.next = Some(next.root.clone());
    let bound = authority(&root, &prefix, &control, &current, Some(&next), None);
    let payload = capability_payload(&next, 900, CapabilityPurpose::CloneRead);
    let envelope = sign1(&next_signer, &next.data_kid, CAPABILITY_AAD, &payload);
    let expected = expected_capability(&next, CapabilityPurpose::CloneRead);
    assert!(
        bound
            .authenticate_capability(&envelope, NOW, &expected)
            .is_ok()
    );

    control.revoked_kids.push(next.data_kid.to_vec().into());
    assert!(
        CredentialAuthority::bind(
            &root,
            &control,
            &prefix,
            BoundRingObjects {
                current: exact(&current),
                next: Some(exact(&next)),
                previous: None,
            },
        )
        .is_err()
    );

    // The old object need not remain bound for the permanent deny set to
    // reject reuse by a newly proposed next ring.
    let later_current = ring_fixture(
        &root_signer,
        &root,
        &current_signer,
        2,
        &[0x91; 32],
        2,
        0x22,
    );
    let reused_next = ring_fixture(
        &root_signer,
        &root,
        &next_signer,
        3,
        &later_current.root.digest,
        2,
        0x21,
    );
    let mut reuse_control = bootstrap_control(&later_current.root, [0x22; 32], [0x33; 32]);
    reuse_control.control_revision = 4;
    reuse_control.next = Some(reused_next.root.clone());
    reuse_control
        .revoked_kids
        .push(reused_next.data_kid.to_vec().into());
    assert!(
        CredentialAuthority::bind(
            &root,
            &reuse_control,
            &prefix,
            BoundRingObjects {
                current: exact(&later_current),
                next: Some(exact(&reused_next)),
                previous: None,
            },
        )
        .is_err()
    );
}

#[test]
fn uuid_and_time_boundaries_use_checked_issued_at_lifetimes() {
    let root_signer = ephemeral_key();
    let root = pinned(&root_signer);
    let data_signer = ephemeral_key();
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let ring = ring_fixture(&root_signer, &root, &data_signer, 1, &[], 2, 0x30);
    let control = bootstrap_control(&ring.root, [0x22; 32], [0x33; 32]);
    let authority = authority(&root, &prefix, &control, &ring, None, None);
    let expected = expected_create(&ring);
    for (lifetime, now, valid) in [
        (600, NOW - 30, true),
        (600, NOW + 630, true),
        (601, NOW, false),
        (600, NOW + 631, false),
    ] {
        let payload = create_payload_with(&ring, lifetime, NOW);
        let envelope = sign1(&data_signer, &ring.data_kid, CREATE_AAD, &payload);
        assert_eq!(
            authority
                .verify_create_intent(&envelope, now, &expected)
                .is_ok(),
            valid
        );
    }
    let mut claims = parse_create(&create_payload(&ring, 600)).unwrap().common;
    claims.issued_at = i64::MIN;
    claims.not_before = i64::MIN;
    claims.expiry = i64::MAX;
    assert!(validate_envelope_time(&claims, 0, 600).is_err());
}

#[test]
fn every_transition_kind_requires_the_complete_exact_evidence_chain() {
    for kind in [
        TransitionKind::Bootstrap,
        TransitionKind::InstallNext,
        TransitionKind::PromoteNext,
        TransitionKind::RetirePrevious,
        TransitionKind::RevokeKid,
        TransitionKind::VerifierSetUpdate,
        TransitionKind::AcknowledgementUpdate,
    ] {
        let fixture = transition_fixture(kind);
        assert!(
            verify_credential_transition(fixture.request()).is_ok(),
            "{kind:?}"
        );
        let mut corrupt = fixture.evidence_owned.1.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let mut request = fixture.request();
        request.evidence.acknowledgement_set = &corrupt;
        assert!(
            verify_credential_transition(request).is_err(),
            "corrupt {kind:?}"
        );
    }
}

#[test]
#[ignore = "emits a public cross-language bootstrap vector; never emits signing keys"]
fn emit_public_bootstrap_vector() {
    let fixture = transition_fixture(TransitionKind::Bootstrap);
    let verified = verify_credential_transition(fixture.request()).unwrap();
    println!("root_public_key={}", hex::encode(fixture.root.public_key()));
    println!("root_kid={}", hex::encode(fixture.root.kid()));
    println!(
        "verifier_set_cose={}",
        hex::encode(&fixture.evidence_owned.0)
    );
    println!(
        "acknowledgement_set={}",
        hex::encode(&fixture.evidence_owned.1)
    );
    println!(
        "transition_proof_cose={}",
        hex::encode(&fixture.evidence_owned.2)
    );
    println!(
        "transition_projection={}",
        hex::encode(verified.projection_bytes())
    );
    println!(
        "transition_proof_digest={}",
        hex::encode(verified.proof_digest())
    );
}

fn ephemeral_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    let key = SigningKey::from_bytes(&bytes);
    bytes.fill(0);
    key
}
fn pinned(signing: &SigningKey) -> PinnedRoot {
    let public = signing.verifying_key().to_bytes();
    let digest = Sha256::new()
        .chain_update(ROOT_KID_DOMAIN)
        .chain_update(public)
        .finalize();
    PinnedRoot::new(public, digest[..16].try_into().unwrap()).unwrap()
}

fn sign1(signing: &SigningKey, kid: &[u8; 16], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let protected = cose::protected(kid);
    let signature = signing
        .sign(&cose::sig_structure(&protected, aad, payload))
        .to_bytes();
    let mut out = Vec::new();
    cbor::array(&mut out, 4);
    cbor::bytes(&mut out, &protected);
    cbor::map(&mut out, 0);
    cbor::bytes(&mut out, payload);
    cbor::bytes(&mut out, &signature);
    out
}
fn uuid(timestamp: i64, tail: u8) -> [u8; 16] {
    let mut out = [tail; 16];
    let ms = (timestamp as u64) * 1000;
    out[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    out[6] = (out[6] & 0x0f) | 0x70;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

struct RingFixture {
    root: VerificationRingRoot,
    body: Vec<u8>,
    data_kid: [u8; 16],
    epoch: u64,
    digest: [u8; 32],
}
fn ring_fixture(
    root_signer: &SigningKey,
    root: &PinnedRoot,
    data_signer: &SigningKey,
    epoch: u64,
    prior: &[u8],
    state: u64,
    tail: u8,
) -> RingFixture {
    let data_kid = [tail; 16];
    let mut payload = Vec::new();
    cbor::map(&mut payload, 6);
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 2);
    cbor::bytes(&mut payload, &uuid(NOW - 10, tail));
    cbor::uint(&mut payload, 3);
    cbor::int(&mut payload, NOW - 10);
    cbor::uint(&mut payload, 4);
    cbor::bytes(&mut payload, prior);
    cbor::uint(&mut payload, 5);
    cbor::array(&mut payload, 1);
    cbor::map(&mut payload, 7);
    cbor::uint(&mut payload, 1);
    cbor::bytes(&mut payload, &data_kid);
    cbor::uint(&mut payload, 2);
    cbor::bytes(&mut payload, &data_signer.verifying_key().to_bytes());
    cbor::uint(&mut payload, 3);
    cbor::bytes(&mut payload, b"cloud-core");
    cbor::uint(&mut payload, 4);
    cbor::array(&mut payload, 1);
    cbor::bytes(&mut payload, b"walgit");
    cbor::uint(&mut payload, 5);
    cbor::int(&mut payload, NOW - 1000);
    cbor::uint(&mut payload, 6);
    cbor::int(&mut payload, NOW + 1000);
    cbor::uint(&mut payload, 7);
    cbor::uint(&mut payload, state);
    cbor::uint(&mut payload, 6);
    cbor::uint(&mut payload, epoch);
    let body = sign1(root_signer, root.kid(), RING_AAD, &payload);
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let key = format!("prod/v2/control/key-rings/{}.cose", hex::encode(digest));
    let root = VerificationRingRoot {
        key: key.into_bytes().into(),
        object_version_id: format!("ring-version-{epoch}").into_bytes().into(),
        digest: digest.to_vec().into(),
        size: body.len() as u64,
        ring_epoch: epoch,
    };
    RingFixture {
        root,
        body,
        data_kid,
        epoch,
        digest,
    }
}
fn bootstrap_control(
    root: &VerificationRingRoot,
    verifier: [u8; 32],
    proof: [u8; 32],
) -> CredentialControl {
    CredentialControl {
        schema_version: 2,
        control_revision: 1,
        issuer_epoch: 1,
        current: Some(root.clone()),
        next: None,
        previous: None,
        previous_last_issue_unix_seconds: None,
        revoked_kids: vec![],
        verifier_set_digest: verifier.to_vec().into(),
        acknowledgement_proof_digest: proof.to_vec().into(),
    }
}
fn exact<'a>(ring: &'a RingFixture) -> ExactRingObject<'a> {
    ExactRingObject {
        key: &ring.root.key,
        object_version_id: &ring.root.object_version_id,
        body: &ring.body,
    }
}
fn authority(
    root: &PinnedRoot,
    prefix: &DeploymentPrefix,
    control: &CredentialControl,
    current: &RingFixture,
    next: Option<&RingFixture>,
    previous: Option<&RingFixture>,
) -> CredentialAuthority {
    CredentialAuthority::bind(
        root,
        control,
        prefix,
        BoundRingObjects {
            current: exact(current),
            next: next.map(exact),
            previous: previous.map(exact),
        },
    )
    .unwrap()
}

fn common_payload(out: &mut Vec<u8>, ring: &RingFixture, kind: u64, issued: i64, expiry: i64) {
    let path = b"tenant/repo";
    let path_digest = Sha256::digest(path);
    let routing = Sha256::new()
        .chain_update(b"walgit-repo-path-v1")
        .chain_update((path.len() as u32).to_be_bytes())
        .chain_update(path)
        .finalize();
    for (key, value) in [(1, 1), (2, kind)] {
        cbor::uint(out, key);
        cbor::uint(out, value);
    }
    cbor::uint(out, 3);
    cbor::bytes(out, b"cloud-core");
    cbor::uint(out, 4);
    cbor::bytes(out, b"walgit");
    cbor::uint(out, 5);
    cbor::bytes(out, &uuid(issued, 0x40));
    cbor::uint(out, 6);
    cbor::int(out, issued);
    cbor::uint(out, 7);
    cbor::int(out, issued);
    cbor::uint(out, 8);
    cbor::int(out, expiry);
    cbor::uint(out, 9);
    cbor::bytes(out, b"tenant");
    cbor::uint(out, 10);
    cbor::bytes(out, b"project");
    cbor::uint(out, 11);
    cbor::bytes(out, &uuid(NOW, 0x41));
    cbor::uint(out, 12);
    cbor::uint(out, 1);
    cbor::uint(out, 13);
    cbor::bytes(out, path);
    cbor::uint(out, 14);
    cbor::bytes(out, &path_digest);
    cbor::uint(out, 15);
    cbor::uint(out, ring.epoch);
    cbor::uint(out, 16);
    cbor::bytes(out, &ring.digest);
    cbor::uint(out, 17);
    cbor::bytes(out, &routing);
}
fn create_payload(ring: &RingFixture, lifetime: i64) -> Vec<u8> {
    create_payload_with(ring, lifetime, NOW)
}
fn create_payload_with(ring: &RingFixture, lifetime: i64, issued: i64) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::map(&mut out, 24);
    common_payload(&mut out, ring, 1, issued, issued.saturating_add(lifetime));
    cbor::uint(&mut out, 20);
    cbor::uint(&mut out, 1);
    cbor::uint(&mut out, 21);
    cbor::uint(&mut out, 1);
    cbor::uint(&mut out, 22);
    cbor::uint(&mut out, 1024);
    cbor::uint(&mut out, 23);
    cbor::bytes(&mut out, b"admin-issuer");
    cbor::uint(&mut out, 24);
    cbor::bytes(&mut out, b"admin-subject");
    cbor::uint(&mut out, 25);
    cbor::uint(&mut out, 7);
    cbor::uint(&mut out, 26);
    cbor::bytes(&mut out, repo_control_key_bytes());
    out
}
fn capability_payload(ring: &RingFixture, lifetime: i64, purpose: CapabilityPurpose) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::map(&mut out, 24);
    common_payload(&mut out, ring, 2, NOW, NOW + lifetime);
    cbor::uint(&mut out, 30);
    cbor::uint(&mut out, purpose as u64);
    cbor::uint(&mut out, 31);
    cbor::uint(&mut out, 9);
    cbor::uint(&mut out, 32);
    cbor::bytes(&mut out, repo_control_key_bytes());
    cbor::uint(&mut out, 33);
    cbor::bytes(&mut out, b"control-version");
    cbor::uint(&mut out, 34);
    cbor::uint(&mut out, 7);
    cbor::uint(&mut out, 35);
    cbor::bytes(&mut out, b"grant-issuer");
    cbor::uint(&mut out, 36);
    cbor::bytes(&mut out, b"grant-subject");
    out
}
fn expected_common(ring: &RingFixture) -> ExpectedCommonClaims<'_> {
    let path = b"tenant/repo";
    let routing: [u8; 32] = Sha256::new()
        .chain_update(b"walgit-repo-path-v1")
        .chain_update((path.len() as u32).to_be_bytes())
        .chain_update(path)
        .finalize()
        .into();
    ExpectedCommonClaims {
        issuer: b"cloud-core",
        audience: b"walgit",
        id: uuid(NOW, 0x40),
        tenant_id: b"tenant",
        project_id: b"project",
        repository_uuid: uuid(NOW, 0x41),
        canonical_path: path,
        ring_epoch: ring.epoch,
        ring_digest: ring.digest,
        routing_digest: routing,
    }
}
fn repo_control_key_bytes() -> &'static [u8] {
    b"prod/v2/repositories/by-path/caedbc51cb4697cda562277410b7673b7016446a0ae13f3b6ca6ab84ba260b78/repo_control.pb"
}
fn expected_create(ring: &RingFixture) -> ExpectedCreateIntent<'_> {
    ExpectedCreateIntent {
        common: expected_common(ring),
        object_format: 1,
        visibility: 1,
        quota: 1024,
        admin_issuer: b"admin-issuer",
        admin_subject: b"admin-subject",
        cutover_generation: 7,
        control_key: repo_control_key_bytes(),
    }
}
fn expected_capability(ring: &RingFixture, purpose: CapabilityPurpose) -> ExpectedCapability<'_> {
    ExpectedCapability {
        common: expected_common(ring),
        purpose,
        authorization_epoch: 9,
        control_key: repo_control_key_bytes(),
        control_version_id: b"control-version",
        cutover_generation: 7,
        grant_issuer: b"grant-issuer",
        grant_subject: b"grant-subject",
    }
}

struct TransitionFixture {
    root: PinnedRoot,
    proposed: CredentialAuthority,
    predecessor: Option<CredentialAuthority>,
    predecessor_body: Vec<u8>,
    predecessor_verifier: Vec<u8>,
    evidence_owned: (Vec<u8>, Vec<u8>, Vec<u8>),
    prefix: DeploymentPrefix,
    bootstrap: Option<[u8; 16]>,
}
impl TransitionFixture {
    fn request(&self) -> TransitionRequest<'_> {
        let evidence = TransitionEvidence {
            verifier_set_cose: &self.evidence_owned.0,
            acknowledgement_set: &self.evidence_owned.1,
            transition_proof_cose: &self.evidence_owned.2,
        };
        let predecessor = self
            .predecessor
            .as_ref()
            .map(|authority| CredentialPredecessor {
                authority,
                control_key: b"prod/v2/control/credential_control.pb",
                object_version_id: b"credential-version",
                exact_body: &self.predecessor_body,
                verifier_set_cose: &self.predecessor_verifier,
            });
        TransitionRequest {
            root: &self.root,
            prefix: &self.prefix,
            proposed: &self.proposed,
            predecessor,
            bootstrap_session: self.bootstrap,
            evidence,
            now_unix_seconds: NOW,
        }
    }
}

fn transition_fixture(kind: TransitionKind) -> TransitionFixture {
    let root_signer = ephemeral_key();
    let root = pinned(&root_signer);
    let data1 = ephemeral_key();
    let data2 = ephemeral_key();
    let member = ephemeral_key();
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let ring1 = ring_fixture(&root_signer, &root, &data1, 1, &[], 2, 0x50);
    let ring2 = ring_fixture(&root_signer, &root, &data2, 2, &ring1.root.digest, 2, 0x51);
    let verifier1 = verifier_set(&root_signer, &root, &member, 1, 0x60);
    let digest1 = semantic(&verifier1, b"walgit-credential-verifier-set-digest-v1");
    let verifier2 = verifier_set(&root_signer, &root, &member, 2, 0x61);
    let digest2 = semantic(&verifier2, b"walgit-credential-verifier-set-digest-v1");
    let mut predecessor = bootstrap_control(&ring1.root, digest1, [0x33; 32]);
    predecessor.control_revision = 2;
    let mut proposed = predecessor.clone();
    proposed.control_revision += 1;
    match kind {
        TransitionKind::Bootstrap => {
            proposed = bootstrap_control(&ring1.root, digest1, [0x33; 32]);
        }
        TransitionKind::InstallNext => {
            proposed.next = Some(ring2.root.clone());
        }
        TransitionKind::PromoteNext => {
            predecessor.next = Some(ring2.root.clone());
            proposed = CredentialControl {
                schema_version: 2,
                control_revision: predecessor.control_revision + 1,
                issuer_epoch: 2,
                current: Some(ring2.root.clone()),
                next: None,
                previous: Some(ring1.root.clone()),
                previous_last_issue_unix_seconds: Some(NOW - 10),
                revoked_kids: vec![],
                verifier_set_digest: digest1.to_vec().into(),
                acknowledgement_proof_digest: vec![0x33; 32].into(),
            };
        }
        TransitionKind::RetirePrevious => {
            predecessor.current = Some(ring2.root.clone());
            predecessor.previous = Some(ring1.root.clone());
            predecessor.previous_last_issue_unix_seconds = Some(NOW - 930);
            proposed = predecessor.clone();
            proposed.control_revision += 1;
            proposed.previous = None;
            proposed.previous_last_issue_unix_seconds = None;
            proposed.revoked_kids.push(ring1.data_kid.to_vec().into());
            proposed.issuer_epoch += 1;
        }
        TransitionKind::RevokeKid => {
            proposed.revoked_kids.push(ring1.data_kid.to_vec().into());
            proposed.issuer_epoch += 1;
        }
        TransitionKind::VerifierSetUpdate => {
            proposed.verifier_set_digest = digest2.to_vec().into();
        }
        TransitionKind::AcknowledgementUpdate => {}
    }
    let chosen_verifier = if kind == TransitionKind::VerifierSetUpdate {
        verifier2.clone()
    } else {
        verifier1.clone()
    };
    let binding = if kind == TransitionKind::Bootstrap {
        Binding::Bootstrap(uuid(NOW, 0x70))
    } else {
        let body = encode_credential_control(&predecessor, &prefix).unwrap();
        Binding::Predecessor {
            key: b"prod/v2/control/credential_control.pb".to_vec(),
            version_id: b"credential-version".to_vec(),
            digest: Sha256::digest(&body).into(),
            size: body.len() as u64,
        }
    };
    let projection =
        walgit_proto::v2::encode_credential_control_projection(&proposed, &prefix).unwrap();
    let projection_digest = semantic(&projection, b"walgit-credential-control-transition-v1");
    let ack = ack_set(
        &member,
        if kind == TransitionKind::VerifierSetUpdate {
            digest2
        } else {
            digest1
        },
        projection_digest,
        kind,
        &binding,
    );
    let ack_digest = semantic(&ack, b"walgit-credential-acknowledgement-set-digest-v1");
    let proof = proof(
        &root_signer,
        &root,
        ProofClaims {
            kind,
            verifier: if kind == TransitionKind::VerifierSetUpdate {
                digest2
            } else {
                digest1
            },
            acknowledgement: ack_digest,
            projection: projection_digest,
            projection_length: projection.len() as u64,
        },
        &binding,
    );
    proposed.acknowledgement_proof_digest = Sha256::digest(&proof).to_vec().into();
    let predecessor_body = if kind == TransitionKind::Bootstrap {
        vec![]
    } else {
        encode_credential_control(&predecessor, &prefix).unwrap()
    };
    let predecessor_authority = if kind == TransitionKind::Bootstrap {
        None
    } else {
        Some(match kind {
            TransitionKind::PromoteNext => {
                authority(&root, &prefix, &predecessor, &ring1, Some(&ring2), None)
            }
            TransitionKind::RetirePrevious => {
                authority(&root, &prefix, &predecessor, &ring2, None, Some(&ring1))
            }
            _ => authority(&root, &prefix, &predecessor, &ring1, None, None),
        })
    };
    let proposed_authority = match kind {
        TransitionKind::InstallNext => {
            authority(&root, &prefix, &proposed, &ring1, Some(&ring2), None)
        }
        TransitionKind::PromoteNext => {
            authority(&root, &prefix, &proposed, &ring2, None, Some(&ring1))
        }
        TransitionKind::RetirePrevious => authority(&root, &prefix, &proposed, &ring2, None, None),
        _ => authority(&root, &prefix, &proposed, &ring1, None, None),
    };
    TransitionFixture {
        root,
        proposed: proposed_authority,
        predecessor: predecessor_authority,
        predecessor_body,
        predecessor_verifier: verifier1,
        evidence_owned: (chosen_verifier, ack, proof),
        prefix,
        bootstrap: if kind == TransitionKind::Bootstrap {
            Some(uuid(NOW, 0x70))
        } else {
            None
        },
    }
}

fn verifier_set(
    root_signer: &SigningKey,
    root: &PinnedRoot,
    member: &SigningKey,
    epoch: u64,
    tail: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    cbor::map(&mut payload, 5);
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 2);
    cbor::bytes(&mut payload, &uuid(NOW, tail));
    cbor::uint(&mut payload, 3);
    cbor::int(&mut payload, NOW - 10);
    cbor::uint(&mut payload, 4);
    cbor::uint(&mut payload, epoch);
    cbor::uint(&mut payload, 5);
    cbor::array(&mut payload, 1);
    cbor::map(&mut payload, 5);
    cbor::uint(&mut payload, 1);
    cbor::bytes(&mut payload, b"member");
    cbor::uint(&mut payload, 2);
    cbor::uint(&mut payload, 15);
    cbor::uint(&mut payload, 3);
    cbor::bytes(&mut payload, &[0x71; 16]);
    cbor::uint(&mut payload, 4);
    cbor::bytes(&mut payload, &member.verifying_key().to_bytes());
    cbor::uint(&mut payload, 5);
    cbor::uint(&mut payload, epoch);
    sign1(
        root_signer,
        root.kid(),
        b"walgit-credential-verifier-set-v1",
        &payload,
    )
}
fn semantic(bytes: &[u8], domain: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update((bytes.len() as u32).to_be_bytes())
        .chain_update(bytes)
        .finalize()
        .into()
}
fn ack_set(
    member: &SigningKey,
    verifier: [u8; 32],
    projection: [u8; 32],
    kind: TransitionKind,
    binding: &Binding,
) -> Vec<u8> {
    let binding_bytes =
        transition::encode_ack_binding(verifier, projection, kind, binding).unwrap();
    let mut unsigned = Vec::new();
    let promote = kind == TransitionKind::PromoteNext;
    cbor::map(&mut unsigned, if promote { 5 } else { 4 });
    cbor::uint(&mut unsigned, 1);
    cbor::bytes(&mut unsigned, b"member");
    cbor::uint(&mut unsigned, 2);
    cbor::uint(
        &mut unsigned,
        if kind == TransitionKind::VerifierSetUpdate {
            2
        } else {
            1
        },
    );
    cbor::uint(&mut unsigned, 3);
    cbor::uint(&mut unsigned, 15);
    cbor::uint(&mut unsigned, 4);
    cbor::int(&mut unsigned, NOW);
    if promote {
        cbor::uint(&mut unsigned, 5);
        cbor::int(&mut unsigned, NOW - 10);
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"walgit-credential-member-ack-v1");
    message.extend_from_slice(&(binding_bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(&binding_bytes);
    message.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
    message.extend_from_slice(&unsigned);
    let signature = member.sign(&message).to_bytes();
    let mut out = Vec::new();
    let bootstrap = kind == TransitionKind::Bootstrap;
    cbor::map(&mut out, if bootstrap { 7 } else { 10 });
    cbor::uint(&mut out, 1);
    cbor::uint(&mut out, 1);
    cbor::uint(&mut out, 2);
    cbor::bytes(&mut out, &verifier);
    cbor::uint(&mut out, 3);
    cbor::bytes(&mut out, &projection);
    cbor::uint(&mut out, 4);
    cbor::uint(&mut out, kind as u64);
    cbor::uint(&mut out, 5);
    cbor::uint(&mut out, if bootstrap { 1 } else { 2 });
    match binding {
        Binding::Bootstrap(session) => {
            cbor::uint(&mut out, 6);
            cbor::bytes(&mut out, session);
        }
        Binding::Predecessor {
            key,
            version_id,
            digest,
            size,
        } => {
            cbor::uint(&mut out, 7);
            cbor::bytes(&mut out, key);
            cbor::uint(&mut out, 8);
            cbor::bytes(&mut out, version_id);
            cbor::uint(&mut out, 9);
            cbor::bytes(&mut out, digest);
            cbor::uint(&mut out, 10);
            cbor::uint(&mut out, *size);
        }
    }
    cbor::uint(&mut out, 11);
    cbor::array(&mut out, 1);
    let row_count = if promote { 6 } else { 5 };
    cbor::map(&mut out, row_count);
    cbor::uint(&mut out, 1);
    cbor::bytes(&mut out, b"member");
    cbor::uint(&mut out, 2);
    cbor::uint(
        &mut out,
        if kind == TransitionKind::VerifierSetUpdate {
            2
        } else {
            1
        },
    );
    cbor::uint(&mut out, 3);
    cbor::uint(&mut out, 15);
    cbor::uint(&mut out, 4);
    cbor::int(&mut out, NOW);
    if promote {
        cbor::uint(&mut out, 5);
        cbor::int(&mut out, NOW - 10);
    }
    cbor::uint(&mut out, 6);
    cbor::bytes(&mut out, &signature);
    out
}
struct ProofClaims {
    kind: TransitionKind,
    verifier: [u8; 32],
    acknowledgement: [u8; 32],
    projection: [u8; 32],
    projection_length: u64,
}

fn proof(
    root_signer: &SigningKey,
    root: &PinnedRoot,
    claims: ProofClaims,
    binding: &Binding,
) -> Vec<u8> {
    let bootstrap = claims.kind == TransitionKind::Bootstrap;
    let mut payload = Vec::new();
    cbor::map(&mut payload, if bootstrap { 11 } else { 14 });
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 1);
    cbor::uint(&mut payload, 2);
    cbor::bytes(&mut payload, &uuid(NOW, 0x72));
    cbor::uint(&mut payload, 3);
    cbor::uint(&mut payload, claims.kind as u64);
    cbor::uint(&mut payload, 4);
    cbor::int(&mut payload, NOW);
    cbor::uint(&mut payload, 5);
    cbor::int(&mut payload, NOW);
    cbor::uint(&mut payload, 6);
    cbor::int(&mut payload, NOW + 600);
    cbor::uint(&mut payload, 7);
    cbor::bytes(&mut payload, &claims.verifier);
    cbor::uint(&mut payload, 8);
    cbor::bytes(&mut payload, &claims.acknowledgement);
    cbor::uint(&mut payload, 9);
    cbor::bytes(&mut payload, &claims.projection);
    cbor::uint(&mut payload, 10);
    cbor::uint(&mut payload, claims.projection_length);
    match binding {
        Binding::Bootstrap(session) => {
            cbor::uint(&mut payload, 15);
            cbor::bytes(&mut payload, session);
        }
        Binding::Predecessor {
            key,
            version_id,
            digest,
            size,
        } => {
            cbor::uint(&mut payload, 11);
            cbor::bytes(&mut payload, key);
            cbor::uint(&mut payload, 12);
            cbor::bytes(&mut payload, version_id);
            cbor::uint(&mut payload, 13);
            cbor::bytes(&mut payload, digest);
            cbor::uint(&mut payload, 14);
            cbor::uint(&mut payload, *size);
        }
    }
    sign1(
        root_signer,
        root.kid(),
        b"walgit-credential-transition-proof-v1",
        &payload,
    )
}

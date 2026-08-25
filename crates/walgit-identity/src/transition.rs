use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    CredentialTransitionKind, decode_credential_control, encode_credential_control_projection,
    keys::{DeploymentPrefix, V2KeyKind, parse_key},
    validate_credential_control_transition_structure,
};

use crate::{
    CredentialAuthority, IdentityError, PinnedRoot, Slot, ascii, cbor, cose, exact_key, exact_uint,
    positive, uuid_v7,
};

const VERIFIER_AAD: &[u8] = b"walgit-credential-verifier-set-v1";
const PROOF_AAD: &[u8] = b"walgit-credential-transition-proof-v1";
const VERIFIER_DIGEST_DOMAIN: &[u8] = b"walgit-credential-verifier-set-digest-v1";
const ACK_DIGEST_DOMAIN: &[u8] = b"walgit-credential-acknowledgement-set-digest-v1";
const PROJECTION_DIGEST_DOMAIN: &[u8] = b"walgit-credential-control-transition-v1";
const MEMBER_ACK_DOMAIN: &[u8] = b"walgit-credential-member-ack-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum TransitionKind {
    Bootstrap = 1,
    InstallNext = 2,
    PromoteNext = 3,
    RetirePrevious = 4,
    RevokeKid = 5,
    VerifierSetUpdate = 6,
    AcknowledgementUpdate = 7,
}

#[derive(Clone, Copy)]
pub struct TransitionEvidence<'a> {
    pub verifier_set_cose: &'a [u8],
    pub acknowledgement_set: &'a [u8],
    pub transition_proof_cose: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct CredentialPredecessor<'a> {
    pub authority: &'a CredentialAuthority,
    pub control_key: &'a [u8],
    pub object_version_id: &'a [u8],
    pub exact_body: &'a [u8],
    pub verifier_set_cose: &'a [u8],
}

pub struct TransitionRequest<'a> {
    pub root: &'a PinnedRoot,
    pub prefix: &'a DeploymentPrefix,
    pub proposed: &'a CredentialAuthority,
    pub predecessor: Option<CredentialPredecessor<'a>>,
    pub bootstrap_session: Option<[u8; 16]>,
    pub evidence: TransitionEvidence<'a>,
    pub now_unix_seconds: i64,
}

/// Opaque evidence that the complete transition chain verified together.
/// No public API exposes a digest-only or partially verified success value.
pub struct VerifiedCredentialTransition {
    projection_bytes: Vec<u8>,
    proof_digest: [u8; 32],
    kind: TransitionKind,
}

impl VerifiedCredentialTransition {
    pub fn projection_bytes(&self) -> &[u8] {
        &self.projection_bytes
    }
    pub fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }
    pub fn kind(&self) -> TransitionKind {
        self.kind
    }
}

pub fn verify_credential_transition(
    request: TransitionRequest<'_>,
) -> Result<VerifiedCredentialTransition, IdentityError> {
    let proposed = request.proposed.control();
    let projection_bytes = encode_credential_control_projection(proposed, request.prefix)
        .map_err(|_| IdentityError::Control)?;
    let projection_digest = semantic_digest(PROJECTION_DIGEST_DOMAIN, &projection_bytes)?;

    let proof_sign1 = cose::Sign1::parse(request.evidence.transition_proof_cose, 8_192, 7_680)?;
    if proof_sign1.kid != *request.root.kid() {
        return Err(IdentityError::Transition("proof root kid mismatch"));
    }
    proof_sign1.verify(request.root.public_key(), PROOF_AAD)?;
    let proof = parse_proof(proof_sign1.payload)?;
    validate_proof_time(&proof, request.now_unix_seconds)?;
    if proof.projection_digest != projection_digest
        || proof.projection_length != projection_bytes.len() as u64
    {
        return Err(IdentityError::Transition(
            "proof projection binding mismatch",
        ));
    }

    let proof_digest: [u8; 32] = Sha256::digest(request.evidence.transition_proof_cose).into();
    if proposed.acknowledgement_proof_digest.as_ref() != proof_digest {
        return Err(IdentityError::Transition(
            "proposed field 10 is not the exact proof digest",
        ));
    }
    let kind = proof.kind;
    validate_binding(&request, &proof)?;
    validate_control_shape(&request, kind)?;

    let verifier = parse_verifier_set(request.root, request.evidence.verifier_set_cose)?;
    let verifier_digest =
        semantic_digest(VERIFIER_DIGEST_DOMAIN, request.evidence.verifier_set_cose)?;
    if proof.verifier_digest != verifier_digest
        || proposed.verifier_set_digest.as_ref() != verifier_digest
    {
        return Err(IdentityError::Transition(
            "verifier-set digest binding mismatch",
        ));
    }
    validate_verifier_evolution(
        &request,
        kind,
        &verifier,
        request.evidence.verifier_set_cose,
    )?;

    let acknowledgement = parse_acknowledgement_set(request.evidence.acknowledgement_set, kind)?;
    let acknowledgement_digest =
        semantic_digest(ACK_DIGEST_DOMAIN, request.evidence.acknowledgement_set)?;
    if proof.acknowledgement_digest != acknowledgement_digest
        || acknowledgement.verifier_digest != verifier_digest
        || acknowledgement.projection_digest != projection_digest
        || acknowledgement.kind != kind
    {
        return Err(IdentityError::Transition(
            "acknowledgement-set digest or projection binding mismatch",
        ));
    }
    validate_ack_binding(&request, &proof, &acknowledgement)?;
    verify_acknowledgements(&verifier, &acknowledgement, &proof)?;
    validate_ring_semantics(&request, kind, &acknowledgement)?;

    Ok(VerifiedCredentialTransition {
        projection_bytes,
        proof_digest,
        kind,
    })
}

#[derive(Clone)]
struct Proof {
    id: [u8; 16],
    kind: TransitionKind,
    issued_at: i64,
    not_before: i64,
    expiry: i64,
    verifier_digest: [u8; 32],
    acknowledgement_digest: [u8; 32],
    projection_digest: [u8; 32],
    projection_length: u64,
    binding: Binding,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Binding {
    Bootstrap([u8; 16]),
    Predecessor {
        key: Vec<u8>,
        version_id: Vec<u8>,
        digest: [u8; 32],
        size: u64,
    },
}

fn parse_proof(payload: &[u8]) -> Result<Proof, IdentityError> {
    let mut cursor = cbor::Cursor::new(payload, 7_680)?;
    let count = cursor.map(11, 14)?;
    exact_key(&mut cursor, 1)?;
    exact_uint(&mut cursor, 1, "proof schema")?;
    exact_key(&mut cursor, 2)?;
    let id = uuid_v7(cursor.bytes(16, 16)?, "proof UUID")?;
    exact_key(&mut cursor, 3)?;
    let kind = parse_kind(cursor.uint()?)?;
    exact_key(&mut cursor, 4)?;
    let issued_at = cursor.int()?;
    exact_key(&mut cursor, 5)?;
    let not_before = cursor.int()?;
    exact_key(&mut cursor, 6)?;
    let expiry = cursor.int()?;
    exact_key(&mut cursor, 7)?;
    let verifier_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(&mut cursor, 8)?;
    let acknowledgement_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(&mut cursor, 9)?;
    let projection_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(&mut cursor, 10)?;
    let projection_length = cursor.uint()?;
    if !(1..=65_536).contains(&projection_length) {
        return Err(IdentityError::Transition(
            "projection length is outside bounds",
        ));
    }
    let binding = if kind == TransitionKind::Bootstrap {
        if count != 11 {
            return Err(IdentityError::Transition(
                "bootstrap proof has wrong key set",
            ));
        }
        exact_key(&mut cursor, 15)?;
        Binding::Bootstrap(uuid_v7(cursor.bytes(16, 16)?, "bootstrap session")?)
    } else {
        if count != 14 {
            return Err(IdentityError::Transition(
                "non-bootstrap proof has wrong key set",
            ));
        }
        exact_key(&mut cursor, 11)?;
        let key = ascii(cursor.bytes(1, 1024)?, "predecessor key")?.to_vec();
        exact_key(&mut cursor, 12)?;
        let version_id = cursor.bytes(1, 1024)?.to_vec();
        exact_key(&mut cursor, 13)?;
        let digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
        exact_key(&mut cursor, 14)?;
        let size = cursor.uint()?;
        if !(1..=65_536).contains(&size) {
            return Err(IdentityError::Transition(
                "predecessor size is outside bounds",
            ));
        }
        Binding::Predecessor {
            key,
            version_id,
            digest,
            size,
        }
    };
    cursor.finish()?;
    Ok(Proof {
        id,
        kind,
        issued_at,
        not_before,
        expiry,
        verifier_digest,
        acknowledgement_digest,
        projection_digest,
        projection_length,
        binding,
    })
}

fn validate_proof_time(proof: &Proof, now: i64) -> Result<(), IdentityError> {
    if proof.issued_at > proof.not_before || proof.not_before > proof.expiry {
        return Err(IdentityError::Transition("invalid proof time order"));
    }
    if (proof.expiry as i128) - (proof.issued_at as i128) > 600 {
        return Err(IdentityError::Transition(
            "proof lifetime exceeds ten minutes",
        ));
    }
    let now = now as i128;
    if now < (proof.not_before as i128) - 30 || now > (proof.expiry as i128) + 30 {
        return Err(IdentityError::Transition(
            "proof is outside its validity window",
        ));
    }
    super::validate_uuid_time(&proof.id, proof.issued_at)
        .map_err(|_| IdentityError::Transition("proof UUID timestamp mismatch"))
}

fn validate_binding(request: &TransitionRequest<'_>, proof: &Proof) -> Result<(), IdentityError> {
    match (
        &proof.binding,
        request.predecessor,
        request.bootstrap_session,
    ) {
        (Binding::Bootstrap(actual), None, Some(expected)) if *actual == expected => Ok(()),
        (
            Binding::Predecessor {
                key,
                version_id,
                digest,
                size,
            },
            Some(predecessor),
            None,
        ) => {
            let decoded = decode_credential_control(predecessor.exact_body, request.prefix)
                .map_err(|_| IdentityError::Transition("predecessor body is not strict control"))?;
            if &decoded != predecessor.authority.control() {
                return Err(IdentityError::Transition(
                    "predecessor body differs from bound authority",
                ));
            }
            let parsed = parse_key(request.prefix, predecessor.control_key)
                .map_err(|_| IdentityError::Transition("predecessor key is outside grammar"))?;
            if parsed.kind != V2KeyKind::CredentialControl
                || key != predecessor.control_key
                || version_id != predecessor.object_version_id
                || *size != predecessor.exact_body.len() as u64
                || digest.as_slice() != Sha256::digest(predecessor.exact_body).as_slice()
            {
                return Err(IdentityError::Transition(
                    "predecessor exact-object binding mismatch",
                ));
            }
            Ok(())
        }
        _ => Err(IdentityError::Transition(
            "bootstrap/predecessor binding is not exact",
        )),
    }
}

fn validate_control_shape(
    request: &TransitionRequest<'_>,
    kind: TransitionKind,
) -> Result<(), IdentityError> {
    match (kind, request.predecessor) {
        (TransitionKind::Bootstrap, None) if request.proposed.control().control_revision == 1 => {
            Ok(())
        }
        (TransitionKind::Bootstrap, _) => Err(IdentityError::Transition(
            "bootstrap requires revision one and no predecessor",
        )),
        (_, Some(predecessor)) => {
            let proto_kind = match kind {
                TransitionKind::InstallNext => CredentialTransitionKind::InstallNext,
                TransitionKind::PromoteNext => CredentialTransitionKind::PromoteNext,
                TransitionKind::RetirePrevious => CredentialTransitionKind::RetirePrevious,
                TransitionKind::RevokeKid => CredentialTransitionKind::RevokeKid,
                TransitionKind::VerifierSetUpdate => CredentialTransitionKind::VerifierSetUpdate,
                TransitionKind::AcknowledgementUpdate => {
                    CredentialTransitionKind::AcknowledgementUpdate
                }
                TransitionKind::Bootstrap => unreachable!(),
            };
            validate_credential_control_transition_structure(
                predecessor.authority.control(),
                request.proposed.control(),
                proto_kind,
                request.prefix,
            )
            .map_err(|_| IdentityError::Transition("protobuf transition structure is invalid"))
        }
        _ => Err(IdentityError::Transition(
            "non-bootstrap transition requires predecessor",
        )),
    }
}

#[derive(Clone)]
struct VerifierSet {
    uuid: [u8; 16],
    issued_at: i64,
    epoch: u64,
    members: Vec<VerifierMember>,
}
#[derive(Clone)]
struct VerifierMember {
    id: Vec<u8>,
    roles: u64,
    kid: [u8; 16],
    public_key: [u8; 32],
    epoch: u64,
}

fn parse_verifier_set(root: &PinnedRoot, bytes: &[u8]) -> Result<VerifierSet, IdentityError> {
    let sign1 = cose::Sign1::parse(bytes, 65_536, 65_024)?;
    if sign1.kid != *root.kid() {
        return Err(IdentityError::Transition("verifier-set root kid mismatch"));
    }
    sign1.verify(root.public_key(), VERIFIER_AAD)?;
    let mut cursor = cbor::Cursor::new(sign1.payload, 65_024)?;
    if cursor.map(5, 5)? != 5 {
        return Err(IdentityError::Transition(
            "verifier set must have five keys",
        ));
    }
    exact_key(&mut cursor, 1)?;
    exact_uint(&mut cursor, 1, "verifier schema")?;
    exact_key(&mut cursor, 2)?;
    let uuid = uuid_v7(cursor.bytes(16, 16)?, "verifier-set UUID")?;
    exact_key(&mut cursor, 3)?;
    let issued_at = cursor.int()?;
    exact_key(&mut cursor, 4)?;
    let epoch = positive(cursor.uint()?, "verifier-set epoch")?;
    exact_key(&mut cursor, 5)?;
    let count = cursor.array(1, 64)?;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        members.push(parse_verifier_member(&mut cursor)?);
    }
    cursor.finish()?;
    for pair in members.windows(2) {
        if (&pair[0].id, pair[0].epoch, &pair[0].kid) >= (&pair[1].id, pair[1].epoch, &pair[1].kid)
        {
            return Err(IdentityError::Transition(
                "verifier members are not canonically sorted",
            ));
        }
    }
    let mut ids = HashSet::new();
    let mut kids = HashSet::new();
    let mut public_keys = HashSet::new();
    for member in &members {
        if !ids.insert(member.id.clone())
            || !kids.insert(member.kid)
            || !public_keys.insert(member.public_key)
        {
            return Err(IdentityError::Transition(
                "verifier member identity is duplicated",
            ));
        }
    }
    Ok(VerifierSet {
        uuid,
        issued_at,
        epoch,
        members,
    })
}

fn parse_verifier_member(cursor: &mut cbor::Cursor<'_>) -> Result<VerifierMember, IdentityError> {
    if cursor.map(5, 5)? != 5 {
        return Err(IdentityError::Transition(
            "verifier member must have five keys",
        ));
    }
    exact_key(cursor, 1)?;
    let id = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 2)?;
    let roles = cursor.uint()?;
    if !(1..=15).contains(&roles) {
        return Err(IdentityError::Transition("invalid verifier role mask"));
    }
    exact_key(cursor, 3)?;
    let kid = cursor.bytes(16, 16)?.try_into().expect("length checked");
    exact_key(cursor, 4)?;
    let public_key = cursor.bytes(32, 32)?.try_into().expect("length checked");
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| IdentityError::Transition("invalid acknowledgement public key"))?;
    exact_key(cursor, 5)?;
    let epoch = positive(cursor.uint()?, "membership epoch")?;
    Ok(VerifierMember {
        id,
        roles,
        kid,
        public_key,
        epoch,
    })
}

fn validate_verifier_evolution(
    request: &TransitionRequest<'_>,
    kind: TransitionKind,
    current: &VerifierSet,
    current_bytes: &[u8],
) -> Result<(), IdentityError> {
    if kind == TransitionKind::Bootstrap {
        if current.epoch != 1 {
            return Err(IdentityError::Transition(
                "bootstrap verifier-set epoch must be one",
            ));
        }
        return Ok(());
    }
    let predecessor = request.predecessor.expect("non-bootstrap checked");
    let previous = parse_verifier_set(request.root, predecessor.verifier_set_cose)?;
    let previous_digest = semantic_digest(VERIFIER_DIGEST_DOMAIN, predecessor.verifier_set_cose)?;
    if predecessor.authority.control().verifier_set_digest.as_ref() != previous_digest {
        return Err(IdentityError::Transition(
            "predecessor verifier-set bytes do not match control",
        ));
    }
    if kind == TransitionKind::VerifierSetUpdate {
        if current.epoch
            != previous
                .epoch
                .checked_add(1)
                .ok_or(IdentityError::Transition("verifier-set epoch wraps"))?
            || current.uuid == previous.uuid
        {
            return Err(IdentityError::Transition(
                "verifier-set update is not the next distinct set",
            ));
        }
    } else if current_bytes != predecessor.verifier_set_cose {
        return Err(IdentityError::Transition(
            "transition changed verifier set outside verifier-set-update",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct AckSet {
    verifier_digest: [u8; 32],
    projection_digest: [u8; 32],
    kind: TransitionKind,
    binding: Binding,
    binding_bytes: Vec<u8>,
    rows: Vec<AckRow>,
}
#[derive(Clone)]
struct AckRow {
    id: Vec<u8>,
    epoch: u64,
    roles: u64,
    acknowledged_at: i64,
    last_issued_at: Option<i64>,
    signature: [u8; 64],
}

fn parse_acknowledgement_set(bytes: &[u8], kind: TransitionKind) -> Result<AckSet, IdentityError> {
    let mut cursor = cbor::Cursor::new(bytes, 65_536)?;
    let bootstrap = kind == TransitionKind::Bootstrap;
    let expected_count = if bootstrap { 7 } else { 10 };
    if cursor.map(expected_count, expected_count)? != expected_count {
        return Err(IdentityError::Transition(
            "acknowledgement set has wrong key count",
        ));
    }
    exact_key(&mut cursor, 1)?;
    exact_uint(&mut cursor, 1, "acknowledgement schema")?;
    exact_key(&mut cursor, 2)?;
    let verifier_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(&mut cursor, 3)?;
    let projection_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(&mut cursor, 4)?;
    let parsed_kind = parse_kind(cursor.uint()?)?;
    exact_key(&mut cursor, 5)?;
    let binding_kind = cursor.uint()?;
    let binding = if bootstrap {
        if binding_kind != 1 {
            return Err(IdentityError::Transition(
                "bootstrap acknowledgement binding kind mismatch",
            ));
        }
        exact_key(&mut cursor, 6)?;
        Binding::Bootstrap(uuid_v7(cursor.bytes(16, 16)?, "bootstrap session")?)
    } else {
        if binding_kind != 2 {
            return Err(IdentityError::Transition(
                "predecessor acknowledgement binding kind mismatch",
            ));
        }
        exact_key(&mut cursor, 7)?;
        let key = ascii(cursor.bytes(1, 1024)?, "predecessor key")?.to_vec();
        exact_key(&mut cursor, 8)?;
        let version_id = cursor.bytes(1, 1024)?.to_vec();
        exact_key(&mut cursor, 9)?;
        let digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
        exact_key(&mut cursor, 10)?;
        let size = cursor.uint()?;
        if !(1..=65_536).contains(&size) {
            return Err(IdentityError::Transition(
                "ack predecessor size outside bounds",
            ));
        }
        Binding::Predecessor {
            key,
            version_id,
            digest,
            size,
        }
    };
    exact_key(&mut cursor, 11)?;
    let count = cursor.array(1, 64)?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        rows.push(parse_ack_row(&mut cursor, kind)?);
    }
    cursor.finish()?;
    let binding_bytes = encode_ack_binding(verifier_digest, projection_digest, kind, &binding)?;
    Ok(AckSet {
        verifier_digest,
        projection_digest,
        kind: parsed_kind,
        binding,
        binding_bytes,
        rows,
    })
}

fn parse_ack_row(
    cursor: &mut cbor::Cursor<'_>,
    kind: TransitionKind,
) -> Result<AckRow, IdentityError> {
    let count = cursor.map(5, 6)?;
    exact_key(cursor, 1)?;
    let id = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 2)?;
    let epoch = positive(cursor.uint()?, "ack membership epoch")?;
    exact_key(cursor, 3)?;
    let roles = cursor.uint()?;
    if !(1..=15).contains(&roles) {
        return Err(IdentityError::Transition(
            "invalid acknowledgement role mask",
        ));
    }
    exact_key(cursor, 4)?;
    let acknowledged_at = cursor.int()?;
    let needs_last = kind == TransitionKind::PromoteNext && roles & 4 != 0;
    let last_issued_at = if needs_last {
        if count != 6 {
            return Err(IdentityError::Transition(
                "issuer promotion acknowledgement lacks last-issued-at",
            ));
        }
        exact_key(cursor, 5)?;
        let value = cursor.int()?;
        if value > acknowledged_at {
            return Err(IdentityError::Transition(
                "last-issued-at follows acknowledgement",
            ));
        }
        Some(value)
    } else {
        if count != 5 {
            return Err(IdentityError::Transition("unexpected last-issued-at"));
        }
        None
    };
    exact_key(cursor, 6)?;
    let signature = cursor.bytes(64, 64)?.try_into().expect("length checked");
    Ok(AckRow {
        id,
        epoch,
        roles,
        acknowledged_at,
        last_issued_at,
        signature,
    })
}

pub(crate) fn encode_ack_binding(
    verifier: [u8; 32],
    projection: [u8; 32],
    kind: TransitionKind,
    binding: &Binding,
) -> Result<Vec<u8>, IdentityError> {
    let mut out = Vec::with_capacity(1200);
    let bootstrap = matches!(binding, Binding::Bootstrap(_));
    cbor::map(&mut out, if bootstrap { 6 } else { 9 });
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
    Ok(out)
}
fn encode_unsigned_ack(row: &AckRow) -> Vec<u8> {
    let mut out = Vec::with_capacity(400);
    cbor::map(&mut out, if row.last_issued_at.is_some() { 5 } else { 4 });
    cbor::uint(&mut out, 1);
    cbor::bytes(&mut out, &row.id);
    cbor::uint(&mut out, 2);
    cbor::uint(&mut out, row.epoch);
    cbor::uint(&mut out, 3);
    cbor::uint(&mut out, row.roles);
    cbor::uint(&mut out, 4);
    cbor::int(&mut out, row.acknowledged_at);
    if let Some(value) = row.last_issued_at {
        cbor::uint(&mut out, 5);
        cbor::int(&mut out, value);
    }
    out
}

fn validate_ack_binding(
    request: &TransitionRequest<'_>,
    proof: &Proof,
    ack: &AckSet,
) -> Result<(), IdentityError> {
    if ack.binding != proof.binding {
        return Err(IdentityError::Transition(
            "acknowledgement and proof bindings differ",
        ));
    }
    match (&ack.binding, request.bootstrap_session, request.predecessor) {
        (Binding::Bootstrap(session), Some(expected), None) if *session == expected => Ok(()),
        (Binding::Predecessor { .. }, None, Some(_)) => Ok(()),
        _ => Err(IdentityError::Transition(
            "acknowledgement binding differs from request",
        )),
    }
}

fn verify_acknowledgements(
    verifier: &VerifierSet,
    ack: &AckSet,
    proof: &Proof,
) -> Result<(), IdentityError> {
    if verifier.issued_at > proof.issued_at || ack.rows.len() != verifier.members.len() {
        return Err(IdentityError::Transition(
            "verifier issue time or acknowledgement row count is invalid",
        ));
    }
    for (member, row) in verifier.members.iter().zip(&ack.rows) {
        if member.id != row.id || member.epoch != row.epoch || member.roles != row.roles {
            return Err(IdentityError::Transition(
                "acknowledgement row does not match verifier member",
            ));
        }
        if row.acknowledged_at < proof.not_before
            || row.acknowledged_at > proof.expiry
            || row.acknowledged_at > proof.issued_at
        {
            return Err(IdentityError::Transition(
                "acknowledgement time is outside proof bounds",
            ));
        }
        let unsigned = encode_unsigned_ack(row);
        let mut message = Vec::with_capacity(
            MEMBER_ACK_DOMAIN.len() + 8 + ack.binding_bytes.len() + unsigned.len(),
        );
        message.extend_from_slice(MEMBER_ACK_DOMAIN);
        message.extend_from_slice(&u32_len(ack.binding_bytes.len())?);
        message.extend_from_slice(&ack.binding_bytes);
        message.extend_from_slice(&u32_len(unsigned.len())?);
        message.extend_from_slice(&unsigned);
        let key = VerifyingKey::from_bytes(&member.public_key)
            .map_err(|_| IdentityError::Transition("invalid member public key"))?;
        let signature = Signature::from_bytes(&row.signature);
        key.verify_strict(&message, &signature)
            .map_err(|_| IdentityError::Signature)?;
    }
    Ok(())
}

fn validate_ring_semantics(
    request: &TransitionRequest<'_>,
    kind: TransitionKind,
    ack: &AckSet,
) -> Result<(), IdentityError> {
    if kind == TransitionKind::Bootstrap {
        return Ok(());
    }
    let predecessor = request.predecessor.expect("checked");
    match kind {
        TransitionKind::RetirePrevious => {
            let previous = predecessor
                .authority
                .rings
                .iter()
                .find(|ring| ring.slot == Slot::Previous)
                .ok_or(IdentityError::Transition("retirement lacks previous ring"))?;
            let mut expected: Vec<Vec<u8>> = predecessor
                .authority
                .control()
                .revoked_kids
                .iter()
                .map(|kid| kid.to_vec())
                .collect();
            expected.extend(previous.keys.iter().map(|key| key.kid.to_vec()));
            expected.sort();
            expected.dedup();
            let actual: Vec<Vec<u8>> = request
                .proposed
                .control()
                .revoked_kids
                .iter()
                .map(|kid| kid.to_vec())
                .collect();
            if actual != expected {
                return Err(IdentityError::Transition(
                    "retirement deny set is not the exact previous-ring union",
                ));
            }
            let deadline = (predecessor
                .authority
                .control()
                .previous_last_issue_unix_seconds
                .ok_or(IdentityError::Transition("missing previous last issue"))?
                as i128)
                + 930;
            if (request.now_unix_seconds as i128) < deadline {
                return Err(IdentityError::Transition(
                    "previous ring retired before drain horizon",
                ));
            }
        }
        TransitionKind::RevokeKid => {
            let old = &predecessor.authority.control().revoked_kids;
            let new = &request.proposed.control().revoked_kids;
            let added = new
                .iter()
                .find(|kid| !old.contains(kid))
                .ok_or(IdentityError::Transition("revocation did not add a kid"))?;
            if !predecessor
                .authority
                .rings
                .iter()
                .flat_map(|ring| &ring.keys)
                .any(|key| key.kid.as_slice() == added.as_ref())
            {
                return Err(IdentityError::Transition(
                    "revoked kid is not bound to a ring",
                ));
            }
        }
        TransitionKind::InstallNext => {
            let current = predecessor
                .authority
                .rings
                .iter()
                .find(|ring| ring.slot == Slot::Current)
                .expect("bound authority has current ring");
            let denied = &predecessor.authority.control().revoked_kids;
            let eventual = denied.len()
                + current
                    .keys
                    .iter()
                    .filter(|key| !denied.iter().any(|kid| kid.as_ref() == key.kid))
                    .count();
            if eventual > 64 {
                return Err(IdentityError::Transition(
                    "install would exceed the permanent retirement deny-set bound",
                ));
            }
        }
        TransitionKind::PromoteNext => {
            let old_current = predecessor
                .authority
                .rings
                .iter()
                .find(|ring| ring.slot == Slot::Current)
                .expect("bound authority has current ring");
            if ack
                .rows
                .iter()
                .filter_map(|row| row.last_issued_at)
                .any(|last| last < old_current.issued_at)
            {
                return Err(IdentityError::Transition(
                    "issuer last-issued-at predates the old current ring",
                ));
            }
            let maximum = ack
                .rows
                .iter()
                .filter_map(|row| row.last_issued_at)
                .max()
                .ok_or(IdentityError::Transition(
                    "promotion has no issuer acknowledgement",
                ))?;
            if request.proposed.control().previous_last_issue_unix_seconds != Some(maximum) {
                return Err(IdentityError::Transition(
                    "promotion last-issue time is not the attested maximum",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_kind(value: u64) -> Result<TransitionKind, IdentityError> {
    match value {
        1 => Ok(TransitionKind::Bootstrap),
        2 => Ok(TransitionKind::InstallNext),
        3 => Ok(TransitionKind::PromoteNext),
        4 => Ok(TransitionKind::RetirePrevious),
        5 => Ok(TransitionKind::RevokeKid),
        6 => Ok(TransitionKind::VerifierSetUpdate),
        7 => Ok(TransitionKind::AcknowledgementUpdate),
        _ => Err(IdentityError::Transition("unknown transition kind")),
    }
}
fn semantic_digest(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], IdentityError> {
    let length = u32_len(bytes.len())?;
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update(length)
        .chain_update(bytes)
        .finalize()
        .into())
}
fn u32_len(length: usize) -> Result<[u8; 4], IdentityError> {
    u32::try_from(length)
        .map(u32::to_be_bytes)
        .map_err(|_| IdentityError::Transition("length exceeds u32"))
}

#[cfg(test)]
mod regression_tests {
    use walgit_proto::v2::CredentialControl;

    use super::*;
    use crate::{DataKey, Ring};

    #[test]
    fn promotion_cannot_attest_before_old_ring_issuance() {
        let old = Ring {
            uuid: [1; 16],
            issued_at: 100,
            prior_digest: Vec::new(),
            epoch: 1,
            digest: [2; 32],
            keys: vec![DataKey {
                kid: [3; 16],
                public_key: [4; 32],
                issuer: b"issuer".to_vec(),
                audiences: vec![b"audience".to_vec()],
                not_before: 0,
                not_after: 200,
                state: crate::KeyState::Active,
            }],
            slot: Slot::Current,
        };
        let predecessor = CredentialAuthority {
            control: CredentialControl::default(),
            rings: vec![old],
            prefix: DeploymentPrefix::parse("prod/").unwrap(),
        };
        let proposed_control = CredentialControl {
            previous_last_issue_unix_seconds: Some(99),
            ..CredentialControl::default()
        };
        let proposed = CredentialAuthority {
            control: proposed_control,
            rings: Vec::new(),
            prefix: DeploymentPrefix::parse("prod/").unwrap(),
        };
        let prefix = DeploymentPrefix::parse("prod/").unwrap();
        let root = PinnedRoot {
            public_key: [0; 32],
            kid: [0; 16],
        };
        let request = TransitionRequest {
            root: &root,
            prefix: &prefix,
            proposed: &proposed,
            predecessor: Some(CredentialPredecessor {
                authority: &predecessor,
                control_key: b"key",
                object_version_id: b"version",
                exact_body: b"body",
                verifier_set_cose: b"set",
            }),
            bootstrap_session: None,
            evidence: TransitionEvidence {
                verifier_set_cose: b"",
                acknowledgement_set: b"",
                transition_proof_cose: b"",
            },
            now_unix_seconds: 100,
        };
        let ack = AckSet {
            verifier_digest: [0; 32],
            projection_digest: [0; 32],
            kind: TransitionKind::PromoteNext,
            binding: Binding::Bootstrap([0; 16]),
            binding_bytes: Vec::new(),
            rows: vec![AckRow {
                id: b"issuer".to_vec(),
                epoch: 1,
                roles: 4,
                acknowledged_at: 100,
                last_issued_at: Some(99),
                signature: [0; 64],
            }],
        };
        assert_eq!(
            validate_ring_semantics(&request, TransitionKind::PromoteNext, &ack),
            Err(IdentityError::Transition(
                "issuer last-issued-at predates the old current ring"
            ))
        );
    }
}

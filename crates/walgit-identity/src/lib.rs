//! Dormant V2 credential verification.
//!
//! This crate performs pure, bounded verification. It has no storage, network,
//! configuration, server, or runtime integration. In particular, successful
//! capability authentication is not repository authorization.

mod cbor;
mod cose;
mod transition;

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use thiserror::Error;
use walgit_proto::v2::{
    CredentialControl, VerificationRingRoot,
    keys::{DeploymentPrefix, RoutingDigest, V2KeyKind, parse_key, repo_control_key},
    validate_credential_control,
};

const ROOT_KID_DOMAIN: &[u8] = b"walgit-ed25519-root-kid-v1";
const RING_AAD: &[u8] = b"walgit-verification-key-ring-v1";
const CREATE_AAD: &[u8] = b"walgit-create-intent-v1";
const CAPABILITY_AAD: &[u8] = b"walgit-capability-v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("input has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid deterministic CBOR: {0}")]
    Cbor(&'static str),
    #[error("invalid COSE_Sign1: {0}")]
    Cose(&'static str),
    #[error("strict Ed25519 verification failed")]
    Signature,
    #[error("claim validation failed: {0}")]
    Claim(&'static str),
    #[error("credential authority binding failed: {0}")]
    Authority(&'static str),
    #[error("credential transition validation failed: {0}")]
    Transition(&'static str),
    #[error("credential-control validation failed")]
    Control,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedRoot {
    public_key: [u8; 32],
    kid: [u8; 16],
}

impl PinnedRoot {
    pub fn new(public_key: [u8; 32], expected_kid: [u8; 16]) -> Result<Self, IdentityError> {
        let digest = Sha256::new()
            .chain_update(ROOT_KID_DOMAIN)
            .chain_update(public_key)
            .finalize();
        if digest[..16] != expected_kid {
            return Err(IdentityError::Authority(
                "root kid does not match pinned public key",
            ));
        }
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| IdentityError::Authority("invalid root public key"))?;
        Ok(Self {
            public_key,
            kid: expected_kid,
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn kid(&self) -> &[u8; 16] {
        &self.kid
    }
}

#[derive(Clone, Copy)]
pub struct ExactRingObject<'a> {
    pub key: &'a [u8],
    pub object_version_id: &'a [u8],
    pub body: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct BoundRingObjects<'a> {
    pub current: ExactRingObject<'a>,
    pub next: Option<ExactRingObject<'a>>,
    pub previous: Option<ExactRingObject<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Current,
    Next,
    Previous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyState {
    Pending,
    Active,
    Retiring,
    Revoked,
}

#[derive(Clone, Debug)]
struct DataKey {
    kid: [u8; 16],
    public_key: [u8; 32],
    issuer: Vec<u8>,
    audiences: Vec<Vec<u8>>,
    not_before: i64,
    not_after: i64,
    state: KeyState,
}

#[derive(Clone, Debug)]
struct Ring {
    uuid: [u8; 16],
    issued_at: i64,
    prior_digest: Vec<u8>,
    epoch: u64,
    digest: [u8; 32],
    keys: Vec<DataKey>,
    slot: Slot,
}

/// A control and the exact immutable rings it roots.
///
/// Construction verifies complete root tuples, pinned-root signatures,
/// lineage visible in the bound slots, key ordering, and the slot/state/deny
/// matrix used by the envelope-specific methods below.
pub struct CredentialAuthority {
    control: CredentialControl,
    rings: Vec<Ring>,
    prefix: DeploymentPrefix,
    root: PinnedRoot,
}

impl CredentialAuthority {
    pub fn bind(
        root: &PinnedRoot,
        control: &CredentialControl,
        prefix: &DeploymentPrefix,
        objects: BoundRingObjects<'_>,
    ) -> Result<Self, IdentityError> {
        validate_credential_control(control, prefix).map_err(|_| IdentityError::Control)?;
        if objects.next.is_some() != control.next.is_some()
            || objects.previous.is_some() != control.previous.is_some()
        {
            return Err(IdentityError::Authority(
                "ring object presence does not match control slots",
            ));
        }
        let mut rings = Vec::with_capacity(3);
        rings.push(bind_ring(
            root,
            control.current.as_ref().expect("validated"),
            objects.current,
            Slot::Current,
            prefix,
        )?);
        if let (Some(expected), Some(object)) = (&control.next, objects.next) {
            rings.push(bind_ring(root, expected, object, Slot::Next, prefix)?);
        }
        if let (Some(expected), Some(object)) = (&control.previous, objects.previous) {
            rings.push(bind_ring(root, expected, object, Slot::Previous, prefix)?);
        }
        validate_bound_rings(control, &rings)?;
        Ok(Self {
            control: control.clone(),
            rings,
            prefix: prefix.clone(),
            root: *root,
        })
    }

    pub fn control(&self) -> &CredentialControl {
        &self.control
    }

    pub fn verify_create_intent(
        &self,
        envelope: &[u8],
        now_unix_seconds: i64,
        expected: &ExpectedCreateIntent<'_>,
    ) -> Result<VerifiedCreateIntent, IdentityError> {
        let sign1 = cose::Sign1::parse(envelope, 8_192, 7_680)?;
        let claims = parse_create(sign1.payload)?;
        self.validate_control_key(&claims.common, &claims.control_key)?;
        let key = self.verifying_key(&sign1.kid, &claims.common, now_unix_seconds, 600)?;
        sign1.verify(&key, CREATE_AAD)?;
        claims.matches(expected)?;
        Ok(VerifiedCreateIntent { claims })
    }

    pub fn authenticate_capability(
        &self,
        envelope: &[u8],
        now_unix_seconds: i64,
        expected: &ExpectedCapability<'_>,
    ) -> Result<AuthenticatedCapability, IdentityError> {
        let sign1 = cose::Sign1::parse(envelope, 8_192, 7_680)?;
        let claims = parse_capability(sign1.payload)?;
        self.validate_control_key(&claims.common, &claims.control_key)?;
        let key = self.verifying_key(&sign1.kid, &claims.common, now_unix_seconds, 900)?;
        sign1.verify(&key, CAPABILITY_AAD)?;
        claims.matches(expected)?;
        Ok(AuthenticatedCapability { claims })
    }

    fn verifying_key(
        &self,
        kid: &[u8; 16],
        claims: &CommonClaims,
        now: i64,
        max_lifetime: i64,
    ) -> Result<[u8; 32], IdentityError> {
        validate_envelope_time(claims, now, max_lifetime)?;
        let mut selected = None;
        for ring in &self.rings {
            for key in &ring.keys {
                if &key.kid != kid {
                    continue;
                }
                if self
                    .control
                    .revoked_kids
                    .iter()
                    .any(|denied| denied.as_ref() == kid)
                {
                    return Err(IdentityError::Authority("signing kid is globally revoked"));
                }
                let slot_allows = matches!(
                    (ring.slot, key.state),
                    (Slot::Current, KeyState::Active | KeyState::Retiring)
                        | (Slot::Next, KeyState::Active)
                        | (Slot::Previous, KeyState::Active | KeyState::Retiring)
                );
                if !slot_allows {
                    return Err(IdentityError::Authority(
                        "slot and state do not permit verification",
                    ));
                }
                if claims.ring_epoch != ring.epoch || claims.ring_digest != ring.digest {
                    return Err(IdentityError::Authority(
                        "envelope does not bind the selected ring root",
                    ));
                }
                if ring.slot == Slot::Previous
                    && claims.issued_at
                        > self
                            .control
                            .previous_last_issue_unix_seconds
                            .expect("validated previous cutoff")
                {
                    return Err(IdentityError::Authority(
                        "envelope was issued after the previous-ring cutoff",
                    ));
                }
                if claims.issued_at < key.not_before || claims.issued_at > key.not_after {
                    return Err(IdentityError::Authority(
                        "envelope issued-at is outside data-key validity",
                    ));
                }
                if claims.issuer != key.issuer
                    || !key
                        .audiences
                        .iter()
                        .any(|audience| audience == &claims.audience)
                {
                    return Err(IdentityError::Authority(
                        "issuer or audience is not bound to signing key",
                    ));
                }
                if selected.replace(key.public_key).is_some() {
                    return Err(IdentityError::Authority("kid resolves more than once"));
                }
            }
        }
        selected.ok_or(IdentityError::Authority(
            "kid is not an eligible bound current key",
        ))
    }

    fn validate_control_key(
        &self,
        claims: &CommonClaims,
        actual: &[u8],
    ) -> Result<(), IdentityError> {
        let expected = repo_control_key(
            &self.prefix,
            RoutingDigest::from_bytes(claims.routing_digest),
        )
        .map_err(|_| IdentityError::Claim("derived control key is outside bounds"))?;
        if actual != expected.as_bytes() {
            return Err(IdentityError::Claim(
                "control key is not derived from the routing digest",
            ));
        }
        Ok(())
    }
}

fn bind_ring(
    root: &PinnedRoot,
    expected: &VerificationRingRoot,
    object: ExactRingObject<'_>,
    slot: Slot,
    prefix: &DeploymentPrefix,
) -> Result<Ring, IdentityError> {
    if object.key != expected.key.as_ref()
        || object.object_version_id != expected.object_version_id.as_ref()
        || object.body.len() as u64 != expected.size
        || Sha256::digest(object.body).as_slice() != expected.digest.as_ref()
    {
        return Err(IdentityError::Authority(
            "exact ring object does not match its five-field root",
        ));
    }
    let parsed = parse_key(prefix, object.key)
        .map_err(|_| IdentityError::Authority("ring key is outside the physical grammar"))?;
    if parsed.kind != V2KeyKind::VerificationKeyRing {
        return Err(IdentityError::Authority(
            "object is not a verification-ring key",
        ));
    }
    let sign1 = cose::Sign1::parse(object.body, 65_536, 65_536)?;
    if sign1.kid != root.kid {
        return Err(IdentityError::Authority(
            "ring root kid differs from pinned root",
        ));
    }
    sign1.verify(&root.public_key, RING_AAD)?;
    let mut ring = parse_ring(sign1.payload)?;
    if ring.epoch != expected.ring_epoch {
        return Err(IdentityError::Authority(
            "ring payload epoch differs from rooted epoch",
        ));
    }
    ring.digest = expected
        .digest
        .as_ref()
        .try_into()
        .expect("validated digest length");
    ring.slot = slot;
    Ok(ring)
}

fn parse_ring(payload: &[u8]) -> Result<Ring, IdentityError> {
    let mut cursor = cbor::Cursor::new(payload, 65_536)?;
    if cursor.map(6, 6)? != 6 {
        return Err(IdentityError::Claim("ring map must have six keys"));
    }
    exact_key(&mut cursor, 1)?;
    exact_uint(&mut cursor, 1, "ring schema")?;
    exact_key(&mut cursor, 2)?;
    let uuid = uuid_v7(cursor.bytes(16, 16)?, "ring UUID")?;
    exact_key(&mut cursor, 3)?;
    let issued_at = cursor.int()?;
    exact_key(&mut cursor, 4)?;
    let prior_digest = cursor.bytes(0, 32)?.to_vec();
    exact_key(&mut cursor, 5)?;
    let count = cursor.array(1, 64)?;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        keys.push(parse_data_key(&mut cursor)?);
    }
    exact_key(&mut cursor, 6)?;
    let epoch = positive(cursor.uint()?, "ring epoch")?;
    cursor.finish()?;
    if keys.windows(2).any(|pair| pair[0].kid >= pair[1].kid) {
        return Err(IdentityError::Claim("ring kids must be sorted and unique"));
    }
    if epoch == 1 {
        if !prior_digest.is_empty() {
            return Err(IdentityError::Claim(
                "bootstrap ring prior digest must be empty",
            ));
        }
    } else if prior_digest.len() != 32 {
        return Err(IdentityError::Claim(
            "non-bootstrap ring prior digest must be 32 bytes",
        ));
    }
    Ok(Ring {
        uuid,
        issued_at,
        prior_digest,
        epoch,
        digest: [0; 32],
        keys,
        slot: Slot::Current,
    })
}

fn parse_data_key(cursor: &mut cbor::Cursor<'_>) -> Result<DataKey, IdentityError> {
    if cursor.map(7, 7)? != 7 {
        return Err(IdentityError::Claim("data-key map must have seven keys"));
    }
    exact_key(cursor, 1)?;
    let kid = cursor.bytes(16, 16)?.try_into().expect("length checked");
    exact_key(cursor, 2)?;
    let public_key = cursor.bytes(32, 32)?.try_into().expect("length checked");
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| IdentityError::Claim("invalid data public key"))?;
    exact_key(cursor, 3)?;
    let issuer = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 4)?;
    let count = cursor.array(0, 16)?;
    let mut audiences = Vec::with_capacity(count);
    for _ in 0..count {
        audiences.push(cursor.bytes(1, 256)?.to_vec());
    }
    if audiences.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(IdentityError::Claim("audiences must be sorted and unique"));
    }
    exact_key(cursor, 5)?;
    let not_before = cursor.int()?;
    exact_key(cursor, 6)?;
    let not_after = cursor.int()?;
    if not_before > not_after {
        return Err(IdentityError::Claim(
            "data-key not-before exceeds not-after",
        ));
    }
    exact_key(cursor, 7)?;
    let state = match cursor.uint()? {
        1 => KeyState::Pending,
        2 => KeyState::Active,
        3 => KeyState::Retiring,
        4 => KeyState::Revoked,
        _ => return Err(IdentityError::Claim("unknown data-key state")),
    };
    Ok(DataKey {
        kid,
        public_key,
        issuer,
        audiences,
        not_before,
        not_after,
        state,
    })
}

fn validate_bound_rings(control: &CredentialControl, rings: &[Ring]) -> Result<(), IdentityError> {
    let mut uuids = HashSet::new();
    let mut kids = HashSet::new();
    let mut public_keys = HashSet::new();
    for ring in rings {
        if !uuids.insert(ring.uuid) {
            return Err(IdentityError::Authority(
                "ring UUID is reused across bound slots",
            ));
        }
        for key in &ring.keys {
            if !kids.insert(key.kid) || !public_keys.insert(key.public_key) {
                return Err(IdentityError::Authority(
                    "data-key identity is reused across bound slots",
                ));
            }
            if ring.slot == Slot::Next
                && control
                    .revoked_kids
                    .iter()
                    .any(|denied| denied.as_ref() == key.kid)
            {
                return Err(IdentityError::Authority(
                    "next ring reuses a globally revoked kid",
                ));
            }
        }
    }
    let current = rings
        .iter()
        .find(|ring| ring.slot == Slot::Current)
        .expect("current bound");
    if current.epoch == 1 && !current.keys.iter().any(|key| key.state == KeyState::Active) {
        return Err(IdentityError::Authority(
            "bootstrap ring requires an active data key",
        ));
    }
    if let Some(next) = rings.iter().find(|ring| ring.slot == Slot::Next)
        && (next.epoch
            != current
                .epoch
                .checked_add(1)
                .ok_or(IdentityError::Authority("ring epoch wraps"))?
            || next.prior_digest.as_slice()
                != control.current.as_ref().expect("validated").digest.as_ref())
    {
        return Err(IdentityError::Authority(
            "next ring is not the exact current descendant",
        ));
    }
    if let Some(previous) = rings.iter().find(|ring| ring.slot == Slot::Previous)
        && (current.epoch
            != previous
                .epoch
                .checked_add(1)
                .ok_or(IdentityError::Authority("ring epoch wraps"))?
            || current.prior_digest.as_slice()
                != control
                    .previous
                    .as_ref()
                    .expect("validated")
                    .digest
                    .as_ref())
    {
        return Err(IdentityError::Authority(
            "current ring does not descend from previous",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommonClaims {
    issuer: Vec<u8>,
    audience: Vec<u8>,
    id: [u8; 16],
    issued_at: i64,
    not_before: i64,
    expiry: i64,
    tenant_id: Vec<u8>,
    project_id: Vec<u8>,
    repository_uuid: [u8; 16],
    generation: u64,
    canonical_path: Vec<u8>,
    canonical_path_digest: [u8; 32],
    ring_epoch: u64,
    ring_digest: [u8; 32],
    routing_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CreateClaims {
    common: CommonClaims,
    object_format: u64,
    visibility: u64,
    quota: u64,
    admin_issuer: Vec<u8>,
    admin_subject: Vec<u8>,
    cutover_generation: u64,
    control_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapabilityClaims {
    common: CommonClaims,
    purpose: CapabilityPurpose,
    authorization_epoch: u64,
    control_key: Vec<u8>,
    control_version_id: Vec<u8>,
    cutover_generation: u64,
    grant_issuer: Vec<u8>,
    grant_subject: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum CapabilityPurpose {
    CloneRead = 1,
    GitRead = 2,
    GitWrite = 3,
    LfsRead = 4,
    LfsFinalize = 5,
    WebhookAdmin = 6,
    ServiceBuild = 7,
    RepositoryAdmin = 8,
}

#[derive(Clone, Copy)]
pub struct ExpectedCommonClaims<'a> {
    pub issuer: &'a [u8],
    pub audience: &'a [u8],
    pub id: [u8; 16],
    pub tenant_id: &'a [u8],
    pub project_id: &'a [u8],
    pub repository_uuid: [u8; 16],
    pub canonical_path: &'a [u8],
    pub ring_epoch: u64,
    pub ring_digest: [u8; 32],
    pub routing_digest: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct ExpectedCreateIntent<'a> {
    pub common: ExpectedCommonClaims<'a>,
    pub object_format: u64,
    pub visibility: u64,
    pub quota: u64,
    pub admin_issuer: &'a [u8],
    pub admin_subject: &'a [u8],
    pub cutover_generation: u64,
    pub control_key: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct ExpectedCapability<'a> {
    pub common: ExpectedCommonClaims<'a>,
    pub purpose: CapabilityPurpose,
    pub authorization_epoch: u64,
    pub control_key: &'a [u8],
    pub control_version_id: &'a [u8],
    pub cutover_generation: u64,
    pub grant_issuer: &'a [u8],
    pub grant_subject: &'a [u8],
}

pub struct VerifiedCreateIntent {
    claims: CreateClaims,
}
impl VerifiedCreateIntent {
    pub fn intent_id(&self) -> &[u8; 16] {
        &self.claims.common.id
    }
}

/// Cryptographic authentication only. The caller must reread repository
/// control and enforce the exact grant, role, authorization epoch, lifecycle,
/// visibility, purpose, and CAS-version rules before allowing any operation.
pub struct AuthenticatedCapability {
    claims: CapabilityClaims,
}
impl AuthenticatedCapability {
    pub fn token_id(&self) -> &[u8; 16] {
        &self.claims.common.id
    }
    pub fn purpose(&self) -> CapabilityPurpose {
        self.claims.purpose
    }
    pub fn authorization_epoch(&self) -> u64 {
        self.claims.authorization_epoch
    }
    pub fn grant(&self) -> (&[u8], &[u8]) {
        (&self.claims.grant_issuer, &self.claims.grant_subject)
    }
}

fn parse_common(
    cursor: &mut cbor::Cursor<'_>,
    expected_type: u64,
) -> Result<CommonClaims, IdentityError> {
    exact_key(cursor, 1)?;
    exact_uint(cursor, 1, "schema version")?;
    exact_key(cursor, 2)?;
    exact_uint(cursor, expected_type, "envelope type")?;
    exact_key(cursor, 3)?;
    let issuer = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 4)?;
    let audience = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 5)?;
    let id = uuid_v7(cursor.bytes(16, 16)?, "intent/token UUID")?;
    exact_key(cursor, 6)?;
    let issued_at = cursor.int()?;
    exact_key(cursor, 7)?;
    let not_before = cursor.int()?;
    exact_key(cursor, 8)?;
    let expiry = cursor.int()?;
    exact_key(cursor, 9)?;
    let tenant_id = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 10)?;
    let project_id = cursor.bytes(1, 256)?.to_vec();
    exact_key(cursor, 11)?;
    let repository_uuid = cursor.bytes(16, 16)?.try_into().expect("length checked");
    exact_key(cursor, 12)?;
    let generation = cursor.uint()?;
    if generation != 1 {
        return Err(IdentityError::Claim("generation must be one"));
    }
    exact_key(cursor, 13)?;
    let canonical_path = cursor.bytes(1, 1024)?.to_vec();
    exact_key(cursor, 14)?;
    let canonical_path_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(cursor, 15)?;
    let ring_epoch = positive(cursor.uint()?, "ring epoch")?;
    exact_key(cursor, 16)?;
    let ring_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    exact_key(cursor, 17)?;
    let routing_digest = cursor.bytes(32, 32)?.try_into().expect("length checked");
    if Sha256::digest(&canonical_path).as_slice() != canonical_path_digest {
        return Err(IdentityError::Claim("canonical path digest mismatch"));
    }
    let mut routing = Sha256::new();
    routing.update(b"walgit-repo-path-v1");
    routing.update((canonical_path.len() as u32).to_be_bytes());
    routing.update(&canonical_path);
    if routing.finalize().as_slice() != routing_digest {
        return Err(IdentityError::Claim("routing digest mismatch"));
    }
    validate_uuid_time(&id, issued_at)?;
    Ok(CommonClaims {
        issuer,
        audience,
        id,
        issued_at,
        not_before,
        expiry,
        tenant_id,
        project_id,
        repository_uuid,
        generation,
        canonical_path,
        canonical_path_digest,
        ring_epoch,
        ring_digest,
        routing_digest,
    })
}

fn parse_create(payload: &[u8]) -> Result<CreateClaims, IdentityError> {
    let mut cursor = cbor::Cursor::new(payload, 7680)?;
    if cursor.map(24, 24)? != 24 {
        return Err(IdentityError::Claim("create map must have 24 keys"));
    }
    let common = parse_common(&mut cursor, 1)?;
    exact_key(&mut cursor, 20)?;
    let object_format = cursor.uint()?;
    if !(1..=2).contains(&object_format) {
        return Err(IdentityError::Claim("unknown object format"));
    }
    exact_key(&mut cursor, 21)?;
    let visibility = cursor.uint()?;
    if !(1..=3).contains(&visibility) {
        return Err(IdentityError::Claim("unknown visibility"));
    }
    exact_key(&mut cursor, 22)?;
    let quota = positive(cursor.uint()?, "quota")?;
    exact_key(&mut cursor, 23)?;
    let admin_issuer = cursor.bytes(1, 256)?.to_vec();
    exact_key(&mut cursor, 24)?;
    let admin_subject = cursor.bytes(1, 256)?.to_vec();
    exact_key(&mut cursor, 25)?;
    let cutover_generation = cursor.uint()?;
    exact_key(&mut cursor, 26)?;
    let control_key = ascii(cursor.bytes(1, 1024)?, "control key")?.to_vec();
    cursor.finish()?;
    Ok(CreateClaims {
        common,
        object_format,
        visibility,
        quota,
        admin_issuer,
        admin_subject,
        cutover_generation,
        control_key,
    })
}

fn parse_capability(payload: &[u8]) -> Result<CapabilityClaims, IdentityError> {
    let mut cursor = cbor::Cursor::new(payload, 7680)?;
    if cursor.map(24, 24)? != 24 {
        return Err(IdentityError::Claim("capability map must have 24 keys"));
    }
    let common = parse_common(&mut cursor, 2)?;
    exact_key(&mut cursor, 30)?;
    let purpose = match cursor.uint()? {
        1 => CapabilityPurpose::CloneRead,
        2 => CapabilityPurpose::GitRead,
        3 => CapabilityPurpose::GitWrite,
        4 => CapabilityPurpose::LfsRead,
        5 => CapabilityPurpose::LfsFinalize,
        6 => CapabilityPurpose::WebhookAdmin,
        7 => CapabilityPurpose::ServiceBuild,
        8 => CapabilityPurpose::RepositoryAdmin,
        _ => return Err(IdentityError::Claim("unknown capability purpose")),
    };
    exact_key(&mut cursor, 31)?;
    let authorization_epoch = cursor.uint()?;
    exact_key(&mut cursor, 32)?;
    let control_key = ascii(cursor.bytes(1, 1024)?, "control key")?.to_vec();
    exact_key(&mut cursor, 33)?;
    let control_version_id = cursor.bytes(1, 1024)?.to_vec();
    exact_key(&mut cursor, 34)?;
    let cutover_generation = cursor.uint()?;
    exact_key(&mut cursor, 35)?;
    let grant_issuer = cursor.bytes(1, 256)?.to_vec();
    exact_key(&mut cursor, 36)?;
    let grant_subject = cursor.bytes(1, 256)?.to_vec();
    cursor.finish()?;
    Ok(CapabilityClaims {
        common,
        purpose,
        authorization_epoch,
        control_key,
        control_version_id,
        cutover_generation,
        grant_issuer,
        grant_subject,
    })
}

impl CommonClaims {
    fn matches(&self, expected: &ExpectedCommonClaims<'_>) -> Result<(), IdentityError> {
        if self.issuer != expected.issuer
            || self.audience != expected.audience
            || self.id != expected.id
            || self.tenant_id != expected.tenant_id
            || self.project_id != expected.project_id
            || self.repository_uuid != expected.repository_uuid
            || self.generation != 1
            || self.canonical_path != expected.canonical_path
            || self.ring_epoch != expected.ring_epoch
            || self.ring_digest != expected.ring_digest
            || self.routing_digest != expected.routing_digest
        {
            return Err(IdentityError::Claim(
                "common claims differ from expected values",
            ));
        }
        Ok(())
    }
}
impl CreateClaims {
    fn matches(&self, e: &ExpectedCreateIntent<'_>) -> Result<(), IdentityError> {
        self.common.matches(&e.common)?;
        if self.object_format != e.object_format
            || self.visibility != e.visibility
            || self.quota != e.quota
            || self.admin_issuer != e.admin_issuer
            || self.admin_subject != e.admin_subject
            || self.cutover_generation != e.cutover_generation
            || self.control_key != e.control_key
        {
            return Err(IdentityError::Claim(
                "create claims differ from expected values",
            ));
        }
        Ok(())
    }
}
impl CapabilityClaims {
    fn matches(&self, e: &ExpectedCapability<'_>) -> Result<(), IdentityError> {
        self.common.matches(&e.common)?;
        if self.purpose != e.purpose
            || self.authorization_epoch != e.authorization_epoch
            || self.control_key != e.control_key
            || self.control_version_id != e.control_version_id
            || self.cutover_generation != e.cutover_generation
            || self.grant_issuer != e.grant_issuer
            || self.grant_subject != e.grant_subject
        {
            return Err(IdentityError::Claim(
                "capability claims differ from expected values",
            ));
        }
        Ok(())
    }
}

fn validate_envelope_time(
    claims: &CommonClaims,
    now: i64,
    max_lifetime: i64,
) -> Result<(), IdentityError> {
    if claims.issued_at > claims.not_before || claims.not_before > claims.expiry {
        return Err(IdentityError::Claim(
            "invalid issued-at/not-before/expiry order",
        ));
    }
    let lifetime = (claims.expiry as i128) - (claims.issued_at as i128);
    if lifetime > max_lifetime as i128 {
        return Err(IdentityError::Claim("envelope lifetime exceeds maximum"));
    }
    let now = now as i128;
    if now < (claims.not_before as i128) - 30 || now > (claims.expiry as i128) + 30 {
        return Err(IdentityError::Claim(
            "envelope is outside its validity window",
        ));
    }
    Ok(())
}
fn validate_uuid_time(uuid: &[u8; 16], issued_at: i64) -> Result<(), IdentityError> {
    let millis = u64::from_be_bytes([0, 0, uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5]]);
    let issued_millis = (issued_at as i128) * 1000;
    if ((millis as i128) - issued_millis).abs() > 30_000 {
        return Err(IdentityError::Claim(
            "UUIDv7 timestamp differs from issued-at",
        ));
    }
    Ok(())
}
fn uuid_v7(bytes: &[u8], field: &'static str) -> Result<[u8; 16], IdentityError> {
    let value: [u8; 16] = bytes.try_into().map_err(|_| IdentityError::Claim(field))?;
    if value[6] >> 4 != 7 || value[8] & 0xc0 != 0x80 {
        return Err(IdentityError::Claim("invalid UUIDv7"));
    }
    Ok(value)
}
fn exact_key(cursor: &mut cbor::Cursor<'_>, expected: u64) -> Result<(), IdentityError> {
    if cursor.uint()? != expected {
        return Err(IdentityError::Cbor(
            "unknown, missing, or reordered map key",
        ));
    }
    Ok(())
}
fn exact_uint(
    cursor: &mut cbor::Cursor<'_>,
    expected: u64,
    field: &'static str,
) -> Result<(), IdentityError> {
    if cursor.uint()? != expected {
        return Err(IdentityError::Claim(field));
    }
    Ok(())
}
fn positive(value: u64, field: &'static str) -> Result<u64, IdentityError> {
    if value == 0 {
        Err(IdentityError::Claim(field))
    } else {
        Ok(value)
    }
}
fn ascii<'a>(value: &'a [u8], field: &'static str) -> Result<&'a [u8], IdentityError> {
    if value.is_ascii() {
        Ok(value)
    } else {
        Err(IdentityError::Claim(field))
    }
}

pub use transition::{
    CredentialPredecessor, TransitionEvidence, TransitionKind, TransitionRequest,
    VerifiedCredentialTransition, verify_credential_transition,
};

#[cfg(test)]
mod tests;

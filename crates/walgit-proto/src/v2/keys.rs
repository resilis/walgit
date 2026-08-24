//! Closed V2 object-key grammar and repository path digests.

use sha2::{Digest, Sha256};

use super::{CatalogKind, digests::StoredDigestKind};

const ROUTING_DOMAIN: &[u8] = b"walgit-repo-path-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalPathDigest([u8; 32]);

impl CanonicalPathDigest {
    pub fn of(canonical_path: &[u8]) -> Self {
        Self(Sha256::digest(canonical_path).into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn lower_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoutingDigest([u8; 32]);

impl RoutingDigest {
    pub fn of(canonical_path: &[u8]) -> Result<Self, KeyError> {
        let len =
            u32::try_from(canonical_path.len()).map_err(|_| KeyError::CanonicalPathTooLong)?;
        let mut hash = Sha256::new();
        hash.update(ROUTING_DOMAIN);
        hash.update(len.to_be_bytes());
        hash.update(canonical_path);
        Ok(Self(hash.finalize().into()))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn lower_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentPrefix(String);

impl DeploymentPrefix {
    pub fn parse(prefix: impl Into<String>) -> Result<Self, KeyError> {
        let prefix = prefix.into();
        validate_deployment_prefix(&prefix)?;
        Ok(Self(prefix))
    }

    pub fn empty() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn apply(&self, suffix: &str) -> Result<String, KeyError> {
        let key = format!("{}{suffix}", self.0);
        if key.len() > 1024 {
            return Err(KeyError::KeyTooLong);
        }
        Ok(key)
    }
}

impl Default for DeploymentPrefix {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryKeyIdentity {
    pub repository_uuid: [u8; 16],
    pub generation: u64,
}

impl RepositoryKeyIdentity {
    pub fn root(&self, prefix: &DeploymentPrefix) -> Result<String, KeyError> {
        if self.generation != 1 {
            return Err(KeyError::InvalidGeneration);
        }
        prefix.apply(&format!(
            "v2/repositories/by-id/{}/g{:016x}/",
            hex::encode(self.repository_uuid),
            self.generation
        ))
    }
}

pub fn repo_control_key(
    prefix: &DeploymentPrefix,
    routing_digest: RoutingDigest,
) -> Result<String, KeyError> {
    prefix.apply(&format!(
        "v2/repositories/by-path/{}/repo_control.pb",
        routing_digest.lower_hex()
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2KeyKind {
    RepoControl,
    Catalog(CatalogKind),
    ReceiptResult,
    EventResult,
    EventArchive,
    EventArchiveWatermark,
    Checkpoint,
    RecoveryJournal,
    RecoveryMapping,
    RecoveryCatalog,
    RecoveryPayloadReference,
    GitPack,
    LfsObject,
    Bundle,
    TemporaryGitPackUpload,
    TemporaryLfsUpload,
    TemporaryBundleUpload,
    TemporaryCatalogCandidate,
    TemporaryRecoveryCopy,
    CutoverControl,
    CredentialControl,
    BucketAdminControl,
    VerificationKeyRing,
    CapacityControl,
    TenantCapacityCatalog,
    CapacityShard,
    RecoveryControl,
    WriterLease,
    HostByPath,
    HostByIdentity,
}

impl V2KeyKind {
    /// Select the exact stored-byte digest contract for this closed key kind.
    pub fn digest_kind(self) -> StoredDigestKind {
        match self {
            Self::GitPack
            | Self::LfsObject
            | Self::Bundle
            | Self::TemporaryGitPackUpload
            | Self::TemporaryLfsUpload
            | Self::TemporaryBundleUpload
            | Self::TemporaryRecoveryCopy => StoredDigestKind::RawPayload,
            Self::VerificationKeyRing => StoredDigestKind::VerificationRing,
            Self::RepoControl
            | Self::Catalog(_)
            | Self::ReceiptResult
            | Self::EventResult
            | Self::EventArchive
            | Self::EventArchiveWatermark
            | Self::Checkpoint
            | Self::RecoveryJournal
            | Self::RecoveryMapping
            | Self::RecoveryCatalog
            | Self::RecoveryPayloadReference
            | Self::TemporaryCatalogCandidate
            | Self::CutoverControl
            | Self::CredentialControl
            | Self::BucketAdminControl
            | Self::CapacityControl
            | Self::TenantCapacityCatalog
            | Self::CapacityShard
            | Self::RecoveryControl
            | Self::WriterLease
            | Self::HostByPath
            | Self::HostByIdentity => StoredDigestKind::ProtobufObject,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedV2Key {
    pub kind: V2KeyKind,
    pub repository: Option<RepositoryKeyIdentity>,
}

pub fn parse_key(prefix: &DeploymentPrefix, key: &[u8]) -> Result<ParsedV2Key, KeyError> {
    if key.is_empty() || key.len() > 1024 || !key.is_ascii() {
        return Err(KeyError::InvalidKey);
    }
    let key = std::str::from_utf8(key).map_err(|_| KeyError::InvalidKey)?;
    let suffix = key
        .strip_prefix(prefix.as_str())
        .ok_or(KeyError::WrongPrefix)?;
    if suffix.is_empty() || suffix.contains("//") {
        return Err(KeyError::InvalidKey);
    }
    let parts: Vec<&str> = suffix.split('/').collect();
    parse_parts(&parts)
}

fn parse_parts(parts: &[&str]) -> Result<ParsedV2Key, KeyError> {
    match parts {
        ["v2", "repositories", "by-path", digest, "repo_control.pb"]
            if is_lower_hex(digest, 64) =>
        {
            return ok(V2KeyKind::RepoControl, None);
        }
        ["v2", "control", "cutover_control.pb"] => return ok(V2KeyKind::CutoverControl, None),
        ["v2", "control", "credential_control.pb"] => {
            return ok(V2KeyKind::CredentialControl, None);
        }
        ["v2", "control", "bucket_admin_control.pb"] => {
            return ok(V2KeyKind::BucketAdminControl, None);
        }
        ["v2", "control", "key-rings", leaf] if digest_leaf(leaf, ".cose") => {
            return ok(V2KeyKind::VerificationKeyRing, None);
        }
        ["v2", "capacity", "capacity_control.pb"] => {
            return ok(V2KeyKind::CapacityControl, None);
        }
        ["v2", "capacity", "catalogs", "tenant", leaf] if digest_leaf(leaf, ".pb") => {
            return ok(V2KeyKind::TenantCapacityCatalog, None);
        }
        ["v2", "capacity", "shards", shard, "capacity_shard.pb"] if is_lower_hex(shard, 2) => {
            return ok(V2KeyKind::CapacityShard, None);
        }
        ["v2", "recovery", "recovery_control.pb"] => {
            return ok(V2KeyKind::RecoveryControl, None);
        }
        ["v2", "leases", "by-id", uuid, generation, "writer_lease.pb"] => {
            let repository = parse_repository(uuid, generation)?;
            return ok(V2KeyKind::WriterLease, Some(repository));
        }
        ["v2", "host_control", "by-path", leaf] if digest_leaf(leaf, ".pb") => {
            return ok(V2KeyKind::HostByPath, None);
        }
        ["v2", "host_control", "by-id", uuid, generation_leaf] => {
            let generation = generation_leaf
                .strip_suffix(".pb")
                .ok_or(KeyError::InvalidKey)?;
            let repository = parse_repository(uuid, generation)?;
            return ok(V2KeyKind::HostByIdentity, Some(repository));
        }
        _ => {}
    }

    let ["v2", "repositories", "by-id", uuid, generation, rest @ ..] = parts else {
        return Err(KeyError::InvalidKey);
    };
    let repository = parse_repository(uuid, generation)?;
    let kind = parse_repository_leaf(rest)?;
    ok(kind, Some(repository))
}

fn parse_repository_leaf(parts: &[&str]) -> Result<V2KeyKind, KeyError> {
    if let ["catalogs", kind, leaf] = parts
        && digest_leaf(leaf, ".pb")
    {
        let kind = match *kind {
            "pack" => CatalogKind::Pack,
            "ref-delta" => CatalogKind::RefDelta,
            "grant" => CatalogKind::Grant,
            "receipt" => CatalogKind::Receipt,
            "event" => CatalogKind::Event,
            "pin" => CatalogKind::Pin,
            "git-ownership" => CatalogKind::GitOwnership,
            "lfs-ownership" => CatalogKind::LfsOwnership,
            "bundle" => CatalogKind::Bundle,
            "recovery" => CatalogKind::Recovery,
            "audit" => CatalogKind::Audit,
            "reclamation" => CatalogKind::Reclamation,
            _ => return Err(KeyError::InvalidKey),
        };
        return Ok(V2KeyKind::Catalog(kind));
    }
    match parts {
        ["receipts", "results", leaf] if uuid_v7_leaf(leaf, ".pb") => Ok(V2KeyKind::ReceiptResult),
        ["events", "results", leaf] if uuid_v7_leaf(leaf, ".pb") => Ok(V2KeyKind::EventResult),
        ["events", "archive", event, leaf] if is_uuid_v7_hex(event) && digest_leaf(leaf, ".pb") => {
            Ok(V2KeyKind::EventArchive)
        }
        ["events", "watermarks", sequence, leaf]
            if is_lower_hex(sequence, 16) && digest_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::EventArchiveWatermark)
        }
        ["checkpoints", sequence, leaf]
            if is_lower_hex(sequence, 16) && digest_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::Checkpoint)
        }
        ["recovery", recovery, "journal", leaf]
            if is_uuid_v7_hex(recovery) && sequence_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::RecoveryJournal)
        }
        ["recovery", recovery, "mapping", leaf]
            if is_uuid_v7_hex(recovery) && sequence_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::RecoveryMapping)
        }
        ["recovery", recovery, "catalog", leaf]
            if is_uuid_v7_hex(recovery) && sequence_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::RecoveryCatalog)
        }
        ["recovery", recovery, "payload", leaf]
            if is_uuid_v7_hex(recovery) && sequence_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::RecoveryPayloadReference)
        }
        ["git", "packs", leaf] if digest_leaf(leaf, ".pack") => Ok(V2KeyKind::GitPack),
        ["lfs", leaf] if digest_leaf(leaf, ".bin") => Ok(V2KeyKind::LfsObject),
        ["bundles", leaf] if digest_leaf(leaf, ".bundle") => Ok(V2KeyKind::Bundle),
        ["tmp", "git-pack-upload", operation, leaf]
            if is_uuid_v7_hex(operation) && sequence_leaf(leaf, ".bin") =>
        {
            Ok(V2KeyKind::TemporaryGitPackUpload)
        }
        ["tmp", "lfs-upload", operation, leaf]
            if is_uuid_v7_hex(operation) && sequence_leaf(leaf, ".bin") =>
        {
            Ok(V2KeyKind::TemporaryLfsUpload)
        }
        ["tmp", "bundle-upload", operation, leaf]
            if is_uuid_v7_hex(operation) && sequence_leaf(leaf, ".bin") =>
        {
            Ok(V2KeyKind::TemporaryBundleUpload)
        }
        ["tmp", "catalog-candidate", operation, leaf]
            if is_uuid_v7_hex(operation) && sequence_leaf(leaf, ".pb") =>
        {
            Ok(V2KeyKind::TemporaryCatalogCandidate)
        }
        ["tmp", "recovery-copy", operation, leaf]
            if is_uuid_v7_hex(operation) && sequence_leaf(leaf, ".bin") =>
        {
            Ok(V2KeyKind::TemporaryRecoveryCopy)
        }
        _ => Err(KeyError::InvalidKey),
    }
}

fn parse_repository(uuid: &str, generation: &str) -> Result<RepositoryKeyIdentity, KeyError> {
    if !is_lower_hex(uuid, 32) {
        return Err(KeyError::InvalidKey);
    }
    let generation = generation
        .strip_prefix('g')
        .filter(|value| is_lower_hex(value, 16))
        .ok_or(KeyError::InvalidKey)?;
    let mut repository_uuid = [0u8; 16];
    hex::decode_to_slice(uuid, &mut repository_uuid).map_err(|_| KeyError::InvalidKey)?;
    let generation = u64::from_str_radix(generation, 16).map_err(|_| KeyError::InvalidKey)?;
    if generation != 1 {
        return Err(KeyError::InvalidGeneration);
    }
    Ok(RepositoryKeyIdentity {
        repository_uuid,
        generation,
    })
}

fn validate_deployment_prefix(prefix: &str) -> Result<(), KeyError> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.len() > 256 || !prefix.is_ascii() || !prefix.ends_with('/') {
        return Err(KeyError::InvalidDeploymentPrefix);
    }
    let body = &prefix[..prefix.len() - 1];
    let segments: Vec<&str> = body.split('/').collect();
    if !(1..=4).contains(&segments.len())
        || segments.iter().any(|segment| {
            !(1..=63).contains(&segment.len())
                || *segment == "."
                || *segment == ".."
                || !segment.as_bytes()[0].is_ascii_lowercase()
                    && !segment.as_bytes()[0].is_ascii_digit()
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
    {
        return Err(KeyError::InvalidDeploymentPrefix);
    }
    Ok(())
}

fn ok(kind: V2KeyKind, repository: Option<RepositoryKeyIdentity>) -> Result<ParsedV2Key, KeyError> {
    Ok(ParsedV2Key { kind, repository })
}

fn digest_leaf(value: &str, extension: &str) -> bool {
    value
        .strip_suffix(extension)
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn uuid_v7_leaf(value: &str, extension: &str) -> bool {
    value.strip_suffix(extension).is_some_and(is_uuid_v7_hex)
}

fn is_uuid_v7_hex(value: &str) -> bool {
    is_lower_hex(value, 32)
        && value.as_bytes()[12] == b'7'
        && matches!(value.as_bytes()[16], b'8'..=b'9' | b'a'..=b'b')
}

fn sequence_leaf(value: &str, extension: &str) -> bool {
    value
        .strip_suffix(extension)
        .is_some_and(|sequence| is_lower_hex(sequence, 16))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("deployment prefix is outside the closed V2 grammar")]
    InvalidDeploymentPrefix,
    #[error("canonical path is too long for its u32 length binding")]
    CanonicalPathTooLong,
    #[error("repository generation must be exactly one in the V2 foundation")]
    InvalidGeneration,
    #[error("object key exceeds the 1024-byte V2 limit")]
    KeyTooLong,
    #[error("object key does not use the configured deployment prefix")]
    WrongPrefix,
    #[error("object key is outside the closed V2 grammar")]
    InvalidKey,
}

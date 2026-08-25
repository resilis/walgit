use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::{
    BucketSafetyBinding, CapacityBinding, CatalogKind, CatalogRoot, GrantRole, Lifecycle,
    ObjectFormat, PackRoot, REPO_CONTROL_SCHEMA_VERSION, ReclamationPhase, RepoControl,
    RepositoryGrant, RepositoryIdentity, TargetObjectRef, Visibility, WalEntryKind, WalState,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, ParsedV2Key, RepositoryKeyIdentity, RoutingDigest,
        V2KeyKind, parse_key, repo_control_key,
    },
    repo_control::{GrantRepresentation, PackRepresentation},
    wal_tail_entry::RefRepresentation,
};

const MAX_CATALOG_DEPTH: u32 = 4;
const MAX_CATALOG_NODES: u64 = 131_072;
const MAX_CATALOG_BYTES: u64 = 68_719_476_736;
const MAX_RECLAMATION_OBJECTS: u64 = 1_000;
const MAX_RECLAMATION_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

pub fn validate_repo_control(control: &RepoControl) -> Result<(), ControlValidationError> {
    if control.schema_version != REPO_CONTROL_SCHEMA_VERSION {
        return Err(invalid("schema_version", "must be exactly 2"));
    }
    let identity = control
        .identity
        .as_ref()
        .ok_or_else(|| missing("identity"))?;
    validate_identity(identity)?;

    validate_uuid_v7("create_intent_id", &control.create_intent_id)?;
    exact_len("create_intent_digest", &control.create_intent_digest, 32)?;
    if control.create_intent_cose.is_empty() || control.create_intent_cose.len() > 8_192 {
        return Err(invalid(
            "create_intent_cose",
            "must contain 1..=8192 exact COSE bytes",
        ));
    }
    let create_digest: [u8; 32] = Sha256::digest(&control.create_intent_cose).into();
    if control.create_intent_digest.as_ref() != create_digest {
        return Err(invalid(
            "create_intent_digest",
            "does not match the exact COSE bytes",
        ));
    }

    let (prefix, parsed_control_key) = validate_control_key(&control.repo_control_key, identity)?;
    if parsed_control_key.kind != V2KeyKind::RepoControl {
        return Err(invalid("repo_control_key", "is not a repo_control key"));
    }
    let routing = RoutingDigest::of(&identity.canonical_path)
        .map_err(|_| invalid("identity.canonical_path", "is too long"))?;
    let expected = repo_control_key(&prefix, routing)
        .map_err(|_| invalid("repo_control_key", "cannot be derived"))?;
    if control.repo_control_key.as_ref() != expected.as_bytes() {
        return Err(invalid(
            "repo_control_key",
            "does not match the identity routing digest",
        ));
    }

    known_nonzero_enum::<ObjectFormat>("object_format", control.object_format)?;
    known_nonzero_enum::<Lifecycle>("lifecycle", control.lifecycle)?;
    known_nonzero_enum::<Visibility>("visibility", control.visibility)?;
    nonzero("control_revision", control.control_revision)?;
    nonzero("cutover_generation", control.cutover_generation)?;

    let writer = control.writer.as_ref().ok_or_else(|| missing("writer"))?;
    bounded_bytes("writer.holder", &writer.holder, 1, 256)?;
    nonzero("writer.epoch", writer.epoch)?;
    nonzero("authorization_epoch", control.authorization_epoch)?;

    validate_quota(control)?;
    validate_capacity(
        control
            .capacity
            .as_ref()
            .ok_or_else(|| missing("capacity"))?,
        identity,
        &prefix,
    )?;
    validate_bucket_safety(
        control
            .bucket_safety
            .as_ref()
            .ok_or_else(|| missing("bucket_safety"))?,
    )?;
    if control.inline_settings.len() > 16_384 {
        return Err(invalid("inline_settings", "exceeds 16384 bytes"));
    }
    if control.inline_policy.len() > 65_536 {
        return Err(invalid("inline_policy", "exceeds 65536 bytes"));
    }

    let wal = control.wal.as_ref().ok_or_else(|| missing("wal"))?;
    validate_wal(wal, identity, &prefix, control.object_format)?;
    validate_reclamation(control)?;
    validate_uuid_v7(
        "last_internal_mutation_id",
        &control.last_internal_mutation_id,
    )?;

    match control
        .pack_representation
        .as_ref()
        .ok_or_else(|| missing("pack_representation"))?
    {
        PackRepresentation::InlinePacks(inline) => {
            if inline.roots.len() > 4_096 {
                return Err(invalid("inline_packs", "exceeds 4096 roots"));
            }
            for pack in &inline.roots {
                validate_pack(
                    pack,
                    identity,
                    &prefix,
                    wal.head_sequence,
                    control.object_format,
                )?;
            }
        }
        PackRepresentation::PackCatalog(root) => {
            validate_catalog_root(root, CatalogKind::Pack, identity, &prefix)?;
        }
    }

    match control
        .grant_representation
        .as_ref()
        .ok_or_else(|| missing("grant_representation"))?
    {
        GrantRepresentation::InlineGrants(inline) => {
            if inline.grants.len() > 256 {
                return Err(invalid("inline_grants", "exceeds 256 grants"));
            }
            validate_grants(&inline.grants)?;
        }
        GrantRepresentation::GrantCatalog(root) => {
            validate_catalog_root(root, CatalogKind::Grant, identity, &prefix)?;
        }
    }

    validate_optional_catalog(
        control.receipt_catalog.as_ref(),
        CatalogKind::Receipt,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.event_catalog.as_ref(),
        CatalogKind::Event,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.pin_catalog.as_ref(),
        CatalogKind::Pin,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.git_ownership_catalog.as_ref(),
        CatalogKind::GitOwnership,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.lfs_ownership_catalog.as_ref(),
        CatalogKind::LfsOwnership,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.bundle_catalog.as_ref(),
        CatalogKind::Bundle,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.recovery_catalog.as_ref(),
        CatalogKind::Recovery,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.audit_catalog.as_ref(),
        CatalogKind::Audit,
        identity,
        &prefix,
    )?;
    validate_optional_catalog(
        control.reclamation_catalog.as_ref(),
        CatalogKind::Reclamation,
        identity,
        &prefix,
    )?;
    Ok(())
}

/// Validate the state-independent invariants of one exact `repo_control` CAS
/// successor. Mutation-specific authorization, capacity, and fencing checks
/// remain the responsibility of the caller that constructs the candidate.
pub fn validate_repo_control_successor(
    previous: &RepoControl,
    successor: &RepoControl,
) -> Result<(), ControlValidationError> {
    validate_repo_control(previous)?;
    validate_repo_control(successor)?;

    if previous.schema_version != successor.schema_version {
        return Err(invalid("schema_version", "cannot change after Create"));
    }
    if previous.identity != successor.identity {
        return Err(invalid("identity", "cannot change after Create"));
    }
    if previous.create_intent_id != successor.create_intent_id {
        return Err(invalid("create_intent_id", "cannot change after Create"));
    }
    if previous.create_intent_digest != successor.create_intent_digest {
        return Err(invalid(
            "create_intent_digest",
            "cannot change after Create",
        ));
    }
    if previous.create_intent_cose != successor.create_intent_cose {
        return Err(invalid("create_intent_cose", "cannot change after Create"));
    }
    if previous.repo_control_key != successor.repo_control_key {
        return Err(invalid("repo_control_key", "cannot change after Create"));
    }
    if previous.object_format != successor.object_format {
        return Err(invalid("object_format", "cannot change after Create"));
    }
    if previous.cutover_generation != successor.cutover_generation {
        return Err(invalid("cutover_generation", "cannot change after Create"));
    }

    let expected_revision = previous
        .control_revision
        .checked_add(1)
        .ok_or_else(|| invalid("control_revision", "cannot advance past u64::MAX"))?;
    if successor.control_revision != expected_revision {
        return Err(invalid("control_revision", "must advance by exactly one"));
    }
    if previous.last_internal_mutation_id == successor.last_internal_mutation_id {
        return Err(invalid(
            "last_internal_mutation_id",
            "must identify this successor mutation",
        ));
    }

    let previous_lifecycle = Lifecycle::try_from(previous.lifecycle)
        .map_err(|_| invalid("lifecycle", "contains an unknown value"))?;
    let successor_lifecycle = Lifecycle::try_from(successor.lifecycle)
        .map_err(|_| invalid("lifecycle", "contains an unknown value"))?;
    let valid_lifecycle = matches!(
        (previous_lifecycle, successor_lifecycle),
        (Lifecycle::Active, Lifecycle::Active | Lifecycle::Deleting)
            | (
                Lifecycle::Deleting,
                Lifecycle::Deleting | Lifecycle::Tombstoned
            )
    );
    if !valid_lifecycle {
        return Err(invalid("lifecycle", "is not an allowed successor"));
    }

    Ok(())
}

fn validate_identity(identity: &RepositoryIdentity) -> Result<(), ControlValidationError> {
    bounded_bytes("identity.tenant_id", &identity.tenant_id, 1, 256)?;
    bounded_bytes("identity.project_id", &identity.project_id, 1, 256)?;
    validate_uuid("identity.repository_uuid", &identity.repository_uuid, false)?;
    if identity.generation != 1 {
        return Err(invalid("identity.generation", "must be exactly 1"));
    }
    bounded_bytes("identity.canonical_path", &identity.canonical_path, 1, 1024)?;
    validate_canonical_path(&identity.canonical_path)?;
    exact_len(
        "identity.canonical_path_digest",
        &identity.canonical_path_digest,
        32,
    )?;
    exact_len("identity.routing_digest", &identity.routing_digest, 32)?;
    if identity.canonical_path_digest.as_ref()
        != CanonicalPathDigest::of(&identity.canonical_path).as_bytes()
    {
        return Err(invalid(
            "identity.canonical_path_digest",
            "does not equal SHA-256(canonical_path)",
        ));
    }
    let routing = RoutingDigest::of(&identity.canonical_path)
        .map_err(|_| invalid("identity.canonical_path", "is too long"))?;
    if identity.routing_digest.as_ref() != routing.as_bytes() {
        return Err(invalid(
            "identity.routing_digest",
            "does not equal the domain-separated routing digest",
        ));
    }
    Ok(())
}

fn validate_canonical_path(path: &[u8]) -> Result<(), ControlValidationError> {
    std::str::from_utf8(path)
        .map_err(|_| invalid("identity.canonical_path", "must be valid UTF-8"))?;
    let segments: Vec<&[u8]> = path.split(|byte| *byte == b'/').collect();
    if !(1..=8).contains(&segments.len())
        || segments.iter().any(|segment| {
            segment.is_empty()
                || *segment == b"."
                || *segment == b".."
                || segment
                    .iter()
                    .any(|byte| *byte == 0 || *byte == b'\\' || *byte == 0x7f || *byte < 0x20)
        })
        || segments
            .last()
            .is_some_and(|segment| segment.ends_with(b".git"))
    {
        return Err(invalid(
            "identity.canonical_path",
            "is outside the V2 canonical path grammar",
        ));
    }
    Ok(())
}

fn validate_control_key(
    key: &[u8],
    identity: &RepositoryIdentity,
) -> Result<(DeploymentPrefix, ParsedV2Key), ControlValidationError> {
    let key_str =
        std::str::from_utf8(key).map_err(|_| invalid("repo_control_key", "must be ASCII"))?;
    let routing = RoutingDigest::of(&identity.canonical_path)
        .map_err(|_| invalid("identity.canonical_path", "is too long"))?;
    let suffix = format!(
        "v2/repositories/by-path/{}/repo_control.pb",
        routing.lower_hex()
    );
    let prefix_bytes = key_str.strip_suffix(&suffix).ok_or_else(|| {
        invalid(
            "repo_control_key",
            "does not end in the derived V2 control key",
        )
    })?;
    let prefix = DeploymentPrefix::parse(prefix_bytes)
        .map_err(|_| invalid("repo_control_key", "has an invalid deployment prefix"))?;
    let parsed = parse_key(&prefix, key)
        .map_err(|_| invalid("repo_control_key", "is outside the closed V2 grammar"))?;
    if parsed.repository.is_some() || identity.generation != 1 {
        return Err(invalid("repo_control_key", "has inconsistent identity"));
    }
    Ok((prefix, parsed))
}

fn validate_quota(control: &RepoControl) -> Result<(), ControlValidationError> {
    let quota = control.quota.as_ref().ok_or_else(|| missing("quota"))?;
    nonzero("quota.logical_quota_bytes", quota.logical_quota_bytes)?;
    let charged = quota
        .charged_git_bytes
        .checked_add(quota.charged_lfs_bytes)
        .ok_or_else(|| invalid("quota", "charged usage overflows u64"))?;
    if charged > quota.logical_quota_bytes {
        return Err(invalid("quota", "charged usage exceeds the finite quota"));
    }
    Ok(())
}

fn validate_capacity(
    capacity: &CapacityBinding,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    nonzero("capacity.allocation_epoch", capacity.allocation_epoch)?;
    if capacity.shard > 255 {
        return Err(invalid("capacity.shard", "must be in 0..=255"));
    }
    if capacity.shard != u32::from(Sha256::digest(&identity.repository_uuid)[0]) {
        return Err(invalid(
            "capacity.shard",
            "does not equal the first byte of SHA-256(repository_uuid)",
        ));
    }
    bounded_bytes("capacity.shard_key", &capacity.shard_key, 1, 1024)?;
    bounded_bytes(
        "capacity.shard_object_version_id",
        &capacity.shard_object_version_id,
        1,
        1024,
    )?;
    let parsed = parse_key(prefix, &capacity.shard_key)
        .map_err(|_| invalid("capacity.shard_key", "is outside the closed V2 grammar"))?;
    if parsed.kind != V2KeyKind::CapacityShard
        || capacity.shard_key.as_ref()
            != format!(
                "{}v2/capacity/shards/{:02x}/capacity_shard.pb",
                prefix.as_str(),
                capacity.shard
            )
            .as_bytes()
    {
        return Err(invalid(
            "capacity.shard_key",
            "does not match the selected capacity shard",
        ));
    }
    if capacity.tenant_slice_bytes > capacity.shard_budget_bytes {
        return Err(invalid(
            "capacity.tenant_slice_bytes",
            "exceeds the immutable shard budget",
        ));
    }
    exact_len("capacity.shard_digest", &capacity.shard_digest, 32)?;
    nonzero("capacity.shard_size", capacity.shard_size)?;
    Ok(())
}

fn validate_bucket_safety(binding: &BucketSafetyBinding) -> Result<(), ControlValidationError> {
    nonzero("bucket_safety.epoch", binding.epoch)?;
    exact_len("bucket_safety.safety_digest", &binding.safety_digest, 32)
}

fn validate_wal(
    wal: &WalState,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
    object_format: i32,
) -> Result<(), ControlValidationError> {
    if wal.tail.len() > 256 {
        return Err(invalid("wal.tail", "exceeds 256 entries"));
    }

    let checkpoint_sequence = match &wal.checkpoint {
        Some(checkpoint) => {
            let parsed = validate_target(checkpoint, identity, prefix, V2KeyKind::Checkpoint)?;
            let sequence = parsed
                .sequence
                .ok_or_else(|| invalid("wal.checkpoint.key", "does not bind a sequence"))?;
            if sequence > wal.head_sequence {
                return Err(invalid(
                    "wal.checkpoint.key",
                    "sequence exceeds the WAL head",
                ));
            }
            Some(sequence)
        }
        None => None,
    };
    let expected_minimum = match checkpoint_sequence {
        Some(sequence) => sequence.checked_add(1).ok_or_else(|| {
            invalid(
                "wal.checkpoint.key",
                "sequence cannot advance without overflowing u64",
            )
        })?,
        None if wal.head_sequence == 0 => 0,
        None => 1,
    };
    if wal.minimum_sequence != expected_minimum {
        return Err(invalid(
            "wal.minimum_sequence",
            "does not immediately follow the checkpoint or genesis",
        ));
    }
    let expected_tail_count =
        if checkpoint_sequence.is_none() && wal.head_sequence == 0 && wal.minimum_sequence == 0 {
            0
        } else if wal.minimum_sequence <= wal.head_sequence {
            wal.head_sequence
                .checked_sub(wal.minimum_sequence)
                .and_then(|span| span.checked_add(1))
                .ok_or_else(|| invalid("wal.tail", "retained sequence span overflows u64"))?
        } else {
            0
        };
    if expected_tail_count > 256 {
        return Err(invalid(
            "wal.tail",
            "retained sequence span exceeds 256 entries",
        ));
    }
    if wal.tail.len() as u64 != expected_tail_count {
        return Err(invalid(
            "wal.tail",
            "does not exactly cover minimum_sequence through head_sequence",
        ));
    }

    let mut aggregate_changes = 0usize;
    for (offset, entry) in wal.tail.iter().enumerate() {
        nonzero("wal.tail.sequence", entry.sequence)?;
        let expected_sequence = wal
            .minimum_sequence
            .checked_add(offset as u64)
            .ok_or_else(|| invalid("wal.tail.sequence", "overflows u64"))?;
        if entry.sequence != expected_sequence {
            return Err(invalid(
                "wal.tail.sequence",
                "is not the exact contiguous retained sequence",
            ));
        }
        known_nonzero_enum::<WalEntryKind>("wal.tail.kind", entry.kind)?;
        validate_uuid_v7("wal.tail.mutation_id", &entry.mutation_id)?;
        if entry.superseded_objects.len() > 256 {
            return Err(invalid(
                "wal.tail.superseded_objects",
                "exceeds 256 references",
            ));
        }
        for object in &entry.superseded_objects {
            validate_target_any_repository_leaf(object, identity, prefix)?;
        }
        match &entry.ref_representation {
            Some(RefRepresentation::InlineRefChanges(inline)) => {
                if inline.changes.len() > 256 {
                    return Err(invalid(
                        "wal.tail.inline_ref_changes",
                        "exceeds 256 changes",
                    ));
                }
                aggregate_changes = aggregate_changes
                    .checked_add(inline.changes.len())
                    .ok_or_else(|| invalid("wal.tail", "aggregate count overflow"))?;
                for change in &inline.changes {
                    bounded_bytes("ref_change.name", &change.name, 1, 1024)?;
                    validate_object_id(
                        "ref_change.old_object_id",
                        &change.old_object_id,
                        object_format,
                        true,
                    )?;
                    validate_object_id(
                        "ref_change.new_object_id",
                        &change.new_object_id,
                        object_format,
                        true,
                    )?;
                    bounded_bytes(
                        "ref_change.new_symbolic_target",
                        &change.new_symbolic_target,
                        0,
                        1024,
                    )?;
                    validate_object_id(
                        "ref_change.new_peeled_object_id",
                        &change.new_peeled_object_id,
                        object_format,
                        true,
                    )?;
                    if !change.new_symbolic_target.is_empty()
                        && (!change.old_object_id.is_empty()
                            || !change.new_object_id.is_empty()
                            || !change.new_peeled_object_id.is_empty())
                    {
                        return Err(invalid(
                            "ref_change",
                            "symbolic and object-ID forms are mutually exclusive",
                        ));
                    }
                    if change.old_object_id.is_empty()
                        && change.new_object_id.is_empty()
                        && change.new_symbolic_target.is_empty()
                    {
                        return Err(invalid("ref_change", "does not change a ref"));
                    }
                }
            }
            Some(RefRepresentation::RefDeltaCatalog(root)) => {
                validate_catalog_root(root, CatalogKind::RefDelta, identity, prefix)?;
                if root.item_count > 256 {
                    return Err(invalid(
                        "wal.tail.ref_delta_catalog.item_count",
                        "exceeds one atomic transaction's 256-change limit",
                    ));
                }
            }
            None => {}
        }
    }
    if aggregate_changes > 4_096 {
        return Err(invalid(
            "wal.tail",
            "exceeds 4096 aggregate inline ref changes",
        ));
    }
    Ok(())
}

fn validate_reclamation(control: &RepoControl) -> Result<(), ControlValidationError> {
    let reclamation = control
        .reclamation
        .as_ref()
        .ok_or_else(|| missing("reclamation"))?;
    known_nonzero_enum::<ReclamationPhase>("reclamation.phase", reclamation.phase)?;
    bounded_bytes("reclamation.cursor", &reclamation.cursor, 0, 4_096)?;
    if reclamation.pass_objects > MAX_RECLAMATION_OBJECTS {
        return Err(invalid("reclamation.pass_objects", "exceeds 1000 objects"));
    }
    if reclamation.pass_bytes > MAX_RECLAMATION_BYTES {
        return Err(invalid("reclamation.pass_bytes", "exceeds 5 TiB"));
    }
    if reclamation.phase != ReclamationPhase::Idle as i32 && control.reclamation_catalog.is_none() {
        return Err(invalid(
            "reclamation_catalog",
            "is required while reclamation is active",
        ));
    }
    Ok(())
}

fn validate_pack(
    pack: &PackRoot,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
    head_sequence: u64,
    object_format: i32,
) -> Result<(), ControlValidationError> {
    validate_target(
        pack.object.as_ref().ok_or_else(|| missing("pack.object"))?,
        identity,
        prefix,
        V2KeyKind::GitPack,
    )?;
    validate_object_id(
        "pack.git_object_id",
        &pack.git_object_id,
        object_format,
        false,
    )?;
    nonzero("pack.introduced_wal_sequence", pack.introduced_wal_sequence)?;
    if pack.introduced_wal_sequence > head_sequence {
        return Err(invalid(
            "pack.introduced_wal_sequence",
            "exceeds the WAL head",
        ));
    }
    nonzero("pack.object_count", pack.object_count)
}

fn validate_grants(grants: &[RepositoryGrant]) -> Result<(), ControlValidationError> {
    let mut identities = HashSet::with_capacity(grants.len());
    for grant in grants {
        bounded_bytes("grant.issuer", &grant.issuer, 1, 256)?;
        bounded_bytes("grant.subject", &grant.subject, 1, 256)?;
        known_nonzero_enum::<GrantRole>("grant.role", grant.role)?;
        if !identities.insert((grant.issuer.as_ref(), grant.subject.as_ref())) {
            return Err(invalid("inline_grants", "contains a duplicate identity"));
        }
    }
    Ok(())
}

fn validate_optional_catalog(
    root: Option<&CatalogRoot>,
    kind: CatalogKind,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if let Some(root) = root {
        validate_catalog_root(root, kind, identity, prefix)?;
    }
    Ok(())
}

fn validate_catalog_root(
    root: &CatalogRoot,
    expected_kind: CatalogKind,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    let kind =
        CatalogKind::try_from(root.kind).map_err(|_| invalid("catalog.kind", "is unknown"))?;
    if kind != expected_kind {
        return Err(invalid("catalog.kind", "does not match its typed slot"));
    }
    validate_target(
        root.object
            .as_ref()
            .ok_or_else(|| missing("catalog.object"))?,
        identity,
        prefix,
        V2KeyKind::Catalog(expected_kind),
    )?;
    if !(1..=MAX_CATALOG_DEPTH).contains(&root.depth) {
        return Err(invalid("catalog.depth", "must be in 1..=4"));
    }
    if root.node_count == 0 || root.node_count > MAX_CATALOG_NODES {
        return Err(invalid("catalog.node_count", "must be in 1..=131072"));
    }
    let max_items = catalog_item_limit(expected_kind);
    if root.item_count > max_items {
        return Err(invalid("catalog.item_count", "exceeds its typed limit"));
    }
    if root.total_encoded_bytes == 0 || root.total_encoded_bytes > MAX_CATALOG_BYTES {
        return Err(invalid(
            "catalog.total_encoded_bytes",
            "is outside the catalog byte limit",
        ));
    }
    Ok(())
}

fn catalog_item_limit(kind: CatalogKind) -> u64 {
    match kind {
        CatalogKind::Pack => 1_000_000,
        CatalogKind::RefDelta => 4_000_000,
        CatalogKind::Grant => 65_536,
        CatalogKind::Receipt => 16_384,
        CatalogKind::Event => 65_536,
        CatalogKind::Pin => 1_000_000,
        CatalogKind::GitOwnership | CatalogKind::LfsOwnership | CatalogKind::Recovery => {
            100_000_000
        }
        CatalogKind::Bundle => 65_536,
        CatalogKind::Audit => 10_000_000,
        CatalogKind::Reclamation => 1_000_000,
        CatalogKind::Unspecified => 0,
    }
}

fn validate_target(
    target: &TargetObjectRef,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
    expected_kind: V2KeyKind,
) -> Result<ParsedV2Key, ControlValidationError> {
    let parsed = validate_target_any_repository_leaf(target, identity, prefix)?;
    if parsed.kind != expected_kind {
        return Err(invalid("target.key", "does not match its typed slot"));
    }
    Ok(parsed)
}

fn validate_target_any_repository_leaf(
    target: &TargetObjectRef,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
) -> Result<ParsedV2Key, ControlValidationError> {
    let target_identity = target
        .identity
        .as_ref()
        .ok_or_else(|| missing("target.identity"))?;
    validate_identity(target_identity)?;
    if target_identity != identity {
        return Err(invalid(
            "target.identity",
            "does not equal the repository control identity",
        ));
    }
    bounded_bytes("target.key", &target.key, 1, 1024)?;
    bounded_bytes(
        "target.object_version_id",
        &target.object_version_id,
        1,
        1024,
    )?;
    exact_len("target.digest", &target.digest, 32)?;
    let parsed = parse_key(prefix, &target.key)
        .map_err(|_| invalid("target.key", "is outside the closed V2 grammar"))?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&identity.repository_uuid);
    if parsed.repository
        != Some(RepositoryKeyIdentity {
            repository_uuid: uuid,
            generation: identity.generation,
        })
    {
        return Err(invalid(
            "target.key",
            "does not match the repository UUID and generation",
        ));
    }
    if let Some(key_digest) = parsed.content_digest
        && target.digest.as_ref() != key_digest.as_bytes()
    {
        return Err(invalid(
            "target.digest",
            "does not equal the content digest encoded in target.key",
        ));
    }
    Ok(parsed)
}

fn validate_object_id(
    field: &'static str,
    value: &[u8],
    object_format: i32,
    allow_empty: bool,
) -> Result<(), ControlValidationError> {
    if allow_empty && value.is_empty() {
        return Ok(());
    }
    let expected = match ObjectFormat::try_from(object_format) {
        Ok(ObjectFormat::Sha1) => 20,
        Ok(ObjectFormat::Sha256) => 32,
        _ => return Err(invalid("object_format", "is unknown")),
    };
    exact_len(field, value, expected)
}

fn known_nonzero_enum<T>(field: &'static str, value: i32) -> Result<(), ControlValidationError>
where
    T: TryFrom<i32>,
{
    if value == 0 || T::try_from(value).is_err() {
        return Err(invalid(field, "must be a known nonzero enum value"));
    }
    Ok(())
}

fn nonzero(field: &'static str, value: u64) -> Result<(), ControlValidationError> {
    if value == 0 {
        return Err(invalid(field, "must be positive"));
    }
    Ok(())
}

fn exact_len(field: &'static str, value: &[u8], len: usize) -> Result<(), ControlValidationError> {
    bounded_bytes(field, value, len, len)
}

fn validate_uuid_v7(field: &'static str, value: &[u8]) -> Result<(), ControlValidationError> {
    validate_uuid(field, value, true)
}

fn validate_uuid(
    field: &'static str,
    value: &[u8],
    require_v7: bool,
) -> Result<(), ControlValidationError> {
    exact_len(field, value, 16)?;
    if value.iter().all(|byte| *byte == 0)
        || value[8] & 0xc0 != 0x80
        || require_v7 && value[6] >> 4 != 7
    {
        return Err(invalid(
            field,
            "is not an RFC 9562 UUID of the required version",
        ));
    }
    Ok(())
}

fn bounded_bytes(
    field: &'static str,
    value: &[u8],
    min: usize,
    max: usize,
) -> Result<(), ControlValidationError> {
    if !(min..=max).contains(&value.len()) {
        return Err(invalid(field, "is outside its byte bound"));
    }
    Ok(())
}

fn missing(field: &'static str) -> ControlValidationError {
    ControlValidationError::Invalid {
        field,
        reason: "is required",
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ControlValidationError {
    ControlValidationError::Invalid { field, reason }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ControlValidationError {
    #[error("invalid V2 repository control field {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
}

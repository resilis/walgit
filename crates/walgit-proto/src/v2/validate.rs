use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::{
    BucketSafetyBinding, CREDENTIAL_CONTROL_SCHEMA_VERSION, CapacityBinding, CatalogKind,
    CatalogRoot, CredentialControl, GrantRole, Lifecycle, MutationKind, MutationReceipt,
    MutationResult, ObjectFormat, PackRoot, RECEIPT_SCHEMA_VERSION, REPO_CONTROL_SCHEMA_VERSION,
    ReceiptCatalog, ReceiptCatalogRow, ReceiptState, ReclamationPhase, RepoControl,
    RepositoryGrant, RepositoryIdentity, TargetObjectRef, VerificationRingRoot, Visibility,
    WalEntryKind, WalState,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, ParsedV2Key, RepositoryKeyIdentity, RoutingDigest,
        V2KeyKind, parse_key, repo_control_key,
    },
    mutation_receipt::{
        CapacityObligation as CapacityObligationChoice, EventObligation as EventObligationChoice,
        Predecessor,
    },
    repo_control::{GrantRepresentation, PackRepresentation},
    wal_tail_entry::RefRepresentation,
};

const MAX_CATALOG_DEPTH: u32 = 4;
const MAX_CATALOG_NODES: u64 = 131_072;
const MAX_CATALOG_BYTES: u64 = 68_719_476_736;
const MAX_RECLAMATION_OBJECTS: u64 = 1_000;
const MAX_RECLAMATION_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialTransitionKind {
    InstallNext,
    PromoteNext,
    RetirePrevious,
    RevokeKid,
    VerifierSetUpdate,
    AcknowledgementUpdate,
}

pub fn validate_mutation_receipt(receipt: &MutationReceipt) -> Result<(), ControlValidationError> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(invalid("receipt.schema_version", "must be exactly 1"));
    }
    let identity = receipt
        .identity
        .as_ref()
        .ok_or_else(|| missing("receipt.identity"))?;
    validate_identity(identity)?;
    validate_uuid_v7("receipt.mutation_id", &receipt.mutation_id)?;
    let kind =
        MutationKind::try_from(receipt.kind).map_err(|_| invalid("receipt.kind", "is unknown"))?;
    if matches!(
        kind,
        MutationKind::Unspecified | MutationKind::InternalSettlement
    ) {
        return Err(invalid("receipt.kind", "must be a non-settlement mutation"));
    }
    nonzero("receipt.writer_epoch", receipt.writer_epoch)?;
    // Control-only mutations bind the exact current WAL head. That head can
    // be zero before the repository's first WAL entry.
    exact_len("receipt.request_digest", &receipt.request_digest, 32)?;
    if receipt.immutable_dependency_digests.len() > 64 {
        return Err(invalid(
            "receipt.immutable_dependency_digests",
            "exceeds 64 entries",
        ));
    }
    for digest in &receipt.immutable_dependency_digests {
        exact_len("receipt.immutable_dependency_digests", digest, 32)?;
    }
    if receipt
        .immutable_dependency_digests
        .windows(2)
        .any(|pair| pair[0].as_ref() >= pair[1].as_ref())
    {
        return Err(invalid(
            "receipt.immutable_dependency_digests",
            "must be binary-sorted and unique",
        ));
    }
    match (&receipt.predecessor, kind) {
        (Some(Predecessor::NoPriorControl(_)), MutationKind::Create) => {}
        (Some(Predecessor::PriorControl(binding)), MutationKind::Create) => {
            let _ = binding;
            return Err(invalid(
                "receipt.predecessor",
                "Create requires explicit NONE",
            ));
        }
        (Some(Predecessor::PriorControl(binding)), _) => {
            bounded_bytes("receipt.prior.cas_token", &binding.cas_token, 1, 256)?;
            bounded_bytes(
                "receipt.prior.object_version_id",
                &binding.object_version_id,
                1,
                1024,
            )?;
        }
        (Some(Predecessor::NoPriorControl(_)), _) => {
            return Err(invalid(
                "receipt.predecessor",
                "non-Create requires an exact prior binding",
            ));
        }
        (None, _) => return Err(missing("receipt.predecessor")),
    }
    match receipt.capacity_obligation.as_ref() {
        Some(CapacityObligationChoice::NoCapacity(_)) => {}
        Some(CapacityObligationChoice::Capacity(capacity)) => {
            nonzero(
                "receipt.capacity.allocation_epoch",
                capacity.allocation_epoch,
            )?;
            bounded_bytes("receipt.capacity.shard_key", &capacity.shard_key, 1, 1024)?;
            bounded_bytes(
                "receipt.capacity.shard_object_version_id",
                &capacity.shard_object_version_id,
                1,
                1024,
            )?;
            validate_uuid_v7("receipt.capacity.reservation_id", &capacity.reservation_id)?;
            nonzero(
                "receipt.capacity.tenant_slice_bytes",
                capacity.tenant_slice_bytes,
            )?;
            if capacity.mutation_id != receipt.mutation_id {
                return Err(invalid(
                    "receipt.capacity.mutation_id",
                    "does not equal receipt mutation ID",
                ));
            }
            nonzero("receipt.capacity.byte_count", capacity.byte_count)?;
        }
        None => return Err(missing("receipt.capacity_obligation")),
    }
    match receipt.event_obligation.as_ref() {
        Some(EventObligationChoice::NoEvent(_)) => {}
        Some(EventObligationChoice::Event(event)) => {
            validate_uuid_v7("receipt.event.event_id", &event.event_id)?;
            if event.wal_sequence != receipt.wal_sequence {
                return Err(invalid(
                    "receipt.event.wal_sequence",
                    "does not equal receipt WAL sequence",
                ));
            }
            exact_len(
                "receipt.event.subscriber_set_digest",
                &event.subscriber_set_digest,
                32,
            )?;
            bounded_ascii("receipt.event.result_key", &event.result_key, 1, 1024)?;
            if event.subscriber_bodies.len() > 64 {
                return Err(invalid(
                    "receipt.event.subscriber_bodies",
                    "exceeds 64 entries",
                ));
            }
            for body in &event.subscriber_bodies {
                exact_len("receipt.event.body.digest", &body.digest, 32)?;
                nonzero("receipt.event.body.size", body.size)?;
            }
            if event.subscriber_bodies.windows(2).any(|pair| {
                (pair[0].digest.as_ref(), pair[0].size) >= (pair[1].digest.as_ref(), pair[1].size)
            }) {
                return Err(invalid(
                    "receipt.event.subscriber_bodies",
                    "must be binary-sorted and unique",
                ));
            }
        }
        None => return Err(missing("receipt.event_obligation")),
    }
    Ok(())
}

pub fn validate_mutation_result(result: &MutationResult) -> Result<(), ControlValidationError> {
    if result.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(invalid("result.schema_version", "must be exactly 1"));
    }
    let identity = result
        .identity
        .as_ref()
        .ok_or_else(|| missing("result.identity"))?;
    validate_identity(identity)?;
    validate_uuid_v7("result.mutation_id", &result.mutation_id)?;
    let kind =
        MutationKind::try_from(result.kind).map_err(|_| invalid("result.kind", "is unknown"))?;
    if matches!(
        kind,
        MutationKind::Unspecified | MutationKind::InternalSettlement
    ) {
        return Err(invalid("result.kind", "must be a non-settlement mutation"));
    }
    let landed = result
        .landed_control
        .as_ref()
        .ok_or_else(|| missing("result.landed_control"))?;
    validate_repo_control_target(landed, identity)?;
    nonzero(
        "result.landed_control_revision",
        result.landed_control_revision,
    )?;
    nonzero("result.writer_epoch", result.writer_epoch)?;
    // The result binds the exact landed WAL head. It can be zero before the
    // repository's first WAL entry for any non-settlement mutation kind.
    Ok(())
}

pub fn validate_receipt_catalog(catalog: &ReceiptCatalog) -> Result<(), ControlValidationError> {
    if catalog.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(invalid(
            "receipt_catalog.schema_version",
            "must be exactly 1",
        ));
    }
    let identity = catalog
        .identity
        .as_ref()
        .ok_or_else(|| missing("receipt_catalog.identity"))?;
    validate_identity(identity)?;
    if catalog.rows.len() > 4_096 {
        return Err(invalid("receipt_catalog.rows", "exceeds 4096 entries"));
    }
    if catalog
        .rows
        .windows(2)
        .any(|pair| pair[0].mutation_id.as_ref() >= pair[1].mutation_id.as_ref())
    {
        return Err(invalid(
            "receipt_catalog.rows",
            "must be binary-sorted and unique",
        ));
    }
    for row in &catalog.rows {
        validate_receipt_catalog_row(row, identity)?;
    }
    Ok(())
}

fn validate_receipt_catalog_row(
    row: &ReceiptCatalogRow,
    identity: &RepositoryIdentity,
) -> Result<(), ControlValidationError> {
    validate_uuid_v7("receipt_catalog.row.mutation_id", &row.mutation_id)?;
    let receipt = row
        .receipt
        .as_ref()
        .ok_or_else(|| missing("receipt_catalog.row.receipt"))?;
    validate_mutation_receipt(receipt)?;
    if receipt.identity.as_ref() != Some(identity) || receipt.mutation_id != row.mutation_id {
        return Err(invalid(
            "receipt_catalog.row.receipt",
            "does not match the catalog row",
        ));
    }
    let state = ReceiptState::try_from(row.state)
        .map_err(|_| invalid("receipt_catalog.row.state", "is unknown"))?;
    match (state, row.result.as_ref()) {
        (ReceiptState::Unresolved, None) => Ok(()),
        (ReceiptState::Settled, Some(result)) => {
            validate_receipt_result_target(result, identity, &row.mutation_id)
        }
        (ReceiptState::Unresolved, Some(_)) => Err(invalid(
            "receipt_catalog.row.result",
            "must be absent while UNRESOLVED",
        )),
        (ReceiptState::Settled, None) => Err(missing("receipt_catalog.row.result")),
        (ReceiptState::Unspecified, _) => Err(invalid(
            "receipt_catalog.row.state",
            "must be UNRESOLVED or SETTLED",
        )),
    }
}

pub fn validate_credential_control(
    control: &CredentialControl,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if control.schema_version != CREDENTIAL_CONTROL_SCHEMA_VERSION {
        return Err(invalid("credential.schema_version", "must be exactly 2"));
    }
    nonzero("credential.control_revision", control.control_revision)?;
    nonzero("credential.issuer_epoch", control.issuer_epoch)?;

    let current = control
        .current
        .as_ref()
        .ok_or_else(|| missing("credential.current"))?;
    validate_verification_ring_root("credential.current", current, prefix)?;
    let mut roots = vec![current];
    if let Some(next) = &control.next {
        validate_verification_ring_root("credential.next", next, prefix)?;
        let expected = current
            .ring_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("credential.next.ring_epoch", "would wrap current epoch"))?;
        if next.ring_epoch != expected {
            return Err(invalid(
                "credential.next.ring_epoch",
                "must be checked current ring epoch plus one",
            ));
        }
        roots.push(next);
    }
    if let Some(previous) = &control.previous {
        validate_verification_ring_root("credential.previous", previous, prefix)?;
        let expected = previous.ring_epoch.checked_add(1).ok_or_else(|| {
            invalid(
                "credential.previous.ring_epoch",
                "cannot precede current without wrapping",
            )
        })?;
        if current.ring_epoch != expected {
            return Err(invalid(
                "credential.previous.ring_epoch",
                "must immediately precede current ring epoch",
            ));
        }
        roots.push(previous);
    }
    if control.previous.is_some() != control.previous_last_issue_unix_seconds.is_some() {
        return Err(invalid(
            "credential.previous_last_issue_unix_seconds",
            "must be present if and only if previous is present",
        ));
    }
    for (index, left) in roots.iter().enumerate() {
        for right in &roots[index + 1..] {
            if left.key == right.key || left.digest == right.digest {
                return Err(invalid(
                    "credential.ring_roots",
                    "slot root identities must be distinct",
                ));
            }
            if left.ring_epoch == right.ring_epoch {
                return Err(invalid(
                    "credential.ring_roots",
                    "slot ring epochs must be distinct",
                ));
            }
        }
    }

    if control.revoked_kids.len() > 64 {
        return Err(invalid(
            "credential.revoked_kids",
            "must contain at most 64 entries",
        ));
    }
    for kid in &control.revoked_kids {
        exact_len("credential.revoked_kids", kid, 16)?;
    }
    if control
        .revoked_kids
        .windows(2)
        .any(|pair| pair[0].as_ref() >= pair[1].as_ref())
    {
        return Err(invalid(
            "credential.revoked_kids",
            "must be binary-sorted and unique",
        ));
    }
    exact_len(
        "credential.verifier_set_digest",
        &control.verifier_set_digest,
        32,
    )?;
    exact_len(
        "credential.acknowledgement_proof_digest",
        &control.acknowledgement_proof_digest,
        32,
    )?;

    if control.control_revision == 1
        && (control.issuer_epoch != 1
            || current.ring_epoch != 1
            || control.next.is_some()
            || control.previous.is_some()
            || control.previous_last_issue_unix_seconds.is_some()
            || !control.revoked_kids.is_empty())
    {
        return Err(invalid(
            "credential.bootstrap",
            "revision one must use the exact frozen bootstrap values",
        ));
    }
    Ok(())
}

/// Validate only transition invariants visible in the two protobuf controls.
///
/// This structural check is not transition authorization. Lineage, ring UUID
/// and data-key non-reuse, prior-ring digest, retirement union, bound-key
/// revocation, and proof acknowledgements require later verified immutable-ring
/// and signed-proof evidence. A runtime caller must fail closed without it.
pub fn validate_credential_control_transition_structure(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
    kind: CredentialTransitionKind,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_credential_control(predecessor, prefix)?;
    validate_credential_control(successor, prefix)?;
    let revision = predecessor
        .control_revision
        .checked_add(1)
        .ok_or_else(|| invalid("credential.control_revision", "cannot wrap"))?;
    if successor.control_revision != revision {
        return Err(invalid(
            "credential.control_revision",
            "must increment by exactly one",
        ));
    }
    if successor.issuer_epoch < predecessor.issuer_epoch {
        return Err(invalid("credential.issuer_epoch", "must never decrease"));
    }
    if successor.acknowledgement_proof_digest == predecessor.acknowledgement_proof_digest {
        return Err(invalid(
            "credential.acknowledgement_proof_digest",
            "must bind the new transition proof",
        ));
    }
    if !is_sorted_subset(&predecessor.revoked_kids, &successor.revoked_kids) {
        return Err(invalid("credential.revoked_kids", "must be append-only"));
    }

    match kind {
        CredentialTransitionKind::InstallNext => validate_install_next(predecessor, successor),
        CredentialTransitionKind::PromoteNext => validate_promote_next(predecessor, successor),
        CredentialTransitionKind::RetirePrevious => {
            validate_retire_previous(predecessor, successor)
        }
        CredentialTransitionKind::RevokeKid => validate_revoke_kid(predecessor, successor),
        CredentialTransitionKind::VerifierSetUpdate => {
            validate_verifier_set_update(predecessor, successor)
        }
        CredentialTransitionKind::AcknowledgementUpdate => {
            validate_acknowledgement_update(predecessor, successor)
        }
    }
}

fn validate_verification_ring_root(
    field: &'static str,
    root: &VerificationRingRoot,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    bounded_bytes(field, &root.key, 1, 1_024)?;
    bounded_bytes(field, &root.object_version_id, 1, 1_024)?;
    exact_len(field, &root.digest, 32)?;
    if root.size == 0 || root.size > 65_536 {
        return Err(invalid(field, "size must be in 1..=65536"));
    }
    nonzero(field, root.ring_epoch)?;

    let parsed = parse_key(prefix, &root.key)
        .map_err(|_| invalid(field, "key is outside the closed V2 grammar"))?;
    if parsed.kind != V2KeyKind::VerificationKeyRing
        || parsed
            .content_digest
            .is_none_or(|digest| digest.as_bytes().as_slice() != root.digest.as_ref())
        || parsed.repository.is_some()
        || parsed.sequence.is_some()
    {
        return Err(invalid(field, "key does not bind this verification ring"));
    }
    Ok(())
}

fn validate_install_next(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    if predecessor.next.is_some()
        || successor.next.is_none()
        || predecessor.current != successor.current
        || predecessor.previous != successor.previous
        || predecessor.previous_last_issue_unix_seconds
            != successor.previous_last_issue_unix_seconds
        || predecessor.revoked_kids != successor.revoked_kids
        || predecessor.verifier_set_digest != successor.verifier_set_digest
        || predecessor.issuer_epoch != successor.issuer_epoch
    {
        return Err(invalid(
            "credential.install_next",
            "must add only one checked next root",
        ));
    }
    let candidate = successor.next.as_ref().expect("checked above");
    for root in [predecessor.current.as_ref(), predecessor.previous.as_ref()]
        .into_iter()
        .flatten()
    {
        if candidate.key == root.key || candidate.digest == root.digest {
            return Err(invalid(
                "credential.install_next",
                "must not reuse a bound ring root identity",
            ));
        }
    }
    Ok(())
}

fn validate_promote_next(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    let expected_current = predecessor
        .next
        .as_ref()
        .ok_or_else(|| invalid("credential.promote_next", "requires next"))?;
    let expected_previous = predecessor
        .current
        .as_ref()
        .ok_or_else(|| missing("credential.current"))?;
    if predecessor.previous.is_some()
        || predecessor.previous_last_issue_unix_seconds.is_some()
        || successor.current.as_ref() != Some(expected_current)
        || successor.previous.as_ref() != Some(expected_previous)
        || successor.next.is_some()
        || successor.previous_last_issue_unix_seconds.is_none()
        || predecessor.revoked_kids != successor.revoked_kids
        || predecessor.verifier_set_digest != successor.verifier_set_digest
        || successor.issuer_epoch != checked_increment(predecessor.issuer_epoch)?
    {
        return Err(invalid(
            "credential.promote_next",
            "must perform only the exact slot move and issuer-epoch increment",
        ));
    }
    Ok(())
}

fn validate_retire_previous(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    if predecessor.previous.is_none()
        || predecessor.previous_last_issue_unix_seconds.is_none()
        || successor.previous.is_some()
        || successor.previous_last_issue_unix_seconds.is_some()
        || predecessor.current != successor.current
        || predecessor.next != successor.next
        || predecessor.verifier_set_digest != successor.verifier_set_digest
    {
        return Err(invalid(
            "credential.retire_previous",
            "must remove only previous and its issue time while extending the deny set",
        ));
    }
    let grew = predecessor.revoked_kids != successor.revoked_kids;
    let expected_epoch = if grew {
        checked_increment(predecessor.issuer_epoch)?
    } else {
        predecessor.issuer_epoch
    };
    if successor.issuer_epoch != expected_epoch {
        return Err(invalid(
            "credential.issuer_epoch",
            "must increment exactly when retirement grows the deny set",
        ));
    }
    Ok(())
}

fn validate_revoke_kid(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    if predecessor.current != successor.current
        || predecessor.next != successor.next
        || predecessor.previous != successor.previous
        || predecessor.previous_last_issue_unix_seconds
            != successor.previous_last_issue_unix_seconds
        || predecessor.verifier_set_digest != successor.verifier_set_digest
        || successor.revoked_kids.len() != predecessor.revoked_kids.len() + 1
        || successor.issuer_epoch != checked_increment(predecessor.issuer_epoch)?
    {
        return Err(invalid(
            "credential.revoke_kid",
            "must append exactly one kid and increment issuer epoch",
        ));
    }
    Ok(())
}

fn validate_verifier_set_update(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    if !same_ring_state(predecessor, successor)
        || predecessor.revoked_kids != successor.revoked_kids
        || predecessor.issuer_epoch != successor.issuer_epoch
        || predecessor.verifier_set_digest == successor.verifier_set_digest
    {
        return Err(invalid(
            "credential.verifier_set_update",
            "must change only verifier-set and proof digests",
        ));
    }
    Ok(())
}

fn validate_acknowledgement_update(
    predecessor: &CredentialControl,
    successor: &CredentialControl,
) -> Result<(), ControlValidationError> {
    if !same_ring_state(predecessor, successor)
        || predecessor.revoked_kids != successor.revoked_kids
        || predecessor.issuer_epoch != successor.issuer_epoch
        || predecessor.verifier_set_digest != successor.verifier_set_digest
    {
        return Err(invalid(
            "credential.acknowledgement_update",
            "must change only control revision and proof digest",
        ));
    }
    Ok(())
}

fn same_ring_state(left: &CredentialControl, right: &CredentialControl) -> bool {
    left.current == right.current
        && left.next == right.next
        && left.previous == right.previous
        && left.previous_last_issue_unix_seconds == right.previous_last_issue_unix_seconds
}

fn is_sorted_subset(subset: &[bytes::Bytes], superset: &[bytes::Bytes]) -> bool {
    let mut candidate = superset.iter();
    subset
        .iter()
        .all(|expected| candidate.by_ref().any(|actual| actual == expected))
}

fn checked_increment(value: u64) -> Result<u64, ControlValidationError> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("credential.issuer_epoch", "cannot wrap"))
}

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

fn validate_repo_control_target(
    target: &super::LandedControlRef,
    identity: &RepositoryIdentity,
) -> Result<(), ControlValidationError> {
    bounded_ascii(
        "result.landed_control.repo_control_key",
        &target.repo_control_key,
        1,
        1024,
    )?;
    bounded_bytes(
        "result.landed_control.object_version_id",
        &target.object_version_id,
        1,
        1024,
    )?;
    exact_len("result.landed_control.digest", &target.digest, 32)?;
    nonzero("result.landed_control.size", target.size)?;
    let routing = RoutingDigest::of(&identity.canonical_path)
        .map_err(|_| invalid("result.identity.canonical_path", "is too long"))?;
    let suffix = format!(
        "v2/repositories/by-path/{}/repo_control.pb",
        routing.lower_hex()
    );
    let key = std::str::from_utf8(&target.repo_control_key)
        .map_err(|_| invalid("result.landed_control.repo_control_key", "must be ASCII"))?;
    let prefix = key.strip_suffix(&suffix).ok_or_else(|| {
        invalid(
            "result.landed_control.repo_control_key",
            "is not the derived control key",
        )
    })?;
    let prefix = DeploymentPrefix::parse(prefix).map_err(|_| {
        invalid(
            "result.landed_control.repo_control_key",
            "has an invalid prefix",
        )
    })?;
    if parse_key(&prefix, &target.repo_control_key)
        .map_err(|_| {
            invalid(
                "result.landed_control.repo_control_key",
                "is outside the V2 grammar",
            )
        })?
        .kind
        != V2KeyKind::RepoControl
    {
        return Err(invalid(
            "result.landed_control.repo_control_key",
            "is not a repo_control key",
        ));
    }
    Ok(())
}

fn validate_receipt_result_target(
    target: &TargetObjectRef,
    identity: &RepositoryIdentity,
    mutation_id: &[u8],
) -> Result<(), ControlValidationError> {
    let mut repository_uuid = [0u8; 16];
    repository_uuid.copy_from_slice(&identity.repository_uuid);
    let suffix = format!(
        "v2/repositories/by-id/{}/g{:016x}/receipts/results/{}.pb",
        hex::encode(repository_uuid),
        identity.generation,
        hex::encode(mutation_id)
    );
    let key = std::str::from_utf8(&target.key)
        .map_err(|_| invalid("receipt_catalog.row.result.key", "must be ASCII"))?;
    let prefix = key
        .strip_suffix(&suffix)
        .ok_or_else(|| invalid("receipt_catalog.row.result.key", "is not deterministic"))?;
    let prefix = DeploymentPrefix::parse(prefix)
        .map_err(|_| invalid("receipt_catalog.row.result.key", "has an invalid prefix"))?;
    let parsed = validate_target_any_repository_leaf(target, identity, &prefix)?;
    if parsed.kind != V2KeyKind::ReceiptResult {
        return Err(invalid(
            "receipt_catalog.row.result.key",
            "is not a receipt result key",
        ));
    }
    Ok(())
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

fn bounded_ascii(
    field: &'static str,
    value: &[u8],
    min: usize,
    max: usize,
) -> Result<(), ControlValidationError> {
    bounded_bytes(field, value, min, max)?;
    if !value.is_ascii() {
        return Err(invalid(field, "must be ASCII"));
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
    #[error("invalid V2 control field {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
}

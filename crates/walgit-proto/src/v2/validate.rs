use std::collections::{HashMap, HashSet};

use prost::Message;
use sha2::{Digest, Sha256};

use super::{
    BucketSafetyBinding, CAPACITY_SCHEMA_VERSION, CREDENTIAL_CONTROL_SCHEMA_VERSION,
    CapacityBinding, CapacityCommitBinding, CapacityConflictClass, CapacityControl,
    CapacityControlState, CapacityObjectRef, CapacityRedistribution, CapacityReservation,
    CapacityReservationState, CapacityShard, CapacityShardBaseline, CapacityShardBudget,
    CapacityShardBudgetProposal, CapacityTenantAccount, CatalogKind, CatalogRoot,
    CredentialControl, GrantRole, LandedControlRef, Lifecycle, MAX_CAPACITY_SHARD_BYTES,
    MAX_MUTATION_RESULT_BYTES, MAX_RECEIPT_CATALOG_BYTES, MAX_RESERVED_TTL_SECONDS,
    MAX_TENANT_CAPACITY_CATALOG_BYTES, MutationKind, MutationReceipt, MutationResult, ObjectFormat,
    PackRoot, RECEIPT_SCHEMA_VERSION, REPO_CONTROL_SCHEMA_VERSION, ReceiptCatalog,
    ReceiptCatalogRow, ReceiptState, ReclamationPhase, RedistributionPhase, RepoControl,
    RepositoryGrant, RepositoryIdentity, TargetObjectRef, TenantCapacityAllocation,
    TenantCapacityCatalogPage, VerificationRingRoot, Visibility, WalEntryKind, WalState,
    aborted_capacity_reservation::Proof as AbortedProof,
    capacity_commit_binding::Predecessor as CapacityCommitPredecessor,
    capacity_control::StatePayload as CapacityControlPayload,
    capacity_reservation::StatePayload as CapacityReservationPayload,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, ParsedV2Key, RepositoryKeyIdentity, RoutingDigest,
        V2KeyKind, capacity_shard_key, parse_key, repo_control_key,
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

/// Exact-loaded repository authority inputs for a capacity terminal proof.
pub struct LoadedRepoControlReceiptView<'a> {
    pub control: &'a RepoControl,
    pub observed_object: &'a LandedControlRef,
    pub receipt_catalog: &'a ReceiptCatalog,
}

/// Exact-loaded COMMITTING capacity-shard inputs for a terminal proof.
pub struct LoadedCommittingCapacityView<'a> {
    pub shard: &'a CapacityShard,
    pub observed_object: &'a CapacityObjectRef,
}

pub fn validate_tenant_capacity_catalog_page(
    page: &TenantCapacityCatalogPage,
) -> Result<(), ControlValidationError> {
    if page.schema_version != CAPACITY_SCHEMA_VERSION {
        return Err(invalid(
            "tenant_capacity_catalog.schema_version",
            "must be exactly 1",
        ));
    }
    if page.allocations.len() > 4_096 {
        return Err(invalid(
            "tenant_capacity_catalog.allocations",
            "exceeds 4096 entries",
        ));
    }
    if page
        .allocations
        .windows(2)
        .any(|pair| pair[0].tenant_id.as_ref() >= pair[1].tenant_id.as_ref())
    {
        return Err(invalid(
            "tenant_capacity_catalog.allocations",
            "must be binary-sorted and unique by tenant ID",
        ));
    }
    for allocation in &page.allocations {
        validate_tenant_capacity_allocation(allocation)?;
    }
    Ok(())
}

pub fn validate_tenant_capacity_catalog_object(
    page: &TenantCapacityCatalogPage,
    object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_tenant_capacity_catalog_page(page)?;
    validate_global_capacity_ref(
        object,
        prefix,
        V2KeyKind::TenantCapacityCatalog,
        None,
        MAX_TENANT_CAPACITY_CATALOG_BYTES,
        "tenant_capacity_catalog.object",
    )?;
    validate_exact_protobuf_object(
        object,
        &page.encode_to_vec(),
        "tenant_capacity_catalog.object",
    )
}

pub fn validate_capacity_shard(
    shard: &CapacityShard,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if shard.schema_version != CAPACITY_SCHEMA_VERSION {
        return Err(invalid(
            "capacity_shard.schema_version",
            "must be exactly 1",
        ));
    }
    nonzero("capacity_shard.control_revision", shard.control_revision)?;
    let shard_number = u8::try_from(shard.shard)
        .map_err(|_| invalid("capacity_shard.shard", "must be in 0..=255"))?;
    nonzero("capacity_shard.allocation_epoch", shard.allocation_epoch)?;
    nonzero("capacity_shard.budget_bytes", shard.budget_bytes)?;
    validate_capacity_tenant_accounts(&shard.tenant_accounts, shard.budget_bytes)?;
    if shard.reservations.len() > 4_096 {
        return Err(invalid(
            "capacity_shard.reservations",
            "exceeds 4096 entries",
        ));
    }
    if shard
        .reservations
        .windows(2)
        .any(|pair| pair[0].reservation_id.as_ref() >= pair[1].reservation_id.as_ref())
    {
        return Err(invalid(
            "capacity_shard.reservations",
            "must be binary-sorted and unique by reservation ID",
        ));
    }

    let mut total_charged = 0u64;
    let mut tenant_totals = HashMap::<Vec<u8>, u64>::new();
    let mut active_repositories = HashSet::<(Vec<u8>, u64)>::new();
    let mut repository_mutations = HashSet::<(Vec<u8>, u64, Vec<u8>)>::new();
    for reservation in &shard.reservations {
        let state = validate_capacity_reservation(
            reservation,
            shard_number,
            shard.allocation_epoch,
            prefix,
        )?;
        let identity = reservation
            .identity
            .as_ref()
            .ok_or_else(|| missing("capacity_reservation.identity"))?;
        if matches!(
            state,
            CapacityReservationState::Reserved | CapacityReservationState::Committing
        ) && !active_repositories
            .insert((identity.repository_uuid.to_vec(), identity.generation))
        {
            return Err(invalid(
                "capacity_shard.reservations",
                "contains more than one nonterminal reservation for a repository",
            ));
        }
        if let Some(mutation_id) = capacity_reservation_commit_mutation_id(reservation)
            && !repository_mutations.insert((
                identity.repository_uuid.to_vec(),
                identity.generation,
                mutation_id.to_vec(),
            ))
        {
            return Err(invalid(
                "capacity_shard.reservations",
                "reuses one repository mutation across reservation rows",
            ));
        }
        if !matches!(state, CapacityReservationState::Aborted) {
            total_charged = total_charged
                .checked_add(reservation.byte_count)
                .ok_or_else(|| invalid("capacity_shard.reservations", "byte total overflows"))?;
            if total_charged > shard.budget_bytes {
                return Err(invalid(
                    "capacity_shard.reservations",
                    "charged bytes exceed the shard budget",
                ));
            }
            let entry = tenant_totals
                .entry(reservation.tenant_id.to_vec())
                .or_default();
            *entry = entry
                .checked_add(reservation.byte_count)
                .ok_or_else(|| invalid("capacity_shard.reservations", "tenant total overflows"))?;
        }
    }
    if tenant_totals.len() != shard.tenant_accounts.len() {
        return Err(invalid(
            "capacity_shard.tenant_accounts",
            "must contain exactly the tenants with nonzero retained usage",
        ));
    }
    for account in &shard.tenant_accounts {
        let used = tenant_totals
            .get(account.tenant_id.as_ref())
            .ok_or_else(|| {
                invalid(
                    "capacity_shard.tenant_accounts",
                    "contains an extraneous tenant account",
                )
            })?;
        if *used > account.current_slice_bytes {
            return Err(invalid(
                "capacity_shard.tenant_accounts",
                "retained usage exceeds the current tenant slice",
            ));
        }
    }
    Ok(())
}

fn capacity_reservation_commit_mutation_id(reservation: &CapacityReservation) -> Option<&[u8]> {
    match reservation.state_payload.as_ref()? {
        CapacityReservationPayload::Committing(value) => value
            .commit
            .as_ref()
            .map(|commit| commit.mutation_id.as_ref()),
        CapacityReservationPayload::Charged(value) => value
            .commit
            .as_ref()
            .map(|commit| commit.mutation_id.as_ref()),
        CapacityReservationPayload::Aborted(value) => match value.proof.as_ref()? {
            AbortedProof::ConflictingCommit(conflict) => conflict
                .commit
                .as_ref()
                .map(|commit| commit.mutation_id.as_ref()),
            AbortedProof::Expired(_) => None,
        },
        CapacityReservationPayload::Reserved(_) => None,
    }
}

pub fn validate_capacity_shard_object(
    shard: &CapacityShard,
    object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_shard(shard, prefix)?;
    let shard_number = u8::try_from(shard.shard)
        .map_err(|_| invalid("capacity_shard.shard", "must be in 0..=255"))?;
    let expected = capacity_shard_key(prefix, shard_number)
        .map_err(|_| invalid("capacity_shard.object.key", "cannot be derived"))?;
    validate_global_capacity_ref(
        object,
        prefix,
        V2KeyKind::CapacityShard,
        Some(expected.as_bytes()),
        MAX_CAPACITY_SHARD_BYTES,
        "capacity_shard.object",
    )?;
    validate_exact_protobuf_object(object, &shard.encode_to_vec(), "capacity_shard.object")
}

/// Exact-bind one loaded historical epoch-start shard body to the matching
/// retained `CapacityShardBudget` proof in either STABLE or PREPARING.
///
/// This proof is deliberately distinct from the mutable current-shard object
/// gate. During PREPARING/APPLYING, a drained baseline can have newer provider
/// metadata than this retained epoch-start proof.
pub fn validate_capacity_retained_shard_budget_object(
    control: &CapacityControl,
    shard: &CapacityShard,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_control(control, prefix)?;
    let shard_index = capacity_shard_index(shard.shard)?;
    let budget = &control.shard_budgets[shard_index];
    validate_capacity_shard_object(
        shard,
        budget
            .shard_object
            .as_ref()
            .ok_or_else(|| missing("capacity_control.shard_budget.shard_object"))?,
        prefix,
    )?;
    validate_retained_capacity_shard_fields(control, shard, budget)
}

/// Exact-bind one loaded mutable current shard body to observed provider
/// metadata and to the matching retained control epoch and shard budget.
///
/// The observed metadata is not compared with the historical epoch-start
/// proof in `CapacityShardBudget`. Terminal transitions can legitimately make
/// the mutable object's version, digest, and size newer than that proof.
pub fn validate_capacity_current_shard_object(
    control: &CapacityControl,
    shard: &CapacityShard,
    observed_object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_control(control, prefix)?;
    validate_capacity_shard_object(shard, observed_object, prefix)?;
    let shard_index = capacity_shard_index(shard.shard)?;
    validate_retained_capacity_shard_fields(control, shard, &control.shard_budgets[shard_index])
}

fn validate_retained_capacity_shard_fields(
    control: &CapacityControl,
    shard: &CapacityShard,
    budget: &CapacityShardBudget,
) -> Result<(), ControlValidationError> {
    if budget.shard != shard.shard {
        return Err(invalid(
            "capacity_control.shard_budget.shard",
            "does not equal the loaded shard number",
        ));
    }
    if shard.allocation_epoch != control.allocation_epoch {
        return Err(invalid(
            "capacity_shard.allocation_epoch",
            "does not equal the retained current control epoch",
        ));
    }
    if shard.budget_bytes != budget.budget_bytes {
        return Err(invalid(
            "capacity_shard.budget_bytes",
            "does not equal the retained current control shard budget",
        ));
    }
    Ok(())
}

fn capacity_shard_index(shard: u32) -> Result<usize, ControlValidationError> {
    usize::try_from(shard)
        .ok()
        .filter(|index| *index < 256)
        .ok_or_else(|| invalid("capacity_shard.shard", "must be in 0..=255"))
}

/// Cross-check current shard tenant accounts against one exact-loaded tenant
/// catalog page. The page's exact root binding is validated separately by
/// [`validate_capacity_control_catalogs`].
pub fn validate_capacity_shard_catalog(
    shard: &CapacityShard,
    page: &TenantCapacityCatalogPage,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_shard(shard, prefix)?;
    validate_tenant_capacity_catalog_page(page)?;
    let shard_index = capacity_shard_index(shard.shard)?;
    for account in &shard.tenant_accounts {
        let allocation_index = page
            .allocations
            .binary_search_by(|allocation| allocation.tenant_id.cmp(&account.tenant_id))
            .map_err(|_| {
                invalid(
                    "capacity_shard.tenant_accounts",
                    "tenant is absent from the current allocation page",
                )
            })?;
        if page.allocations[allocation_index].slices[shard_index].byte_count
            != account.current_slice_bytes
        {
            return Err(invalid(
                "capacity_shard.tenant_account.current_slice_bytes",
                "does not equal the exact current catalog slice",
            ));
        }
    }
    for reservation in &shard.reservations {
        if reservation.allocation_epoch != shard.allocation_epoch
            || reservation.state == CapacityReservationState::Aborted as i32
        {
            continue;
        }
        let account_index = shard
            .tenant_accounts
            .binary_search_by(|account| account.tenant_id.cmp(&reservation.tenant_id))
            .map_err(|_| {
                invalid(
                    "capacity_shard.reservations",
                    "current reservation tenant has no current account",
                )
            })?;
        if reservation.tenant_slice_bytes
            != shard.tenant_accounts[account_index].current_slice_bytes
        {
            return Err(invalid(
                "capacity_reservation.tenant_slice_bytes",
                "does not equal the exact current account and catalog slice",
            ));
        }
    }
    Ok(())
}

pub fn validate_capacity_control(
    control: &CapacityControl,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if control.schema_version != CAPACITY_SCHEMA_VERSION {
        return Err(invalid(
            "capacity_control.schema_version",
            "must be exactly 1",
        ));
    }
    nonzero(
        "capacity_control.control_revision",
        control.control_revision,
    )?;
    let state = CapacityControlState::try_from(control.state)
        .map_err(|_| invalid("capacity_control.state", "is unknown"))?;
    if state == CapacityControlState::Unspecified {
        return Err(invalid(
            "capacity_control.state",
            "must be a known nonzero state",
        ));
    }
    let writer = control
        .writer
        .as_ref()
        .ok_or_else(|| missing("capacity_control.writer"))?;
    bounded_bytes("capacity_control.writer.holder", &writer.holder, 1, 256)?;
    nonzero("capacity_control.writer.epoch", writer.epoch)?;
    nonzero(
        "capacity_control.allocation_epoch",
        control.allocation_epoch,
    )?;
    nonzero(
        "capacity_control.global_allocatable_bytes",
        control.global_allocatable_bytes,
    )?;
    validate_global_capacity_ref(
        control
            .tenant_catalog
            .as_ref()
            .ok_or_else(|| missing("capacity_control.tenant_catalog"))?,
        prefix,
        V2KeyKind::TenantCapacityCatalog,
        None,
        MAX_TENANT_CAPACITY_CATALOG_BYTES,
        "capacity_control.tenant_catalog",
    )?;
    validate_shard_budgets(
        &control.shard_budgets,
        control.global_allocatable_bytes,
        prefix,
    )?;

    match (state, control.state_payload.as_ref()) {
        (CapacityControlState::Stable, Some(CapacityControlPayload::Stable(_))) => {}
        (
            CapacityControlState::Preparing,
            Some(CapacityControlPayload::Redistribution(redistribution)),
        ) => validate_capacity_redistribution(control, redistribution, prefix)?,
        (CapacityControlState::Stable, _) => {
            return Err(invalid(
                "capacity_control.state_payload",
                "STABLE requires the stable payload",
            ));
        }
        (CapacityControlState::Preparing, _) => {
            return Err(invalid(
                "capacity_control.state_payload",
                "PREPARING requires the redistribution payload",
            ));
        }
        (CapacityControlState::Unspecified, _) => unreachable!(),
    }
    Ok(())
}

/// Validate one capacity control together with the exact immutable tenant
/// catalog bodies that its current and optional target plans root.
///
/// Local control validation cannot prove referenced page contents. A future
/// controller must call this helper after exact strict loads and before
/// publishing a plan or admitting a reservation.
pub fn validate_capacity_control_catalogs(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    target_page: Option<&TenantCapacityCatalogPage>,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_current_catalog(control, current_page, prefix)?;

    match (CapacityControlState::try_from(control.state), target_page) {
        (Ok(CapacityControlState::Stable), None) => Ok(()),
        (Ok(CapacityControlState::Stable), Some(_)) => Err(invalid(
            "capacity_control.target_tenant_catalog",
            "STABLE must not supply a target tenant page",
        )),
        (Ok(CapacityControlState::Preparing), Some(target_page)) => {
            let Some(CapacityControlPayload::Redistribution(redistribution)) =
                control.state_payload.as_ref()
            else {
                return Err(invalid(
                    "capacity_control.state_payload",
                    "PREPARING requires redistribution",
                ));
            };
            validate_tenant_capacity_catalog_object(
                target_page,
                redistribution
                    .target_tenant_catalog
                    .as_ref()
                    .ok_or_else(|| {
                        missing("capacity_control.redistribution.target_tenant_catalog")
                    })?,
                prefix,
            )?;
            validate_capacity_catalog_columns(
                target_page,
                redistribution
                    .target_shard_budgets
                    .iter()
                    .map(|budget| budget.budget_bytes),
                redistribution.target_global_allocatable_bytes,
                "capacity_control.redistribution.target_tenant_catalog",
            )
        }
        (Ok(CapacityControlState::Preparing), None) => Err(missing(
            "capacity_control.redistribution.target_tenant_catalog_body",
        )),
        _ => Err(invalid("capacity_control.state", "is unknown")),
    }
}

/// Validate the complete current capacity view used by future admission or a
/// terminal transition: retained control plan, exact tenant page, current
/// mutable shard, and every current tenant account.
///
/// Admission additionally requires `control.state == STABLE`. PREPARING uses
/// this same gate only for terminal drainage. The shard provider version is
/// deliberately not compared with the historical STABLE epoch-start proof.
pub fn validate_capacity_current_shard_view(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    shard: &CapacityShard,
    observed_object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_current_catalog(control, current_page, prefix)?;
    validate_capacity_current_shard_object(control, shard, observed_object, prefix)?;
    validate_capacity_shard_catalog(shard, current_page, prefix)?;
    Ok(())
}

/// Validate the exact current view and require the only state that can admit a
/// new reservation. PREPARING callers must use the drainage-only helper above.
pub fn validate_capacity_admission_view(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    shard: &CapacityShard,
    observed_object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_current_shard_view(control, current_page, shard, observed_object, prefix)?;
    if CapacityControlState::try_from(control.state) != Ok(CapacityControlState::Stable) {
        return Err(invalid(
            "capacity_control.state",
            "admission requires STABLE",
        ));
    }
    Ok(())
}

/// Compose the complete pre-CAS gate for one STABLE shard successor.
///
/// Lower-level object, catalog, and transition validators are insufficient on
/// their own: publication must bind the exact current view and prove the
/// candidate against the same control plan and tenant page.
pub fn validate_capacity_stable_admission_successor(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    previous: &CapacityShard,
    observed_previous_object: &CapacityObjectRef,
    successor: &CapacityShard,
    observed_now_unix_seconds: u64,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_admission_view(
        control,
        current_page,
        previous,
        observed_previous_object,
        prefix,
    )?;
    validate_capacity_shard_successor(previous, successor, observed_now_unix_seconds, prefix)?;
    if previous == successor {
        return Err(invalid(
            "capacity_shard.successor",
            "pre-CAS publication requires a real successor",
        ));
    }
    validate_capacity_candidate_current_plan(control, current_page, successor, prefix)
}

/// Compose the complete pre-CAS gate for terminal drainage during
/// PREPARING/DRAINING. It rejects insertions and all nonterminal successors.
pub fn validate_capacity_preparing_drainage_successor(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    previous: &CapacityShard,
    observed_previous_object: &CapacityObjectRef,
    successor: &CapacityShard,
    observed_now_unix_seconds: u64,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_current_shard_view(
        control,
        current_page,
        previous,
        observed_previous_object,
        prefix,
    )?;
    let Some(CapacityControlPayload::Redistribution(redistribution)) =
        control.state_payload.as_ref()
    else {
        return Err(invalid(
            "capacity_control.state_payload",
            "drainage requires PREPARING/DRAINING",
        ));
    };
    if control.state != CapacityControlState::Preparing as i32
        || redistribution.phase != RedistributionPhase::Draining as i32
    {
        return Err(invalid(
            "capacity_control.redistribution.phase",
            "drainage requires PREPARING/DRAINING",
        ));
    }
    validate_capacity_shard_successor(previous, successor, observed_now_unix_seconds, prefix)?;
    validate_capacity_candidate_current_plan(control, current_page, successor, prefix)?;
    let (previous_state, successor_state) =
        changed_capacity_reservation_states(previous, successor)?;
    if !matches!(
        (previous_state, successor_state),
        (
            CapacityReservationState::Reserved,
            CapacityReservationState::Aborted,
        ) | (
            CapacityReservationState::Committing,
            CapacityReservationState::Charged | CapacityReservationState::Aborted,
        )
    ) {
        return Err(invalid(
            "capacity_shard.successor",
            "PREPARING/DRAINING permits only a terminal reservation transition",
        ));
    }
    Ok(())
}

fn validate_capacity_candidate_current_plan(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    successor: &CapacityShard,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_shard_catalog(successor, current_page, prefix)?;
    let shard_index = capacity_shard_index(successor.shard)?;
    validate_retained_capacity_shard_fields(control, successor, &control.shard_budgets[shard_index])
}

fn changed_capacity_reservation_states(
    previous: &CapacityShard,
    successor: &CapacityShard,
) -> Result<(CapacityReservationState, CapacityReservationState), ControlValidationError> {
    let mut changed = None;
    for candidate in &successor.reservations {
        let Ok(index) = previous
            .reservations
            .binary_search_by(|row| row.reservation_id.cmp(&candidate.reservation_id))
        else {
            return Err(invalid(
                "capacity_shard.successor",
                "PREPARING/DRAINING cannot insert a reservation",
            ));
        };
        let prior = &previous.reservations[index];
        if prior != candidate {
            if changed.is_some() {
                return Err(invalid(
                    "capacity_shard.successor",
                    "must contain exactly one reservation transition",
                ));
            }
            changed = Some((
                CapacityReservationState::try_from(prior.state)
                    .map_err(|_| invalid("capacity_reservation.state", "is unknown"))?,
                CapacityReservationState::try_from(candidate.state)
                    .map_err(|_| invalid("capacity_reservation.state", "is unknown"))?,
            ));
        }
    }
    changed.ok_or_else(|| {
        invalid(
            "capacity_shard.successor",
            "pre-CAS publication requires one reservation transition",
        )
    })
}

/// Validate an exact retry or one legal reservation transition between two
/// exact capacity-shard states. The caller supplies its observed wall-clock
/// seconds; this validator never reads a clock.
pub fn validate_capacity_shard_successor(
    previous: &CapacityShard,
    successor: &CapacityShard,
    observed_now_unix_seconds: u64,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_shard(previous, prefix)?;
    validate_capacity_shard(successor, prefix)?;
    if previous == successor {
        return Ok(());
    }
    if previous.schema_version != successor.schema_version
        || previous.shard != successor.shard
        || previous.allocation_epoch != successor.allocation_epoch
        || previous.budget_bytes != successor.budget_bytes
    {
        return Err(invalid(
            "capacity_shard.successor",
            "cannot change schema, shard, allocation epoch, or budget",
        ));
    }
    let expected_revision = previous.control_revision.checked_add(1).ok_or_else(|| {
        invalid(
            "capacity_shard.control_revision",
            "cannot advance past u64::MAX",
        )
    })?;
    if successor.control_revision != expected_revision {
        return Err(invalid(
            "capacity_shard.control_revision",
            "must advance by exactly one for a real successor",
        ));
    }

    let mut previous_index = 0usize;
    let mut successor_index = 0usize;
    let mut effect = None;
    while previous_index < previous.reservations.len()
        || successor_index < successor.reservations.len()
    {
        match (
            previous.reservations.get(previous_index),
            successor.reservations.get(successor_index),
        ) {
            (Some(before), Some(after)) => match before.reservation_id.cmp(&after.reservation_id) {
                std::cmp::Ordering::Equal => {
                    if before != after {
                        set_capacity_transition_effect(
                            &mut effect,
                            validate_capacity_reservation_successor(
                                before,
                                after,
                                observed_now_unix_seconds,
                            )?,
                        )?;
                    }
                    previous_index += 1;
                    successor_index += 1;
                }
                std::cmp::Ordering::Less => {
                    return Err(invalid(
                        "capacity_shard.reservations",
                        "a successor cannot remove a retained reservation row",
                    ));
                }
                std::cmp::Ordering::Greater => {
                    set_capacity_transition_effect(
                        &mut effect,
                        validate_new_reserved_capacity_reservation(
                            after,
                            observed_now_unix_seconds,
                        )?,
                    )?;
                    successor_index += 1;
                }
            },
            (Some(_), None) => {
                return Err(invalid(
                    "capacity_shard.reservations",
                    "a successor cannot remove a retained reservation row",
                ));
            }
            (None, Some(after)) => {
                set_capacity_transition_effect(
                    &mut effect,
                    validate_new_reserved_capacity_reservation(after, observed_now_unix_seconds)?,
                )?;
                successor_index += 1;
            }
            (None, None) => break,
        }
    }
    let effect = effect.ok_or_else(|| {
        invalid(
            "capacity_shard.successor",
            "a revision advance requires exactly one reservation transition",
        )
    })?;
    validate_capacity_successor_accounts(previous, successor, &effect)
}

#[derive(Clone, Debug)]
enum CapacityTransitionEffect {
    AddReserved {
        tenant_id: Vec<u8>,
        tenant_slice_bytes: u64,
    },
    PreserveAccount {
        tenant_id: Vec<u8>,
    },
    ReleaseAccount {
        tenant_id: Vec<u8>,
    },
}

fn set_capacity_transition_effect(
    current: &mut Option<CapacityTransitionEffect>,
    candidate: CapacityTransitionEffect,
) -> Result<(), ControlValidationError> {
    if current.replace(candidate).is_some() {
        return Err(invalid(
            "capacity_shard.reservations",
            "a successor must contain exactly one reservation transition",
        ));
    }
    Ok(())
}

fn validate_new_reserved_capacity_reservation(
    reservation: &CapacityReservation,
    observed_now_unix_seconds: u64,
) -> Result<CapacityTransitionEffect, ControlValidationError> {
    let Some(CapacityReservationPayload::Reserved(reserved)) = reservation.state_payload.as_ref()
    else {
        return Err(invalid(
            "capacity_shard.reservations",
            "a new row must start in RESERVED",
        ));
    };
    if reservation.state != CapacityReservationState::Reserved as i32
        || reserved.created_at_unix_seconds > observed_now_unix_seconds
        || observed_now_unix_seconds >= reserved.expires_at_unix_seconds
    {
        return Err(invalid(
            "capacity_reservation.reserved",
            "creation requires created_at <= observed now < expires_at",
        ));
    }
    Ok(CapacityTransitionEffect::AddReserved {
        tenant_id: reservation.tenant_id.to_vec(),
        tenant_slice_bytes: reservation.tenant_slice_bytes,
    })
}

fn validate_capacity_reservation_successor(
    previous: &CapacityReservation,
    successor: &CapacityReservation,
    observed_now_unix_seconds: u64,
) -> Result<CapacityTransitionEffect, ControlValidationError> {
    if previous.reservation_id != successor.reservation_id
        || previous.identity != successor.identity
        || previous.tenant_id != successor.tenant_id
        || previous.allocation_epoch != successor.allocation_epoch
        || previous.byte_count != successor.byte_count
        || previous.tenant_slice_bytes != successor.tenant_slice_bytes
    {
        return Err(invalid(
            "capacity_reservation.successor",
            "cannot change immutable reservation fields",
        ));
    }
    let previous_state = CapacityReservationState::try_from(previous.state)
        .map_err(|_| invalid("capacity_reservation.state", "is unknown"))?;
    let successor_state = CapacityReservationState::try_from(successor.state)
        .map_err(|_| invalid("capacity_reservation.state", "is unknown"))?;
    if previous_state == successor_state {
        return Err(invalid(
            "capacity_reservation.successor",
            "a same-state retry must be byte-exact",
        ));
    }

    let tenant_id = previous.tenant_id.to_vec();
    match (
        previous_state,
        successor_state,
        previous.state_payload.as_ref(),
        successor.state_payload.as_ref(),
    ) {
        (
            CapacityReservationState::Reserved,
            CapacityReservationState::Committing,
            Some(CapacityReservationPayload::Reserved(reserved)),
            Some(CapacityReservationPayload::Committing(_)),
        ) => {
            if reserved.created_at_unix_seconds > observed_now_unix_seconds
                || observed_now_unix_seconds >= reserved.expires_at_unix_seconds
            {
                return Err(invalid(
                    "capacity_reservation.committing",
                    "requires reserved.created_at <= observed now < reserved.expires_at",
                ));
            }
            Ok(CapacityTransitionEffect::PreserveAccount { tenant_id })
        }
        (
            CapacityReservationState::Reserved,
            CapacityReservationState::Aborted,
            Some(CapacityReservationPayload::Reserved(reserved)),
            Some(CapacityReservationPayload::Aborted(aborted)),
        ) => {
            let Some(AbortedProof::Expired(expired)) = aborted.proof.as_ref() else {
                return Err(invalid(
                    "capacity_reservation.aborted.proof",
                    "RESERVED can abort only with its exact expiry proof",
                ));
            };
            if expired.created_at_unix_seconds != reserved.created_at_unix_seconds
                || expired.expires_at_unix_seconds != reserved.expires_at_unix_seconds
                || expired.observed_now_unix_seconds != observed_now_unix_seconds
                || observed_now_unix_seconds < reserved.expires_at_unix_seconds
            {
                return Err(invalid(
                    "capacity_reservation.aborted.expired",
                    "must repeat the exact window and bind the caller-observed expiry time",
                ));
            }
            Ok(CapacityTransitionEffect::ReleaseAccount { tenant_id })
        }
        (
            CapacityReservationState::Committing,
            CapacityReservationState::Charged,
            Some(CapacityReservationPayload::Committing(committing)),
            Some(CapacityReservationPayload::Charged(charged)),
        ) if committing.commit == charged.commit => {
            Ok(CapacityTransitionEffect::PreserveAccount { tenant_id })
        }
        (
            CapacityReservationState::Committing,
            CapacityReservationState::Aborted,
            Some(CapacityReservationPayload::Committing(committing)),
            Some(CapacityReservationPayload::Aborted(aborted)),
        ) => {
            let Some(AbortedProof::ConflictingCommit(conflict)) = aborted.proof.as_ref() else {
                return Err(invalid(
                    "capacity_reservation.aborted.proof",
                    "COMMITTING can abort only with a conflicting-commit proof",
                ));
            };
            if committing.commit != conflict.commit {
                return Err(invalid(
                    "capacity_reservation.aborted.conflicting_commit.commit",
                    "must repeat the exact COMMITTING binding",
                ));
            }
            Ok(CapacityTransitionEffect::ReleaseAccount { tenant_id })
        }
        _ => Err(invalid(
            "capacity_reservation.successor",
            "is not a legal reservation transition",
        )),
    }
}

fn validate_capacity_successor_accounts(
    previous: &CapacityShard,
    successor: &CapacityShard,
    effect: &CapacityTransitionEffect,
) -> Result<(), ControlValidationError> {
    let mut expected = previous.tenant_accounts.clone();
    match effect {
        CapacityTransitionEffect::PreserveAccount { tenant_id } => {
            if expected != successor.tenant_accounts {
                return Err(invalid(
                    "capacity_shard.tenant_accounts",
                    "must remain byte-exact for this transition",
                ));
            }
            if !successor
                .tenant_accounts
                .iter()
                .any(|account| account.tenant_id.as_ref() == tenant_id)
            {
                return Err(invalid(
                    "capacity_shard.tenant_accounts",
                    "transition tenant account is missing",
                ));
            }
        }
        CapacityTransitionEffect::AddReserved {
            tenant_id,
            tenant_slice_bytes,
        } => match expected.binary_search_by(|account| account.tenant_id.as_ref().cmp(tenant_id)) {
            Ok(index) => {
                if expected[index].current_slice_bytes != *tenant_slice_bytes {
                    return Err(invalid(
                        "capacity_shard.tenant_accounts",
                        "new reservation slice differs from the current tenant account",
                    ));
                }
            }
            Err(index) => expected.insert(
                index,
                CapacityTenantAccount {
                    tenant_id: tenant_id.clone().into(),
                    current_slice_bytes: *tenant_slice_bytes,
                },
            ),
        },
        CapacityTransitionEffect::ReleaseAccount { tenant_id } => {
            let still_used = successor.reservations.iter().any(|reservation| {
                reservation.tenant_id.as_ref() == tenant_id
                    && reservation.state != CapacityReservationState::Aborted as i32
            });
            if !still_used {
                let index = expected
                    .binary_search_by(|account| account.tenant_id.as_ref().cmp(tenant_id))
                    .map_err(|_| {
                        invalid(
                            "capacity_shard.tenant_accounts",
                            "released reservation tenant account is missing",
                        )
                    })?;
                expected.remove(index);
            }
        }
    }
    if expected != successor.tenant_accounts {
        return Err(invalid(
            "capacity_shard.tenant_accounts",
            "contains a change outside the selected reservation transition",
        ));
    }
    Ok(())
}

/// Bind a prepared capacity receipt to the exact COMMITTING shard body that
/// it names. The shard body must be strict-loaded with the supplied provider
/// metadata, and it must contain the exact reservation row.
pub fn validate_capacity_receipt_obligation(
    committing_reservation: &CapacityReservation,
    committing_shard: &CapacityShard,
    observed_shard_object: &CapacityObjectRef,
    receipt: &MutationReceipt,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_shard_object(committing_shard, observed_shard_object, prefix)?;
    if committing_reservation.state != CapacityReservationState::Committing as i32 {
        return Err(invalid(
            "capacity_reservation.state",
            "receipt obligation requires a COMMITTING reservation",
        ));
    }
    let Some(CapacityReservationPayload::Committing(committing)) =
        committing_reservation.state_payload.as_ref()
    else {
        return Err(invalid(
            "capacity_reservation.state_payload",
            "receipt obligation requires the COMMITTING payload",
        ));
    };
    let rooted_reservation = committing_shard
        .reservations
        .binary_search_by(|candidate| {
            candidate
                .reservation_id
                .cmp(&committing_reservation.reservation_id)
        })
        .ok()
        .and_then(|index| committing_shard.reservations.get(index))
        .ok_or_else(|| {
            invalid(
                "capacity_shard.reservations",
                "does not contain the receipt reservation",
            )
        })?;
    if rooted_reservation != committing_reservation {
        return Err(invalid(
            "capacity_shard.reservations",
            "does not contain the exact COMMITTING reservation",
        ));
    }
    validate_mutation_receipt(receipt)?;
    if receipt.identity != committing_reservation.identity {
        return Err(invalid(
            "receipt.identity",
            "does not equal the capacity reservation identity",
        ));
    }
    let commit = committing
        .commit
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.committing.commit"))?;
    if receipt.mutation_id != commit.mutation_id
        || receipt.kind != commit.kind
        || receipt.writer_epoch != commit.writer_epoch
        || !capacity_commit_predecessor_matches_receipt(commit, receipt)
    {
        return Err(invalid(
            "receipt",
            "does not equal the prepared capacity commit binding",
        ));
    }
    let Some(CapacityObligationChoice::Capacity(obligation)) = receipt.capacity_obligation.as_ref()
    else {
        return Err(invalid(
            "receipt.capacity_obligation",
            "must carry the exact capacity obligation",
        ));
    };
    if obligation.allocation_epoch != committing_reservation.allocation_epoch
        || obligation.shard_key != observed_shard_object.key
        || obligation.shard_object_version_id != observed_shard_object.object_version_id
        || obligation.reservation_id != committing_reservation.reservation_id
        || obligation.tenant_slice_bytes != committing_reservation.tenant_slice_bytes
        || obligation.mutation_id != commit.mutation_id
        || obligation.byte_count != committing_reservation.byte_count
    {
        return Err(invalid(
            "receipt.capacity",
            "does not equal the exact COMMITTING shard reservation and object",
        ));
    }
    Ok(())
}

fn capacity_commit_predecessor_matches_receipt(
    commit: &CapacityCommitBinding,
    receipt: &MutationReceipt,
) -> bool {
    match (&commit.predecessor, &receipt.predecessor) {
        (
            Some(CapacityCommitPredecessor::NoPriorControl(_)),
            Some(Predecessor::NoPriorControl(_)),
        ) => true,
        (
            Some(CapacityCommitPredecessor::PriorControl(commit_prior)),
            Some(Predecessor::PriorControl(receipt_prior)),
        ) => commit_prior == receipt_prior,
        _ => false,
    }
}

/// Exact-bind one CHARGED reservation proof to the prior COMMITTING shard,
/// its rooted mutation receipt, the landed `RepoControl` body, and provider
/// metadata observed for both exact loads.
pub fn validate_capacity_charged_repo_control(
    reservation: &CapacityReservation,
    landed: LoadedRepoControlReceiptView<'_>,
    committing: LoadedCommittingCapacityView<'_>,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_terminal_capacity_reservation(reservation, prefix)?;
    let Some(CapacityReservationPayload::Charged(charged)) = reservation.state_payload.as_ref()
    else {
        return Err(invalid("capacity_reservation.state", "must be CHARGED"));
    };
    let commit = charged
        .commit
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.charged.commit"))?;
    let kind = MutationKind::try_from(commit.kind)
        .map_err(|_| invalid("capacity_commit.kind", "is unknown"))?;
    let writer_epoch = if kind == MutationKind::WriterTakeover {
        commit.writer_epoch.checked_add(1).ok_or_else(|| {
            invalid(
                "capacity_commit.writer_epoch",
                "cannot advance past u64::MAX",
            )
        })?
    } else {
        commit.writer_epoch
    };
    validate_exact_landed_capacity_repo_control(
        reservation,
        landed.control,
        charged
            .landed_control
            .as_ref()
            .ok_or_else(|| missing("capacity_reservation.charged.landed_control"))?,
        landed.observed_object,
        CapacityRepoControlExpectation {
            mutation_id: &commit.mutation_id,
            require_reservation_identity: true,
            writer_epoch: CapacityWriterEpochExpectation::Exact(writer_epoch),
        },
        prefix,
    )?;
    validate_repo_control_receipt_catalog(landed.control, landed.receipt_catalog, prefix)?;
    let row = receipt_catalog_row(landed.receipt_catalog, &commit.mutation_id)?;
    let committing_reservation = committing_shard_reservation(committing.shard, reservation)?;
    validate_capacity_reservation_successor(committing_reservation, reservation, 0)?;
    validate_capacity_receipt_obligation(
        committing_reservation,
        committing.shard,
        committing.observed_object,
        row.receipt
            .as_ref()
            .ok_or_else(|| missing("receipt_catalog.row.receipt"))?,
        prefix,
    )
}

/// Exact-bind one conflicting-commit ABORTED proof to the strict-loaded
/// conflicting `RepoControl`, exact current receipt catalog, prepared receipt,
/// and prior COMMITTING shard. The closed conflict class is accepted only when
/// the loaded control corroborates its object-version and writer-epoch cell.
pub fn validate_capacity_conflicting_repo_control(
    reservation: &CapacityReservation,
    conflicting: LoadedRepoControlReceiptView<'_>,
    expected_receipt: &MutationReceipt,
    committing: LoadedCommittingCapacityView<'_>,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_terminal_capacity_reservation(reservation, prefix)?;
    let Some(CapacityReservationPayload::Aborted(aborted)) = reservation.state_payload.as_ref()
    else {
        return Err(invalid(
            "capacity_reservation.state",
            "must be ABORTED with a conflicting-commit proof",
        ));
    };
    let Some(AbortedProof::ConflictingCommit(conflict)) = aborted.proof.as_ref() else {
        return Err(invalid(
            "capacity_reservation.aborted.proof",
            "must be the conflicting-commit arm",
        ));
    };
    let commit = conflict
        .commit
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.aborted.conflicting_commit.commit"))?;
    let expected_object = conflict.conflicting_control.as_ref().ok_or_else(|| {
        missing("capacity_reservation.aborted.conflicting_commit.conflicting_control")
    })?;
    let class = validate_capacity_conflict_class(commit, conflict.conflict_class)?;
    let (require_reservation_identity, expected_writer_epoch) = match class {
        CapacityConflictClass::CreateControlExists => (false, CapacityWriterEpochExpectation::Any),
        CapacityConflictClass::SameWriterVersionAdvanced => {
            let Some(CapacityCommitPredecessor::PriorControl(prior)) = &commit.predecessor else {
                return Err(invalid(
                    "capacity_commit.predecessor",
                    "same-writer conflict requires an exact prior binding",
                ));
            };
            if expected_object.object_version_id == prior.object_version_id {
                return Err(invalid(
                    "capacity_reservation.aborted.conflicting_commit.conflicting_control",
                    "must differ from the exact expected predecessor version",
                ));
            }
            (
                true,
                CapacityWriterEpochExpectation::Exact(commit.writer_epoch),
            )
        }
        CapacityConflictClass::WriterEpochAdvanced => {
            let Some(CapacityCommitPredecessor::PriorControl(prior)) = &commit.predecessor else {
                return Err(invalid(
                    "capacity_commit.predecessor",
                    "writer-epoch conflict requires an exact prior binding",
                ));
            };
            if expected_object.object_version_id == prior.object_version_id {
                return Err(invalid(
                    "capacity_reservation.aborted.conflicting_commit.conflicting_control",
                    "must differ from the exact expected predecessor version",
                ));
            }
            (
                true,
                CapacityWriterEpochExpectation::GreaterThan(commit.writer_epoch),
            )
        }
        CapacityConflictClass::Unspecified => {
            return Err(invalid("capacity_conflict.class", "must be nonzero"));
        }
    };
    validate_exact_landed_capacity_repo_control(
        reservation,
        conflicting.control,
        expected_object,
        conflicting.observed_object,
        CapacityRepoControlExpectation {
            mutation_id: &conflict.conflicting_mutation_id,
            require_reservation_identity,
            writer_epoch: expected_writer_epoch,
        },
        prefix,
    )?;
    validate_repo_control_receipt_catalog(
        conflicting.control,
        conflicting.receipt_catalog,
        prefix,
    )?;
    let committing_reservation = committing_shard_reservation(committing.shard, reservation)?;
    validate_capacity_reservation_successor(committing_reservation, reservation, 0)?;
    validate_capacity_receipt_obligation(
        committing_reservation,
        committing.shard,
        committing.observed_object,
        expected_receipt,
        prefix,
    )?;
    if conflicting.receipt_catalog.rows.iter().any(|row| {
        row.mutation_id == expected_receipt.mutation_id
            || row.settlement_mutation_id == expected_receipt.mutation_id
    }) {
        return Err(invalid(
            "capacity_reservation.aborted.conflicting_commit",
            "expected mutation is already represented by the current receipt catalog",
        ));
    }
    Ok(())
}

fn committing_shard_reservation<'a>(
    shard: &'a CapacityShard,
    terminal: &CapacityReservation,
) -> Result<&'a CapacityReservation, ControlValidationError> {
    shard
        .reservations
        .binary_search_by(|candidate| candidate.reservation_id.cmp(&terminal.reservation_id))
        .ok()
        .and_then(|index| shard.reservations.get(index))
        .ok_or_else(|| {
            invalid(
                "capacity_shard.reservations",
                "does not contain the prior COMMITTING reservation",
            )
        })
}

fn receipt_catalog_row<'a>(
    catalog: &'a ReceiptCatalog,
    mutation_id: &[u8],
) -> Result<&'a ReceiptCatalogRow, ControlValidationError> {
    catalog
        .rows
        .binary_search_by(|row| row.mutation_id.as_ref().cmp(mutation_id))
        .ok()
        .and_then(|index| catalog.rows.get(index))
        .ok_or_else(|| {
            invalid(
                "receipt_catalog.rows",
                "does not contain the capacity mutation receipt",
            )
        })
}

fn validate_terminal_capacity_reservation(
    reservation: &CapacityReservation,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    let identity = reservation
        .identity
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.identity"))?;
    let shard = Sha256::digest(&identity.repository_uuid)[0];
    validate_capacity_reservation(reservation, shard, reservation.allocation_epoch, prefix)?;
    Ok(())
}

struct CapacityRepoControlExpectation<'a> {
    mutation_id: &'a [u8],
    require_reservation_identity: bool,
    writer_epoch: CapacityWriterEpochExpectation,
}

enum CapacityWriterEpochExpectation {
    Any,
    Exact(u64),
    GreaterThan(u64),
}

fn validate_exact_landed_capacity_repo_control(
    reservation: &CapacityReservation,
    control: &RepoControl,
    expected_object: &LandedControlRef,
    observed_object: &LandedControlRef,
    expectation: CapacityRepoControlExpectation<'_>,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_repo_control(control)?;
    let identity = reservation
        .identity
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.identity"))?;
    if expectation.require_reservation_identity && control.identity.as_ref() != Some(identity) {
        return Err(invalid(
            "capacity_repo_control.identity",
            "does not equal the reservation repository identity",
        ));
    }
    validate_capacity_landed_control(
        expected_object,
        identity,
        prefix,
        "capacity_reservation.landed_control",
    )?;
    validate_capacity_landed_control(
        observed_object,
        identity,
        prefix,
        "capacity_reservation.observed_landed_control",
    )?;
    if expected_object != observed_object {
        return Err(invalid(
            "capacity_reservation.landed_control",
            "does not equal the exact provider binding observed on load",
        ));
    }
    if control.repo_control_key != expected_object.repo_control_key {
        return Err(invalid(
            "capacity_repo_control.repo_control_key",
            "does not equal the exact landed-control key",
        ));
    }
    if control.last_internal_mutation_id.as_ref() != expectation.mutation_id {
        return Err(invalid(
            "capacity_repo_control.last_internal_mutation_id",
            "does not equal the proof mutation ID",
        ));
    }
    let writer_epoch = control
        .writer
        .as_ref()
        .ok_or_else(|| missing("capacity_repo_control.writer"))?
        .epoch;
    let writer_epoch_matches = match expectation.writer_epoch {
        CapacityWriterEpochExpectation::Any => true,
        CapacityWriterEpochExpectation::Exact(expected) => writer_epoch == expected,
        CapacityWriterEpochExpectation::GreaterThan(prior) => prior
            .checked_add(1)
            .is_some_and(|minimum| writer_epoch >= minimum),
    };
    if !writer_epoch_matches {
        return Err(invalid(
            "capacity_repo_control.writer.epoch",
            "does not satisfy the proof writer epoch relation",
        ));
    }
    let encoded = control.encode_to_vec();
    if expected_object.size != encoded.len() as u64 {
        return Err(invalid(
            "capacity_reservation.landed_control.size",
            "does not equal the canonical repo_control body size",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    if expected_object.digest.as_ref() != digest {
        return Err(invalid(
            "capacity_reservation.landed_control.digest",
            "does not equal the canonical repo_control body digest",
        ));
    }
    Ok(())
}

/// Exact-bind one loaded drained shard to its APPLYING baseline row and prove
/// that only terminal reservation history remains.
pub fn validate_capacity_applying_baseline(
    control: &CapacityControl,
    shard: &CapacityShard,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_control(control, prefix)?;
    let Some(CapacityControlPayload::Redistribution(redistribution)) =
        control.state_payload.as_ref()
    else {
        return Err(invalid(
            "capacity_control.state_payload",
            "an APPLYING redistribution is required",
        ));
    };
    if control.state != CapacityControlState::Preparing as i32
        || redistribution.phase != RedistributionPhase::Applying as i32
    {
        return Err(invalid(
            "capacity_control.redistribution.phase",
            "an APPLYING redistribution is required",
        ));
    }
    let shard_index = usize::try_from(shard.shard)
        .ok()
        .filter(|index| *index < 256)
        .ok_or_else(|| invalid("capacity_shard.shard", "must be in 0..=255"))?;
    let baseline = &redistribution.baselines[shard_index];
    validate_capacity_shard_object(
        shard,
        baseline
            .shard_object
            .as_ref()
            .ok_or_else(|| missing("capacity_control.redistribution.baseline.shard_object"))?,
        prefix,
    )?;
    if shard.allocation_epoch != baseline.allocation_epoch
        || shard.budget_bytes != baseline.budget_bytes
    {
        return Err(invalid(
            "capacity_control.redistribution.baseline",
            "loaded shard epoch or budget differs from the exact baseline row",
        ));
    }
    if shard.reservations.iter().any(|reservation| {
        matches!(
            CapacityReservationState::try_from(reservation.state),
            Ok(CapacityReservationState::Reserved | CapacityReservationState::Committing)
        )
    }) {
        return Err(invalid(
            "capacity_control.redistribution.baseline",
            "drained baseline contains a nonterminal reservation",
        ));
    }
    Ok(())
}

fn validate_capacity_current_catalog(
    control: &CapacityControl,
    current_page: &TenantCapacityCatalogPage,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_capacity_control(control, prefix)?;
    validate_tenant_capacity_catalog_object(
        current_page,
        control
            .tenant_catalog
            .as_ref()
            .ok_or_else(|| missing("capacity_control.tenant_catalog"))?,
        prefix,
    )?;
    validate_capacity_catalog_columns(
        current_page,
        control
            .shard_budgets
            .iter()
            .map(|budget| budget.budget_bytes),
        control.global_allocatable_bytes,
        "capacity_control.tenant_catalog",
    )
}

fn validate_capacity_catalog_columns(
    page: &TenantCapacityCatalogPage,
    budgets: impl Iterator<Item = u64>,
    global_allocatable_bytes: u64,
    field: &'static str,
) -> Result<(), ControlValidationError> {
    let budgets = budgets.collect::<Vec<_>>();
    if budgets.len() != 256 {
        return Err(invalid(field, "must have exactly 256 shard budgets"));
    }
    let mut columns = [0u64; 256];
    for allocation in &page.allocations {
        for (column, slice) in columns.iter_mut().zip(&allocation.slices) {
            *column = column
                .checked_add(slice.byte_count)
                .ok_or_else(|| invalid(field, "tenant slice column sum overflows"))?;
        }
    }
    let mut aggregate = 0u64;
    for (column, budget) in columns.into_iter().zip(budgets) {
        if column > budget {
            return Err(invalid(
                field,
                "tenant slice column exceeds its shard budget",
            ));
        }
        aggregate = aggregate
            .checked_add(column)
            .ok_or_else(|| invalid(field, "tenant allocation aggregate overflows"))?;
    }
    if aggregate > global_allocatable_bytes {
        return Err(invalid(
            field,
            "tenant allocation aggregate exceeds global allocatable bytes",
        ));
    }
    Ok(())
}

fn validate_tenant_capacity_allocation(
    allocation: &TenantCapacityAllocation,
) -> Result<(), ControlValidationError> {
    bounded_bytes(
        "tenant_capacity_allocation.tenant_id",
        &allocation.tenant_id,
        1,
        256,
    )?;
    nonzero(
        "tenant_capacity_allocation.total_bytes",
        allocation.total_bytes,
    )?;
    if allocation.slices.len() != 256 {
        return Err(invalid(
            "tenant_capacity_allocation.slices",
            "must contain exactly 256 entries",
        ));
    }
    let mut total = 0u64;
    for (index, slice) in allocation.slices.iter().enumerate() {
        if slice.shard as usize != index {
            return Err(invalid(
                "tenant_capacity_allocation.slices",
                "must be ordered by every shard 0 through 255",
            ));
        }
        nonzero(
            "tenant_capacity_allocation.slice.byte_count",
            slice.byte_count,
        )?;
        total = total
            .checked_add(slice.byte_count)
            .ok_or_else(|| invalid("tenant_capacity_allocation.slices", "slice total overflows"))?;
    }
    if total != allocation.total_bytes {
        return Err(invalid(
            "tenant_capacity_allocation.total_bytes",
            "must equal the checked sum of all 256 slices",
        ));
    }
    Ok(())
}

fn validate_capacity_tenant_accounts(
    accounts: &[CapacityTenantAccount],
    shard_budget_bytes: u64,
) -> Result<(), ControlValidationError> {
    if accounts.len() > 4_096 {
        return Err(invalid(
            "capacity_shard.tenant_accounts",
            "exceeds 4096 entries",
        ));
    }
    if accounts
        .windows(2)
        .any(|pair| pair[0].tenant_id.as_ref() >= pair[1].tenant_id.as_ref())
    {
        return Err(invalid(
            "capacity_shard.tenant_accounts",
            "must be binary-sorted and unique by tenant ID",
        ));
    }
    for account in accounts {
        bounded_bytes(
            "capacity_shard.tenant_account.tenant_id",
            &account.tenant_id,
            1,
            256,
        )?;
        nonzero(
            "capacity_shard.tenant_account.current_slice_bytes",
            account.current_slice_bytes,
        )?;
        if account.current_slice_bytes > shard_budget_bytes {
            return Err(invalid(
                "capacity_shard.tenant_account.current_slice_bytes",
                "cannot exceed the immutable shard budget",
            ));
        }
    }
    Ok(())
}

fn validate_capacity_reservation(
    reservation: &CapacityReservation,
    owning_shard: u8,
    allocation_epoch: u64,
    prefix: &DeploymentPrefix,
) -> Result<CapacityReservationState, ControlValidationError> {
    validate_uuid_v7(
        "capacity_reservation.reservation_id",
        &reservation.reservation_id,
    )?;
    let identity = reservation
        .identity
        .as_ref()
        .ok_or_else(|| missing("capacity_reservation.identity"))?;
    validate_identity(identity)?;
    bounded_bytes(
        "capacity_reservation.tenant_id",
        &reservation.tenant_id,
        1,
        256,
    )?;
    if reservation.tenant_id != identity.tenant_id {
        return Err(invalid(
            "capacity_reservation.tenant_id",
            "must equal the repository identity tenant",
        ));
    }
    nonzero(
        "capacity_reservation.allocation_epoch",
        reservation.allocation_epoch,
    )?;
    if reservation.allocation_epoch > allocation_epoch {
        return Err(invalid(
            "capacity_reservation.allocation_epoch",
            "cannot be newer than the owning shard epoch",
        ));
    }
    nonzero("capacity_reservation.byte_count", reservation.byte_count)?;
    nonzero(
        "capacity_reservation.tenant_slice_bytes",
        reservation.tenant_slice_bytes,
    )?;
    if reservation.byte_count > reservation.tenant_slice_bytes {
        return Err(invalid(
            "capacity_reservation.byte_count",
            "exceeds the exact tenant shard slice",
        ));
    }
    if Sha256::digest(&identity.repository_uuid)[0] != owning_shard {
        return Err(invalid(
            "capacity_reservation.identity.repository_uuid",
            "does not hash to the owning shard",
        ));
    }
    let state = CapacityReservationState::try_from(reservation.state)
        .map_err(|_| invalid("capacity_reservation.state", "is unknown"))?;
    if matches!(
        state,
        CapacityReservationState::Reserved | CapacityReservationState::Committing
    ) && reservation.allocation_epoch != allocation_epoch
    {
        return Err(invalid(
            "capacity_reservation.allocation_epoch",
            "nonterminal reservations must equal the current shard epoch",
        ));
    }
    match (state, reservation.state_payload.as_ref()) {
        (
            CapacityReservationState::Reserved,
            Some(CapacityReservationPayload::Reserved(reserved)),
        ) => validate_reservation_window(
            reserved.created_at_unix_seconds,
            reserved.expires_at_unix_seconds,
            "capacity_reservation.reserved",
        )?,
        (
            CapacityReservationState::Committing,
            Some(CapacityReservationPayload::Committing(committing)),
        ) => validate_capacity_commit(
            committing
                .commit
                .as_ref()
                .ok_or_else(|| missing("capacity_reservation.committing.commit"))?,
        )?,
        (CapacityReservationState::Charged, Some(CapacityReservationPayload::Charged(charged))) => {
            validate_capacity_commit(
                charged
                    .commit
                    .as_ref()
                    .ok_or_else(|| missing("capacity_reservation.charged.commit"))?,
            )?;
            validate_capacity_landed_control(
                charged
                    .landed_control
                    .as_ref()
                    .ok_or_else(|| missing("capacity_reservation.charged.landed_control"))?,
                identity,
                prefix,
                "capacity_reservation.charged.landed_control",
            )?;
        }
        (CapacityReservationState::Aborted, Some(CapacityReservationPayload::Aborted(aborted))) => {
            match aborted.proof.as_ref() {
                Some(AbortedProof::Expired(expired)) => {
                    validate_reservation_window(
                        expired.created_at_unix_seconds,
                        expired.expires_at_unix_seconds,
                        "capacity_reservation.aborted.expired",
                    )?;
                    if expired.observed_now_unix_seconds < expired.expires_at_unix_seconds {
                        return Err(invalid(
                            "capacity_reservation.aborted.expired.observed_now_unix_seconds",
                            "must be at or after expiry",
                        ));
                    }
                }
                Some(AbortedProof::ConflictingCommit(conflict)) => {
                    let commit = conflict.commit.as_ref().ok_or_else(|| {
                        missing("capacity_reservation.aborted.conflicting_commit.commit")
                    })?;
                    validate_capacity_commit(commit)?;
                    validate_capacity_landed_control(
                    conflict.conflicting_control.as_ref().ok_or_else(|| {
                        missing(
                            "capacity_reservation.aborted.conflicting_commit.conflicting_control",
                        )
                    })?,
                    identity,
                    prefix,
                    "capacity_reservation.aborted.conflicting_commit.conflicting_control",
                )?;
                    validate_uuid_v7(
                        "capacity_reservation.aborted.conflicting_commit.conflicting_mutation_id",
                        &conflict.conflicting_mutation_id,
                    )?;
                    if conflict.conflicting_mutation_id == commit.mutation_id {
                        return Err(invalid(
                            "capacity_reservation.aborted.conflicting_commit.conflicting_mutation_id",
                            "must differ from the expected commit mutation",
                        ));
                    }
                    validate_capacity_conflict_class(commit, conflict.conflict_class)?;
                }
                None => return Err(missing("capacity_reservation.aborted.proof")),
            }
        }
        (CapacityReservationState::Unspecified, _) => {
            return Err(invalid(
                "capacity_reservation.state",
                "must be a known nonzero state",
            ));
        }
        _ => {
            return Err(invalid(
                "capacity_reservation.state_payload",
                "does not match the selected state",
            ));
        }
    }
    Ok(state)
}

fn validate_reservation_window(
    created: u64,
    expires: u64,
    field: &'static str,
) -> Result<(), ControlValidationError> {
    nonzero(field, created)?;
    let ttl = expires
        .checked_sub(created)
        .ok_or_else(|| invalid(field, "expiry must be after creation"))?;
    if !(1..=MAX_RESERVED_TTL_SECONDS).contains(&ttl) {
        return Err(invalid(field, "TTL must be in 1..=900 seconds"));
    }
    Ok(())
}

fn validate_capacity_commit(commit: &CapacityCommitBinding) -> Result<(), ControlValidationError> {
    nonzero("capacity_commit.writer_epoch", commit.writer_epoch)?;
    validate_uuid_v7("capacity_commit.mutation_id", &commit.mutation_id)?;
    let kind = MutationKind::try_from(commit.kind)
        .map_err(|_| invalid("capacity_commit.kind", "is unknown"))?;
    if matches!(
        kind,
        MutationKind::Unspecified | MutationKind::InternalSettlement
    ) {
        return Err(invalid(
            "capacity_commit.kind",
            "must be a non-settlement mutation",
        ));
    }
    match (&commit.predecessor, kind) {
        (Some(CapacityCommitPredecessor::NoPriorControl(_)), MutationKind::Create) => {}
        (Some(CapacityCommitPredecessor::PriorControl(_)), MutationKind::Create) => {
            return Err(invalid(
                "capacity_commit.predecessor",
                "Create requires explicit NONE",
            ));
        }
        (Some(CapacityCommitPredecessor::PriorControl(prior)), _) => {
            bounded_bytes(
                "capacity_commit.prior_control.cas_token",
                &prior.cas_token,
                1,
                256,
            )?;
            bounded_bytes(
                "capacity_commit.prior_control.object_version_id",
                &prior.object_version_id,
                1,
                1024,
            )?;
        }
        (Some(CapacityCommitPredecessor::NoPriorControl(_)), _) => {
            return Err(invalid(
                "capacity_commit.predecessor",
                "non-Create requires an exact prior binding",
            ));
        }
        (None, _) => return Err(missing("capacity_commit.predecessor")),
    }
    Ok(())
}

fn validate_capacity_conflict_class(
    commit: &CapacityCommitBinding,
    raw_class: i32,
) -> Result<CapacityConflictClass, ControlValidationError> {
    let class = CapacityConflictClass::try_from(raw_class)
        .map_err(|_| invalid("capacity_conflict.class", "is unknown"))?;
    let kind = MutationKind::try_from(commit.kind)
        .map_err(|_| invalid("capacity_commit.kind", "is unknown"))?;
    let valid = match (&commit.predecessor, kind, class) {
        (
            Some(CapacityCommitPredecessor::NoPriorControl(_)),
            MutationKind::Create,
            CapacityConflictClass::CreateControlExists,
        ) => true,
        (
            Some(CapacityCommitPredecessor::PriorControl(_)),
            kind,
            CapacityConflictClass::SameWriterVersionAdvanced
            | CapacityConflictClass::WriterEpochAdvanced,
        ) if kind != MutationKind::Create => true,
        _ => false,
    };
    if !valid {
        return Err(invalid(
            "capacity_conflict.class",
            "does not match the expected commit predecessor",
        ));
    }
    Ok(class)
}

fn validate_capacity_landed_control(
    target: &LandedControlRef,
    identity: &RepositoryIdentity,
    prefix: &DeploymentPrefix,
    field: &'static str,
) -> Result<(), ControlValidationError> {
    validate_repo_control_target(target, identity)?;
    if target.size > super::MAX_REPO_CONTROL_BYTES as u64 {
        return Err(invalid(
            field,
            "size exceeds the repo_control object maximum",
        ));
    }
    let parsed = parse_key(prefix, &target.repo_control_key)
        .map_err(|_| invalid(field, "key is outside the selected deployment prefix"))?;
    if parsed.kind != V2KeyKind::RepoControl {
        return Err(invalid(field, "key is not a repo_control key"));
    }
    let expected = repo_control_key(
        prefix,
        RoutingDigest::of(&identity.canonical_path)
            .map_err(|_| invalid(field, "repo_control key cannot be derived"))?,
    )
    .map_err(|_| invalid(field, "repo_control key cannot be derived"))?;
    if target.repo_control_key.as_ref() != expected.as_bytes() {
        return Err(invalid(field, "key does not match the repository identity"));
    }
    Ok(())
}

fn validate_shard_budgets(
    budgets: &[CapacityShardBudget],
    global_allocatable_bytes: u64,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if budgets.len() != 256 {
        return Err(invalid(
            "capacity_control.shard_budgets",
            "must contain exactly 256 entries",
        ));
    }
    let mut sum = 0u64;
    for (index, budget) in budgets.iter().enumerate() {
        if budget.shard as usize != index {
            return Err(invalid(
                "capacity_control.shard_budgets",
                "must be ordered by every shard 0 through 255",
            ));
        }
        nonzero(
            "capacity_control.shard_budget.budget_bytes",
            budget.budget_bytes,
        )?;
        let expected = capacity_shard_key(prefix, index as u8)
            .map_err(|_| invalid("capacity_control.shard_budget", "key cannot be derived"))?;
        validate_global_capacity_ref(
            budget
                .shard_object
                .as_ref()
                .ok_or_else(|| missing("capacity_control.shard_budget.shard_object"))?,
            prefix,
            V2KeyKind::CapacityShard,
            Some(expected.as_bytes()),
            MAX_CAPACITY_SHARD_BYTES,
            "capacity_control.shard_budget.shard_object",
        )?;
        sum = sum
            .checked_add(budget.budget_bytes)
            .ok_or_else(|| invalid("capacity_control.shard_budgets", "budget sum overflows"))?;
    }
    if sum > global_allocatable_bytes {
        return Err(invalid(
            "capacity_control.shard_budgets",
            "budget sum exceeds global allocatable bytes",
        ));
    }
    Ok(())
}

fn validate_capacity_redistribution(
    control: &CapacityControl,
    redistribution: &CapacityRedistribution,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    let phase = RedistributionPhase::try_from(redistribution.phase)
        .map_err(|_| invalid("capacity_control.redistribution.phase", "is unknown"))?;
    if phase == RedistributionPhase::Unspecified {
        return Err(invalid(
            "capacity_control.redistribution.phase",
            "must be a known nonzero phase",
        ));
    }
    if control.allocation_epoch.checked_add(1) != Some(redistribution.target_epoch) {
        return Err(invalid(
            "capacity_control.redistribution.target_epoch",
            "must be exactly the next allocation epoch",
        ));
    }
    nonzero(
        "capacity_control.redistribution.target_global_allocatable_bytes",
        redistribution.target_global_allocatable_bytes,
    )?;
    validate_global_capacity_ref(
        redistribution
            .target_tenant_catalog
            .as_ref()
            .ok_or_else(|| missing("capacity_control.redistribution.target_tenant_catalog"))?,
        prefix,
        V2KeyKind::TenantCapacityCatalog,
        None,
        MAX_TENANT_CAPACITY_CATALOG_BYTES,
        "capacity_control.redistribution.target_tenant_catalog",
    )?;
    validate_shard_budget_proposals(
        &redistribution.target_shard_budgets,
        redistribution.target_global_allocatable_bytes,
    )?;
    validate_uuid_v7(
        "capacity_control.redistribution.admission_fence_id",
        &redistribution.admission_fence_id,
    )?;
    match phase {
        RedistributionPhase::Draining if redistribution.baselines.is_empty() => Ok(()),
        RedistributionPhase::Draining => Err(invalid(
            "capacity_control.redistribution.baselines",
            "must be empty while DRAINING",
        )),
        RedistributionPhase::Applying => {
            validate_shard_baselines(control, &redistribution.baselines, prefix)
        }
        RedistributionPhase::Unspecified => unreachable!(),
    }
}

fn validate_shard_budget_proposals(
    budgets: &[CapacityShardBudgetProposal],
    global_allocatable_bytes: u64,
) -> Result<(), ControlValidationError> {
    if budgets.len() != 256 {
        return Err(invalid(
            "capacity_control.redistribution.target_shard_budgets",
            "must contain exactly 256 entries",
        ));
    }
    let mut sum = 0u64;
    for (index, budget) in budgets.iter().enumerate() {
        if budget.shard as usize != index {
            return Err(invalid(
                "capacity_control.redistribution.target_shard_budgets",
                "must be ordered by every shard 0 through 255",
            ));
        }
        nonzero(
            "capacity_control.redistribution.target_shard_budget.budget_bytes",
            budget.budget_bytes,
        )?;
        sum = sum.checked_add(budget.budget_bytes).ok_or_else(|| {
            invalid(
                "capacity_control.redistribution.target_shard_budgets",
                "budget sum overflows",
            )
        })?;
    }
    if sum > global_allocatable_bytes {
        return Err(invalid(
            "capacity_control.redistribution.target_shard_budgets",
            "budget sum exceeds target global allocatable bytes",
        ));
    }
    Ok(())
}

fn validate_shard_baselines(
    control: &CapacityControl,
    baselines: &[CapacityShardBaseline],
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    if baselines.len() != 256 {
        return Err(invalid(
            "capacity_control.redistribution.baselines",
            "must contain exactly 256 entries while APPLYING",
        ));
    }
    for (index, baseline) in baselines.iter().enumerate() {
        if baseline.shard as usize != index {
            return Err(invalid(
                "capacity_control.redistribution.baselines",
                "must be ordered by every shard 0 through 255",
            ));
        }
        if baseline.allocation_epoch != control.allocation_epoch {
            return Err(invalid(
                "capacity_control.redistribution.baseline.allocation_epoch",
                "must equal the retained prior stable epoch",
            ));
        }
        if baseline.budget_bytes != control.shard_budgets[index].budget_bytes {
            return Err(invalid(
                "capacity_control.redistribution.baseline.budget_bytes",
                "must equal the retained prior stable shard budget",
            ));
        }
        let expected = capacity_shard_key(prefix, index as u8).map_err(|_| {
            invalid(
                "capacity_control.redistribution.baseline",
                "key cannot be derived",
            )
        })?;
        validate_global_capacity_ref(
            baseline
                .shard_object
                .as_ref()
                .ok_or_else(|| missing("capacity_control.redistribution.baseline.shard_object"))?,
            prefix,
            V2KeyKind::CapacityShard,
            Some(expected.as_bytes()),
            MAX_CAPACITY_SHARD_BYTES,
            "capacity_control.redistribution.baseline.shard_object",
        )?;
    }
    Ok(())
}

fn validate_global_capacity_ref(
    object: &CapacityObjectRef,
    prefix: &DeploymentPrefix,
    expected_kind: V2KeyKind,
    expected_key: Option<&[u8]>,
    maximum_object_bytes: usize,
    field: &'static str,
) -> Result<ParsedV2Key, ControlValidationError> {
    bounded_ascii(field, &object.key, 1, 1024)?;
    bounded_bytes(field, &object.object_version_id, 1, 1024)?;
    exact_len(field, &object.digest, 32)?;
    if object.size == 0 || object.size > maximum_object_bytes as u64 {
        return Err(invalid(field, "size is outside the typed object maximum"));
    }
    let parsed = parse_key(prefix, &object.key)
        .map_err(|_| invalid(field, "key is outside the selected deployment prefix"))?;
    if parsed.kind != expected_kind {
        return Err(invalid(field, "key does not match the typed capacity slot"));
    }
    if let Some(expected_key) = expected_key
        && object.key.as_ref() != expected_key
    {
        return Err(invalid(field, "key does not match the selected shard"));
    }
    if let Some(content_digest) = parsed.content_digest
        && object.digest.as_ref() != content_digest.as_bytes()
    {
        return Err(invalid(
            field,
            "digest does not equal the content-addressed key leaf",
        ));
    }
    Ok(parsed)
}

fn validate_exact_protobuf_object(
    object: &CapacityObjectRef,
    encoded: &[u8],
    field: &'static str,
) -> Result<(), ControlValidationError> {
    let digest: [u8; 32] = Sha256::digest(encoded).into();
    if object.size != encoded.len() as u64 || object.digest.as_ref() != digest {
        return Err(invalid(
            field,
            "metadata does not bind the exact canonical protobuf bytes",
        ));
    }
    Ok(())
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
            validate_receipt_capacity_shard_key(identity, &capacity.shard_key)?;
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
            validate_receipt_event_result_key(identity, &event.event_id, &event.result_key)?;
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
    let mut mutation_ids = HashSet::with_capacity(catalog.rows.len().saturating_mul(2));
    for row in &catalog.rows {
        validate_receipt_catalog_row(row, identity)?;
        if !mutation_ids.insert(row.mutation_id.as_ref())
            || (!row.settlement_mutation_id.is_empty()
                && !mutation_ids.insert(row.settlement_mutation_id.as_ref()))
        {
            return Err(invalid(
                "receipt_catalog.rows",
                "receipt and settlement mutation IDs must be globally unique",
            ));
        }
    }
    Ok(())
}

/// Exact-bind a loaded flat receipt catalog body to its `RepoControl` root.
///
/// This gate also proves the serialized one-at-a-time state invariant: at
/// most one receipt is unresolved, and the control's last internal mutation
/// is either that unresolved receipt or a retained settlement mutation ID.
/// A typed current provider GET remains the caller's responsibility.
pub fn validate_repo_control_receipt_catalog(
    control: &RepoControl,
    catalog: &ReceiptCatalog,
    prefix: &DeploymentPrefix,
) -> Result<(), ControlValidationError> {
    validate_repo_control(control)?;
    validate_receipt_catalog(catalog)?;
    let identity = control
        .identity
        .as_ref()
        .ok_or_else(|| missing("repo.identity"))?;
    if catalog.identity.as_ref() != Some(identity) {
        return Err(invalid(
            "receipt_catalog.identity",
            "does not equal the rooted repository identity",
        ));
    }
    let root = control
        .receipt_catalog
        .as_ref()
        .ok_or_else(|| missing("repo.receipt_catalog"))?;
    validate_catalog_root(root, CatalogKind::Receipt, identity, prefix)?;
    let encoded_len = catalog.encoded_len();
    if encoded_len > MAX_RECEIPT_CATALOG_BYTES {
        return Err(invalid(
            "receipt_catalog",
            "encoded body exceeds 524288 bytes",
        ));
    }
    let encoded = catalog.encode_to_vec();
    let object = root
        .object
        .as_ref()
        .ok_or_else(|| missing("repo.receipt_catalog.object"))?;
    if object.size != encoded.len() as u64 {
        return Err(invalid(
            "repo.receipt_catalog.object.size",
            "does not equal the canonical receipt catalog body size",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    if object.digest.as_ref() != digest {
        return Err(invalid(
            "repo.receipt_catalog.object.digest",
            "does not equal the canonical receipt catalog body digest",
        ));
    }
    if root.depth != 1
        || root.node_count != 1
        || root.item_count != catalog.rows.len() as u64
        || root.total_encoded_bytes != encoded.len() as u64
    {
        return Err(invalid(
            "repo.receipt_catalog",
            "does not describe the exact flat receipt catalog body",
        ));
    }

    let mut unresolved = None;
    for row in &catalog.rows {
        if row.state == ReceiptState::Unresolved as i32 && unresolved.replace(row).is_some() {
            return Err(invalid(
                "receipt_catalog.rows",
                "contains more than one unresolved receipt",
            ));
        }
    }
    if let Some(row) = unresolved
        && row.mutation_id != control.last_internal_mutation_id
    {
        return Err(invalid(
            "receipt_catalog.rows",
            "unresolved mutation does not equal the control last mutation",
        ));
    }
    let represented = catalog.rows.iter().any(|row| {
        (row.state == ReceiptState::Unresolved as i32
            && row.mutation_id == control.last_internal_mutation_id)
            || (row.state == ReceiptState::Settled as i32
                && row.settlement_mutation_id == control.last_internal_mutation_id)
    });
    if !represented {
        return Err(invalid(
            "repo.last_internal_mutation_id",
            "is not represented by the exact receipt catalog state",
        ));
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
    match state {
        ReceiptState::Unresolved => {
            if !row.settlement_mutation_id.is_empty() {
                return Err(invalid(
                    "receipt_catalog.row.settlement_mutation_id",
                    "must be absent while UNRESOLVED",
                ));
            }
            if row.result.is_some() {
                return Err(invalid(
                    "receipt_catalog.row.result",
                    "must be absent while UNRESOLVED",
                ));
            }
            Ok(())
        }
        ReceiptState::Settled => {
            validate_uuid_v7(
                "receipt_catalog.row.settlement_mutation_id",
                &row.settlement_mutation_id,
            )?;
            let result = row
                .result
                .as_ref()
                .ok_or_else(|| missing("receipt_catalog.row.result"))?;
            validate_receipt_result_target(result, identity, &row.mutation_id)
        }
        ReceiptState::Unspecified => Err(invalid(
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
    if target.size == 0 || target.size > MAX_MUTATION_RESULT_BYTES as u64 {
        return Err(invalid(
            "receipt_catalog.row.result.size",
            "must be in 1..=65536",
        ));
    }
    Ok(())
}

fn validate_receipt_capacity_shard_key(
    identity: &RepositoryIdentity,
    key: &[u8],
) -> Result<(), ControlValidationError> {
    bounded_ascii("receipt.capacity.shard_key", key, 1, 1024)?;
    let shard = Sha256::digest(&identity.repository_uuid)[0];
    let suffix = format!("v2/capacity/shards/{shard:02x}/capacity_shard.pb");
    let key_text = std::str::from_utf8(key)
        .map_err(|_| invalid("receipt.capacity.shard_key", "must be ASCII"))?;
    let prefix = key_text
        .strip_suffix(&suffix)
        .ok_or_else(|| invalid("receipt.capacity.shard_key", "is not deterministic"))?;
    let prefix = DeploymentPrefix::parse(prefix)
        .map_err(|_| invalid("receipt.capacity.shard_key", "has an invalid prefix"))?;
    let parsed = parse_key(&prefix, key)
        .map_err(|_| invalid("receipt.capacity.shard_key", "is outside the V2 grammar"))?;
    if parsed.kind != V2KeyKind::CapacityShard {
        return Err(invalid(
            "receipt.capacity.shard_key",
            "is not the repository capacity shard key",
        ));
    }
    Ok(())
}

fn validate_receipt_event_result_key(
    identity: &RepositoryIdentity,
    event_id: &[u8],
    key: &[u8],
) -> Result<(), ControlValidationError> {
    bounded_ascii("receipt.event.result_key", key, 1, 1024)?;
    let mut repository_uuid = [0u8; 16];
    repository_uuid.copy_from_slice(&identity.repository_uuid);
    let suffix = format!(
        "v2/repositories/by-id/{}/g{:016x}/events/results/{}.pb",
        hex::encode(repository_uuid),
        identity.generation,
        hex::encode(event_id)
    );
    let key_text = std::str::from_utf8(key)
        .map_err(|_| invalid("receipt.event.result_key", "must be ASCII"))?;
    let prefix = key_text
        .strip_suffix(&suffix)
        .ok_or_else(|| invalid("receipt.event.result_key", "is not deterministic"))?;
    let prefix = DeploymentPrefix::parse(prefix)
        .map_err(|_| invalid("receipt.event.result_key", "has an invalid prefix"))?;
    let parsed = parse_key(&prefix, key)
        .map_err(|_| invalid("receipt.event.result_key", "is outside the V2 grammar"))?;
    if parsed.kind != V2KeyKind::EventResult
        || parsed.repository
            != Some(RepositoryKeyIdentity {
                repository_uuid,
                generation: identity.generation,
            })
    {
        return Err(invalid(
            "receipt.event.result_key",
            "does not match the repository identity and event ID",
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

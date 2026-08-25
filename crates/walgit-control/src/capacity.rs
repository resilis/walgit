//! Dormant capacity reservation admission and expiry.
//!
//! Purpose is a closed admission discriminator only. Reservations persist
//! fungible bytes; a future runtime and COMMITTING slice must bind purpose to
//! an authenticated capability and mutation kind.

use bytes::Bytes;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walgit_proto::v2::{
    AbortedCapacityReservation, CapacityControlState, CapacityReservation,
    CapacityReservationState, CapacityShard, CapacityTenantAccount, ExpiredCapacityReservation,
    Lifecycle, MAX_RESERVED_TTL_SECONDS, RedistributionPhase, ReservedCapacityReservation,
    aborted_capacity_reservation::Proof as AbortedProof,
    capacity_control::StatePayload as ControlPayload,
    capacity_reservation::StatePayload as ReservationPayload,
    keys::{V2KeyKind, parse_key},
    validate_capacity_admission_view, validate_capacity_applying_current_shard,
    validate_capacity_current_shard_view,
};
use walgit_store::{
    v2_capacity::{CapacityStore, CapacityStoreError, ShardCompareAndSwapOutcome},
    v2_control::StoredRepoControl,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityReservationPurpose {
    GitWrite,
    LfsFinalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveCapacityRequest {
    pub reservation_id: [u8; 16],
    pub requested_bytes: u64,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub observed_now_unix_seconds: u64,
    pub purpose: CapacityReservationPurpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpireCapacityRequest {
    pub reservation_id: [u8; 16],
    pub observed_now_unix_seconds: u64,
}

#[derive(Debug, Error)]
pub enum CapacityError {
    #[error(transparent)]
    Store(#[from] CapacityStoreError),
    #[error("repository is not eligible for capacity reservation")]
    RepositoryDenied,
    #[error("capacity authority is missing")]
    MissingCapacityControl,
    #[error("current capacity shard is missing")]
    MissingCapacityShard,
    #[error("tenant has no current capacity allocation")]
    TenantNotAllocated,
    #[error("capacity reservation request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("capacity reservation conflicts with retained state")]
    ReservationConflict,
}

#[derive(Clone)]
pub struct CapacityReservations {
    store: CapacityStore,
}

impl CapacityReservations {
    pub fn new(store: CapacityStore) -> Self {
        Self { store }
    }

    /// Insert exactly one new RESERVED row while the global control is STABLE.
    pub async fn reserve(
        &self,
        repository: &StoredRepoControl,
        request: ReserveCapacityRequest,
    ) -> Result<ShardCompareAndSwapOutcome, CapacityError> {
        let identity = self.active_repository_identity(repository)?;
        if request.requested_bytes == 0 {
            return Err(CapacityError::InvalidRequest(
                "requested_bytes must be nonzero",
            ));
        }
        if request.created_at_unix_seconds == 0 {
            return Err(CapacityError::InvalidRequest(
                "created_at_unix_seconds must be nonzero",
            ));
        }
        let lifetime = request
            .expires_at_unix_seconds
            .checked_sub(request.created_at_unix_seconds)
            .ok_or(CapacityError::InvalidRequest(
                "expires_at_unix_seconds precedes creation",
            ))?;
        if !(1..=MAX_RESERVED_TTL_SECONDS).contains(&lifetime) {
            return Err(CapacityError::InvalidRequest(
                "reservation lifetime must be in 1..=900",
            ));
        }
        if request.created_at_unix_seconds > request.observed_now_unix_seconds
            || request.observed_now_unix_seconds >= request.expires_at_unix_seconds
        {
            return Err(CapacityError::InvalidRequest(
                "reservation is not live at observed_now_unix_seconds",
            ));
        }
        match request.purpose {
            CapacityReservationPurpose::GitWrite | CapacityReservationPurpose::LfsFinalize => {}
        }

        let control = self
            .store
            .load_current_control()
            .await?
            .ok_or(CapacityError::MissingCapacityControl)?;
        if control.control().state != CapacityControlState::Stable as i32 {
            return Err(CapacityError::InvalidRequest(
                "new reservations require STABLE capacity control",
            ));
        }
        let tenant_catalog = control
            .control()
            .tenant_catalog
            .as_ref()
            .ok_or(CapacityError::TenantNotAllocated)?;
        let shard_number = Sha256::digest(&identity.repository_uuid)[0];
        let (page, shard) = tokio::join!(
            self.store.load_exact_tenant_catalog(tenant_catalog),
            self.store.load_current_shard(shard_number),
        );
        let page = page?;
        let shard = shard?.ok_or(CapacityError::MissingCapacityShard)?;
        validate_capacity_admission_view(
            control.control(),
            page.page(),
            shard.shard(),
            shard.binding().object(),
            self.store.deployment_prefix(),
        )
        .map_err(CapacityStoreError::from)?;

        let allocation = page
            .page()
            .allocations
            .binary_search_by(|row| row.tenant_id.cmp(&identity.tenant_id))
            .ok()
            .map(|index| &page.page().allocations[index])
            .ok_or(CapacityError::TenantNotAllocated)?;
        let tenant_slice_bytes = allocation.slices[usize::from(shard_number)].byte_count;
        if request.requested_bytes > tenant_slice_bytes {
            return Err(CapacityError::InvalidRequest(
                "requested_bytes exceeds the tenant shard slice",
            ));
        }

        let reservation_id = Bytes::copy_from_slice(&request.reservation_id);
        let reservation = CapacityReservation {
            reservation_id: reservation_id.clone(),
            identity: Some(identity.clone()),
            tenant_id: identity.tenant_id.clone(),
            allocation_epoch: control.control().allocation_epoch,
            byte_count: request.requested_bytes,
            tenant_slice_bytes,
            state: CapacityReservationState::Reserved as i32,
            state_payload: Some(ReservationPayload::Reserved(ReservedCapacityReservation {
                created_at_unix_seconds: request.created_at_unix_seconds,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
            })),
        };
        let insertion = shard
            .shard()
            .reservations
            .binary_search_by(|row| row.reservation_id.cmp(&reservation_id));
        let index = match insertion {
            Ok(index) if shard.shard().reservations[index] == reservation => {
                return Ok(ShardCompareAndSwapOutcome::Committed(shard));
            }
            Ok(_) => return Err(CapacityError::ReservationConflict),
            Err(index) => index,
        };
        let mut successor = shard.shard().clone();
        successor.control_revision =
            successor
                .control_revision
                .checked_add(1)
                .ok_or(CapacityError::InvalidRequest(
                    "capacity shard revision overflows",
                ))?;
        successor.reservations.insert(index, reservation);
        insert_or_validate_tenant_account(&mut successor, &identity.tenant_id, tenant_slice_bytes)?;

        self.store
            .reserve_cas(
                &control,
                &page,
                &shard,
                successor,
                request.observed_now_unix_seconds,
            )
            .await
            .map_err(Into::into)
    }

    /// Transition one exact RESERVED row to ABORTED with its expiry proof.
    pub async fn expire(
        &self,
        repository: &StoredRepoControl,
        request: ExpireCapacityRequest,
    ) -> Result<ShardCompareAndSwapOutcome, CapacityError> {
        let identity = self.repository_identity(repository)?;
        let control = self
            .store
            .load_current_control()
            .await?
            .ok_or(CapacityError::MissingCapacityControl)?;
        let tenant_catalog = control
            .control()
            .tenant_catalog
            .as_ref()
            .ok_or(CapacityError::TenantNotAllocated)?;
        let shard_number = Sha256::digest(&identity.repository_uuid)[0];
        let (page, shard) = tokio::join!(
            self.store.load_exact_tenant_catalog(tenant_catalog),
            self.store.load_current_shard(shard_number),
        );
        let page = page?;
        let shard = shard?.ok_or(CapacityError::MissingCapacityShard)?;
        let applying = match (
            CapacityControlState::try_from(control.control().state),
            control.control().state_payload.as_ref(),
        ) {
            (
                Ok(CapacityControlState::Preparing),
                Some(ControlPayload::Redistribution(redistribution)),
            ) if redistribution.phase == RedistributionPhase::Applying as i32 => {
                Some(redistribution.as_ref())
            }
            _ => None,
        };
        if let Some(redistribution) = applying {
            let target_catalog = redistribution.target_tenant_catalog.as_ref().ok_or(
                CapacityError::InvalidRequest("APPLYING control omits its target tenant catalog"),
            )?;
            let baseline_object = redistribution
                .baselines
                .get(usize::from(shard_number))
                .and_then(|baseline| baseline.shard_object.as_ref())
                .ok_or(CapacityError::InvalidRequest(
                    "APPLYING control omits the shard baseline",
                ))?;
            let (target_page, baseline) = tokio::join!(
                async {
                    if target_catalog == tenant_catalog {
                        Ok(page.clone())
                    } else {
                        self.store.load_exact_tenant_catalog(target_catalog).await
                    }
                },
                async {
                    if baseline_object == shard.binding().object() {
                        Ok(shard.clone())
                    } else {
                        self.store.load_exact_shard(baseline_object).await
                    }
                },
            );
            let target_page = target_page?;
            let baseline = baseline?;
            validate_capacity_applying_current_shard(
                control.control(),
                page.page(),
                target_page.page(),
                baseline.shard(),
                shard.shard(),
                shard.binding().object(),
                self.store.deployment_prefix(),
            )
            .map_err(CapacityStoreError::from)?;
        } else {
            validate_capacity_current_shard_view(
                control.control(),
                page.page(),
                shard.shard(),
                shard.binding().object(),
                self.store.deployment_prefix(),
            )
            .map_err(CapacityStoreError::from)?;
        }

        let reservation_id = request.reservation_id.as_slice();
        let index = shard
            .shard()
            .reservations
            .binary_search_by(|row| row.reservation_id.as_ref().cmp(reservation_id))
            .map_err(|_| CapacityError::ReservationConflict)?;
        let previous = &shard.shard().reservations[index];
        if previous.identity.as_ref() != Some(identity) {
            return Err(CapacityError::ReservationConflict);
        }
        if previous.state == CapacityReservationState::Aborted as i32
            && matches!(
                previous.state_payload.as_ref(),
                Some(ReservationPayload::Aborted(aborted))
                    if matches!(aborted.proof.as_ref(), Some(AbortedProof::Expired(_)))
            )
        {
            return Ok(ShardCompareAndSwapOutcome::Committed(shard));
        }
        require_expiry_control_state(control.control())?;
        if previous.state != CapacityReservationState::Reserved as i32 {
            return Err(CapacityError::ReservationConflict);
        }
        let Some(ReservationPayload::Reserved(reserved)) = previous.state_payload.as_ref() else {
            return Err(CapacityError::ReservationConflict);
        };
        if request.observed_now_unix_seconds < reserved.expires_at_unix_seconds {
            return Err(CapacityError::InvalidRequest("reservation has not expired"));
        }

        let mut successor = shard.shard().clone();
        successor.control_revision =
            successor
                .control_revision
                .checked_add(1)
                .ok_or(CapacityError::InvalidRequest(
                    "capacity shard revision overflows",
                ))?;
        successor.reservations[index].state = CapacityReservationState::Aborted as i32;
        successor.reservations[index].state_payload =
            Some(ReservationPayload::Aborted(AbortedCapacityReservation {
                proof: Some(AbortedProof::Expired(ExpiredCapacityReservation {
                    created_at_unix_seconds: reserved.created_at_unix_seconds,
                    expires_at_unix_seconds: reserved.expires_at_unix_seconds,
                    observed_now_unix_seconds: request.observed_now_unix_seconds,
                })),
            }));
        let tenant_id = previous.tenant_id.clone();
        let tenant_still_used = successor.reservations.iter().any(|row| {
            row.tenant_id == tenant_id && row.state != CapacityReservationState::Aborted as i32
        });
        if !tenant_still_used {
            let account_index = successor
                .tenant_accounts
                .binary_search_by(|row| row.tenant_id.cmp(&tenant_id))
                .map_err(|_| CapacityError::ReservationConflict)?;
            successor.tenant_accounts.remove(account_index);
        }

        self.store
            .expire_reserved_cas(
                &control,
                &page,
                &shard,
                successor,
                request.observed_now_unix_seconds,
            )
            .await
            .map_err(Into::into)
    }

    fn repository_identity<'a>(
        &self,
        repository: &'a StoredRepoControl,
    ) -> Result<&'a walgit_proto::v2::RepositoryIdentity, CapacityError> {
        let control = repository.control();
        if !matches!(
            Lifecycle::try_from(control.lifecycle),
            Ok(Lifecycle::Active | Lifecycle::Deleting | Lifecycle::Tombstoned)
        ) || repository.binding().full_key().as_bytes() != control.repo_control_key.as_ref()
        {
            return Err(CapacityError::RepositoryDenied);
        }
        let parsed = parse_key(self.store.deployment_prefix(), &control.repo_control_key)
            .map_err(|_| CapacityError::RepositoryDenied)?;
        if parsed.kind != V2KeyKind::RepoControl {
            return Err(CapacityError::RepositoryDenied);
        }
        control
            .identity
            .as_ref()
            .ok_or(CapacityError::RepositoryDenied)
    }

    fn active_repository_identity<'a>(
        &self,
        repository: &'a StoredRepoControl,
    ) -> Result<&'a walgit_proto::v2::RepositoryIdentity, CapacityError> {
        let identity = self.repository_identity(repository)?;
        if repository.control().lifecycle != Lifecycle::Active as i32 {
            return Err(CapacityError::RepositoryDenied);
        }
        Ok(identity)
    }
}

fn require_expiry_control_state(
    control: &walgit_proto::v2::CapacityControl,
) -> Result<(), CapacityError> {
    match (
        CapacityControlState::try_from(control.state),
        control.state_payload.as_ref(),
    ) {
        (Ok(CapacityControlState::Stable), Some(ControlPayload::Stable(_))) => Ok(()),
        (
            Ok(CapacityControlState::Preparing),
            Some(ControlPayload::Redistribution(redistribution)),
        ) if redistribution.phase == RedistributionPhase::Draining as i32 => Ok(()),
        _ => Err(CapacityError::InvalidRequest(
            "expiry requires STABLE or PREPARING/DRAINING capacity control",
        )),
    }
}

fn insert_or_validate_tenant_account(
    shard: &mut CapacityShard,
    tenant_id: &Bytes,
    tenant_slice_bytes: u64,
) -> Result<(), CapacityError> {
    match shard
        .tenant_accounts
        .binary_search_by(|row| row.tenant_id.cmp(tenant_id))
    {
        Ok(index) if shard.tenant_accounts[index].current_slice_bytes == tenant_slice_bytes => {
            Ok(())
        }
        Ok(_) => Err(CapacityError::ReservationConflict),
        Err(index) => {
            shard.tenant_accounts.insert(
                index,
                CapacityTenantAccount {
                    tenant_id: tenant_id.clone(),
                    current_slice_bytes: tenant_slice_bytes,
                },
            );
            Ok(())
        }
    }
}

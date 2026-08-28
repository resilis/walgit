//! Dormant V2 capacity persistence.
//!
//! This adapter performs strict typed loads and one conditional shard write.
//! It never retries, rebases, lists, or substitutes provider version fields.

use bytes::Bytes;
use walgit_proto::v2::{
    CapacityControl, CapacityObjectRef, CapacityReservationState, CapacityShard, ControlCodecError,
    ControlValidationError, MAX_CAPACITY_CONTROL_BYTES, MAX_CAPACITY_SHARD_BYTES,
    MAX_TENANT_CAPACITY_CATALOG_BYTES, TenantCapacityCatalogPage,
    aborted_capacity_reservation::Proof as AbortedProof,
    capacity_reservation::StatePayload as ReservationPayload,
    decode_capacity_control, decode_capacity_shard, decode_tenant_capacity_catalog_page,
    digests::ProtobufObjectDigest,
    encode_capacity_shard,
    keys::{DeploymentPrefix, V2KeyKind, capacity_control_key, capacity_shard_key, parse_key},
    validate_capacity_preparing_drainage_successor, validate_capacity_shard_object,
    validate_capacity_stable_admission_successor, validate_tenant_capacity_catalog_object,
};

use crate::{
    CasToken, DynStore, GetOptions, GetResult, ObjectMeta, ObjectStoreExt, ObjectVersionId,
    PutMode, StoreError, util,
};

const MAX_CAS_TOKEN_BYTES: usize = 256;
const MAX_OBJECT_VERSION_ID_BYTES: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityBinding {
    object: CapacityObjectRef,
    cas_token: CasToken,
}

impl CapacityBinding {
    pub fn object(&self) -> &CapacityObjectRef {
        &self.object
    }

    pub fn cas_token(&self) -> &CasToken {
        &self.cas_token
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredCapacityControl {
    control: CapacityControl,
    binding: CapacityBinding,
}

impl StoredCapacityControl {
    pub fn control(&self) -> &CapacityControl {
        &self.control
    }

    pub fn binding(&self) -> &CapacityBinding {
        &self.binding
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredTenantCapacityCatalogPage {
    page: TenantCapacityCatalogPage,
    binding: CapacityBinding,
}

impl StoredTenantCapacityCatalogPage {
    pub fn page(&self) -> &TenantCapacityCatalogPage {
        &self.page
    }

    pub fn binding(&self) -> &CapacityBinding {
        &self.binding
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredCapacityShard {
    shard: CapacityShard,
    binding: CapacityBinding,
}

impl StoredCapacityShard {
    pub fn shard(&self) -> &CapacityShard {
        &self.shard
    }

    pub fn binding(&self) -> &CapacityBinding {
        &self.binding
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ShardCompareAndSwapOutcome {
    Committed(StoredCapacityShard),
    Conflict(Option<StoredCapacityShard>),
    NotCommitted(StoredCapacityShard),
    Indeterminate,
}

#[derive(Debug, thiserror::Error)]
pub enum CapacityStoreError {
    #[error(transparent)]
    Codec(#[from] ControlCodecError),
    #[error(transparent)]
    InvalidObject(#[from] ControlValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("invalid V2 capacity-store configuration: {0}")]
    Configuration(&'static str),
    #[error("invalid V2 capacity object key: {0}")]
    Key(&'static str),
    #[error("invalid V2 capacity object metadata: {0}")]
    Metadata(&'static str),
    #[error("invalid V2 capacity store operation: {0}")]
    Operation(&'static str),
}

#[derive(Clone)]
pub struct CapacityStore {
    store: DynStore,
    deployment_prefix: DeploymentPrefix,
}

impl CapacityStore {
    pub fn new(
        store: DynStore,
        deployment_prefix: DeploymentPrefix,
    ) -> Result<Self, CapacityStoreError> {
        if store.applied_prefix() != deployment_prefix.as_str() {
            return Err(CapacityStoreError::Configuration(
                "store physical prefix must equal the deployment prefix",
            ));
        }
        Ok(Self {
            store,
            deployment_prefix,
        })
    }

    pub fn deployment_prefix(&self) -> &DeploymentPrefix {
        &self.deployment_prefix
    }

    /// Load the current global capacity control with one unconditional GET.
    pub async fn load_current_control(
        &self,
    ) -> Result<Option<StoredCapacityControl>, CapacityStoreError> {
        let full_key = capacity_control_key(&self.deployment_prefix)
            .map_err(|_| CapacityStoreError::Key("cannot derive capacity_control key"))?;
        let relative = self.relative_key(&full_key, V2KeyKind::CapacityControl)?;
        let Some((meta, encoded)) = self
            .load_current(relative, MAX_CAPACITY_CONTROL_BYTES)
            .await?
        else {
            return Ok(None);
        };
        let control = decode_capacity_control(&encoded, &self.deployment_prefix)?;
        let binding = self.binding(&full_key, relative, &encoded, meta)?;
        Ok(Some(StoredCapacityControl { control, binding }))
    }

    /// Load the exact immutable tenant catalog version rooted by capacity control.
    pub async fn load_exact_tenant_catalog(
        &self,
        expected: &CapacityObjectRef,
    ) -> Result<StoredTenantCapacityCatalogPage, CapacityStoreError> {
        let full_key = object_key(expected)?;
        let relative = self.relative_key(full_key, V2KeyKind::TenantCapacityCatalog)?;
        let version = object_version(expected)?;
        let (meta, encoded) = self
            .load_exact(relative, version, MAX_TENANT_CAPACITY_CATALOG_BYTES)
            .await?;
        let page = decode_tenant_capacity_catalog_page(&encoded)?;
        let binding = self.binding(full_key, relative, &encoded, meta)?;
        validate_exact_requested(expected, &binding.object)?;
        validate_tenant_capacity_catalog_object(&page, expected, &self.deployment_prefix)?;
        Ok(StoredTenantCapacityCatalogPage { page, binding })
    }

    /// Load the current mutable shard derived from its numeric shard identity.
    pub async fn load_current_shard(
        &self,
        shard: u8,
    ) -> Result<Option<StoredCapacityShard>, CapacityStoreError> {
        let full_key = capacity_shard_key(&self.deployment_prefix, shard)
            .map_err(|_| CapacityStoreError::Key("cannot derive capacity_shard key"))?;
        let relative = self.relative_key(&full_key, V2KeyKind::CapacityShard)?;
        let Some((meta, encoded)) = self
            .load_current(relative, MAX_CAPACITY_SHARD_BYTES)
            .await?
        else {
            return Ok(None);
        };
        let value = decode_capacity_shard(&encoded, &self.deployment_prefix)?;
        if value.shard != u32::from(shard) {
            return Err(CapacityStoreError::Key(
                "decoded shard differs from the requested shard",
            ));
        }
        let binding = self.binding(&full_key, relative, &encoded, meta)?;
        validate_capacity_shard_object(&value, &binding.object, &self.deployment_prefix)?;
        Ok(Some(StoredCapacityShard {
            shard: value,
            binding,
        }))
    }

    /// Load one exact historical shard version.
    pub async fn load_exact_shard(
        &self,
        expected: &CapacityObjectRef,
    ) -> Result<StoredCapacityShard, CapacityStoreError> {
        let full_key = object_key(expected)?;
        let relative = self.relative_key(full_key, V2KeyKind::CapacityShard)?;
        let version = object_version(expected)?;
        let (meta, encoded) = self
            .load_exact(relative, version, MAX_CAPACITY_SHARD_BYTES)
            .await?;
        let shard = decode_capacity_shard(&encoded, &self.deployment_prefix)?;
        let binding = self.binding(full_key, relative, &encoded, meta)?;
        validate_exact_requested(expected, &binding.object)?;
        validate_capacity_shard_object(&shard, expected, &self.deployment_prefix)?;
        Ok(StoredCapacityShard { shard, binding })
    }

    /// Publish one validated RESERVED insertion with one conditional write.
    pub async fn reserve_cas(
        &self,
        control: &StoredCapacityControl,
        page: &StoredTenantCapacityCatalogPage,
        previous: &StoredCapacityShard,
        successor: CapacityShard,
        observed_now_unix_seconds: u64,
    ) -> Result<ShardCompareAndSwapOutcome, CapacityStoreError> {
        validate_capacity_stable_admission_successor(
            control.control(),
            page.page(),
            previous.shard(),
            previous.binding().object(),
            &successor,
            observed_now_unix_seconds,
            &self.deployment_prefix,
        )?;
        require_reserved_insertion(previous.shard(), &successor)?;
        self.compare_and_swap_shard(previous, successor).await
    }

    /// Publish one validated RESERVED-to-expired-ABORTED transition.
    pub async fn expire_reserved_cas(
        &self,
        control: &StoredCapacityControl,
        page: &StoredTenantCapacityCatalogPage,
        previous: &StoredCapacityShard,
        successor: CapacityShard,
        observed_now_unix_seconds: u64,
    ) -> Result<ShardCompareAndSwapOutcome, CapacityStoreError> {
        if control.control().state == walgit_proto::v2::CapacityControlState::Stable as i32 {
            validate_capacity_stable_admission_successor(
                control.control(),
                page.page(),
                previous.shard(),
                previous.binding().object(),
                &successor,
                observed_now_unix_seconds,
                &self.deployment_prefix,
            )?;
        } else {
            validate_capacity_preparing_drainage_successor(
                control.control(),
                page.page(),
                previous.shard(),
                previous.binding().object(),
                &successor,
                observed_now_unix_seconds,
                &self.deployment_prefix,
            )?;
        }
        require_expired_transition(previous.shard(), &successor)?;
        self.compare_and_swap_shard(previous, successor).await
    }

    /// Attempt exactly one conditional shard write, then at most one strict GET.
    async fn compare_and_swap_shard(
        &self,
        previous: &StoredCapacityShard,
        successor: CapacityShard,
    ) -> Result<ShardCompareAndSwapOutcome, CapacityStoreError> {
        let encoded = Bytes::from(encode_capacity_shard(&successor, &self.deployment_prefix)?);
        let shard = u8::try_from(successor.shard)
            .map_err(|_| CapacityStoreError::Key("successor shard is outside 0..=255"))?;
        let full_key = capacity_shard_key(&self.deployment_prefix, shard)
            .map_err(|_| CapacityStoreError::Key("cannot derive successor shard key"))?;
        if previous.binding.object.key.as_ref() != full_key.as_bytes() {
            return Err(CapacityStoreError::Key(
                "successor key differs from the loaded shard binding",
            ));
        }
        let relative = self
            .relative_key(&full_key, V2KeyKind::CapacityShard)?
            .to_owned();
        match self
            .store
            .put_bytes(
                &relative,
                encoded.clone(),
                PutMode::Update(previous.binding.cas_token.clone()),
            )
            .await
        {
            Ok(meta) => match self.stored_shard(successor.clone(), &encoded, meta) {
                Ok(stored) => Ok(ShardCompareAndSwapOutcome::Committed(stored)),
                Err(_) => Ok(self.resolve_ambiguous(previous, &successor).await),
            },
            Err(error) if error.is_precondition_failed() => {
                let outcome = match self.load_current_shard(shard).await {
                    Ok(Some(current)) if current.shard == successor => {
                        ShardCompareAndSwapOutcome::Committed(current)
                    }
                    Ok(current) => ShardCompareAndSwapOutcome::Conflict(current),
                    Err(_) => ShardCompareAndSwapOutcome::Conflict(None),
                };
                Ok(outcome)
            }
            Err(_) => Ok(self.resolve_ambiguous(previous, &successor).await),
        }
    }

    async fn resolve_ambiguous(
        &self,
        previous: &StoredCapacityShard,
        successor: &CapacityShard,
    ) -> ShardCompareAndSwapOutcome {
        let shard = match u8::try_from(successor.shard) {
            Ok(shard) => shard,
            Err(_) => return ShardCompareAndSwapOutcome::Indeterminate,
        };
        match self.load_current_shard(shard).await {
            Ok(Some(current)) if current.shard == *successor => {
                ShardCompareAndSwapOutcome::Committed(current)
            }
            Ok(Some(current)) if current.binding == previous.binding => {
                ShardCompareAndSwapOutcome::NotCommitted(current)
            }
            Ok(Some(_)) | Ok(None) | Err(_) => ShardCompareAndSwapOutcome::Indeterminate,
        }
    }

    fn stored_shard(
        &self,
        shard: CapacityShard,
        encoded: &[u8],
        meta: ObjectMeta,
    ) -> Result<StoredCapacityShard, CapacityStoreError> {
        let shard_number = u8::try_from(shard.shard)
            .map_err(|_| CapacityStoreError::Key("shard is outside 0..=255"))?;
        let full_key = capacity_shard_key(&self.deployment_prefix, shard_number)
            .map_err(|_| CapacityStoreError::Key("cannot derive shard key"))?;
        let relative = self.relative_key(&full_key, V2KeyKind::CapacityShard)?;
        let binding = self.binding(&full_key, relative, encoded, meta)?;
        validate_capacity_shard_object(&shard, &binding.object, &self.deployment_prefix)?;
        Ok(StoredCapacityShard { shard, binding })
    }

    async fn load_current(
        &self,
        relative: &str,
        maximum: usize,
    ) -> Result<Option<(ObjectMeta, Bytes)>, CapacityStoreError> {
        match self.store.get(relative, GetOptions::default()).await {
            Ok(GetResult::Object { meta, body }) => {
                validate_provider_size(meta.size, maximum)?;
                let size = meta.size;
                Ok(Some((meta, util::collect_exact(body, size).await?)))
            }
            Ok(GetResult::NotModified { .. }) => Err(CapacityStoreError::Metadata(
                "unconditional GET returned NotModified",
            )),
            Err(StoreError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn load_exact(
        &self,
        relative: &str,
        version: ObjectVersionId,
        maximum: usize,
    ) -> Result<(ObjectMeta, Bytes), CapacityStoreError> {
        match self.store.get_version(relative, &version, None).await? {
            GetResult::Object { meta, body } => {
                validate_provider_size(meta.size, maximum)?;
                let size = meta.size;
                Ok((meta, util::collect_exact(body, size).await?))
            }
            GetResult::NotModified { .. } => Err(CapacityStoreError::Metadata(
                "exact GET returned NotModified",
            )),
        }
    }

    fn binding(
        &self,
        full_key: &str,
        relative: &str,
        encoded: &[u8],
        meta: ObjectMeta,
    ) -> Result<CapacityBinding, CapacityStoreError> {
        if meta.key != relative {
            return Err(CapacityStoreError::Metadata(
                "provider key differs from the requested store-relative key",
            ));
        }
        if meta.size != encoded.len() as u64 {
            return Err(CapacityStoreError::Metadata(
                "provider size differs from the strict encoded size",
            ));
        }
        validate_opaque(meta.version.as_str(), MAX_CAS_TOKEN_BYTES, "CasToken")?;
        let object_version_id = meta.object_version_id.ok_or(CapacityStoreError::Metadata(
            "provider omitted ObjectVersionId",
        ))?;
        validate_opaque(
            object_version_id.as_str(),
            MAX_OBJECT_VERSION_ID_BYTES,
            "ObjectVersionId",
        )?;
        Ok(CapacityBinding {
            object: CapacityObjectRef {
                key: Bytes::copy_from_slice(full_key.as_bytes()),
                object_version_id: Bytes::copy_from_slice(object_version_id.as_str().as_bytes()),
                digest: Bytes::copy_from_slice(
                    ProtobufObjectDigest::of_exact_protobuf(encoded).as_bytes(),
                ),
                size: meta.size,
            },
            cas_token: meta.version,
        })
    }

    fn relative_key<'a>(
        &self,
        full_key: &'a str,
        expected_kind: V2KeyKind,
    ) -> Result<&'a str, CapacityStoreError> {
        let parsed = parse_key(&self.deployment_prefix, full_key.as_bytes())
            .map_err(|_| CapacityStoreError::Key("outside the configured V2 key grammar"))?;
        if parsed.kind != expected_kind {
            return Err(CapacityStoreError::Key("has the wrong V2 object kind"));
        }
        full_key
            .strip_prefix(self.deployment_prefix.as_str())
            .filter(|relative| !relative.is_empty())
            .ok_or(CapacityStoreError::Key(
                "does not begin with the configured deployment prefix",
            ))
    }
}

fn require_reserved_insertion(
    previous: &CapacityShard,
    successor: &CapacityShard,
) -> Result<(), CapacityStoreError> {
    if successor.reservations.len() != previous.reservations.len().saturating_add(1) {
        return Err(CapacityStoreError::Operation(
            "reserve_cas requires exactly one inserted reservation",
        ));
    }
    let mut previous_index = 0usize;
    let mut inserted = 0usize;
    for candidate in &successor.reservations {
        if previous
            .reservations
            .get(previous_index)
            .is_some_and(|prior| prior == candidate)
        {
            previous_index += 1;
            continue;
        }
        if inserted != 0
            || candidate.state != CapacityReservationState::Reserved as i32
            || !matches!(
                candidate.state_payload.as_ref(),
                Some(ReservationPayload::Reserved(_))
            )
        {
            return Err(CapacityStoreError::Operation(
                "reserve_cas accepts only one new RESERVED row",
            ));
        }
        inserted = 1;
    }
    if inserted != 1 || previous_index != previous.reservations.len() {
        return Err(CapacityStoreError::Operation(
            "reserve_cas changed a retained reservation",
        ));
    }
    Ok(())
}

fn require_expired_transition(
    previous: &CapacityShard,
    successor: &CapacityShard,
) -> Result<(), CapacityStoreError> {
    if successor.reservations.len() != previous.reservations.len() {
        return Err(CapacityStoreError::Operation(
            "expire_reserved_cas cannot insert or remove reservations",
        ));
    }
    let mut transitions = 0usize;
    for (prior, candidate) in previous.reservations.iter().zip(&successor.reservations) {
        if prior == candidate {
            continue;
        }
        if transitions != 0
            || prior.state != CapacityReservationState::Reserved as i32
            || candidate.state != CapacityReservationState::Aborted as i32
            || !matches!(
                candidate.state_payload.as_ref(),
                Some(ReservationPayload::Aborted(aborted))
                    if matches!(aborted.proof.as_ref(), Some(AbortedProof::Expired(_)))
            )
        {
            return Err(CapacityStoreError::Operation(
                "expire_reserved_cas accepts only one RESERVED-to-expired-ABORTED row",
            ));
        }
        transitions = 1;
    }
    if transitions != 1 {
        return Err(CapacityStoreError::Operation(
            "expire_reserved_cas requires exactly one expiry transition",
        ));
    }
    Ok(())
}

fn validate_provider_size(size: u64, maximum: usize) -> Result<(), CapacityStoreError> {
    if size > maximum as u64 {
        return Err(CapacityStoreError::Metadata(
            "provider size exceeds the capacity object bound",
        ));
    }
    Ok(())
}

fn validate_opaque(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), CapacityStoreError> {
    if value.is_empty() || value.len() > maximum {
        return Err(CapacityStoreError::Metadata(match field {
            "CasToken" => "CasToken is empty or exceeds 256 bytes",
            _ => "ObjectVersionId is empty or exceeds 1024 bytes",
        }));
    }
    Ok(())
}

fn object_key(object: &CapacityObjectRef) -> Result<&str, CapacityStoreError> {
    std::str::from_utf8(&object.key)
        .map_err(|_| CapacityStoreError::Key("capacity object key must be UTF-8"))
}

fn object_version(object: &CapacityObjectRef) -> Result<ObjectVersionId, CapacityStoreError> {
    let value = std::str::from_utf8(&object.object_version_id)
        .map_err(|_| CapacityStoreError::Metadata("ObjectVersionId must be UTF-8"))?;
    validate_opaque(value, MAX_OBJECT_VERSION_ID_BYTES, "ObjectVersionId")?;
    Ok(ObjectVersionId::new(value))
}

fn validate_exact_requested(
    expected: &CapacityObjectRef,
    observed: &CapacityObjectRef,
) -> Result<(), CapacityStoreError> {
    if expected != observed {
        return Err(CapacityStoreError::Metadata(
            "exact provider metadata differs from the rooted object reference",
        ));
    }
    Ok(())
}

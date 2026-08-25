//! Dormant V2 repository authorization and mutation settlement.
//!
//! This crate owns repository policy and state-machine rules. It is not wired
//! into the V1 server. Persistence stays in `walgit-store`.

use std::collections::HashSet;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walgit_identity::{AuthenticatedCapability, CapabilityPurpose};
use walgit_proto::v2::{
    CatalogKind, CatalogRoot, ControlCodecError, GrantRole, InlineGrants, LandedControlRef,
    Lifecycle, MAX_MUTATION_RESULT_BYTES, MutationKind, MutationReceipt, MutationResult,
    NoCapacityObligation, NoEventObligation, PriorControlBinding, ReceiptCatalog,
    ReceiptCatalogRow, ReceiptState, RepoControl, RepositoryGrant, RepositoryIdentity,
    TargetObjectRef, WriterFence, decode_mutation_result, decode_receipt_catalog,
    digests::{ContentAddressDigest, ProtobufObjectDigest},
    encode_mutation_result, encode_receipt_catalog,
    keys::{DeploymentPrefix, RepositoryKeyIdentity, V2KeyKind, parse_key},
    mutation_receipt::{CapacityObligation, EventObligation, Predecessor},
    repo_control::GrantRepresentation,
};
use walgit_store::{
    DynStore, GetOptions, GetResult, ObjectMeta, ObjectStoreExt, ObjectVersionId, PutMode, util,
    v2_control::{CompareAndSwapOutcome, ControlStore, StoredRepoControl},
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"walgit-repository-mutation-request-v1";
const MAX_RECEIPT_ROWS: usize = 4_096;

/// One repository operation checked against the exact current inline grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryAction {
    CloneRead,
    GitRead,
    GitWrite,
    LfsRead,
    LfsFinalize,
    WebhookAdmin,
    ServiceBuild,
    RepositoryAdmin,
}

impl RepositoryAction {
    fn purpose(self) -> CapabilityPurpose {
        match self {
            Self::CloneRead => CapabilityPurpose::CloneRead,
            Self::GitRead => CapabilityPurpose::GitRead,
            Self::GitWrite => CapabilityPurpose::GitWrite,
            Self::LfsRead => CapabilityPurpose::LfsRead,
            Self::LfsFinalize => CapabilityPurpose::LfsFinalize,
            Self::WebhookAdmin => CapabilityPurpose::WebhookAdmin,
            Self::ServiceBuild => CapabilityPurpose::ServiceBuild,
            Self::RepositoryAdmin => CapabilityPurpose::RepositoryAdmin,
        }
    }
}

/// The only ordinary mutation kinds implemented by this dormant slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedMutationKind {
    Settings,
    Grants,
}

impl TryFrom<MutationKind> for SupportedMutationKind {
    type Error = ControlError;

    fn try_from(kind: MutationKind) -> Result<Self, Self::Error> {
        match kind {
            MutationKind::Settings => Ok(Self::Settings),
            MutationKind::Grants => Ok(Self::Grants),
            _ => Err(ControlError::UnsupportedMutation),
        }
    }
}

/// A domain-separated digest of the exact mutation request bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationRequestDigest([u8; 32]);

impl MutationRequestDigest {
    pub fn of(kind: MutationKind, exact_request: &[u8]) -> Result<Self, ControlError> {
        let preimage = mutation_request_preimage(kind, exact_request)?;
        let digest = Sha256::digest(preimage);
        Ok(Self(digest.into()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn mutation_request_preimage(
    kind: MutationKind,
    exact_request: &[u8],
) -> Result<Vec<u8>, ControlError> {
    if !matches!(
        kind,
        MutationKind::Settings | MutationKind::Grants | MutationKind::WriterTakeover
    ) {
        return Err(ControlError::UnsupportedMutation);
    }
    let length = u64::try_from(exact_request.len()).map_err(|_| ControlError::InvalidRequest)?;
    let mut preimage =
        Vec::with_capacity(REQUEST_DIGEST_DOMAIN.len() + 4 + 8 + exact_request.len());
    preimage.extend_from_slice(REQUEST_DIGEST_DOMAIN);
    preimage.extend_from_slice(&(kind as u32).to_be_bytes());
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(exact_request);
    Ok(preimage)
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("repository authorization denied")]
    Denied,
    #[error("repository grant catalogs are not supported by this dormant authorization slice")]
    GrantCatalogUnsupported,
    #[error("repository writer fence does not match")]
    StaleWriterFence,
    #[error("repository mutation kind is not supported by this dormant slice")]
    UnsupportedMutation,
    #[error("repository mutation request is invalid")]
    InvalidRequest,
    #[error("repository has an unresolved mutation receipt")]
    PendingSettlement,
    #[error("repository receipt catalog reached its fixed limit")]
    ReceiptCatalogFull,
    #[error("repository mutation replay conflicts with the persisted receipt")]
    ReplayConflict,
    #[error("repository mutation transition is out of order")]
    OutOfOrder,
    #[error("repository immutable control object is invalid")]
    InvalidObject,
    #[error("repository immutable write outcome is indeterminate")]
    Indeterminate,
    #[error("repository control persistence failed")]
    Persistence(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ControlError {
    fn persistence(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Persistence(Box::new(error))
    }
}

/// Authorize one authenticated capability against one exact current control.
///
/// This function has no credential parsing path. Only `walgit-identity` can
/// construct the required authenticated capability.
pub fn authorize_inline_grant(
    current: &StoredRepoControl,
    capability: &AuthenticatedCapability,
    action: RepositoryAction,
) -> Result<GrantRole, ControlError> {
    authorize_binding(
        current,
        CapabilityBinding {
            purpose: capability.purpose(),
            tenant_id: capability.tenant_id(),
            project_id: capability.project_id(),
            repository_uuid: capability.repository_uuid(),
            generation: capability.generation(),
            canonical_path: capability.canonical_path(),
            canonical_path_digest: capability.canonical_path_digest(),
            routing_digest: capability.routing_digest(),
            control_key: capability.control_key(),
            control_version_id: capability.control_version_id(),
            cutover_generation: capability.cutover_generation(),
            authorization_epoch: capability.authorization_epoch(),
            grant: capability.grant(),
        },
        action,
    )
}

#[derive(Clone, Copy)]
struct CapabilityBinding<'a> {
    purpose: CapabilityPurpose,
    tenant_id: &'a [u8],
    project_id: &'a [u8],
    repository_uuid: &'a [u8; 16],
    generation: u64,
    canonical_path: &'a [u8],
    canonical_path_digest: &'a [u8; 32],
    routing_digest: &'a [u8; 32],
    control_key: &'a [u8],
    control_version_id: &'a [u8],
    cutover_generation: u64,
    authorization_epoch: u64,
    grant: (&'a [u8], &'a [u8]),
}

fn authorize_binding(
    current: &StoredRepoControl,
    capability: CapabilityBinding<'_>,
    action: RepositoryAction,
) -> Result<GrantRole, ControlError> {
    authorize_control(
        current.control(),
        current.binding().object_version_id().as_str().as_bytes(),
        capability,
        action,
    )
}

fn authorize_control(
    control: &RepoControl,
    current_object_version_id: &[u8],
    capability: CapabilityBinding<'_>,
    action: RepositoryAction,
) -> Result<GrantRole, ControlError> {
    let identity = control.identity.as_ref().ok_or(ControlError::Denied)?;
    if control.lifecycle != Lifecycle::Active as i32
        || capability.purpose != action.purpose()
        || capability.tenant_id != identity.tenant_id.as_ref()
        || capability.project_id != identity.project_id.as_ref()
        || capability.repository_uuid.as_slice() != identity.repository_uuid.as_ref()
        || capability.generation != identity.generation
        || capability.canonical_path != identity.canonical_path.as_ref()
        || capability.canonical_path_digest.as_slice() != identity.canonical_path_digest.as_ref()
        || capability.routing_digest.as_slice() != identity.routing_digest.as_ref()
        || capability.control_key != control.repo_control_key.as_ref()
        || capability.control_version_id != current_object_version_id
        || capability.cutover_generation != control.cutover_generation
        || capability.authorization_epoch != control.authorization_epoch
    {
        return Err(ControlError::Denied);
    }

    let grants = match control.grant_representation.as_ref() {
        Some(GrantRepresentation::InlineGrants(inline)) => &inline.grants,
        Some(GrantRepresentation::GrantCatalog(_)) | None => {
            return Err(ControlError::GrantCatalogUnsupported);
        }
    };
    let (issuer, subject) = capability.grant;
    let grant = grants
        .iter()
        .find(|grant| grant.issuer.as_ref() == issuer && grant.subject.as_ref() == subject)
        .ok_or(ControlError::Denied)?;
    let role = GrantRole::try_from(grant.role).map_err(|_| ControlError::Denied)?;
    if role_allows(role, action) {
        Ok(role)
    } else {
        Err(ControlError::Denied)
    }
}

fn role_allows(role: GrantRole, action: RepositoryAction) -> bool {
    match action {
        RepositoryAction::CloneRead
        | RepositoryAction::GitRead
        | RepositoryAction::LfsRead
        | RepositoryAction::ServiceBuild => matches!(
            role,
            GrantRole::Reader | GrantRole::Writer | GrantRole::Administrator
        ),
        RepositoryAction::GitWrite | RepositoryAction::LfsFinalize => {
            matches!(role, GrantRole::Writer | GrantRole::Administrator)
        }
        RepositoryAction::WebhookAdmin | RepositoryAction::RepositoryAdmin => {
            role == GrantRole::Administrator
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MutationOutcome {
    Committed(StoredRepoControl),
    ExactReplay(RootedMutationResult),
    RecoveryRequired(StoredRepoControl),
    Conflict(Option<StoredRepoControl>),
    NotCommitted(StoredRepoControl),
    Indeterminate,
}

/// One immutable result whose exact rooted version and receipt binding were
/// verified before it was returned by the controller.
#[derive(Clone, Debug, PartialEq)]
pub struct RootedMutationResult {
    target: TargetObjectRef,
    result: MutationResult,
}

impl RootedMutationResult {
    pub fn target(&self) -> &TargetObjectRef {
        &self.target
    }

    pub fn result(&self) -> &MutationResult {
        &self.result
    }
}

/// Domain controller over the real V2 control and object-store adapters.
#[derive(Clone)]
pub struct RepositoryController {
    control: ControlStore,
    objects: DynStore,
    prefix: DeploymentPrefix,
}

impl RepositoryController {
    pub fn new(objects: DynStore, prefix: DeploymentPrefix) -> Result<Self, ControlError> {
        let control = ControlStore::new(objects.clone(), prefix.clone())
            .map_err(ControlError::persistence)?;
        Ok(Self {
            control,
            objects,
            prefix,
        })
    }

    pub async fn change_settings(
        &self,
        previous: &StoredRepoControl,
        capability: &AuthenticatedCapability,
        expected_writer: &WriterFence,
        mutation_id: [u8; 16],
        settings: Bytes,
    ) -> Result<MutationOutcome, ControlError> {
        authorize_inline_grant(previous, capability, RepositoryAction::RepositoryAdmin)?;
        require_writer(previous.control(), expected_writer)?;
        if settings.len() > 16_384 {
            return Err(ControlError::InvalidRequest);
        }
        let request_digest = MutationRequestDigest::of(MutationKind::Settings, &settings)?;
        let mut successor = ordinary_successor(previous.control(), mutation_id)?;
        successor.inline_settings = settings;
        self.publish(
            previous,
            successor,
            MutationKind::Settings,
            mutation_id,
            request_digest,
        )
        .await
    }

    pub async fn change_grants(
        &self,
        previous: &StoredRepoControl,
        capability: &AuthenticatedCapability,
        expected_writer: &WriterFence,
        mutation_id: [u8; 16],
        grants: Vec<RepositoryGrant>,
    ) -> Result<MutationOutcome, ControlError> {
        authorize_inline_grant(previous, capability, RepositoryAction::RepositoryAdmin)?;
        require_writer(previous.control(), expected_writer)?;
        let request = canonical_grant_request(&grants)?;
        let request_digest = MutationRequestDigest::of(MutationKind::Grants, &request)?;
        let mut successor = ordinary_successor(previous.control(), mutation_id)?;
        successor.authorization_epoch = successor
            .authorization_epoch
            .checked_add(1)
            .ok_or(ControlError::InvalidRequest)?;
        successor.grant_representation =
            Some(GrantRepresentation::InlineGrants(InlineGrants { grants }));
        self.publish(
            previous,
            successor,
            MutationKind::Grants,
            mutation_id,
            request_digest,
        )
        .await
    }

    /// Materialize the result for the one unresolved landed mutation, or
    /// verify and return the immutable result already rooted by settlement.
    pub async fn materialize_result(
        &self,
        landed: &StoredRepoControl,
        mutation_id: [u8; 16],
    ) -> Result<TargetObjectRef, ControlError> {
        require_uuid_v7(&mutation_id)?;
        let catalog = self.load_current_catalog(landed.control()).await?;
        let row = catalog
            .rows
            .iter()
            .find(|row| row.mutation_id.as_ref() == mutation_id)
            .ok_or(ControlError::OutOfOrder)?;
        let receipt = row.receipt.as_ref().ok_or(ControlError::InvalidObject)?;
        require_none_obligations(receipt)?;
        if row.state == ReceiptState::Settled as i32 {
            let target = row.result.as_ref().ok_or(ControlError::InvalidObject)?;
            return Ok(self.load_rooted_result(target, receipt).await?.target);
        }
        if row.state != ReceiptState::Unresolved as i32 || row.result.is_some() {
            return Err(ControlError::OutOfOrder);
        }
        if landed.control().last_internal_mutation_id.as_ref() != mutation_id {
            return Err(ControlError::OutOfOrder);
        }
        let result = MutationResult {
            schema_version: 1,
            identity: landed.control().identity.clone(),
            mutation_id: Bytes::copy_from_slice(&mutation_id),
            kind: receipt.kind,
            landed_control: Some(LandedControlRef {
                repo_control_key: landed.control().repo_control_key.clone(),
                object_version_id: Bytes::copy_from_slice(
                    landed.binding().object_version_id().as_str().as_bytes(),
                ),
                digest: Bytes::copy_from_slice(landed.binding().digest().as_bytes()),
                size: landed.binding().size(),
            }),
            landed_control_revision: landed.control().control_revision,
            writer_epoch: landed
                .control()
                .writer
                .as_ref()
                .ok_or(ControlError::InvalidObject)?
                .epoch,
            wal_sequence: landed
                .control()
                .wal
                .as_ref()
                .ok_or(ControlError::InvalidObject)?
                .head_sequence,
        };
        let encoded = encode_mutation_result(&result).map_err(ControlError::persistence)?;
        let full_key = receipt_result_key(
            &self.prefix,
            landed
                .control()
                .identity
                .as_ref()
                .ok_or(ControlError::InvalidObject)?,
            &mutation_id,
        )?;
        let meta = self
            .persist_immutable(&full_key, &encoded, V2KeyKind::ReceiptResult)
            .await?;
        Ok(target_from_meta(
            landed
                .control()
                .identity
                .clone()
                .ok_or(ControlError::InvalidObject)?,
            full_key,
            &encoded,
            meta,
        )?)
    }

    /// Root one previously materialized result and preserve the receipt row as
    /// SETTLED. This is the only receiptless CAS in this controller.
    pub async fn settle(
        &self,
        previous: &StoredRepoControl,
        expected_writer: &WriterFence,
        receipt_mutation_id: [u8; 16],
        settlement_mutation_id: [u8; 16],
    ) -> Result<MutationOutcome, ControlError> {
        require_uuid_v7(&receipt_mutation_id)?;
        require_uuid_v7(&settlement_mutation_id)?;
        require_writer(previous.control(), expected_writer)?;
        let mut catalog = self.load_current_catalog(previous.control()).await?;
        let row_index = catalog
            .rows
            .iter()
            .position(|row| row.mutation_id.as_ref() == receipt_mutation_id)
            .ok_or(ControlError::OutOfOrder)?;
        let row = &catalog.rows[row_index];
        if row.state == ReceiptState::Settled as i32 {
            if row.settlement_mutation_id.as_ref() != settlement_mutation_id {
                return Err(ControlError::ReplayConflict);
            }
            let receipt = row.receipt.as_ref().ok_or(ControlError::InvalidObject)?;
            require_none_obligations(receipt)?;
            let target = row.result.as_ref().ok_or(ControlError::InvalidObject)?;
            let rooted = self.load_rooted_result(target, receipt).await?;
            return Ok(MutationOutcome::ExactReplay(rooted));
        }
        if row.state != ReceiptState::Unresolved as i32
            || row.result.is_some()
            || !row.settlement_mutation_id.is_empty()
        {
            return Err(ControlError::OutOfOrder);
        }
        let receipt = row.receipt.clone().ok_or(ControlError::InvalidObject)?;
        require_none_obligations(&receipt)?;
        let result_target = self
            .load_expected_result(previous, &receipt_mutation_id, &receipt)
            .await?;
        let row = &mut catalog.rows[row_index];
        row.state = ReceiptState::Settled as i32;
        row.result = Some(result_target);
        row.settlement_mutation_id = Bytes::copy_from_slice(&settlement_mutation_id);

        let root = self.persist_catalog(&catalog).await?;
        let mut successor = ordinary_successor(previous.control(), settlement_mutation_id)?;
        successor.receipt_catalog = Some(root);
        self.cas(previous, successor).await
    }

    async fn publish(
        &self,
        previous: &StoredRepoControl,
        mut successor: RepoControl,
        kind: MutationKind,
        mutation_id: [u8; 16],
        request_digest: MutationRequestDigest,
    ) -> Result<MutationOutcome, ControlError> {
        require_uuid_v7(&mutation_id)?;
        SupportedMutationKind::try_from(kind)?;
        let mut catalog = self.load_current_catalog(previous.control()).await?;
        if let Some(existing) = catalog
            .rows
            .iter()
            .find(|row| row.mutation_id.as_ref() == mutation_id)
        {
            let receipt = existing
                .receipt
                .as_ref()
                .ok_or(ControlError::InvalidObject)?;
            if receipt.kind != kind as i32
                || receipt.request_digest.as_ref() != request_digest.as_bytes()
            {
                return Err(ControlError::ReplayConflict);
            }
            return match ReceiptState::try_from(existing.state) {
                Ok(ReceiptState::Unresolved) => {
                    Ok(MutationOutcome::RecoveryRequired(previous.clone()))
                }
                Ok(ReceiptState::Settled) => {
                    let target = existing
                        .result
                        .as_ref()
                        .ok_or(ControlError::InvalidObject)?;
                    Ok(MutationOutcome::ExactReplay(
                        self.load_rooted_result(target, receipt).await?,
                    ))
                }
                _ => Err(ControlError::InvalidObject),
            };
        }
        if catalog
            .rows
            .iter()
            .any(|row| row.state == ReceiptState::Unresolved as i32)
        {
            return Err(ControlError::PendingSettlement);
        }
        if catalog.rows.len() >= MAX_RECEIPT_ROWS {
            return Err(ControlError::ReceiptCatalogFull);
        }

        let identity = previous
            .control()
            .identity
            .clone()
            .ok_or(ControlError::InvalidObject)?;
        let writer_epoch = previous
            .control()
            .writer
            .as_ref()
            .ok_or(ControlError::InvalidObject)?
            .epoch;
        let wal_sequence = successor
            .wal
            .as_ref()
            .ok_or(ControlError::InvalidObject)?
            .head_sequence;
        let receipt = MutationReceipt {
            schema_version: 1,
            identity: Some(identity),
            mutation_id: Bytes::copy_from_slice(&mutation_id),
            kind: kind as i32,
            writer_epoch,
            wal_sequence,
            request_digest: Bytes::copy_from_slice(request_digest.as_bytes()),
            immutable_dependency_digests: Vec::new(),
            predecessor: Some(Predecessor::PriorControl(PriorControlBinding {
                cas_token: Bytes::copy_from_slice(
                    previous.binding().cas_token().as_str().as_bytes(),
                ),
                object_version_id: Bytes::copy_from_slice(
                    previous.binding().object_version_id().as_str().as_bytes(),
                ),
            })),
            capacity_obligation: Some(CapacityObligation::NoCapacity(NoCapacityObligation {})),
            event_obligation: Some(EventObligation::NoEvent(NoEventObligation {})),
        };
        catalog.rows.push(ReceiptCatalogRow {
            mutation_id: Bytes::copy_from_slice(&mutation_id),
            state: ReceiptState::Unresolved as i32,
            receipt: Some(receipt),
            result: None,
            settlement_mutation_id: Bytes::new(),
        });
        catalog
            .rows
            .sort_by(|left, right| left.mutation_id.cmp(&right.mutation_id));
        ensure_settlement_capacity(&catalog, &self.prefix, &mutation_id)?;
        successor.receipt_catalog = Some(self.persist_catalog(&catalog).await?);
        self.cas(previous, successor).await
    }

    async fn cas(
        &self,
        previous: &StoredRepoControl,
        successor: RepoControl,
    ) -> Result<MutationOutcome, ControlError> {
        let outcome = self
            .control
            .compare_and_swap(previous, successor)
            .await
            .map_err(ControlError::persistence)?;
        Ok(match outcome {
            CompareAndSwapOutcome::Committed(value) => MutationOutcome::Committed(value),
            CompareAndSwapOutcome::Conflict(value) => MutationOutcome::Conflict(value),
            CompareAndSwapOutcome::NotCommitted(value) => MutationOutcome::NotCommitted(value),
            CompareAndSwapOutcome::Indeterminate => MutationOutcome::Indeterminate,
        })
    }

    async fn load_current_catalog(
        &self,
        control: &RepoControl,
    ) -> Result<ReceiptCatalog, ControlError> {
        let catalog = match control.receipt_catalog.as_ref() {
            Some(root) => {
                let identity = control
                    .identity
                    .as_ref()
                    .ok_or(ControlError::InvalidObject)?;
                self.load_catalog(root, identity).await?
            }
            None => ReceiptCatalog {
                schema_version: 1,
                identity: control.identity.clone(),
                rows: Vec::new(),
            },
        };
        let mut unresolved = catalog
            .rows
            .iter()
            .filter(|row| row.state == ReceiptState::Unresolved as i32);
        if let Some(row) = unresolved.next() {
            if unresolved.next().is_some() || row.mutation_id != control.last_internal_mutation_id {
                return Err(ControlError::InvalidObject);
            }
        }
        Ok(catalog)
    }

    async fn load_catalog(
        &self,
        root: &CatalogRoot,
        expected_identity: &RepositoryIdentity,
    ) -> Result<ReceiptCatalog, ControlError> {
        if root.kind != CatalogKind::Receipt as i32 || root.depth != 1 || root.node_count != 1 {
            return Err(ControlError::InvalidObject);
        }
        let object = root.object.as_ref().ok_or(ControlError::InvalidObject)?;
        if object.identity.as_ref() != Some(expected_identity) {
            return Err(ControlError::InvalidObject);
        }
        let rooted_digest: [u8; 32] = object
            .digest
            .as_ref()
            .try_into()
            .map_err(|_| ControlError::InvalidObject)?;
        let key = std::str::from_utf8(&object.key).map_err(|_| ControlError::InvalidObject)?;
        let parsed =
            parse_key(&self.prefix, key.as_bytes()).map_err(|_| ControlError::InvalidObject)?;
        if parsed.content_digest != Some(ContentAddressDigest::from_bytes(rooted_digest)) {
            return Err(ControlError::InvalidObject);
        }
        let (meta, body) = self
            .load_exact(object, V2KeyKind::Catalog(CatalogKind::Receipt))
            .await?;
        if meta.size != object.size
            || body.len() as u64 != object.size
            || root.total_encoded_bytes != object.size
        {
            return Err(ControlError::InvalidObject);
        }
        let digest = ProtobufObjectDigest::of_exact_protobuf(&body);
        if digest.as_bytes().as_slice() != object.digest.as_ref() {
            return Err(ControlError::InvalidObject);
        }
        let catalog = decode_receipt_catalog(&body).map_err(ControlError::persistence)?;
        if catalog.identity.as_ref() != Some(expected_identity)
            || root.item_count != catalog.rows.len() as u64
        {
            return Err(ControlError::InvalidObject);
        }
        Ok(catalog)
    }

    async fn persist_catalog(&self, catalog: &ReceiptCatalog) -> Result<CatalogRoot, ControlError> {
        let encoded = encode_catalog_with_backpressure(catalog)?;
        let digest = ProtobufObjectDigest::of_exact_protobuf(&encoded);
        let identity = catalog
            .identity
            .as_ref()
            .ok_or(ControlError::InvalidObject)?;
        let full_key = receipt_catalog_key(&self.prefix, identity, digest)?;
        let meta = self
            .persist_immutable(
                &full_key,
                &encoded,
                V2KeyKind::Catalog(CatalogKind::Receipt),
            )
            .await?;
        Ok(CatalogRoot {
            kind: CatalogKind::Receipt as i32,
            object: Some(target_from_meta(
                identity.clone(),
                full_key,
                &encoded,
                meta,
            )?),
            depth: 1,
            node_count: 1,
            item_count: catalog.rows.len() as u64,
            total_encoded_bytes: encoded.len() as u64,
        })
    }

    async fn load_expected_result(
        &self,
        landed: &StoredRepoControl,
        mutation_id: &[u8; 16],
        receipt: &MutationReceipt,
    ) -> Result<TargetObjectRef, ControlError> {
        let identity = landed
            .control()
            .identity
            .as_ref()
            .ok_or(ControlError::InvalidObject)?;
        let full_key = receipt_result_key(&self.prefix, identity, mutation_id)?;
        let relative = self.relative_key(&full_key, V2KeyKind::ReceiptResult)?;
        let (meta, body) = self
            .objects
            .get_bytes(relative)
            .await
            .map_err(ControlError::persistence)?
            .ok_or(ControlError::OutOfOrder)?;
        if meta.key != relative
            || meta.size != body.len() as u64
            || meta.object_version_id.is_none()
        {
            return Err(ControlError::InvalidObject);
        }
        let result = decode_mutation_result(&body).map_err(ControlError::persistence)?;
        let control_ref = result
            .landed_control
            .as_ref()
            .ok_or(ControlError::InvalidObject)?;
        let receipt_kind =
            MutationKind::try_from(receipt.kind).map_err(|_| ControlError::InvalidObject)?;
        let expected_result_writer_epoch = if receipt_kind == MutationKind::WriterTakeover {
            receipt
                .writer_epoch
                .checked_add(1)
                .ok_or(ControlError::InvalidObject)?
        } else {
            receipt.writer_epoch
        };
        if result.mutation_id.as_ref() != mutation_id
            || result.identity.as_ref() != Some(identity)
            || result.kind != receipt.kind
            || result.landed_control_revision != landed.control().control_revision
            || result.writer_epoch != expected_result_writer_epoch
            || result.writer_epoch
                != landed
                    .control()
                    .writer
                    .as_ref()
                    .ok_or(ControlError::InvalidObject)?
                    .epoch
            || result.wal_sequence
                != landed
                    .control()
                    .wal
                    .as_ref()
                    .ok_or(ControlError::InvalidObject)?
                    .head_sequence
            || result.wal_sequence != receipt.wal_sequence
            || control_ref.repo_control_key != landed.control().repo_control_key
            || control_ref.object_version_id.as_ref()
                != landed.binding().object_version_id().as_str().as_bytes()
            || control_ref.digest.as_ref() != landed.binding().digest().as_bytes()
            || control_ref.size != landed.binding().size()
        {
            return Err(ControlError::OutOfOrder);
        }
        target_from_meta(identity.clone(), full_key, &body, meta)
    }

    async fn load_rooted_result(
        &self,
        target: &TargetObjectRef,
        receipt: &MutationReceipt,
    ) -> Result<RootedMutationResult, ControlError> {
        let identity = receipt
            .identity
            .as_ref()
            .ok_or(ControlError::InvalidObject)?;
        let mutation_id: [u8; 16] = receipt
            .mutation_id
            .as_ref()
            .try_into()
            .map_err(|_| ControlError::InvalidObject)?;
        let expected_key = receipt_result_key(&self.prefix, identity, &mutation_id)?;
        if target.identity.as_ref() != Some(identity)
            || target.key.as_ref() != expected_key.as_bytes()
            || target.size == 0
            || target.size > MAX_MUTATION_RESULT_BYTES as u64
        {
            return Err(ControlError::InvalidObject);
        }
        let (meta, body) = self.load_exact(target, V2KeyKind::ReceiptResult).await?;
        if meta.size != body.len() as u64 || body.len() as u64 != target.size {
            return Err(ControlError::InvalidObject);
        }
        let digest = ProtobufObjectDigest::of_exact_protobuf(&body);
        if digest.as_bytes().as_slice() != target.digest.as_ref() {
            return Err(ControlError::InvalidObject);
        }
        let result = decode_mutation_result(&body).map_err(ControlError::persistence)?;
        verify_result_receipt_binding(&result, receipt)?;
        Ok(RootedMutationResult {
            target: target.clone(),
            result,
        })
    }

    async fn load_exact(
        &self,
        object: &TargetObjectRef,
        expected_kind: V2KeyKind,
    ) -> Result<(ObjectMeta, Bytes), ControlError> {
        let full_key = std::str::from_utf8(&object.key).map_err(|_| ControlError::InvalidObject)?;
        let relative = self.relative_key(full_key, expected_kind)?;
        let version = std::str::from_utf8(&object.object_version_id)
            .map_err(|_| ControlError::InvalidObject)?;
        let result = self
            .objects
            .get(
                relative,
                GetOptions {
                    object_version_id: Some(ObjectVersionId::new(version.to_owned())),
                    ..GetOptions::default()
                },
            )
            .await
            .map_err(ControlError::persistence)?;
        let GetResult::Object { meta, body } = result else {
            return Err(ControlError::InvalidObject);
        };
        if meta.key != relative
            || meta.size != object.size
            || meta.object_version_id.as_ref().map(ObjectVersionId::as_str) != Some(version)
        {
            return Err(ControlError::InvalidObject);
        }
        let bytes = util::collect_exact(body, meta.size)
            .await
            .map_err(ControlError::persistence)?;
        Ok((meta, bytes))
    }

    async fn persist_immutable(
        &self,
        full_key: &str,
        encoded: &[u8],
        expected_kind: V2KeyKind,
    ) -> Result<ObjectMeta, ControlError> {
        let relative = self.relative_key(full_key, expected_kind)?;
        match self
            .objects
            .put_bytes(relative, Bytes::copy_from_slice(encoded), PutMode::Create)
            .await
        {
            Ok(meta) => match verify_written_meta(relative, encoded, meta) {
                Ok(meta) => Ok(meta),
                Err(_) => self.resolve_immutable(relative, encoded).await,
            },
            Err(_write_error) => self.resolve_immutable(relative, encoded).await,
        }
    }

    async fn resolve_immutable(
        &self,
        relative: &str,
        encoded: &[u8],
    ) -> Result<ObjectMeta, ControlError> {
        match self.objects.get_bytes(relative).await {
            Ok(Some((meta, current))) if current.as_ref() == encoded => {
                verify_written_meta(relative, encoded, meta)
                    .map_err(|_| ControlError::Indeterminate)
            }
            Ok(Some(_)) => Err(ControlError::ReplayConflict),
            Ok(None) | Err(_) => Err(ControlError::Indeterminate),
        }
    }

    fn relative_key<'a>(
        &self,
        full_key: &'a str,
        expected_kind: V2KeyKind,
    ) -> Result<&'a str, ControlError> {
        let parsed = parse_key(&self.prefix, full_key.as_bytes())
            .map_err(|_| ControlError::InvalidObject)?;
        if parsed.kind != expected_kind {
            return Err(ControlError::InvalidObject);
        }
        full_key
            .strip_prefix(self.prefix.as_str())
            .filter(|relative| !relative.is_empty())
            .ok_or(ControlError::InvalidObject)
    }
}

fn require_writer(control: &RepoControl, expected: &WriterFence) -> Result<(), ControlError> {
    if control.writer.as_ref() == Some(expected) {
        Ok(())
    } else {
        Err(ControlError::StaleWriterFence)
    }
}

fn require_uuid_v7(value: &[u8; 16]) -> Result<(), ControlError> {
    if value[6] >> 4 == 7 && value[8] >> 6 == 2 {
        Ok(())
    } else {
        Err(ControlError::InvalidRequest)
    }
}

fn require_none_obligations(receipt: &MutationReceipt) -> Result<(), ControlError> {
    if matches!(
        receipt.capacity_obligation.as_ref(),
        Some(CapacityObligation::NoCapacity(_))
    ) && matches!(
        receipt.event_obligation.as_ref(),
        Some(EventObligation::NoEvent(_))
    ) {
        Ok(())
    } else {
        Err(ControlError::UnsupportedMutation)
    }
}

fn verify_result_receipt_binding(
    result: &MutationResult,
    receipt: &MutationReceipt,
) -> Result<(), ControlError> {
    let kind = MutationKind::try_from(receipt.kind).map_err(|_| ControlError::InvalidObject)?;
    let expected_writer_epoch = if kind == MutationKind::WriterTakeover {
        receipt
            .writer_epoch
            .checked_add(1)
            .ok_or(ControlError::InvalidObject)?
    } else {
        receipt.writer_epoch
    };
    if result.identity != receipt.identity
        || result.mutation_id != receipt.mutation_id
        || result.kind != receipt.kind
        || result.writer_epoch != expected_writer_epoch
        || result.wal_sequence != receipt.wal_sequence
    {
        return Err(ControlError::InvalidObject);
    }
    Ok(())
}

fn ordinary_successor(
    previous: &RepoControl,
    mutation_id: [u8; 16],
) -> Result<RepoControl, ControlError> {
    let mut successor = previous.clone();
    successor.control_revision = successor
        .control_revision
        .checked_add(1)
        .ok_or(ControlError::InvalidRequest)?;
    successor.last_internal_mutation_id = Bytes::copy_from_slice(&mutation_id);
    Ok(successor)
}

fn canonical_grant_request(grants: &[RepositoryGrant]) -> Result<Vec<u8>, ControlError> {
    if grants.len() > 256 {
        return Err(ControlError::InvalidRequest);
    }
    let mut identities = HashSet::with_capacity(grants.len());
    for grant in grants {
        if grant.issuer.is_empty()
            || grant.issuer.len() > 256
            || grant.subject.is_empty()
            || grant.subject.len() > 256
            || !matches!(
                GrantRole::try_from(grant.role),
                Ok(GrantRole::Reader | GrantRole::Writer | GrantRole::Administrator)
            )
        {
            return Err(ControlError::InvalidRequest);
        }
        if !identities.insert((grant.issuer.as_ref(), grant.subject.as_ref())) {
            return Err(ControlError::InvalidRequest);
        }
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(grants.len() as u32).to_be_bytes());
    for grant in grants {
        let issuer_len =
            u32::try_from(grant.issuer.len()).map_err(|_| ControlError::InvalidRequest)?;
        let subject_len =
            u32::try_from(grant.subject.len()).map_err(|_| ControlError::InvalidRequest)?;
        encoded.extend_from_slice(&issuer_len.to_be_bytes());
        encoded.extend_from_slice(&grant.issuer);
        encoded.extend_from_slice(&subject_len.to_be_bytes());
        encoded.extend_from_slice(&grant.subject);
        encoded.extend_from_slice(&grant.role.to_be_bytes());
    }
    Ok(encoded)
}

fn ensure_settlement_capacity(
    catalog: &ReceiptCatalog,
    prefix: &DeploymentPrefix,
    mutation_id: &[u8; 16],
) -> Result<(), ControlError> {
    let mut settled = catalog.clone();
    let identity = settled
        .identity
        .clone()
        .ok_or(ControlError::InvalidObject)?;
    let row = settled
        .rows
        .iter_mut()
        .find(|row| row.mutation_id.as_ref() == mutation_id)
        .ok_or(ControlError::InvalidObject)?;
    row.state = ReceiptState::Settled as i32;
    row.settlement_mutation_id = Bytes::from_static(&[
        0x01, 0x89, 0x0f, 0x47, 0x76, 0x44, 0x7b, 0x8b, 0x9d, 0x7a, 0x87, 0x65, 0x43, 0x21, 0x0a,
        0xff,
    ]);
    row.result = Some(TargetObjectRef {
        identity: Some(identity.clone()),
        key: Bytes::from(receipt_result_key(prefix, &identity, mutation_id)?),
        object_version_id: Bytes::from(vec![b'v'; 1_024]),
        digest: Bytes::from(vec![0xff; 32]),
        size: MAX_MUTATION_RESULT_BYTES as u64,
    });
    encode_catalog_with_backpressure(&settled).map(|_| ())
}

fn encode_catalog_with_backpressure(catalog: &ReceiptCatalog) -> Result<Vec<u8>, ControlError> {
    match encode_receipt_catalog(catalog) {
        Ok(encoded) => Ok(encoded),
        Err(ControlCodecError::MessageTooLarge { .. })
        | Err(ControlCodecError::CountExceeded { .. }) => Err(ControlError::ReceiptCatalogFull),
        Err(error) => Err(ControlError::persistence(error)),
    }
}

fn receipt_catalog_key(
    prefix: &DeploymentPrefix,
    identity: &RepositoryIdentity,
    digest: ProtobufObjectDigest,
) -> Result<String, ControlError> {
    let root = repository_root(prefix, identity)?;
    Ok(format!("{root}catalogs/receipt/{}.pb", digest.lower_hex()))
}

fn receipt_result_key(
    prefix: &DeploymentPrefix,
    identity: &RepositoryIdentity,
    mutation_id: &[u8; 16],
) -> Result<String, ControlError> {
    let root = repository_root(prefix, identity)?;
    Ok(format!(
        "{root}receipts/results/{}.pb",
        hex::encode(mutation_id)
    ))
}

fn repository_root(
    prefix: &DeploymentPrefix,
    identity: &RepositoryIdentity,
) -> Result<String, ControlError> {
    let repository_uuid: [u8; 16] = identity
        .repository_uuid
        .as_ref()
        .try_into()
        .map_err(|_| ControlError::InvalidObject)?;
    RepositoryKeyIdentity {
        repository_uuid,
        generation: identity.generation,
    }
    .root(prefix)
    .map_err(ControlError::persistence)
}

fn verify_written_meta(
    relative_key: &str,
    encoded: &[u8],
    meta: ObjectMeta,
) -> Result<ObjectMeta, ControlError> {
    if meta.key != relative_key
        || meta.size != encoded.len() as u64
        || meta.object_version_id.is_none()
    {
        return Err(ControlError::InvalidObject);
    }
    Ok(meta)
}

fn target_from_meta(
    identity: RepositoryIdentity,
    full_key: String,
    encoded: &[u8],
    meta: ObjectMeta,
) -> Result<TargetObjectRef, ControlError> {
    let version = meta.object_version_id.ok_or(ControlError::InvalidObject)?;
    Ok(TargetObjectRef {
        identity: Some(identity),
        key: Bytes::from(full_key),
        object_version_id: Bytes::copy_from_slice(version.as_str().as_bytes()),
        digest: Bytes::copy_from_slice(ProtobufObjectDigest::of_exact_protobuf(encoded).as_bytes()),
        size: encoded.len() as u64,
    })
}

#[cfg(test)]
mod tests;

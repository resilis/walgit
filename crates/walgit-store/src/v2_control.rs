//! Dormant V2 repository-control persistence.
//!
//! This adapter is deliberately separate from [`crate::coord`]. It accepts
//! only strict V2 control bytes, performs one conditional write against the
//! caller's exact snapshot, and never retries or rebases a mutation.

use bytes::Bytes;
use walgit_proto::v2::{
    ControlCodecError, ControlValidationError, Lifecycle, MAX_REPO_CONTROL_BYTES, RepoControl,
    decode_repo_control,
    digests::ProtobufObjectDigest,
    encode_repo_control,
    keys::{DeploymentPrefix, V2KeyKind, parse_key},
    validate_repo_control_successor,
};

use crate::{
    CasToken, DynStore, GetOptions, GetResult, ObjectMeta, ObjectStoreExt, ObjectVersionId,
    PutMode, StoreError, util,
};

const MAX_CAS_TOKEN_BYTES: usize = 256;
const MAX_OBJECT_VERSION_ID_BYTES: usize = 1_024;

/// Exact provider binding of one strictly decoded `repo_control` version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlBinding {
    full_key: String,
    cas_token: CasToken,
    object_version_id: ObjectVersionId,
    digest: ProtobufObjectDigest,
    size: u64,
}

impl ControlBinding {
    pub fn full_key(&self) -> &str {
        &self.full_key
    }

    pub fn cas_token(&self) -> &CasToken {
        &self.cas_token
    }

    pub fn object_version_id(&self) -> &ObjectVersionId {
        &self.object_version_id
    }

    pub fn digest(&self) -> ProtobufObjectDigest {
        self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A V2 control value and the exact object version from which it was decoded.
#[derive(Clone, PartialEq)]
pub struct StoredRepoControl {
    control: RepoControl,
    binding: ControlBinding,
}

impl std::fmt::Debug for StoredRepoControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRepoControl")
            .field("control_revision", &self.control.control_revision)
            .field("lifecycle", &self.control.lifecycle)
            .field("binding", &self.binding)
            .finish()
    }
}

impl StoredRepoControl {
    pub fn control(&self) -> &RepoControl {
        &self.control
    }

    pub fn binding(&self) -> &ControlBinding {
        &self.binding
    }

    pub fn into_control(self) -> RepoControl {
        self.control
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CreateOutcome {
    /// This invocation received complete provider proof of the Create.
    Committed(StoredRepoControl),
    /// The exact immutable create binding already exists.
    ExactReplay(StoredRepoControl),
    /// Another create binding owns the key. The current value is absent only
    /// when the one conflict read could not produce a strict current value.
    Conflict(Option<StoredRepoControl>),
    /// One fresh read could not prove a safe terminal result.
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompareAndSwapOutcome {
    /// The requested successor is the current exact object version.
    Committed(StoredRepoControl),
    /// The conditional update lost to another control version.
    Conflict(Option<StoredRepoControl>),
    /// The fresh read proved that the exact prior binding is still current.
    NotCommitted(StoredRepoControl),
    /// The current state is neither the prior binding nor the candidate, or
    /// the one allowed resolution read failed.
    Indeterminate,
}

/// Errors that occur before a write is attempted, or while directly loading
/// repository control. Provider write errors are returned as classified write
/// outcomes because their application status can be ambiguous.
#[derive(Debug, thiserror::Error)]
pub enum ControlStoreError {
    #[error(transparent)]
    Codec(#[from] ControlCodecError),
    #[error(transparent)]
    InvalidSuccessor(#[from] ControlValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("invalid V2 control-store configuration: {0}")]
    Configuration(&'static str),
    #[error("invalid V2 repo_control key: {0}")]
    Key(&'static str),
    #[error("invalid V2 repo_control object metadata: {0}")]
    Metadata(&'static str),
    #[error("invalid initial V2 repo_control: {0}")]
    InitialControl(&'static str),
}

/// Strict storage adapter for the dormant V2 repository authority.
///
/// `store` must already be scoped to `deployment_prefix`, as `open_store`
/// scopes production stores. Persisted control carries the full physical key;
/// this adapter validates and removes that prefix exactly once before calling
/// the store.
#[derive(Clone)]
pub struct ControlStore {
    store: DynStore,
    deployment_prefix: DeploymentPrefix,
}

impl ControlStore {
    pub fn new(
        store: DynStore,
        deployment_prefix: DeploymentPrefix,
    ) -> Result<Self, ControlStoreError> {
        if store.applied_prefix() != deployment_prefix.as_str() {
            return Err(ControlStoreError::Configuration(
                "store physical prefix must equal the deployment prefix",
            ));
        }
        Ok(Self {
            store,
            deployment_prefix,
        })
    }

    /// Load the current exact control version. This is one unconditional GET
    /// and never falls back to HEAD or LIST.
    pub async fn load(
        &self,
        full_key: &str,
    ) -> Result<Option<StoredRepoControl>, ControlStoreError> {
        let relative_key = self.relative_control_key(full_key)?;
        self.load_relative(full_key, relative_key).await
    }

    /// Create the initial control object. Revision one is the only valid
    /// initial revision. A 412 is resolved as an exact create replay only when
    /// the immutable create binding matches.
    pub async fn create(&self, control: RepoControl) -> Result<CreateOutcome, ControlStoreError> {
        if control.control_revision != 1 {
            return Err(ControlStoreError::InitialControl(
                "control_revision must be exactly one",
            ));
        }
        if control.lifecycle != Lifecycle::Active as i32 {
            return Err(ControlStoreError::InitialControl(
                "lifecycle must be ACTIVE",
            ));
        }
        let encoded = Bytes::from(encode_repo_control(&control)?);
        let full_key = control_key(&control)?;
        let relative_key = self.relative_control_key(full_key)?.to_owned();

        match self
            .store
            .put_bytes(&relative_key, encoded.clone(), PutMode::Create)
            .await
        {
            Ok(meta) => match self.stored_from_candidate(control.clone(), &encoded, meta) {
                Ok(stored) => Ok(CreateOutcome::Committed(stored)),
                Err(_) => Ok(self.resolve_ambiguous_create(&control, full_key).await),
            },
            Err(error) if error.is_precondition_failed() => {
                Ok(self.resolve_create_conflict(&control, full_key).await)
            }
            Err(_) => Ok(self.resolve_ambiguous_create(&control, full_key).await),
        }
    }

    /// Attempt exactly one CAS from `previous` to `successor`.
    ///
    /// This method never retries, rebases, or delegates to `coord::cas_update`.
    pub async fn compare_and_swap(
        &self,
        previous: &StoredRepoControl,
        successor: RepoControl,
    ) -> Result<CompareAndSwapOutcome, ControlStoreError> {
        validate_repo_control_successor(previous.control(), &successor)?;
        let encoded = Bytes::from(encode_repo_control(&successor)?);
        let full_key = control_key(&successor)?;
        if full_key != previous.binding.full_key {
            return Err(ControlStoreError::Key(
                "successor key differs from the loaded binding",
            ));
        }
        let relative_key = self.relative_control_key(full_key)?.to_owned();

        match self
            .store
            .put_bytes(
                &relative_key,
                encoded.clone(),
                PutMode::Update(previous.binding.cas_token.clone()),
            )
            .await
        {
            Ok(meta) => match self.stored_from_candidate(successor.clone(), &encoded, meta) {
                Ok(stored) => Ok(CompareAndSwapOutcome::Committed(stored)),
                Err(_) => Ok(self
                    .resolve_ambiguous_cas(previous, &successor, full_key)
                    .await),
            },
            Err(error) if error.is_precondition_failed() => {
                let outcome = match self.load(full_key).await {
                    Ok(Some(current)) if same_exact_control(&current, &successor) => {
                        CompareAndSwapOutcome::Committed(current)
                    }
                    Ok(current) => CompareAndSwapOutcome::Conflict(current),
                    Err(_) => CompareAndSwapOutcome::Conflict(None),
                };
                Ok(outcome)
            }
            Err(_) => Ok(self
                .resolve_ambiguous_cas(previous, &successor, full_key)
                .await),
        }
    }

    async fn resolve_create_conflict(
        &self,
        candidate: &RepoControl,
        full_key: &str,
    ) -> CreateOutcome {
        match self.load(full_key).await {
            Ok(Some(current)) if same_create_binding(current.control(), candidate) => {
                CreateOutcome::ExactReplay(current)
            }
            Ok(current) => CreateOutcome::Conflict(current),
            Err(_) => CreateOutcome::Conflict(None),
        }
    }

    async fn resolve_ambiguous_create(
        &self,
        candidate: &RepoControl,
        full_key: &str,
    ) -> CreateOutcome {
        match self.load(full_key).await {
            Ok(Some(current)) if same_create_binding(current.control(), candidate) => {
                CreateOutcome::ExactReplay(current)
            }
            Ok(Some(current)) => CreateOutcome::Conflict(Some(current)),
            // Absence cannot prove that a version did not land and was then
            // removed. Create has no exact prior binding to compare.
            Ok(None) => CreateOutcome::Indeterminate,
            Err(_) => CreateOutcome::Indeterminate,
        }
    }

    async fn resolve_ambiguous_cas(
        &self,
        previous: &StoredRepoControl,
        candidate: &RepoControl,
        full_key: &str,
    ) -> CompareAndSwapOutcome {
        let current = match self.load(full_key).await {
            Ok(Some(current)) => current,
            Ok(None) | Err(_) => return CompareAndSwapOutcome::Indeterminate,
        };
        if same_exact_control(&current, candidate) {
            CompareAndSwapOutcome::Committed(current)
        } else if current.binding == previous.binding {
            CompareAndSwapOutcome::NotCommitted(current)
        } else {
            CompareAndSwapOutcome::Indeterminate
        }
    }

    async fn load_relative(
        &self,
        full_key: &str,
        relative_key: &str,
    ) -> Result<Option<StoredRepoControl>, ControlStoreError> {
        let (meta, body) = match self.store.get(relative_key, GetOptions::default()).await {
            Ok(GetResult::Object { meta, body }) => (meta, body),
            Ok(GetResult::NotModified { .. }) => {
                return Err(ControlStoreError::Metadata(
                    "unconditional GET returned NotModified",
                ));
            }
            Err(StoreError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if meta.size > MAX_REPO_CONTROL_BYTES as u64 {
            return Err(ControlStoreError::Metadata(
                "provider size exceeds the 1 MiB repo_control bound",
            ));
        }
        let encoded = util::collect_exact(body, meta.size).await?;
        let control = decode_repo_control(&encoded)?;
        if control.repo_control_key.as_ref() != full_key.as_bytes() {
            return Err(ControlStoreError::Key(
                "decoded control key differs from the requested key",
            ));
        }
        Ok(Some(self.stored_from_candidate(control, &encoded, meta)?))
    }

    fn stored_from_candidate(
        &self,
        control: RepoControl,
        encoded: &[u8],
        meta: ObjectMeta,
    ) -> Result<StoredRepoControl, ControlStoreError> {
        let full_key = control_key(&control)?.to_owned();
        let expected_relative = self.relative_control_key(&full_key)?;
        if meta.key != expected_relative {
            return Err(ControlStoreError::Metadata(
                "provider key differs from the requested store-relative key",
            ));
        }
        if meta.size != encoded.len() as u64 {
            return Err(ControlStoreError::Metadata(
                "provider size differs from the strict encoded size",
            ));
        }
        if meta.version.as_str().is_empty() || meta.version.as_str().len() > MAX_CAS_TOKEN_BYTES {
            return Err(ControlStoreError::Metadata(
                "CasToken is empty or exceeds 256 bytes",
            ));
        }
        let object_version_id = meta.object_version_id.ok_or(ControlStoreError::Metadata(
            "provider omitted ObjectVersionId",
        ))?;
        if object_version_id.as_str().is_empty()
            || object_version_id.as_str().len() > MAX_OBJECT_VERSION_ID_BYTES
        {
            return Err(ControlStoreError::Metadata(
                "ObjectVersionId is empty or exceeds 1024 bytes",
            ));
        }

        Ok(StoredRepoControl {
            control,
            binding: ControlBinding {
                full_key,
                cas_token: meta.version,
                object_version_id,
                digest: ProtobufObjectDigest::of_exact_protobuf(encoded),
                size: meta.size,
            },
        })
    }

    fn relative_control_key<'a>(&self, full_key: &'a str) -> Result<&'a str, ControlStoreError> {
        let parsed = parse_key(&self.deployment_prefix, full_key.as_bytes())
            .map_err(|_| ControlStoreError::Key("outside the configured V2 key grammar"))?;
        if parsed.kind != V2KeyKind::RepoControl {
            return Err(ControlStoreError::Key("is not a repo_control key"));
        }
        full_key
            .strip_prefix(self.deployment_prefix.as_str())
            .filter(|relative| !relative.is_empty())
            .ok_or(ControlStoreError::Key(
                "does not begin with the configured deployment prefix",
            ))
    }
}

fn control_key(control: &RepoControl) -> Result<&str, ControlStoreError> {
    std::str::from_utf8(&control.repo_control_key)
        .map_err(|_| ControlStoreError::Key("must be UTF-8"))
}

fn same_create_binding(left: &RepoControl, right: &RepoControl) -> bool {
    left.schema_version == right.schema_version
        && left.identity == right.identity
        && left.create_intent_id == right.create_intent_id
        && left.create_intent_digest == right.create_intent_digest
        && left.create_intent_cose == right.create_intent_cose
        && left.repo_control_key == right.repo_control_key
        && left.object_format == right.object_format
        && left.cutover_generation == right.cutover_generation
}

fn same_exact_control(stored: &StoredRepoControl, candidate: &RepoControl) -> bool {
    stored.control() == candidate
}

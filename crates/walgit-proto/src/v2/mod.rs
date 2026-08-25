//! Dormant V2 control schemas.
//!
//! These types are not wired into the V1 registry or publication path. Use
//! [`codec`] for persisted bytes; direct `prost::Message::decode` is not the V2
//! storage contract.

mod generated {
    include!(concat!(env!("OUT_DIR"), "/walgit.v2.rs"));
}

pub use generated::*;

pub mod codec;
pub mod digests;
pub mod keys;
mod validate;

pub use codec::{
    ControlCodecError, decode_capacity_control, decode_capacity_shard, decode_credential_control,
    decode_mutation_receipt, decode_mutation_result, decode_receipt_catalog, decode_repo_control,
    decode_tenant_capacity_catalog_page, encode_capacity_control, encode_capacity_shard,
    encode_credential_control, encode_credential_control_projection, encode_mutation_receipt,
    encode_mutation_result, encode_receipt_catalog, encode_repo_control,
    encode_tenant_capacity_catalog_page, lint_v2_descriptors, preflight_capacity_control,
    preflight_capacity_shard, preflight_credential_control, preflight_mutation_receipt,
    preflight_mutation_result, preflight_receipt_catalog, preflight_repo_control,
    preflight_tenant_capacity_catalog_page,
};
pub use validate::{
    ControlValidationError, CredentialTransitionKind, LoadedCommittingCapacityView,
    LoadedRepoControlReceiptView, validate_capacity_admission_view,
    validate_capacity_applying_baseline, validate_capacity_charged_repo_control,
    validate_capacity_conflicting_repo_control, validate_capacity_control,
    validate_capacity_control_catalogs, validate_capacity_current_shard_object,
    validate_capacity_current_shard_view, validate_capacity_preparing_drainage_successor,
    validate_capacity_receipt_obligation, validate_capacity_retained_shard_budget_object,
    validate_capacity_shard, validate_capacity_shard_catalog, validate_capacity_shard_object,
    validate_capacity_shard_successor, validate_capacity_stable_admission_successor,
    validate_credential_control, validate_credential_control_transition_structure,
    validate_mutation_receipt, validate_mutation_result, validate_receipt_catalog,
    validate_repo_control, validate_repo_control_receipt_catalog, validate_repo_control_successor,
    validate_tenant_capacity_catalog_object, validate_tenant_capacity_catalog_page,
};

/// Frozen V2 repository-control schema version.
pub const REPO_CONTROL_SCHEMA_VERSION: u32 = 2;
/// Maximum exact deterministic protobuf size of one `repo_control` object.
pub const MAX_REPO_CONTROL_BYTES: usize = 1_048_576;
/// Frozen V2 credential-control schema version.
pub const CREDENTIAL_CONTROL_SCHEMA_VERSION: u32 = 2;
/// Maximum exact deterministic protobuf size of one `credential_control` object.
pub const MAX_CREDENTIAL_CONTROL_BYTES: usize = 65_536;
/// Frozen mutation receipt/result/catalog schema version.
pub const RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const MAX_MUTATION_RECEIPT_BYTES: usize = 65_536;
pub const MAX_MUTATION_RESULT_BYTES: usize = 65_536;
pub const MAX_RECEIPT_CATALOG_BYTES: usize = 524_288;
/// Frozen dormant capacity schema version.
pub const CAPACITY_SCHEMA_VERSION: u32 = 1;
/// Maximum provisional reservation lifetime. Validators consume explicit time.
pub const MAX_RESERVED_TTL_SECONDS: u64 = 900;
/// Dormant flat tenant-allocation page row bound.
pub const MAX_TENANT_CAPACITY_ALLOCATIONS: usize = 4_096;
/// Maximum exact encoded flat tenant-allocation page size.
pub const MAX_TENANT_CAPACITY_CATALOG_BYTES: usize = 524_288;
/// Maximum exact encoded capacity shard size.
pub const MAX_CAPACITY_SHARD_BYTES: usize = 1_048_576;
/// Maximum exact encoded capacity-control size.
pub const MAX_CAPACITY_CONTROL_BYTES: usize = 1_048_576;

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
    ControlCodecError, decode_credential_control, decode_repo_control, encode_credential_control,
    encode_credential_control_projection, encode_repo_control, lint_v2_descriptors,
    preflight_credential_control, preflight_repo_control,
};
pub use validate::{
    ControlValidationError, CredentialTransitionKind, validate_credential_control,
    validate_credential_control_transition_structure, validate_repo_control,
    validate_repo_control_successor,
};

/// Frozen V2 repository-control schema version.
pub const REPO_CONTROL_SCHEMA_VERSION: u32 = 2;
/// Maximum exact deterministic protobuf size of one `repo_control` object.
pub const MAX_REPO_CONTROL_BYTES: usize = 1_048_576;
/// Frozen V2 credential-control schema version.
pub const CREDENTIAL_CONTROL_SCHEMA_VERSION: u32 = 2;
/// Maximum exact deterministic protobuf size of one `credential_control` object.
pub const MAX_CREDENTIAL_CONTROL_BYTES: usize = 65_536;

//! Strict deterministic codec for persisted V2 controls.

use std::sync::OnceLock;

use prost::Message;
use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor};

use super::{
    CredentialControl, MAX_CREDENTIAL_CONTROL_BYTES, MAX_REPO_CONTROL_BYTES, RepoControl,
    keys::DeploymentPrefix, validate_credential_control, validate_repo_control,
};

const MAX_NESTING_DEPTH: usize = 16;
const MESSAGE_MAX_OPTION: &str = "walgit.v2.max_encoded_bytes";
const FIELD_MIN_BYTES_OPTION: &str = "walgit.v2.min_bytes";
const FIELD_MAX_BYTES_OPTION: &str = "walgit.v2.max_bytes";
const FIELD_MIN_ITEMS_OPTION: &str = "walgit.v2.min_items";
const FIELD_MAX_ITEMS_OPTION: &str = "walgit.v2.max_items";

pub fn encode_repo_control(control: &RepoControl) -> Result<Vec<u8>, ControlCodecError> {
    validate_repo_control(control)?;
    if control.encoded_len() > MAX_REPO_CONTROL_BYTES {
        return Err(ControlCodecError::MessageTooLarge {
            message: "walgit.v2.RepoControl".to_string(),
            actual: control.encoded_len(),
            maximum: MAX_REPO_CONTROL_BYTES,
        });
    }
    let bytes = control.encode_to_vec();
    preflight_repo_control(&bytes)?;
    Ok(bytes)
}

pub fn decode_repo_control(bytes: &[u8]) -> Result<RepoControl, ControlCodecError> {
    preflight_repo_control(bytes)?;
    let control = RepoControl::decode(bytes)?;
    validate_repo_control(&control)?;
    if control.encode_to_vec() != bytes {
        return Err(ControlCodecError::NonCanonical(
            "generated re-encoding differs from the stored bytes",
        ));
    }
    Ok(control)
}

pub fn preflight_repo_control(bytes: &[u8]) -> Result<(), ControlCodecError> {
    let schema = preflight_schema();
    preflight_message(schema, schema.repo_control_root, bytes, 1).map(|_| ())
}

pub fn encode_credential_control(
    control: &CredentialControl,
    prefix: &DeploymentPrefix,
) -> Result<Vec<u8>, ControlCodecError> {
    validate_credential_control(control, prefix)?;
    if control.encoded_len() > MAX_CREDENTIAL_CONTROL_BYTES {
        return Err(ControlCodecError::MessageTooLarge {
            message: "walgit.v2.CredentialControl".to_string(),
            actual: control.encoded_len(),
            maximum: MAX_CREDENTIAL_CONTROL_BYTES,
        });
    }
    let bytes = control.encode_to_vec();
    preflight_credential_control(&bytes)?;
    Ok(bytes)
}

pub fn decode_credential_control(
    bytes: &[u8],
    prefix: &DeploymentPrefix,
) -> Result<CredentialControl, ControlCodecError> {
    preflight_credential_control(bytes)?;
    let control = CredentialControl::decode(bytes)?;
    validate_credential_control(&control, prefix)?;
    if control.encode_to_vec() != bytes {
        return Err(ControlCodecError::NonCanonical(
            "generated re-encoding differs from the stored bytes",
        ));
    }
    Ok(control)
}

pub fn preflight_credential_control(bytes: &[u8]) -> Result<(), ControlCodecError> {
    let schema = preflight_schema();
    preflight_message(schema, schema.credential_control_root, bytes, 1).map(|_| ())
}

/// Prove that every persisted V2 message and variable field has descriptor
/// bounds that the raw preflight can enforce.
pub fn lint_v2_descriptors() -> Result<(), ControlCodecError> {
    crate::descriptor_lint::lint_v2_descriptors(descriptor_pool())
        .map_err(ControlCodecError::Descriptor)
}

fn preflight_message(
    schema: &PreflightSchema,
    message_index: usize,
    bytes: &[u8],
    depth: usize,
) -> Result<u64, ControlCodecError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(ControlCodecError::Malformed("message nesting exceeds 16"));
    }
    let descriptor = &schema.messages[message_index];
    let maximum = descriptor.maximum;
    if bytes.len() > maximum {
        return Err(ControlCodecError::MessageTooLarge {
            message: descriptor.name.clone(),
            actual: bytes.len(),
            maximum,
        });
    }

    let mut input = bytes;
    let mut previous_field = 0u32;
    let mut oneofs = 0u64;
    let mut counts = [0u64; 64];
    let mut aggregate_ref_changes = 0u64;
    while !input.is_empty() {
        let tag = take_varint(&mut input)?;
        let number = u32::try_from(tag >> 3)
            .ok()
            .filter(|number| (1..=(1 << 29) - 1).contains(number))
            .ok_or(ControlCodecError::Malformed(
                "invalid protobuf field number",
            ))?;
        let wire = (tag & 0x07) as u8;
        let field_index = descriptor
            .fields
            .binary_search_by_key(&number, |field| field.number)
            .map_err(|_| ControlCodecError::UnknownField {
                message: descriptor.name.clone(),
                number,
            })?;
        let field = &descriptor.fields[field_index];

        if number < previous_field || (number == previous_field && !field.repeated) {
            return Err(ControlCodecError::NonCanonical(
                "fields must be ascending and repeated occurrences contiguous",
            ));
        }
        previous_field = number;
        if let Some(oneof) = field.oneof {
            let mask = 1u64 << oneof;
            if oneofs & mask != 0 {
                return Err(ControlCodecError::DuplicateField {
                    field: field.name.clone(),
                });
            }
            oneofs |= mask;
        }
        if field.repeated {
            counts[field_index] = counts[field_index]
                .checked_add(1)
                .ok_or(ControlCodecError::Malformed("repeated count overflow"))?;
            if counts[field_index] > field.maximum_items {
                return Err(ControlCodecError::CountExceeded {
                    field: field.name.clone(),
                    actual: counts[field_index],
                    maximum: field.maximum_items,
                });
            }
        }

        match &field.kind {
            PreflightKind::Int64 | PreflightKind::Uint32 | PreflightKind::Uint64 => {
                require_wire(field, wire, 0)?;
                if take_varint(&mut input)? == 0 && !field.allows_explicit_default {
                    return Err(ControlCodecError::NonCanonical(
                        "an explicit proto3 scalar default is prohibited",
                    ));
                }
            }
            PreflightKind::Enum(values) => {
                require_wire(field, wire, 0)?;
                let value = take_varint(&mut input)?;
                let value = i32::try_from(value)
                    .map_err(|_| ControlCodecError::Malformed("enum value exceeds i32"))?;
                if value == 0 || values.binary_search(&value).is_err() {
                    return Err(ControlCodecError::Malformed("unknown or zero enum value"));
                }
            }
            PreflightKind::Bytes { utf8 } => {
                require_wire(field, wire, 2)?;
                let value = take_length_delimited(&mut input)?;
                let actual = value.len() as u64;
                if actual < field.minimum_bytes || actual > field.maximum_bytes {
                    return Err(ControlCodecError::BytesOutsideBounds {
                        field: field.name.clone(),
                        actual,
                        minimum: field.minimum_bytes,
                        maximum: field.maximum_bytes,
                    });
                }
                if actual == 0 {
                    return Err(ControlCodecError::NonCanonical(
                        "an explicit empty proto3 byte or string field is prohibited",
                    ));
                }
                if *utf8 && std::str::from_utf8(value).is_err() {
                    return Err(ControlCodecError::Malformed("protobuf string is not UTF-8"));
                }
            }
            PreflightKind::Message(nested) => {
                require_wire(field, wire, 2)?;
                let value = take_length_delimited(&mut input)?;
                aggregate_ref_changes = aggregate_ref_changes
                    .checked_add(preflight_message(schema, *nested, value, depth + 1)?)
                    .ok_or(ControlCodecError::Malformed(
                        "aggregate inline ref-change count overflow",
                    ))?;
                if aggregate_ref_changes > 4_096 {
                    return Err(ControlCodecError::CountExceeded {
                        field: "walgit.v2.RepoControl.wal.inline_ref_changes".to_string(),
                        actual: aggregate_ref_changes,
                        maximum: 4_096,
                    });
                }
            }
        }
    }

    for (index, field) in descriptor.fields.iter().enumerate() {
        if field.repeated && counts[index] < field.minimum_items {
            return Err(ControlCodecError::CountBelowMinimum {
                field: field.name.clone(),
                actual: counts[index],
                minimum: field.minimum_items,
            });
        }
    }
    if descriptor.inline_ref_changes {
        Ok(counts[0])
    } else {
        Ok(aggregate_ref_changes)
    }
}

#[derive(Debug)]
struct PreflightSchema {
    repo_control_root: usize,
    credential_control_root: usize,
    messages: Vec<PreflightMessage>,
}

#[derive(Debug)]
struct PreflightMessage {
    name: String,
    maximum: usize,
    fields: Vec<PreflightField>,
    inline_ref_changes: bool,
}

#[derive(Debug)]
struct PreflightField {
    number: u32,
    name: String,
    kind: PreflightKind,
    repeated: bool,
    oneof: Option<usize>,
    minimum_bytes: u64,
    maximum_bytes: u64,
    minimum_items: u64,
    maximum_items: u64,
    allows_explicit_default: bool,
}

#[derive(Debug)]
enum PreflightKind {
    Int64,
    Uint32,
    Uint64,
    Enum(Vec<i32>),
    Bytes { utf8: bool },
    Message(usize),
}

impl PreflightSchema {
    fn build(pool: &DescriptorPool) -> Result<Self, ControlCodecError> {
        let descriptors = pool
            .all_messages()
            .filter(|message| message.full_name().starts_with("walgit.v2."))
            .collect::<Vec<_>>();
        let indexes = descriptors
            .iter()
            .enumerate()
            .map(|(index, message)| (message.full_name().to_string(), index))
            .collect::<std::collections::HashMap<_, _>>();
        let repo_control_root = *indexes.get("walgit.v2.RepoControl").ok_or_else(|| {
            ControlCodecError::Descriptor("RepoControl descriptor is missing".into())
        })?;
        let credential_control_root =
            *indexes.get("walgit.v2.CredentialControl").ok_or_else(|| {
                ControlCodecError::Descriptor("CredentialControl descriptor is missing".into())
            })?;
        let mut messages = Vec::with_capacity(descriptors.len());
        for descriptor in &descriptors {
            let maximum = usize::try_from(message_bound(descriptor)?).map_err(|_| {
                ControlCodecError::Descriptor(format!(
                    "{} message bound does not fit usize",
                    descriptor.full_name()
                ))
            })?;
            let mut fields = Vec::with_capacity(descriptor.fields().count());
            for field in descriptor.fields() {
                let (minimum_bytes, maximum_bytes) =
                    if matches!(field.kind(), Kind::Bytes | Kind::String) {
                        (
                            field_bound(&field, FIELD_MIN_BYTES_OPTION)?,
                            field_bound(&field, FIELD_MAX_BYTES_OPTION)?,
                        )
                    } else {
                        (0, 0)
                    };
                let (minimum_items, maximum_items) = if field.is_list() {
                    (
                        field_bound(&field, FIELD_MIN_ITEMS_OPTION)?,
                        field_bound(&field, FIELD_MAX_ITEMS_OPTION)?,
                    )
                } else {
                    (0, 1)
                };
                let kind = match field.kind() {
                    Kind::Int64 => PreflightKind::Int64,
                    Kind::Uint32 => PreflightKind::Uint32,
                    Kind::Uint64 => PreflightKind::Uint64,
                    Kind::Enum(enumeration) => {
                        let mut values = enumeration
                            .values()
                            .map(|value| value.number())
                            .collect::<Vec<_>>();
                        values.sort_unstable();
                        PreflightKind::Enum(values)
                    }
                    Kind::Bytes => PreflightKind::Bytes { utf8: false },
                    Kind::String => PreflightKind::Bytes { utf8: true },
                    Kind::Message(message) => PreflightKind::Message(
                        *indexes.get(message.full_name()).ok_or_else(|| {
                            ControlCodecError::Descriptor(format!(
                                "{} references a message outside V2",
                                field.full_name()
                            ))
                        })?,
                    ),
                    _ => {
                        return Err(ControlCodecError::Descriptor(format!(
                            "{} uses an unsupported scalar kind",
                            field.full_name()
                        )));
                    }
                };
                let proto3_optional = field.field_descriptor_proto().proto3_optional == Some(true);
                let oneof = if proto3_optional {
                    None
                } else {
                    field.containing_oneof().map(|oneof| {
                        usize::try_from(*oneof.path().last().expect("oneof path has an index"))
                            .expect("descriptor linter rejected a negative oneof index")
                    })
                };
                fields.push(PreflightField {
                    number: field.number(),
                    name: field.full_name().to_string(),
                    kind,
                    repeated: field.is_list(),
                    oneof,
                    minimum_bytes,
                    maximum_bytes,
                    minimum_items,
                    maximum_items,
                    allows_explicit_default: proto3_optional,
                });
            }
            messages.push(PreflightMessage {
                name: descriptor.full_name().to_string(),
                maximum,
                fields,
                inline_ref_changes: descriptor.full_name() == "walgit.v2.InlineRefChanges",
            });
        }
        Ok(Self {
            repo_control_root,
            credential_control_root,
            messages,
        })
    }
}

fn preflight_schema() -> &'static PreflightSchema {
    static SCHEMA: OnceLock<PreflightSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        PreflightSchema::build(descriptor_pool())
            .expect("embedded V2 descriptors passed the build-time descriptor linter")
    })
}

fn descriptor_pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(crate::FILE_DESCRIPTOR_SET)
            .expect("embedded protobuf descriptors were compiled by protoc")
    })
}

fn message_bound(descriptor: &MessageDescriptor) -> Result<u64, ControlCodecError> {
    option_u64(
        &descriptor.options(),
        MESSAGE_MAX_OPTION,
        descriptor.full_name(),
    )
}

fn field_bound(field: &FieldDescriptor, option: &'static str) -> Result<u64, ControlCodecError> {
    option_u64(&field.options(), option, field.full_name())
}

fn option_u64(
    options: &prost_reflect::DynamicMessage,
    option_name: &'static str,
    owner: &str,
) -> Result<u64, ControlCodecError> {
    let extension = descriptor_pool()
        .get_extension_by_name(option_name)
        .ok_or_else(|| ControlCodecError::Descriptor(format!("{option_name} is missing")))?;
    if !options.has_extension(&extension) {
        return Err(ControlCodecError::Descriptor(format!(
            "{owner} has no {option_name} annotation"
        )));
    }
    match options.get_extension(&extension).as_ref() {
        prost_reflect::Value::U64(value) => Ok(*value),
        _ => Err(ControlCodecError::Descriptor(format!(
            "{owner} has a non-u64 {option_name} annotation"
        ))),
    }
}

fn require_wire(field: &PreflightField, actual: u8, expected: u8) -> Result<(), ControlCodecError> {
    if actual != expected {
        return Err(ControlCodecError::WrongWireType {
            field: field.name.clone(),
            actual,
            expected,
        });
    }
    Ok(())
}

fn take_length_delimited<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ControlCodecError> {
    let len = usize::try_from(take_varint(input)?)
        .map_err(|_| ControlCodecError::Malformed("length does not fit usize"))?;
    if input.len() < len {
        return Err(ControlCodecError::Malformed(
            "truncated length-delimited field",
        ));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn take_varint(input: &mut &[u8]) -> Result<u64, ControlCodecError> {
    let original_len = input.len();
    let mut value = 0u64;
    for index in 0..10 {
        let (&byte, rest) = input
            .split_first()
            .ok_or(ControlCodecError::Malformed("truncated varint"))?;
        *input = rest;
        if index == 9 && byte > 1 {
            return Err(ControlCodecError::Malformed("varint exceeds u64"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            let consumed = original_len - input.len();
            if consumed != varint_len(value) {
                return Err(ControlCodecError::NonCanonical("varint is not minimal"));
            }
            return Ok(value);
        }
    }
    Err(ControlCodecError::Malformed("varint exceeds ten bytes"))
}

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[derive(Debug, thiserror::Error)]
pub enum ControlCodecError {
    #[error("invalid V2 descriptor contract: {0}")]
    Descriptor(String),
    #[error("malformed V2 protobuf: {0}")]
    Malformed(&'static str),
    #[error("non-canonical V2 protobuf: {0}")]
    NonCanonical(&'static str),
    #[error("unknown field {number} in {message}")]
    UnknownField { message: String, number: u32 },
    #[error("duplicate singular or oneof field {field}")]
    DuplicateField { field: String },
    #[error("wrong wire type for {field}: got {actual}, expected {expected}")]
    WrongWireType {
        field: String,
        actual: u8,
        expected: u8,
    },
    #[error("{message} is {actual} bytes; maximum is {maximum}")]
    MessageTooLarge {
        message: String,
        actual: usize,
        maximum: usize,
    },
    #[error("{field} is {actual} bytes; required range is {minimum}..={maximum}")]
    BytesOutsideBounds {
        field: String,
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    #[error("{field} contains {actual} items; maximum is {maximum}")]
    CountExceeded {
        field: String,
        actual: u64,
        maximum: u64,
    },
    #[error("{field} contains {actual} items; minimum is {minimum}")]
    CountBelowMinimum {
        field: String,
        actual: u64,
        minimum: u64,
    },
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    Validation(#[from] super::ControlValidationError),
}

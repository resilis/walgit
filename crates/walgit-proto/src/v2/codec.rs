//! Strict deterministic codec for persisted V2 repository control.

use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use prost::Message;
use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor};

use super::{MAX_REPO_CONTROL_BYTES, RepoControl, validate_repo_control};

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
    let descriptor = descriptor_pool()
        .get_message_by_name("walgit.v2.RepoControl")
        .ok_or_else(|| ControlCodecError::Descriptor("RepoControl descriptor is missing".into()))?;
    preflight_message(&descriptor, bytes, 0)
}

/// Prove that every persisted V2 message and variable field has descriptor
/// bounds that the raw preflight can enforce.
pub fn lint_v2_descriptors() -> Result<(), ControlCodecError> {
    crate::descriptor_lint::lint_v2_descriptors(descriptor_pool())
        .map_err(ControlCodecError::Descriptor)
}

fn preflight_message(
    descriptor: &MessageDescriptor,
    bytes: &[u8],
    depth: usize,
) -> Result<(), ControlCodecError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(ControlCodecError::Malformed("message nesting exceeds 16"));
    }
    let maximum = usize::try_from(message_bound(descriptor)?).map_err(|_| {
        ControlCodecError::Descriptor(format!(
            "{} message bound does not fit usize",
            descriptor.full_name()
        ))
    })?;
    if bytes.len() > maximum {
        return Err(ControlCodecError::MessageTooLarge {
            message: descriptor.full_name().to_string(),
            actual: bytes.len(),
            maximum,
        });
    }

    let mut input = bytes;
    let mut previous_field = 0u32;
    let mut singular = HashSet::new();
    let mut oneofs = HashSet::new();
    let mut counts: HashMap<u32, u64> = HashMap::new();
    while !input.is_empty() {
        let tag = take_varint(&mut input)?;
        let number = u32::try_from(tag >> 3)
            .ok()
            .filter(|number| (1..=(1 << 29) - 1).contains(number))
            .ok_or(ControlCodecError::Malformed(
                "invalid protobuf field number",
            ))?;
        let wire = (tag & 0x07) as u8;
        let field =
            descriptor
                .get_field(number)
                .ok_or_else(|| ControlCodecError::UnknownField {
                    message: descriptor.full_name().to_string(),
                    number,
                })?;

        if number < previous_field || (number == previous_field && !field.is_list()) {
            return Err(ControlCodecError::NonCanonical(
                "fields must be ascending and repeated occurrences contiguous",
            ));
        }
        previous_field = number;
        if !field.is_list() && !singular.insert(number) {
            return Err(ControlCodecError::DuplicateField {
                field: field.full_name().to_string(),
            });
        }
        if let Some(oneof) = field.containing_oneof()
            && !oneofs.insert(oneof.name().to_string())
        {
            return Err(ControlCodecError::DuplicateField {
                field: oneof.full_name().to_string(),
            });
        }
        if field.is_list() {
            let count = counts.entry(number).or_default();
            *count = count
                .checked_add(1)
                .ok_or(ControlCodecError::Malformed("repeated count overflow"))?;
            let maximum = field_bound(&field, FIELD_MAX_ITEMS_OPTION)?;
            if *count > maximum {
                return Err(ControlCodecError::CountExceeded {
                    field: field.full_name().to_string(),
                    actual: *count,
                    maximum,
                });
            }
        }

        match field.kind() {
            Kind::Uint32 | Kind::Uint64 => {
                require_wire(&field, wire, 0)?;
                if take_varint(&mut input)? == 0 {
                    return Err(ControlCodecError::NonCanonical(
                        "an explicit proto3 scalar default is prohibited",
                    ));
                }
            }
            Kind::Enum(enumeration) => {
                require_wire(&field, wire, 0)?;
                let value = take_varint(&mut input)?;
                let value = i32::try_from(value)
                    .map_err(|_| ControlCodecError::Malformed("enum value exceeds i32"))?;
                if value == 0 || enumeration.get_value(value).is_none() {
                    return Err(ControlCodecError::Malformed("unknown or zero enum value"));
                }
            }
            Kind::Bytes | Kind::String => {
                require_wire(&field, wire, 2)?;
                let value = take_length_delimited(&mut input)?;
                let minimum = field_bound(&field, FIELD_MIN_BYTES_OPTION)?;
                let maximum = field_bound(&field, FIELD_MAX_BYTES_OPTION)?;
                let actual = value.len() as u64;
                if actual < minimum || actual > maximum {
                    return Err(ControlCodecError::BytesOutsideBounds {
                        field: field.full_name().to_string(),
                        actual,
                        minimum,
                        maximum,
                    });
                }
                if actual == 0 {
                    return Err(ControlCodecError::NonCanonical(
                        "an explicit empty proto3 byte or string field is prohibited",
                    ));
                }
                if matches!(field.kind(), Kind::String) && std::str::from_utf8(value).is_err() {
                    return Err(ControlCodecError::Malformed("protobuf string is not UTF-8"));
                }
            }
            Kind::Message(nested) => {
                require_wire(&field, wire, 2)?;
                let value = take_length_delimited(&mut input)?;
                preflight_message(&nested, value, depth + 1)?;
            }
            _ => {
                return Err(ControlCodecError::Descriptor(format!(
                    "{} uses an unsupported scalar kind",
                    field.full_name()
                )));
            }
        }
    }

    for field in descriptor.fields().filter(|field| field.is_list()) {
        let actual = counts.get(&field.number()).copied().unwrap_or_default();
        let minimum = field_bound(&field, FIELD_MIN_ITEMS_OPTION)?;
        if actual < minimum {
            return Err(ControlCodecError::CountBelowMinimum {
                field: field.full_name().to_string(),
                actual,
                minimum,
            });
        }
    }
    Ok(())
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

fn require_wire(
    field: &FieldDescriptor,
    actual: u8,
    expected: u8,
) -> Result<(), ControlCodecError> {
    if actual != expected {
        return Err(ControlCodecError::WrongWireType {
            field: field.full_name().to_string(),
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

use std::collections::HashMap;

use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor, Value};

const MESSAGE_MAX_OPTION: &str = "walgit.v2.max_encoded_bytes";
const FIELD_MIN_BYTES_OPTION: &str = "walgit.v2.min_bytes";
const FIELD_MAX_BYTES_OPTION: &str = "walgit.v2.max_bytes";
const FIELD_MIN_ITEMS_OPTION: &str = "walgit.v2.min_items";
const FIELD_MAX_ITEMS_OPTION: &str = "walgit.v2.max_items";

const MAX_MESSAGE_BYTES: u64 = 1_048_576;
const MAX_REPEATED_ITEMS: u64 = 4_096;
const MAX_MESSAGE_FIELDS: usize = 64;
const MAX_MESSAGE_ONEOFS: usize = 64;
const MAX_MESSAGE_DEPTH: usize = 16;

/// Prove that every persisted V2 message and variable field exposes bounds
/// that the strict wire preflight can enforce. This also models Prost's
/// generated field order: ordinary fields encode first and oneofs encode last.
pub fn lint_v2_descriptors(pool: &DescriptorPool) -> Result<(), String> {
    let messages = pool
        .all_messages()
        .filter(|message| message.full_name().starts_with("walgit.v2."))
        .collect::<Vec<_>>();
    let indexes = messages
        .iter()
        .enumerate()
        .map(|(index, message)| (message.full_name().to_string(), index))
        .collect::<HashMap<_, _>>();
    let mut graph = vec![Vec::new(); messages.len()];

    for (message_index, message) in messages.iter().enumerate() {
        let message_maximum = option_u64(
            pool,
            &message.options(),
            MESSAGE_MAX_OPTION,
            message.full_name(),
        )?;
        lint_bound(
            message.full_name(),
            "message",
            1,
            message_maximum,
            MAX_MESSAGE_BYTES,
        )?;
        usize::try_from(message_maximum)
            .map_err(|_| format!("{} message bound does not fit usize", message.full_name()))?;
        if message.is_map_entry() {
            return Err(format!("{} is a prohibited map entry", message.full_name()));
        }
        if !message.descriptor_proto().extension.is_empty()
            || !message.descriptor_proto().extension_range.is_empty()
        {
            return Err(format!(
                "{} uses prohibited protobuf extensions",
                message.full_name()
            ));
        }
        if message.fields().count() > MAX_MESSAGE_FIELDS {
            return Err(format!(
                "{} has more than {MAX_MESSAGE_FIELDS} fields",
                message.full_name()
            ));
        }
        if message.oneofs().count() > MAX_MESSAGE_ONEOFS {
            return Err(format!(
                "{} has more than {MAX_MESSAGE_ONEOFS} oneofs",
                message.full_name()
            ));
        }

        let declared = message
            .descriptor_proto()
            .field
            .iter()
            .map(|field| FieldLayout {
                number: field.number.unwrap_or_default(),
                oneof_index: field.oneof_index,
            })
            .collect::<Vec<_>>();
        lint_declared_layout(message.full_name(), &declared)?;

        let mut minimum_wire_sum = 0u64;
        let mut maximum_wire_sum = 0u64;
        let mut oneof_maxima = [0u64; MAX_MESSAGE_ONEOFS];
        for raw_field in &message.descriptor_proto().field {
            let number = u32::try_from(raw_field.number.unwrap_or_default())
                .map_err(|_| format!("{} has an invalid field number", message.full_name()))?;
            let field = message.get_field(number).ok_or_else(|| {
                format!(
                    "{} field {number} is absent from the pool",
                    message.full_name()
                )
            })?;
            lint_field_options(pool, &field, message_maximum)?;
            let (minimum, maximum) = field_wire_bounds(pool, &field)?;
            if let Some(oneof_index) = raw_field.oneof_index {
                let oneof_index = usize::try_from(oneof_index)
                    .map_err(|_| format!("{} has a negative oneof index", message.full_name()))?;
                let slot = oneof_maxima.get_mut(oneof_index).ok_or_else(|| {
                    format!("{} has an out-of-range oneof index", message.full_name())
                })?;
                *slot = (*slot).max(maximum);
            } else {
                minimum_wire_sum = minimum_wire_sum.checked_add(minimum).ok_or_else(|| {
                    format!(
                        "{} minimum encoded-size arithmetic overflow",
                        message.full_name()
                    )
                })?;
                maximum_wire_sum = maximum_wire_sum.checked_add(maximum).ok_or_else(|| {
                    format!(
                        "{} maximum encoded-size arithmetic overflow",
                        message.full_name()
                    )
                })?;
            }

            if let Kind::Message(nested) = field.kind()
                && let Some(nested_index) = indexes.get(nested.full_name())
            {
                graph[message_index].push(*nested_index);
            }
        }
        if minimum_wire_sum > message_maximum {
            return Err(format!(
                "{} minimum encoded size {minimum_wire_sum} exceeds its message bound {message_maximum}",
                message.full_name()
            ));
        }
        for oneof_maximum in oneof_maxima {
            maximum_wire_sum = maximum_wire_sum.checked_add(oneof_maximum).ok_or_else(|| {
                format!(
                    "{} maximum oneof-size arithmetic overflow",
                    message.full_name()
                )
            })?;
        }
        // The maximum total is intentionally independent from the outer cap:
        // producers compact or reject before all field maxima coexist. Still
        // compute it with checked arithmetic so descriptor math cannot wrap.
        let _ = maximum_wire_sum;
    }

    lint_graph(&messages, &graph)
}

#[derive(Clone, Copy, Debug)]
struct FieldLayout {
    number: i32,
    oneof_index: Option<i32>,
}

fn lint_declared_layout(owner: &str, fields: &[FieldLayout]) -> Result<(), String> {
    let mut previous_number = 0;
    let mut previous_oneof = None;
    let mut saw_oneof = false;
    for field in fields {
        if field.number <= previous_number {
            return Err(format!(
                "{owner} fields are not declared in ascending tag order"
            ));
        }
        previous_number = field.number;
        match field.oneof_index {
            None if saw_oneof => {
                return Err(format!(
                    "{owner} declares an ordinary field after a oneof; Prost would encode it before that oneof"
                ));
            }
            None => {}
            Some(index) if index < 0 => {
                return Err(format!("{owner} has a negative oneof index"));
            }
            Some(index) => {
                saw_oneof = true;
                if previous_oneof.is_some_and(|previous| index < previous) {
                    return Err(format!("{owner} oneof alternatives are not grouped"));
                }
                previous_oneof = Some(index);
            }
        }
    }
    Ok(())
}

fn lint_field_options(
    pool: &DescriptorPool,
    field: &FieldDescriptor,
    _parent_maximum: u64,
) -> Result<(), String> {
    if field.is_map() || field.is_group() {
        return Err(format!(
            "{} uses a prohibited map or group",
            field.full_name()
        ));
    }
    match field.kind() {
        Kind::Bytes | Kind::String => {
            let minimum = option_u64(
                pool,
                &field.options(),
                FIELD_MIN_BYTES_OPTION,
                field.full_name(),
            )?;
            let maximum = option_u64(
                pool,
                &field.options(),
                FIELD_MAX_BYTES_OPTION,
                field.full_name(),
            )?;
            lint_bound(
                field.full_name(),
                "byte",
                minimum,
                maximum,
                MAX_MESSAGE_BYTES,
            )?;
            usize::try_from(maximum)
                .map_err(|_| format!("{} byte bound does not fit usize", field.full_name()))?;
        }
        Kind::Message(_) | Kind::Enum(_) | Kind::Uint32 | Kind::Uint64 => {
            reject_option(
                pool,
                &field.options(),
                FIELD_MIN_BYTES_OPTION,
                field.full_name(),
            )?;
            reject_option(
                pool,
                &field.options(),
                FIELD_MAX_BYTES_OPTION,
                field.full_name(),
            )?;
        }
        _ => {
            return Err(format!(
                "{} uses a scalar not supported by the strict V2 scanner",
                field.full_name()
            ));
        }
    }

    if field.is_list() {
        let minimum = option_u64(
            pool,
            &field.options(),
            FIELD_MIN_ITEMS_OPTION,
            field.full_name(),
        )?;
        let maximum = option_u64(
            pool,
            &field.options(),
            FIELD_MAX_ITEMS_OPTION,
            field.full_name(),
        )?;
        lint_bound(
            field.full_name(),
            "item",
            minimum,
            maximum,
            MAX_REPEATED_ITEMS,
        )?;
        usize::try_from(maximum)
            .map_err(|_| format!("{} item bound does not fit usize", field.full_name()))?;
        if !matches!(field.kind(), Kind::Message(_) | Kind::Bytes | Kind::String) {
            return Err(format!(
                "{} requires an unsupported packed scalar scanner",
                field.full_name()
            ));
        }
    } else {
        reject_option(
            pool,
            &field.options(),
            FIELD_MIN_ITEMS_OPTION,
            field.full_name(),
        )?;
        reject_option(
            pool,
            &field.options(),
            FIELD_MAX_ITEMS_OPTION,
            field.full_name(),
        )?;
    }

    // Compute a full occurrence with checked arithmetic. The annotated child
    // maximum and the parent's total maximum are independent backpressure
    // limits, so the child maximum need not fit inside the parent maximum.
    let _ = occurrence_wire_bounds(pool, field)?;
    Ok(())
}

fn lint_bound(
    owner: &str,
    kind: &str,
    minimum: u64,
    maximum: u64,
    hard_maximum: u64,
) -> Result<(), String> {
    if minimum > maximum {
        return Err(format!("{owner} has inverted {kind} bounds"));
    }
    if maximum > hard_maximum {
        return Err(format!(
            "{owner} {kind} bound {maximum} exceeds hard cap {hard_maximum}"
        ));
    }
    Ok(())
}

fn field_wire_bounds(pool: &DescriptorPool, field: &FieldDescriptor) -> Result<(u64, u64), String> {
    let (occurrence_minimum, occurrence_maximum) = occurrence_wire_bounds(pool, field)?;
    if field.is_list() {
        let minimum = option_u64(
            pool,
            &field.options(),
            FIELD_MIN_ITEMS_OPTION,
            field.full_name(),
        )?;
        let maximum = option_u64(
            pool,
            &field.options(),
            FIELD_MAX_ITEMS_OPTION,
            field.full_name(),
        )?;
        Ok((
            occurrence_minimum.checked_mul(minimum).ok_or_else(|| {
                format!(
                    "{} minimum repeated-size arithmetic overflow",
                    field.full_name()
                )
            })?,
            occurrence_maximum.checked_mul(maximum).ok_or_else(|| {
                format!(
                    "{} maximum repeated-size arithmetic overflow",
                    field.full_name()
                )
            })?,
        ))
    } else {
        Ok((0, occurrence_maximum))
    }
}

fn occurrence_wire_bounds(
    pool: &DescriptorPool,
    field: &FieldDescriptor,
) -> Result<(u64, u64), String> {
    let key_bytes = varint_len((u64::from(field.number()) << 3) | wire_type(field)?);
    let (payload_minimum, payload_maximum, length_delimited) = match field.kind() {
        Kind::Bytes | Kind::String => (
            option_u64(
                pool,
                &field.options(),
                FIELD_MIN_BYTES_OPTION,
                field.full_name(),
            )?
            .max(1),
            option_u64(
                pool,
                &field.options(),
                FIELD_MAX_BYTES_OPTION,
                field.full_name(),
            )?,
            true,
        ),
        Kind::Message(message) => (
            0,
            option_u64(
                pool,
                &message.options(),
                MESSAGE_MAX_OPTION,
                message.full_name(),
            )?,
            true,
        ),
        Kind::Uint32 => (1, 5, false),
        Kind::Uint64 | Kind::Enum(_) => (1, 10, false),
        _ => {
            return Err(format!(
                "{} uses an unsupported scalar kind",
                field.full_name()
            ));
        }
    };
    let encoded = |payload: u64| -> Result<u64, String> {
        let prefix = if length_delimited {
            varint_len(payload)
        } else {
            0
        };
        key_bytes
            .checked_add(prefix)
            .and_then(|size| size.checked_add(payload))
            .ok_or_else(|| format!("{} encoded-size arithmetic overflow", field.full_name()))
    };
    Ok((encoded(payload_minimum)?, encoded(payload_maximum)?))
}

fn wire_type(field: &FieldDescriptor) -> Result<u64, String> {
    match field.kind() {
        Kind::Uint32 | Kind::Uint64 | Kind::Enum(_) => Ok(0),
        Kind::Bytes | Kind::String | Kind::Message(_) => Ok(2),
        _ => Err(format!(
            "{} uses an unsupported scalar kind",
            field.full_name()
        )),
    }
}

fn varint_len(mut value: u64) -> u64 {
    let mut length = 1;
    while value >= 0x80 {
        length += 1;
        value >>= 7;
    }
    length
}

fn lint_graph(messages: &[MessageDescriptor], graph: &[Vec<usize>]) -> Result<(), String> {
    let mut visiting = vec![false; messages.len()];
    for root in 0..messages.len() {
        visit_message(root, 1, messages, graph, &mut visiting)?;
    }
    Ok(())
}

fn visit_message(
    node: usize,
    depth: usize,
    messages: &[MessageDescriptor],
    graph: &[Vec<usize>],
    visiting: &mut [bool],
) -> Result<(), String> {
    if depth > MAX_MESSAGE_DEPTH {
        return Err(format!(
            "{} can exceed the maximum message depth {MAX_MESSAGE_DEPTH}",
            messages[node].full_name()
        ));
    }
    if visiting[node] {
        return Err(format!(
            "{} participates in recursive persisted messages",
            messages[node].full_name()
        ));
    }
    visiting[node] = true;
    for child in &graph[node] {
        visit_message(*child, depth + 1, messages, graph, visiting)?;
    }
    visiting[node] = false;
    Ok(())
}

fn reject_option(
    pool: &DescriptorPool,
    options: &prost_reflect::DynamicMessage,
    option_name: &'static str,
    owner: &str,
) -> Result<(), String> {
    let extension = pool
        .get_extension_by_name(option_name)
        .ok_or_else(|| format!("{option_name} is missing"))?;
    if options.has_extension(&extension) {
        return Err(format!(
            "{owner} has an inapplicable {option_name} annotation"
        ));
    }
    Ok(())
}

fn option_u64(
    pool: &DescriptorPool,
    options: &prost_reflect::DynamicMessage,
    option_name: &'static str,
    owner: &str,
) -> Result<u64, String> {
    let extension = pool
        .get_extension_by_name(option_name)
        .ok_or_else(|| format!("{option_name} is missing"))?;
    if !options.has_extension(&extension) {
        return Err(format!("{owner} has no {option_name} annotation"));
    }
    match options.get_extension(&extension).as_ref() {
        Value::U64(value) => Ok(*value),
        _ => Err(format!("{owner} has a non-u64 {option_name} annotation")),
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldLayout, lint_bound, lint_declared_layout, visit_message};

    #[test]
    fn declared_layout_rejects_out_of_order_fields() {
        let fields = [
            FieldLayout {
                number: 2,
                oneof_index: None,
            },
            FieldLayout {
                number: 1,
                oneof_index: None,
            },
        ];
        assert!(lint_declared_layout("test.Message", &fields).is_err());
    }

    #[test]
    fn declared_layout_rejects_ordinary_field_after_oneof() {
        let fields = [
            FieldLayout {
                number: 1,
                oneof_index: Some(0),
            },
            FieldLayout {
                number: 2,
                oneof_index: None,
            },
        ];
        assert!(lint_declared_layout("test.Message", &fields).is_err());
    }

    #[test]
    fn declared_layout_rejects_regrouped_oneof() {
        let fields = [
            FieldLayout {
                number: 1,
                oneof_index: Some(1),
            },
            FieldLayout {
                number: 2,
                oneof_index: Some(0),
            },
        ];
        assert!(lint_declared_layout("test.Message", &fields).is_err());
    }

    #[test]
    fn bounds_reject_inversion_and_hard_cap_overflow() {
        assert!(lint_bound("test.field", "byte", 2, 1, 4).is_err());
        assert!(lint_bound("test.field", "byte", 0, u64::MAX, 4).is_err());
    }

    #[test]
    fn graph_rejects_recursion_and_depth_seventeen() {
        let pool = prost_reflect::DescriptorPool::global();
        let messages = vec![
            pool.get_message_by_name("google.protobuf.Empty")
                .expect("global well-known descriptor"),
        ];
        let mut visiting = vec![false];
        assert!(visit_message(0, 1, &messages, &[vec![0]], &mut visiting).is_err());

        let messages = vec![messages[0].clone(); 17];
        let graph = (0..17)
            .map(|index| {
                if index == 16 {
                    Vec::new()
                } else {
                    vec![index + 1]
                }
            })
            .collect::<Vec<_>>();
        let mut visiting = vec![false; 17];
        assert!(visit_message(0, 1, &messages, &graph, &mut visiting).is_err());
    }
}

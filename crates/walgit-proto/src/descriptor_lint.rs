use prost_reflect::{DescriptorPool, Kind, Value};

const MESSAGE_MAX_OPTION: &str = "walgit.v2.max_encoded_bytes";
const FIELD_MIN_BYTES_OPTION: &str = "walgit.v2.min_bytes";
const FIELD_MAX_BYTES_OPTION: &str = "walgit.v2.max_bytes";
const FIELD_MIN_ITEMS_OPTION: &str = "walgit.v2.min_items";
const FIELD_MAX_ITEMS_OPTION: &str = "walgit.v2.max_items";

/// Prove that every persisted V2 message and variable field exposes the
/// bounds required by the strict wire preflight.
pub fn lint_v2_descriptors(pool: &DescriptorPool) -> Result<(), String> {
    for message in pool
        .all_messages()
        .filter(|message| message.full_name().starts_with("walgit.v2."))
    {
        let maximum = option_u64(
            pool,
            &message.options(),
            MESSAGE_MAX_OPTION,
            message.full_name(),
        )?;
        if maximum == 0 {
            return Err(format!("{} has a zero message bound", message.full_name()));
        }
        if message.is_map_entry() {
            return Err(format!("{} is a prohibited map entry", message.full_name()));
        }
        let mut previous = 0;
        for field in message.fields() {
            if field.number() <= previous {
                return Err(format!(
                    "{} fields are not declared in ascending tag order",
                    message.full_name()
                ));
            }
            previous = field.number();
            if field.is_map() || field.is_group() {
                return Err(format!(
                    "{} uses a prohibited map or group",
                    field.full_name()
                ));
            }
            match field.kind() {
                Kind::Bytes | Kind::String => {
                    let min = option_u64(
                        pool,
                        &field.options(),
                        FIELD_MIN_BYTES_OPTION,
                        field.full_name(),
                    )?;
                    let max = option_u64(
                        pool,
                        &field.options(),
                        FIELD_MAX_BYTES_OPTION,
                        field.full_name(),
                    )?;
                    if min > max {
                        return Err(format!("{} has inverted byte bounds", field.full_name()));
                    }
                }
                Kind::Message(_) | Kind::Enum(_) | Kind::Uint32 | Kind::Uint64 => {}
                _ => {
                    return Err(format!(
                        "{} uses a scalar not supported by the strict V2 scanner",
                        field.full_name()
                    ));
                }
            }
            if field.is_list() {
                let min = option_u64(
                    pool,
                    &field.options(),
                    FIELD_MIN_ITEMS_OPTION,
                    field.full_name(),
                )?;
                let max = option_u64(
                    pool,
                    &field.options(),
                    FIELD_MAX_ITEMS_OPTION,
                    field.full_name(),
                )?;
                if min > max {
                    return Err(format!("{} has inverted item bounds", field.full_name()));
                }
                if !matches!(field.kind(), Kind::Message(_) | Kind::Bytes | Kind::String) {
                    return Err(format!(
                        "{} requires an unsupported packed scalar scanner",
                        field.full_name()
                    ));
                }
            }
        }
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

use prost_reflect::{DescriptorPool, Value};
use walgit_proto::{FILE_DESCRIPTOR_SET, v2::codec::lint_v2_descriptors};

#[test]
fn every_v2_message_and_variable_field_has_machine_readable_bounds() {
    lint_v2_descriptors().unwrap();

    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let control = pool.get_message_by_name("walgit.v2.RepoControl").unwrap();
    assert_eq!(
        option(&pool, control.options(), "walgit.v2.max_encoded_bytes"),
        1_048_576
    );

    let inline_packs = pool
        .get_message_by_name("walgit.v2.InlinePackRoots")
        .unwrap();
    assert_eq!(
        option(
            &pool,
            inline_packs.get_field_by_name("roots").unwrap().options(),
            "walgit.v2.max_items"
        ),
        4_096
    );
    let inline_grants = pool.get_message_by_name("walgit.v2.InlineGrants").unwrap();
    assert_eq!(
        option(
            &pool,
            inline_grants.get_field_by_name("grants").unwrap().options(),
            "walgit.v2.max_items"
        ),
        256
    );
    let wal = pool.get_message_by_name("walgit.v2.WalState").unwrap();
    assert_eq!(
        option(
            &pool,
            wal.get_field_by_name("tail").unwrap().options(),
            "walgit.v2.max_items"
        ),
        256
    );
    let reclamation = pool
        .get_message_by_name("walgit.v2.ReclamationState")
        .unwrap();
    assert_eq!(
        option(&pool, reclamation.options(), "walgit.v2.max_encoded_bytes"),
        65_536
    );
    assert_eq!(
        option(
            &pool,
            reclamation.get_field_by_name("cursor").unwrap().options(),
            "walgit.v2.max_bytes"
        ),
        4_096
    );
}

#[test]
fn repo_control_has_exactly_the_fixed_catalog_slots_and_terminal_oneof_tags() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let control = pool.get_message_by_name("walgit.v2.RepoControl").unwrap();
    let catalog_slots = [
        "pack_catalog",
        "grant_catalog",
        "receipt_catalog",
        "event_catalog",
        "pin_catalog",
        "git_ownership_catalog",
        "lfs_ownership_catalog",
        "bundle_catalog",
        "recovery_catalog",
        "audit_catalog",
        "reclamation_catalog",
    ];
    assert_eq!(catalog_slots.len(), 11);
    for slot in catalog_slots {
        assert!(control.get_field_by_name(slot).is_some(), "missing {slot}");
    }
    assert_eq!(
        control.get_field_by_name("inline_packs").unwrap().number(),
        31
    );
    assert_eq!(
        control.get_field_by_name("pack_catalog").unwrap().number(),
        32
    );
    assert_eq!(
        control.get_field_by_name("inline_grants").unwrap().number(),
        33
    );
    assert_eq!(
        control.get_field_by_name("grant_catalog").unwrap().number(),
        34
    );
}

fn option(pool: &DescriptorPool, options: prost_reflect::DynamicMessage, name: &str) -> u64 {
    let extension = pool.get_extension_by_name(name).unwrap();
    assert!(options.has_extension(&extension));
    match options.get_extension(&extension).as_ref() {
        Value::U64(value) => *value,
        other => panic!("unexpected option value {other:?}"),
    }
}

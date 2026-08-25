use prost_reflect::{DescriptorPool, Kind, Value};
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

#[test]
fn credential_control_has_the_exact_v5_9_tags_presence_and_bounds() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let root = pool
        .get_message_by_name("walgit.v2.VerificationRingRoot")
        .unwrap();
    assert_eq!(
        option(&pool, root.options(), "walgit.v2.max_encoded_bytes"),
        4_096
    );
    let root_fields = [
        ("key", 1),
        ("object_version_id", 2),
        ("digest", 3),
        ("size", 4),
        ("ring_epoch", 5),
    ];
    for (name, tag) in root_fields {
        assert_eq!(root.get_field_by_name(name).unwrap().number(), tag);
    }
    for name in ["key", "object_version_id", "digest"] {
        assert!(matches!(
            root.get_field_by_name(name).unwrap().kind(),
            Kind::Bytes
        ));
    }
    for name in ["size", "ring_epoch"] {
        assert!(matches!(
            root.get_field_by_name(name).unwrap().kind(),
            Kind::Uint64
        ));
    }

    let control = pool
        .get_message_by_name("walgit.v2.CredentialControl")
        .unwrap();
    assert_eq!(
        option(&pool, control.options(), "walgit.v2.max_encoded_bytes"),
        65_536
    );
    let fields = [
        ("schema_version", 1),
        ("control_revision", 2),
        ("issuer_epoch", 3),
        ("current", 4),
        ("next", 5),
        ("previous", 6),
        ("previous_last_issue_unix_seconds", 7),
        ("revoked_kids", 8),
        ("verifier_set_digest", 9),
        ("acknowledgement_proof_digest", 10),
    ];
    for (name, tag) in fields {
        assert_eq!(control.get_field_by_name(name).unwrap().number(), tag);
    }
    assert!(matches!(
        control.get_field_by_name("schema_version").unwrap().kind(),
        Kind::Uint32
    ));
    for name in ["control_revision", "issuer_epoch"] {
        assert!(matches!(
            control.get_field_by_name(name).unwrap().kind(),
            Kind::Uint64
        ));
    }
    for name in ["current", "next", "previous"] {
        let Kind::Message(message) = control.get_field_by_name(name).unwrap().kind() else {
            panic!("{name} is not a message")
        };
        assert_eq!(message.full_name(), "walgit.v2.VerificationRingRoot");
    }
    let last_issue = control
        .get_field_by_name("previous_last_issue_unix_seconds")
        .unwrap();
    assert!(last_issue.supports_presence());
    assert_eq!(
        last_issue.field_descriptor_proto().proto3_optional,
        Some(true)
    );
    assert!(matches!(last_issue.kind(), Kind::Int64));
    let revoked = control.get_field_by_name("revoked_kids").unwrap();
    assert!(revoked.is_list());
    assert_eq!(option(&pool, revoked.options(), "walgit.v2.min_bytes"), 16);
    assert_eq!(option(&pool, revoked.options(), "walgit.v2.max_bytes"), 16);
    assert_eq!(option(&pool, revoked.options(), "walgit.v2.max_items"), 64);
}

fn option(pool: &DescriptorPool, options: prost_reflect::DynamicMessage, name: &str) -> u64 {
    let extension = pool.get_extension_by_name(name).unwrap();
    assert!(options.has_extension(&extension));
    match options.get_extension(&extension).as_ref() {
        Value::U64(value) => *value,
        other => panic!("unexpected option value {other:?}"),
    }
}

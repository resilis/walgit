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

#[test]
fn mutation_receipt_schema_has_the_frozen_numeric_contract() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let kinds = pool.get_enum_by_name("walgit.v2.MutationKind").unwrap();
    let expected = [
        ("MUTATION_KIND_UNSPECIFIED", 0),
        ("MUTATION_KIND_CREATE", 1),
        ("MUTATION_KIND_PUSH", 2),
        ("MUTATION_KIND_REF_UPDATE", 3),
        ("MUTATION_KIND_LFS_FINALIZE", 4),
        ("MUTATION_KIND_POLICY", 5),
        ("MUTATION_KIND_SETTINGS", 6),
        ("MUTATION_KIND_GRANTS", 7),
        ("MUTATION_KIND_LIFECYCLE", 8),
        ("MUTATION_KIND_CHECKPOINT", 9),
        ("MUTATION_KIND_COMPACTION", 10),
        ("MUTATION_KIND_BUNDLE", 11),
        ("MUTATION_KIND_FOLLOW", 12),
        ("MUTATION_KIND_IMPORT", 13),
        ("MUTATION_KIND_REPAIR", 14),
        ("MUTATION_KIND_PIN", 15),
        ("MUTATION_KIND_EVENT", 16),
        ("MUTATION_KIND_RECLAMATION", 17),
        ("MUTATION_KIND_WRITER_TAKEOVER", 18),
        ("MUTATION_KIND_INTERNAL_SETTLEMENT", 19),
    ];
    assert_eq!(
        kinds
            .values()
            .map(|value| (value.name().to_string(), value.number()))
            .collect::<Vec<_>>(),
        expected
            .into_iter()
            .map(|(name, number)| (name.to_string(), number))
            .collect::<Vec<_>>()
    );

    let states = pool.get_enum_by_name("walgit.v2.ReceiptState").unwrap();
    assert_eq!(
        states
            .values()
            .map(|value| (value.name().to_string(), value.number()))
            .collect::<Vec<_>>(),
        vec![
            ("RECEIPT_STATE_UNSPECIFIED".to_string(), 0),
            ("RECEIPT_STATE_UNRESOLVED".to_string(), 1),
            ("RECEIPT_STATE_SETTLED".to_string(), 2),
        ]
    );

    for message in [
        "MutationReceipt",
        "MutationResult",
        "ReceiptCatalogRow",
        "ReceiptCatalog",
    ] {
        assert!(
            pool.get_message_by_name(&format!("walgit.v2.{message}"))
                .is_some(),
            "missing {message}"
        );
    }

    assert_fields(&pool, "NoPriorControl", &[]);
    assert_fields(
        &pool,
        "PriorControlBinding",
        &[("cas_token", 1, "bytes"), ("object_version_id", 2, "bytes")],
    );
    assert_fields(&pool, "NoCapacityObligation", &[]);
    assert_fields(
        &pool,
        "CapacityObligation",
        &[
            ("allocation_epoch", 1, "uint64"),
            ("shard_key", 2, "bytes"),
            ("shard_object_version_id", 3, "bytes"),
            ("reservation_id", 4, "bytes"),
            ("tenant_slice_bytes", 5, "uint64"),
            ("mutation_id", 6, "bytes"),
            ("byte_count", 7, "uint64"),
        ],
    );
    assert_fields(&pool, "NoEventObligation", &[]);
    assert_fields(
        &pool,
        "EventSubscriberBody",
        &[("digest", 1, "bytes"), ("size", 2, "uint64")],
    );
    assert_fields(
        &pool,
        "EventObligation",
        &[
            ("event_id", 1, "bytes"),
            ("wal_sequence", 2, "uint64"),
            ("subscriber_set_digest", 3, "bytes"),
            ("result_key", 4, "bytes"),
            ("subscriber_bodies", 5, "message"),
        ],
    );
    assert_fields(
        &pool,
        "MutationReceipt",
        &[
            ("schema_version", 1, "uint32"),
            ("identity", 2, "message"),
            ("mutation_id", 3, "bytes"),
            ("kind", 4, "enum"),
            ("writer_epoch", 5, "uint64"),
            ("wal_sequence", 6, "uint64"),
            ("request_digest", 7, "bytes"),
            ("immutable_dependency_digests", 8, "bytes"),
            ("no_prior_control", 9, "message"),
            ("prior_control", 10, "message"),
            ("no_capacity", 11, "message"),
            ("capacity", 12, "message"),
            ("no_event", 13, "message"),
            ("event", 14, "message"),
        ],
    );
    assert_fields(
        &pool,
        "LandedControlRef",
        &[
            ("repo_control_key", 1, "bytes"),
            ("object_version_id", 2, "bytes"),
            ("digest", 3, "bytes"),
            ("size", 4, "uint64"),
        ],
    );
    assert_fields(
        &pool,
        "MutationResult",
        &[
            ("schema_version", 1, "uint32"),
            ("identity", 2, "message"),
            ("mutation_id", 3, "bytes"),
            ("kind", 4, "enum"),
            ("landed_control", 5, "message"),
            ("landed_control_revision", 6, "uint64"),
            ("writer_epoch", 7, "uint64"),
            ("wal_sequence", 8, "uint64"),
        ],
    );
    assert_fields(
        &pool,
        "ReceiptCatalogRow",
        &[
            ("mutation_id", 1, "bytes"),
            ("state", 2, "enum"),
            ("receipt", 3, "message"),
            ("result", 4, "message"),
            ("settlement_mutation_id", 5, "bytes"),
        ],
    );
    assert_fields(
        &pool,
        "ReceiptCatalog",
        &[
            ("schema_version", 1, "uint32"),
            ("identity", 2, "message"),
            ("rows", 3, "message"),
        ],
    );
    let catalog = pool
        .get_message_by_name("walgit.v2.ReceiptCatalog")
        .unwrap();
    assert_eq!(
        option(&pool, catalog.options(), "walgit.v2.max_encoded_bytes"),
        524_288
    );
}

fn assert_fields(pool: &DescriptorPool, message: &str, expected: &[(&str, u32, &str)]) {
    let message = pool
        .get_message_by_name(&format!("walgit.v2.{message}"))
        .unwrap();
    let actual = message
        .fields()
        .map(|field| {
            let kind = match field.kind() {
                Kind::Uint32 => "uint32",
                Kind::Uint64 => "uint64",
                Kind::Bytes => "bytes",
                Kind::Enum(_) => "enum",
                Kind::Message(_) => "message",
                other => panic!("unexpected field kind {other:?}"),
            };
            (field.name().to_owned(), field.number(), kind)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|(name, number, kind)| ((*name).to_owned(), *number, *kind))
            .collect::<Vec<_>>()
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

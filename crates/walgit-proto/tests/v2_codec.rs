mod support;

use bytes::Bytes;
use prost::Message;
use walgit_proto::v2::{
    CatalogKind, CatalogRoot, InlinePackRoots, InlineRefChanges, Lifecycle, PackRoot, RefChange,
    RepoControl, TargetObjectRef, WalEntryKind, WalState, WalTailEntry,
    codec::{ControlCodecError, preflight_repo_control},
    decode_repo_control, encode_repo_control,
    keys::{DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::PackRepresentation,
    validate_repo_control_successor,
    wal_tail_entry::RefRepresentation,
};

#[test]
fn exact_successor_freezes_create_binding_and_advances_one_revision() {
    let previous = support::sample_control();
    let mut successor = previous.clone();
    successor.control_revision = 2;
    successor.last_internal_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abf").unwrap());
    validate_repo_control_successor(&previous, &successor).unwrap();

    let mut revision_gap = successor.clone();
    revision_gap.control_revision = 3;
    assert!(validate_repo_control_successor(&previous, &revision_gap).is_err());

    let mut changed_identity = successor.clone();
    changed_identity.identity.as_mut().unwrap().project_id = Bytes::from_static(b"other-project");
    assert!(validate_repo_control_successor(&previous, &changed_identity).is_err());

    let mut reused_mutation = successor;
    reused_mutation.last_internal_mutation_id = previous.last_internal_mutation_id.clone();
    assert!(validate_repo_control_successor(&previous, &reused_mutation).is_err());
}

#[test]
fn exact_successor_enforces_terminal_lifecycle_and_revision_overflow() {
    let mut deleting = support::sample_control();
    deleting.lifecycle = Lifecycle::Deleting as i32;
    let mut tombstoned = deleting.clone();
    tombstoned.lifecycle = Lifecycle::Tombstoned as i32;
    tombstoned.control_revision = 2;
    tombstoned.last_internal_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abf").unwrap());
    validate_repo_control_successor(&deleting, &tombstoned).unwrap();

    let mut after_tombstone = tombstoned.clone();
    after_tombstone.control_revision = 3;
    after_tombstone.last_internal_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210ac0").unwrap());
    assert!(validate_repo_control_successor(&tombstoned, &after_tombstone).is_err());

    let mut maximum = support::sample_control();
    maximum.control_revision = u64::MAX;
    let mut overflow = maximum.clone();
    overflow.last_internal_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abf").unwrap());
    assert!(validate_repo_control_successor(&maximum, &overflow).is_err());
}

#[test]
fn exact_canonical_roundtrip() {
    let control = support::sample_control();
    let bytes = encode_repo_control(&control).unwrap();
    assert_eq!(decode_repo_control(&bytes).unwrap(), control);
}

#[test]
fn rejects_unknown_duplicate_nonminimal_and_out_of_order_wire() {
    let bytes = encode_repo_control(&support::sample_control()).unwrap();

    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[0xf8, 0x07, 0x01]); // field 127, varint 1
    assert!(matches!(
        decode_repo_control(&unknown),
        Err(ControlCodecError::UnknownField { .. })
    ));

    let mut duplicate = vec![0x08, 0x02];
    duplicate.extend_from_slice(&bytes);
    assert!(matches!(
        decode_repo_control(&duplicate),
        Err(ControlCodecError::NonCanonical(_)) | Err(ControlCodecError::DuplicateField { .. })
    ));

    let mut nonminimal = bytes.clone();
    nonminimal.splice(1..2, [0x82, 0x00]);
    assert!(matches!(
        decode_repo_control(&nonminimal),
        Err(ControlCodecError::NonCanonical(_))
    ));

    let mut out_of_order = bytes[2..].to_vec();
    out_of_order.extend_from_slice(&bytes[..2]);
    assert!(matches!(
        decode_repo_control(&out_of_order),
        Err(ControlCodecError::NonCanonical(_))
    ));
}

#[test]
fn preflight_rejects_unknown_enums_and_two_members_of_one_oneof() {
    assert!(matches!(
        preflight_repo_control(&[0x08, 0x02, 0x38, 0x63]),
        Err(ControlCodecError::Malformed("unknown or zero enum value"))
    ));

    // Empty field 31 followed by empty field 32: two pack-representation arms.
    assert!(matches!(
        preflight_repo_control(&[0xfa, 0x01, 0x00, 0x82, 0x02, 0x00]),
        Err(ControlCodecError::DuplicateField { .. })
    ));
}

#[test]
fn preflight_stops_repeated_collections_before_generated_decode() {
    let mut too_many_packs = support::sample_control();
    too_many_packs.pack_representation = Some(PackRepresentation::InlinePacks(InlinePackRoots {
        roots: vec![PackRoot::default(); 4_097],
    }));
    let bytes = too_many_packs.encode_to_vec();
    assert!(matches!(
        preflight_repo_control(&bytes),
        Err(ControlCodecError::CountExceeded { maximum: 4_096, .. })
    ));

    let mut too_many_tail = support::sample_control();
    too_many_tail.wal.as_mut().unwrap().tail = vec![WalTailEntry::default(); 257];
    let bytes = too_many_tail.encode_to_vec();
    assert!(matches!(
        preflight_repo_control(&bytes),
        Err(ControlCodecError::CountExceeded { maximum: 256, .. })
    ));
}

#[test]
fn preflight_enforces_the_aggregate_inline_ref_change_bound() {
    preflight_repo_control(&raw_inline_ref_control(&[256; 16])).unwrap();

    let mut four_thousand_ninety_seven = vec![256; 16];
    four_thousand_ninety_seven.push(1);
    assert!(matches!(
        preflight_repo_control(&raw_inline_ref_control(&four_thousand_ninety_seven)),
        Err(ControlCodecError::CountExceeded {
            actual: 4_097,
            maximum: 4_096,
            ..
        })
    ));

    assert!(matches!(
        preflight_repo_control(&raw_inline_ref_control(&[256; 256])),
        Err(ControlCodecError::CountExceeded { maximum: 4_096, .. })
    ));
}

#[test]
fn semantic_validation_rejects_aggregate_ref_change_overflow() {
    let mut control = support::sample_control();
    let wal = control.wal.as_mut().unwrap();
    wal.head_sequence = 17;
    wal.minimum_sequence = 1;
    wal.tail = (1..=17)
        .map(|sequence| {
            let count = if sequence == 17 { 1 } else { 256 };
            WalTailEntry {
                sequence,
                kind: WalEntryKind::Push as i32,
                mutation_id: {
                    let mut id = hex::decode("01890f4776447b8b9d7a876543210a00").unwrap();
                    id[15] = sequence as u8;
                    Bytes::from(id)
                },
                superseded_objects: Vec::new(),
                ref_representation: Some(RefRepresentation::InlineRefChanges(InlineRefChanges {
                    changes: (0..count)
                        .map(|index| RefChange {
                            name: Bytes::from(format!("refs/heads/{sequence}-{index}")),
                            new_object_id: Bytes::from(vec![0x77; 20]),
                            ..Default::default()
                        })
                        .collect(),
                })),
            }
        })
        .collect();
    let error = encode_repo_control(&control).unwrap_err().to_string();
    assert!(error.contains("4096 aggregate inline ref changes"));
}

#[test]
fn wal_requires_exact_checkpoint_and_tail_coverage() {
    let mut no_checkpoint = support::sample_control();
    no_checkpoint.wal = Some(WalState {
        head_sequence: 3,
        minimum_sequence: 1,
        checkpoint: None,
        tail: (1..=3).map(wal_entry).collect(),
    });
    encode_repo_control(&no_checkpoint).unwrap();

    for sequences in [
        vec![],
        vec![2, 3],
        vec![1, 3],
        vec![1, 3, 4],
        vec![1, 3, 2],
        vec![1, 2],
        vec![1, 2, 2],
    ] {
        let mut invalid = no_checkpoint.clone();
        invalid.wal.as_mut().unwrap().tail = sequences.into_iter().map(wal_entry).collect();
        assert!(encode_repo_control(&invalid).is_err());
    }

    let digest = [0xaa; 32];
    let mut checkpointed = support::sample_control();
    checkpointed.wal = Some(WalState {
        head_sequence: 5,
        minimum_sequence: 4,
        checkpoint: Some(checkpoint_target(&checkpointed, 3, digest, digest)),
        tail: (4..=5).map(wal_entry).collect(),
    });
    encode_repo_control(&checkpointed).unwrap();

    let mut checkpoint_at_head = checkpointed.clone();
    checkpoint_at_head.wal = Some(WalState {
        head_sequence: 5,
        minimum_sequence: 6,
        checkpoint: Some(checkpoint_target(&checkpoint_at_head, 5, digest, digest)),
        tail: Vec::new(),
    });
    encode_repo_control(&checkpoint_at_head).unwrap();

    let mut wrong_key_sequence = checkpoint_at_head.clone();
    wrong_key_sequence.wal.as_mut().unwrap().checkpoint =
        Some(checkpoint_target(&wrong_key_sequence, 4, digest, digest));
    assert!(encode_repo_control(&wrong_key_sequence).is_err());

    let mut overflow = support::sample_control();
    overflow.wal = Some(WalState {
        head_sequence: u64::MAX,
        minimum_sequence: u64::MAX,
        checkpoint: Some(checkpoint_target(&overflow, u64::MAX, digest, digest)),
        tail: Vec::new(),
    });
    assert!(encode_repo_control(&overflow).is_err());
}

#[test]
fn content_addressed_targets_bind_key_digest_to_reference_digest() {
    let key_digest = [0xaa; 32];
    let target_digest = [0xbb; 32];

    let mut catalog = support::sample_control();
    catalog.audit_catalog = Some(catalog_root(
        &catalog,
        CatalogKind::Audit,
        "audit",
        1,
        key_digest,
        target_digest,
    ));
    assert!(
        encode_repo_control(&catalog)
            .unwrap_err()
            .to_string()
            .contains("content digest encoded in target.key")
    );

    let mut checkpoint = support::sample_control();
    checkpoint.wal = Some(WalState {
        head_sequence: 0,
        minimum_sequence: 1,
        checkpoint: Some(checkpoint_target(&checkpoint, 0, key_digest, target_digest)),
        tail: Vec::new(),
    });
    assert!(encode_repo_control(&checkpoint).is_err());

    let mut pack = support::sample_control();
    pack.wal = Some(WalState {
        head_sequence: 1,
        minimum_sequence: 1,
        checkpoint: None,
        tail: vec![wal_entry(1)],
    });
    pack.pack_representation = Some(PackRepresentation::InlinePacks(InlinePackRoots {
        roots: vec![PackRoot {
            object: Some(repository_target(
                &pack,
                &format!("git/packs/{}.pack", hex::encode(key_digest)),
                target_digest,
            )),
            git_object_id: Bytes::from(vec![0x11; 20]),
            introduced_wal_sequence: 1,
            object_count: 1,
        }],
    }));
    assert!(encode_repo_control(&pack).is_err());

    for suffix in [
        format!(
            "events/watermarks/{:016x}/{}.pb",
            1,
            hex::encode(key_digest)
        ),
        format!("lfs/{}.bin", hex::encode(key_digest)),
        format!("bundles/{}.bundle", hex::encode(key_digest)),
    ] {
        let mut control = support::sample_control();
        control.wal = Some(WalState {
            head_sequence: 1,
            minimum_sequence: 1,
            checkpoint: None,
            tail: vec![WalTailEntry {
                superseded_objects: vec![repository_target(&control, &suffix, target_digest)],
                ..wal_entry(1)
            }],
        });
        assert!(encode_repo_control(&control).is_err(), "accepted {suffix}");
    }
}

#[test]
fn wal_ref_delta_catalog_cannot_exceed_one_atomic_transaction() {
    let digest = [0xaa; 32];
    let mut control = support::sample_control();
    control.wal = Some(WalState {
        head_sequence: 1,
        minimum_sequence: 1,
        checkpoint: None,
        tail: vec![WalTailEntry {
            ref_representation: Some(RefRepresentation::RefDeltaCatalog(Box::new(catalog_root(
                &control,
                CatalogKind::RefDelta,
                "ref-delta",
                256,
                digest,
                digest,
            )))),
            ..wal_entry(1)
        }],
    });
    encode_repo_control(&control).unwrap();

    let root = match control.wal.as_mut().unwrap().tail[0]
        .ref_representation
        .as_mut()
        .unwrap()
    {
        RefRepresentation::RefDeltaCatalog(root) => root,
        RefRepresentation::InlineRefChanges(_) => unreachable!(),
    };
    root.item_count = 257;
    assert!(
        encode_repo_control(&control)
            .unwrap_err()
            .to_string()
            .contains("256-change limit")
    );
}

#[test]
fn reclamation_cursor_accepts_absent_and_maximum_but_rejects_over_maximum() {
    let mut control = support::sample_control();
    encode_repo_control(&control).unwrap();

    control.reclamation.as_mut().unwrap().cursor = Bytes::from(vec![0x55; 4_096]);
    encode_repo_control(&control).unwrap();

    control.reclamation.as_mut().unwrap().cursor = Bytes::from(vec![0x55; 4_097]);
    let raw = control.encode_to_vec();
    assert!(matches!(
        preflight_repo_control(&raw),
        Err(ControlCodecError::BytesOutsideBounds {
            actual: 4_097,
            maximum: 4_096,
            ..
        })
    ));
    assert!(encode_repo_control(&control).is_err());
}

#[test]
fn semantic_validation_keeps_path_digests_distinct() {
    let mut control = support::sample_control();
    let identity = control.identity.as_mut().unwrap();
    identity.routing_digest = identity.canonical_path_digest.clone();
    let error = encode_repo_control(&control).unwrap_err().to_string();
    assert!(error.contains("routing_digest"));
}

#[test]
fn semantic_validation_derives_capacity_shard_from_repository_uuid() {
    let mut control = support::sample_control();
    control.capacity.as_mut().unwrap().shard = 17;
    let error = encode_repo_control(&control).unwrap_err().to_string();
    assert!(error.contains("SHA-256(repository_uuid)"));
}

#[test]
fn control_key_suffix_extraction_does_not_confuse_prefix_segments() {
    let mut control = support::sample_control();
    let prefix = DeploymentPrefix::parse("v2/repositories/by-path/").unwrap();
    let identity = control.identity.as_ref().unwrap();
    let routing = RoutingDigest::of(&identity.canonical_path).unwrap();
    control.repo_control_key = Bytes::from(repo_control_key(&prefix, routing).unwrap());
    control.capacity.as_mut().unwrap().shard_key =
        Bytes::from_static(b"v2/repositories/by-path/v2/capacity/shards/c1/capacity_shard.pb");
    encode_repo_control(&control).unwrap();
}

#[test]
fn rejects_control_larger_than_one_mibibyte() {
    let bytes = vec![0; 1_048_577];
    assert!(matches!(
        preflight_repo_control(&bytes),
        Err(ControlCodecError::MessageTooLarge {
            maximum: 1_048_576,
            ..
        })
    ));
}

fn raw_inline_ref_control(counts: &[usize]) -> Vec<u8> {
    RepoControl {
        wal: Some(WalState {
            tail: counts
                .iter()
                .map(|count| WalTailEntry {
                    ref_representation: Some(RefRepresentation::InlineRefChanges(
                        InlineRefChanges {
                            changes: vec![RefChange::default(); *count],
                        },
                    )),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

fn wal_entry(sequence: u64) -> WalTailEntry {
    let mut mutation_id = hex::decode("01890f4776447b8b9d7a876543210a00").unwrap();
    mutation_id[14..].copy_from_slice(&(sequence as u16).to_be_bytes());
    WalTailEntry {
        sequence,
        kind: WalEntryKind::Settings as i32,
        mutation_id: Bytes::from(mutation_id),
        superseded_objects: Vec::new(),
        ref_representation: None,
    }
}

fn checkpoint_target(
    control: &RepoControl,
    sequence: u64,
    key_digest: [u8; 32],
    target_digest: [u8; 32],
) -> TargetObjectRef {
    repository_target(
        control,
        &format!("checkpoints/{sequence:016x}/{}.pb", hex::encode(key_digest)),
        target_digest,
    )
}

fn catalog_root(
    control: &RepoControl,
    kind: CatalogKind,
    kind_segment: &str,
    item_count: u64,
    key_digest: [u8; 32],
    target_digest: [u8; 32],
) -> CatalogRoot {
    CatalogRoot {
        kind: kind as i32,
        object: Some(repository_target(
            control,
            &format!("catalogs/{kind_segment}/{}.pb", hex::encode(key_digest)),
            target_digest,
        )),
        depth: 1,
        node_count: 1,
        item_count,
        total_encoded_bytes: 1,
    }
}

fn repository_target(control: &RepoControl, suffix: &str, digest: [u8; 32]) -> TargetObjectRef {
    let identity = control.identity.as_ref().unwrap();
    TargetObjectRef {
        identity: Some(identity.clone()),
        key: Bytes::from(format!(
            "prod/v2/repositories/by-id/{}/g{:016x}/{suffix}",
            hex::encode(&identity.repository_uuid),
            identity.generation
        )),
        object_version_id: Bytes::from_static(b"version-1"),
        digest: Bytes::copy_from_slice(&digest),
        size: 1,
    }
}

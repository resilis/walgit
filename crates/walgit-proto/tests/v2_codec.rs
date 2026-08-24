mod support;

use bytes::Bytes;
use prost::Message;
use walgit_proto::v2::{
    InlinePackRoots, InlineRefChanges, PackRoot, RefChange, WalEntryKind, WalTailEntry,
    codec::{ControlCodecError, preflight_repo_control},
    decode_repo_control, encode_repo_control,
    keys::{DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::PackRepresentation,
    wal_tail_entry::RefRepresentation,
};

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

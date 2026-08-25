mod support;

use bytes::Bytes;
use prost::Message;
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    CapacityObligation as CapacityObligationValue, CatalogKind, CatalogRoot, ControlCodecError,
    EventObligation as EventObligationValue, EventSubscriberBody, LandedControlRef,
    MAX_MUTATION_RECEIPT_BYTES, MAX_MUTATION_RESULT_BYTES, MAX_RECEIPT_CATALOG_BYTES, MutationKind,
    MutationReceipt, MutationResult, NoCapacityObligation, NoEventObligation, NoPriorControl,
    PriorControlBinding, ReceiptCatalog, ReceiptCatalogRow, ReceiptState, TargetObjectRef,
    decode_mutation_receipt, decode_mutation_result, decode_receipt_catalog,
    digests::ProtobufObjectDigest,
    encode_mutation_receipt, encode_mutation_result, encode_receipt_catalog,
    mutation_receipt::{CapacityObligation, EventObligation, Predecessor},
};

#[derive(Clone, PartialEq, Message)]
struct MutationKindCarrier {
    #[prost(enumeration = "MutationKind", tag = "1")]
    kind: i32,
}

const MUTATION_ID: &str = "01890f4776447b8b9d7a876543210ac0";

#[test]
fn receipt_result_and_catalog_have_stable_golden_bytes() {
    let receipt = receipt();
    let receipt_bytes = encode_mutation_receipt(&receipt).unwrap();
    assert_eq!(
        hex::encode(&receipt_bytes),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac02006280130013a2044444444444444444444444444444444444444444444444444444444444444444220555555555555555555555555555555555555555555555555555555555555555552120a056361732d31120976657273696f6e2d315a006a00",
        "receipt bytes changed"
    );
    assert_eq!(decode_mutation_receipt(&receipt_bytes).unwrap(), receipt);

    let result = result();
    let result_bytes = encode_mutation_result(&result).unwrap();
    assert_eq!(
        hex::encode(&result_bytes),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac020062a9f010a6d70726f642f76322f7265706f7369746f726965732f62792d706174682f346531613433646366333438333834383138306338376236633666613265663533376238373564643231356137366366316662363730376133653963393831662f7265706f5f636f6e74726f6c2e7062120976657273696f6e2d321a206666666666666666666666666666666666666666666666666666666666666666208020300238014001",
        "result bytes changed"
    );
    assert_eq!(decode_mutation_result(&result_bytes).unwrap(), result);

    let settled_catalog = catalog(ReceiptState::Settled, Some(result_target()));
    let catalog_bytes = encode_receipt_catalog(&settled_catalog).unwrap();
    assert_eq!(
        hex::encode(&catalog_bytes),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1ae8040a1001890f4776447b8b9d7a876543210ac010021afb0108011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac02006280130013a2044444444444444444444444444444444444444444444444444444444444444444220555555555555555555555555555555555555555555555555555555555555555552120a056361732d31120976657273696f6e2d315a006a0022c1020a82010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f12820170726f642f76322f7265706f7369746f726965732f62792d69642f30313839306634373736343437623862396437613837363534333231306162642f67303030303030303030303030303030312f72656365697074732f726573756c74732f30313839306634373736343437623862396437613837363534333231306163302e70621a10726573756c742d76657273696f6e2d31222077777777777777777777777777777777777777777777777777777777777777772880042a1001890f4776447b8b9d7a876543210aff",
        "catalog bytes changed"
    );
    assert_eq!(
        decode_receipt_catalog(&catalog_bytes).unwrap(),
        settled_catalog
    );
    assert_eq!(
        ProtobufObjectDigest::of_exact_protobuf(&receipt_bytes).lower_hex(),
        "d9ace950006a9b8607925d1caed739a6478666b921bbf4cfe86e10c44879f1b1"
    );
    assert_eq!(
        ProtobufObjectDigest::of_exact_protobuf(&result_bytes).lower_hex(),
        "43f09892077da691a26aedd7dc9498554cebd841e7567e1d2549af7eb1fc33ef"
    );
    assert_eq!(
        ProtobufObjectDigest::of_exact_protobuf(&catalog_bytes).lower_hex(),
        "c86e220d555ca2118bbf1832fcf823d0e641a4ad833917b117971305a3b5a810"
    );
    let unresolved_catalog = catalog(ReceiptState::Unresolved, None);
    let unresolved_bytes = encode_receipt_catalog(&unresolved_catalog).unwrap();
    assert_eq!(
        ProtobufObjectDigest::of_exact_protobuf(&unresolved_bytes).lower_hex(),
        "128597e30a9ab65e132a1b738ad59c65866ebd642fa47293bdd1f97b34f39fc7"
    );
    assert_catalog_root(&unresolved_catalog, &unresolved_bytes);
    assert_catalog_root(&settled_catalog, &catalog_bytes);
}

#[test]
fn every_mutation_kind_has_the_frozen_wire_value() {
    for value in 0..=19 {
        let bytes = MutationKindCarrier { kind: value }.encode_to_vec();
        let expected = if value == 0 {
            vec![]
        } else {
            vec![0x08, value as u8]
        };
        assert_eq!(bytes, expected, "MutationKind wire value {value} changed");
    }
}

#[test]
fn predecessor_capacity_and_event_arms_have_stable_golden_bytes() {
    let mut no_prior = receipt();
    no_prior.kind = MutationKind::Create as i32;
    no_prior.predecessor = Some(Predecessor::NoPriorControl(NoPriorControl {}));
    assert_eq!(
        hex::encode(encode_mutation_receipt(&no_prior).unwrap()),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac02001280130013a204444444444444444444444444444444444444444444444444444444444444444422055555555555555555555555555555555555555555555555555555555555555554a005a006a00"
    );

    let capacity = capacity_receipt();
    assert_eq!(
        hex::encode(encode_mutation_receipt(&capacity).unwrap()),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac02006280130013a2044444444444444444444444444444444444444444444444444444444444444444220555555555555555555555555555555555555555555555555555555555555555552120a056361732d31120976657273696f6e2d3162650801122c70726f642f76322f63617061636974792f7368617264732f63312f63617061636974795f73686172642e70621a0b63617061636974792d7631221001890f4776447b8b9d7a876543210ac02801321001890f4776447b8b9d7a876543210ac038016a00"
    );

    let event = event_receipt();
    assert_eq!(
        hex::encode(encode_mutation_receipt(&event).unwrap()),
        "08011282010a0874656e616e742d31120970726f6a6563742d311a1001890f4776447b8b9d7a876543210abd20012a1374656e616e742f70726f6a6563742f7265706f322004b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb513a204e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f1a1001890f4776447b8b9d7a876543210ac02006280130013a2044444444444444444444444444444444444444444444444444444444444444444220555555555555555555555555555555555555555555555555555555555555555552120a056361732d31120976657273696f6e2d315a0072df010a1001890f4776447b8b9d7a876543210ac010011a20666666666666666666666666666666666666666666666666666666666666666622800170726f642f76322f7265706f7369746f726965732f62792d69642f30313839306634373736343437623862396437613837363534333231306162642f67303030303030303030303030303030312f6576656e74732f726573756c74732f30313839306634373736343437623862396437613837363534333231306163302e70622a240a2077777777777777777777777777777777777777777777777777777777777777771001"
    );
}

#[test]
fn strict_receipt_codecs_reject_unknown_reordered_duplicate_and_nonminimal_wire() {
    let bytes = encode_mutation_receipt(&receipt()).unwrap();

    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
    assert!(matches!(
        decode_mutation_receipt(&unknown),
        Err(ControlCodecError::UnknownField { .. })
    ));

    let mut reordered = vec![0x20, MutationKind::Settings as u8];
    reordered.extend_from_slice(&bytes);
    assert!(matches!(
        decode_mutation_receipt(&reordered),
        Err(ControlCodecError::NonCanonical(_)) | Err(ControlCodecError::DuplicateField { .. })
    ));

    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&[0x20, MutationKind::Settings as u8]);
    assert!(matches!(
        decode_mutation_receipt(&duplicate),
        Err(ControlCodecError::DuplicateField { .. }) | Err(ControlCodecError::NonCanonical(_))
    ));

    let mut dual_predecessor = bytes.clone();
    dual_predecessor.extend_from_slice(&[0x4a, 0x00]);
    assert!(decode_mutation_receipt(&dual_predecessor).is_err());

    let nonminimal = [0x08, 0x81, 0x00];
    assert!(matches!(
        decode_mutation_receipt(&nonminimal),
        Err(ControlCodecError::NonCanonical("varint is not minimal"))
    ));
}

#[test]
fn every_new_root_rejects_wrong_wire_truncation_malformed_tail_oversize_and_bad_semantics() {
    let receipt_bytes = encode_mutation_receipt(&receipt()).unwrap();
    let result_bytes = encode_mutation_result(&result()).unwrap();
    let catalog_bytes =
        encode_receipt_catalog(&catalog(ReceiptState::Settled, Some(result_target()))).unwrap();

    let mut wrong_wire = receipt_bytes.clone();
    wrong_wire[0] = 0x0a;
    assert!(decode_mutation_receipt(&wrong_wire).is_err());
    let mut wrong_wire = result_bytes.clone();
    wrong_wire[0] = 0x0a;
    assert!(decode_mutation_result(&wrong_wire).is_err());
    let mut wrong_wire = catalog_bytes.clone();
    wrong_wire[0] = 0x0a;
    assert!(decode_receipt_catalog(&wrong_wire).is_err());

    let mut truncated = receipt_bytes.clone();
    truncated.pop();
    assert!(decode_mutation_receipt(&truncated).is_err());
    let mut truncated = result_bytes.clone();
    truncated.pop();
    assert!(decode_mutation_result(&truncated).is_err());
    let mut truncated = catalog_bytes.clone();
    truncated.pop();
    assert!(decode_receipt_catalog(&truncated).is_err());

    let mut malformed = receipt_bytes;
    malformed.push(0x80);
    assert!(decode_mutation_receipt(&malformed).is_err());
    let mut malformed = result_bytes;
    malformed.push(0x80);
    assert!(decode_mutation_result(&malformed).is_err());
    let mut malformed = catalog_bytes;
    malformed.push(0x80);
    assert!(decode_receipt_catalog(&malformed).is_err());

    assert!(decode_mutation_receipt(&vec![0; MAX_MUTATION_RECEIPT_BYTES + 1]).is_err());
    assert!(decode_mutation_result(&vec![0; MAX_MUTATION_RESULT_BYTES + 1]).is_err());
    assert!(decode_receipt_catalog(&vec![0; MAX_RECEIPT_CATALOG_BYTES + 1]).is_err());

    let mut value = receipt();
    value.writer_epoch = 0;
    assert!(encode_mutation_receipt(&value).is_err());
    let mut value = receipt();
    value.kind = 99;
    assert!(encode_mutation_receipt(&value).is_err());
    let mut value = receipt();
    value.predecessor = None;
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = result();
    value.landed_control_revision = 0;
    assert!(encode_mutation_result(&value).is_err());
    let mut value = result();
    value.kind = 99;
    assert!(encode_mutation_result(&value).is_err());

    let mut value = catalog(ReceiptState::Settled, Some(result_target()));
    value.schema_version = 0;
    assert!(encode_receipt_catalog(&value).is_err());
    let mut value = catalog(ReceiptState::Settled, Some(result_target()));
    value.rows[0].state = 99;
    assert!(encode_receipt_catalog(&value).is_err());
}

#[test]
fn receipt_unions_and_catalog_states_are_closed_and_internal_settlement_is_receiptless() {
    let mut value = receipt();
    value.kind = MutationKind::InternalSettlement as i32;
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = receipt();
    value.capacity_obligation = None;
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = receipt();
    value.event_obligation = None;
    assert!(encode_mutation_receipt(&value).is_err());

    assert!(encode_receipt_catalog(&catalog(ReceiptState::Unresolved, None)).is_ok());
    assert!(
        encode_receipt_catalog(&catalog(ReceiptState::Unresolved, Some(result_target()))).is_err()
    );
    assert!(encode_receipt_catalog(&catalog(ReceiptState::Settled, None)).is_err());
    assert!(encode_receipt_catalog(&catalog(ReceiptState::Settled, Some(result_target()))).is_ok());

    let mut unresolved = catalog(ReceiptState::Unresolved, None);
    unresolved.rows[0].settlement_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210aff").unwrap());
    assert!(encode_receipt_catalog(&unresolved).is_err());
    let mut settled = catalog(ReceiptState::Settled, Some(result_target()));
    settled.rows[0].settlement_mutation_id = Bytes::new();
    assert!(encode_receipt_catalog(&settled).is_err());
    settled.rows[0].settlement_mutation_id = Bytes::from_static(b"not-a-uuid-v7!!");
    assert!(encode_receipt_catalog(&settled).is_err());
}

#[test]
fn create_uses_explicit_no_prior_and_results_can_bind_wal_head_zero() {
    let mut create = receipt();
    create.kind = MutationKind::Create as i32;
    create.wal_sequence = 0;
    create.predecessor = Some(Predecessor::NoPriorControl(NoPriorControl {}));
    assert!(encode_mutation_receipt(&create).is_ok());
    create.predecessor = Some(Predecessor::PriorControl(PriorControlBinding {
        cas_token: Bytes::from_static(b"cas"),
        object_version_id: Bytes::from_static(b"version"),
    }));
    assert!(encode_mutation_receipt(&create).is_err());

    for kind in [
        MutationKind::Settings,
        MutationKind::Grants,
        MutationKind::WriterTakeover,
    ] {
        let mut value = result();
        value.kind = kind as i32;
        value.wal_sequence = 0;
        assert!(encode_mutation_result(&value).is_ok(), "kind={kind:?}");
    }
    let mut push = result();
    push.kind = MutationKind::Push as i32;
    push.wal_sequence = 0;
    assert!(encode_mutation_result(&push).is_ok());
}

#[test]
fn catalog_rows_and_dependencies_require_deterministic_unique_order() {
    let mut value = receipt();
    value.immutable_dependency_digests = vec![Bytes::from(vec![2; 32]), Bytes::from(vec![1; 32])];
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = catalog(ReceiptState::Unresolved, None);
    let mut second = value.rows[0].clone();
    second.mutation_id = value.rows[0].mutation_id.clone();
    value.rows.push(second);
    assert!(encode_receipt_catalog(&value).is_err());
}

#[test]
fn exact_maximum_tokens_versions_event_keys_and_sorted_bodies_are_closed() {
    let mut value = receipt();
    value.predecessor = Some(Predecessor::PriorControl(PriorControlBinding {
        cas_token: Bytes::from(vec![b'c'; 256]),
        object_version_id: Bytes::from(vec![b'v'; 1_024]),
    }));
    assert!(encode_mutation_receipt(&value).is_ok());
    let Some(Predecessor::PriorControl(prior)) = value.predecessor.as_mut() else {
        unreachable!()
    };
    prior.object_version_id = Bytes::from(vec![b'v'; 1_025]);
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = receipt();
    let identity = value.identity.as_ref().unwrap();
    let event_result_key = format!(
        "prod/v2/repositories/by-id/{}/g{:016x}/events/results/{}.pb",
        hex::encode(&identity.repository_uuid),
        identity.generation,
        hex::encode(&value.mutation_id)
    );
    value.event_obligation = Some(EventObligation::Event(EventObligationValue {
        event_id: value.mutation_id.clone(),
        wal_sequence: value.wal_sequence,
        subscriber_set_digest: Bytes::from(vec![0x66; 32]),
        result_key: Bytes::from(event_result_key),
        subscriber_bodies: vec![
            EventSubscriberBody {
                digest: Bytes::from(vec![1; 32]),
                size: 1,
            },
            EventSubscriberBody {
                digest: Bytes::from(vec![2; 32]),
                size: 1,
            },
        ],
    }));
    assert!(encode_mutation_receipt(&value).is_ok());
    match value.event_obligation.as_mut() {
        Some(EventObligation::Event(event)) => event.subscriber_bodies.swap(0, 1),
        _ => unreachable!(),
    }
    assert!(encode_mutation_receipt(&value).is_err());
    match value.event_obligation.as_mut() {
        Some(EventObligation::Event(event)) => {
            event.subscriber_bodies.swap(0, 1);
            event.result_key = Bytes::from_static(b"prod/v2/events/results/arbitrary.pb");
        }
        _ => unreachable!(),
    }
    assert!(encode_mutation_receipt(&value).is_err());

    let mut value = catalog(ReceiptState::Settled, Some(result_target()));
    value.rows[0].result.as_mut().unwrap().object_version_id = Bytes::from(vec![b'v'; 1_024]);
    assert!(encode_receipt_catalog(&value).is_ok());
    value.rows[0].result.as_mut().unwrap().object_version_id = Bytes::from(vec![b'v'; 1_025]);
    assert!(encode_receipt_catalog(&value).is_err());
}

#[test]
fn obligation_keys_and_receipt_result_sizes_are_exact() {
    let mut capacity = capacity_receipt();
    let shard = Sha256::digest(&capacity.identity.as_ref().unwrap().repository_uuid)[0];
    assert!(encode_mutation_receipt(&capacity).is_ok());
    let Some(CapacityObligation::Capacity(binding)) = capacity.capacity_obligation.as_mut() else {
        unreachable!()
    };
    binding.shard_key = Bytes::from(format!("v2/capacity/shards/{shard:02x}/capacity_shard.pb"));
    assert!(encode_mutation_receipt(&capacity).is_ok());
    let Some(CapacityObligation::Capacity(binding)) = capacity.capacity_obligation.as_mut() else {
        unreachable!()
    };
    binding.shard_key = Bytes::from(format!(
        "prod/v2/capacity/shards/{:02x}/capacity_shard.pb",
        shard.wrapping_add(1)
    ));
    assert!(encode_mutation_receipt(&capacity).is_err());

    let mut event = event_receipt();
    assert!(encode_mutation_receipt(&event).is_ok());
    let Some(EventObligation::Event(binding)) = event.event_obligation.as_mut() else {
        unreachable!()
    };
    binding.result_key = Bytes::from(format!(
        "v2/repositories/by-id/{}/g{:016x}/events/results/{}.pb",
        hex::encode(&event.identity.as_ref().unwrap().repository_uuid),
        event.identity.as_ref().unwrap().generation,
        hex::encode(&binding.event_id)
    ));
    assert!(encode_mutation_receipt(&event).is_ok());
    let Some(EventObligation::Event(binding)) = event.event_obligation.as_mut() else {
        unreachable!()
    };
    binding.result_key = Bytes::from(format!(
        "prod/v2/repositories/by-id/{}/g{:016x}/events/results/{}.pb",
        hex::encode(&event.identity.as_ref().unwrap().repository_uuid),
        event.identity.as_ref().unwrap().generation,
        "01890f4776447b8b9d7a876543210afe"
    ));
    assert!(encode_mutation_receipt(&event).is_err());

    let mut settled = catalog(ReceiptState::Settled, Some(result_target()));
    settled.rows[0].result.as_mut().unwrap().size = 0;
    assert!(encode_receipt_catalog(&settled).is_err());
    settled.rows[0].result.as_mut().unwrap().size = MAX_MUTATION_RESULT_BYTES as u64;
    assert!(encode_receipt_catalog(&settled).is_ok());
    settled.rows[0].result.as_mut().unwrap().size = MAX_MUTATION_RESULT_BYTES as u64 + 1;
    assert!(encode_receipt_catalog(&settled).is_err());
}

fn receipt() -> MutationReceipt {
    let control = support::sample_control();
    MutationReceipt {
        schema_version: 1,
        identity: control.identity,
        mutation_id: Bytes::from(hex::decode(MUTATION_ID).unwrap()),
        kind: MutationKind::Settings as i32,
        writer_epoch: 1,
        wal_sequence: 1,
        request_digest: Bytes::from(vec![0x44; 32]),
        immutable_dependency_digests: vec![Bytes::from(vec![0x55; 32])],
        predecessor: Some(Predecessor::PriorControl(PriorControlBinding {
            cas_token: Bytes::from_static(b"cas-1"),
            object_version_id: Bytes::from_static(b"version-1"),
        })),
        capacity_obligation: Some(CapacityObligation::NoCapacity(NoCapacityObligation {})),
        event_obligation: Some(EventObligation::NoEvent(NoEventObligation {})),
    }
}

fn capacity_receipt() -> MutationReceipt {
    let mut receipt = receipt();
    let shard = Sha256::digest(&receipt.identity.as_ref().unwrap().repository_uuid)[0];
    receipt.capacity_obligation = Some(CapacityObligation::Capacity(CapacityObligationValue {
        allocation_epoch: 1,
        shard_key: Bytes::from(format!(
            "prod/v2/capacity/shards/{shard:02x}/capacity_shard.pb"
        )),
        shard_object_version_id: Bytes::from_static(b"capacity-v1"),
        reservation_id: receipt.mutation_id.clone(),
        tenant_slice_bytes: 1,
        mutation_id: receipt.mutation_id.clone(),
        byte_count: 1,
    }));
    receipt
}

fn event_receipt() -> MutationReceipt {
    let mut receipt = receipt();
    let identity = receipt.identity.as_ref().unwrap();
    receipt.event_obligation = Some(EventObligation::Event(EventObligationValue {
        event_id: receipt.mutation_id.clone(),
        wal_sequence: receipt.wal_sequence,
        subscriber_set_digest: Bytes::from(vec![0x66; 32]),
        result_key: Bytes::from(format!(
            "prod/v2/repositories/by-id/{}/g{:016x}/events/results/{}.pb",
            hex::encode(&identity.repository_uuid),
            identity.generation,
            hex::encode(&receipt.mutation_id)
        )),
        subscriber_bodies: vec![EventSubscriberBody {
            digest: Bytes::from(vec![0x77; 32]),
            size: 1,
        }],
    }));
    receipt
}

fn result() -> MutationResult {
    let control = support::sample_control();
    MutationResult {
        schema_version: 1,
        identity: control.identity,
        mutation_id: Bytes::from(hex::decode(MUTATION_ID).unwrap()),
        kind: MutationKind::Settings as i32,
        landed_control: Some(LandedControlRef {
            repo_control_key: control.repo_control_key,
            object_version_id: Bytes::from_static(b"version-2"),
            digest: Bytes::from(vec![0x66; 32]),
            size: 4096,
        }),
        landed_control_revision: 2,
        writer_epoch: 1,
        wal_sequence: 1,
    }
}

fn catalog(state: ReceiptState, result: Option<TargetObjectRef>) -> ReceiptCatalog {
    let receipt = receipt();
    ReceiptCatalog {
        schema_version: 1,
        identity: receipt.identity.clone(),
        rows: vec![ReceiptCatalogRow {
            mutation_id: receipt.mutation_id.clone(),
            state: state as i32,
            receipt: Some(receipt),
            result,
            settlement_mutation_id: if state == ReceiptState::Settled {
                Bytes::from(hex::decode("01890f4776447b8b9d7a876543210aff").unwrap())
            } else {
                Bytes::new()
            },
        }],
    }
}

fn result_target() -> TargetObjectRef {
    let control = support::sample_control();
    let identity = control.identity.unwrap();
    TargetObjectRef {
        identity: Some(identity.clone()),
        key: Bytes::from(format!(
            "prod/v2/repositories/by-id/{}/g{:016x}/receipts/results/{MUTATION_ID}.pb",
            hex::encode(&identity.repository_uuid),
            identity.generation
        )),
        object_version_id: Bytes::from_static(b"result-version-1"),
        digest: Bytes::from(vec![0x77; 32]),
        size: 512,
    }
}

fn assert_catalog_root(catalog: &ReceiptCatalog, encoded: &[u8]) {
    let identity = catalog.identity.clone().unwrap();
    let digest = ProtobufObjectDigest::of_exact_protobuf(encoded);
    let key = format!(
        "prod/v2/repositories/by-id/{}/g{:016x}/catalogs/receipt/{}.pb",
        hex::encode(&identity.repository_uuid),
        identity.generation,
        digest.lower_hex()
    );
    let root = CatalogRoot {
        kind: CatalogKind::Receipt as i32,
        object: Some(TargetObjectRef {
            identity: Some(identity),
            key: Bytes::from(key.clone()),
            object_version_id: Bytes::from_static(b"catalog-version-1"),
            digest: Bytes::copy_from_slice(digest.as_bytes()),
            size: encoded.len() as u64,
        }),
        depth: 1,
        node_count: 1,
        item_count: catalog.rows.len() as u64,
        total_encoded_bytes: encoded.len() as u64,
    };
    assert_eq!(root.kind, CatalogKind::Receipt as i32);
    assert_eq!(root.depth, 1);
    assert_eq!(root.node_count, 1);
    assert_eq!(root.item_count, 1);
    assert_eq!(root.total_encoded_bytes, encoded.len() as u64);
    let object = root.object.unwrap();
    assert_eq!(object.key.as_ref(), key.as_bytes());
    assert_eq!(object.digest.as_ref(), digest.as_bytes());
    assert_eq!(object.size, encoded.len() as u64);
}

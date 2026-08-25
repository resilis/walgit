use walgit_proto::v2::{
    digests::{
        ProtobufObjectDigest, RawPayloadDigest, SignedEnvelopeDigest, StoredDigestKind,
        VerificationRingDigest,
    },
    keys::V2KeyKind,
};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn stored_digest_types_hash_the_exact_supplied_bytes() {
    assert_eq!(
        ProtobufObjectDigest::of_exact_protobuf(b"").lower_hex(),
        EMPTY_SHA256
    );
    assert_eq!(
        RawPayloadDigest::of_exact_payload(b"").lower_hex(),
        EMPTY_SHA256
    );
    assert_eq!(
        SignedEnvelopeDigest::of_exact_cose_sign1(b"").lower_hex(),
        EMPTY_SHA256
    );
    assert_eq!(
        VerificationRingDigest::of_exact_ring_cose_sign1(b"").lower_hex(),
        EMPTY_SHA256
    );
}

#[test]
fn every_closed_key_kind_selects_one_digest_preimage() {
    assert_eq!(
        V2KeyKind::RepoControl.digest_kind(),
        StoredDigestKind::ProtobufObject
    );
    assert_eq!(
        V2KeyKind::GitPack.digest_kind(),
        StoredDigestKind::RawPayload
    );
    assert_eq!(
        V2KeyKind::VerificationKeyRing.digest_kind(),
        StoredDigestKind::VerificationRing
    );
}

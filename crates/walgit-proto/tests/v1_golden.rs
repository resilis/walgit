use prost::Message;
use walgit_proto::v1::Manifest;

#[test]
fn v1_manifest_wire_bytes_remain_stable() {
    let manifest = Manifest {
        format_version: 1,
        repo: "acme/r".into(),
        object_format: "sha1".into(),
        head_seq: 3,
        revision: 1,
        ..Default::default()
    };
    let expected = hex::decode("0801120661636d652f721a047368613120035801").unwrap();
    assert_eq!(manifest.encode_to_vec(), expected);
    assert_eq!(Manifest::decode(expected.as_slice()).unwrap(), manifest);
}

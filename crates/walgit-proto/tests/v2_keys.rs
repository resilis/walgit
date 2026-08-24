use walgit_proto::v2::{
    CatalogKind,
    keys::{
        CanonicalPathDigest, DeploymentPrefix, KeyError, RepositoryKeyIdentity, RoutingDigest,
        V2KeyKind, parse_key, repo_control_key,
    },
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UUID: &str = "01890f4776447b8b9d7a876543210abd";
const UUID_BYTES: [u8; 16] = [
    0x01, 0x89, 0x0f, 0x47, 0x76, 0x44, 0x7b, 0x8b, 0x9d, 0x7a, 0x87, 0x65, 0x43, 0x21, 0x0a, 0xbd,
];
const SEQUENCE: &str = "0000000000000001";

#[test]
fn canonical_and_routing_digest_vectors_are_distinct() {
    let path = b"tenant/project/repo";
    assert_eq!(
        CanonicalPathDigest::of(path).lower_hex(),
        "04b769541bf0e8952bdfb4977f0a0139c5a41d024caeacf621a03a40ac1aeb51"
    );
    assert_eq!(
        RoutingDigest::of(path).unwrap().lower_hex(),
        "4e1a43dcf3483848180c87b6c6fa2ef537b875dd215a76cf1fb6707a3e9c981f"
    );
    assert_ne!(
        CanonicalPathDigest::of(path).as_bytes(),
        RoutingDigest::of(path).unwrap().as_bytes()
    );
}

#[test]
fn deployment_prefix_and_direct_control_key_are_exact() {
    let prefix = DeploymentPrefix::parse("prod/eu-1/").unwrap();
    let routing = RoutingDigest::from_bytes([0xab; 32]);
    assert_eq!(
        repo_control_key(&prefix, routing).unwrap(),
        format!(
            "prod/eu-1/v2/repositories/by-path/{}/repo_control.pb",
            "ab".repeat(32)
        )
    );
    let max_segment = format!("a{}", "b".repeat(62));
    let max_prefix = format!("{0}/{0}/{0}/{0}/", max_segment);
    assert_eq!(max_prefix.len(), 256);
    DeploymentPrefix::parse(max_prefix).unwrap();
    for invalid in ["Prod/", "prod", "prod//", "./", "a/b/c/d/e/"] {
        assert_eq!(
            DeploymentPrefix::parse(invalid).unwrap_err(),
            KeyError::InvalidDeploymentPrefix
        );
    }
}

#[test]
fn every_repository_leaf_has_one_closed_kind() {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let root = format!("prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/");
    let cases = [
        (
            format!("catalogs/pack/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Pack),
        ),
        (
            format!("catalogs/ref-delta/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::RefDelta),
        ),
        (
            format!("catalogs/grant/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Grant),
        ),
        (
            format!("catalogs/receipt/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Receipt),
        ),
        (
            format!("catalogs/event/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Event),
        ),
        (
            format!("catalogs/pin/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Pin),
        ),
        (
            format!("catalogs/git-ownership/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::GitOwnership),
        ),
        (
            format!("catalogs/lfs-ownership/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::LfsOwnership),
        ),
        (
            format!("catalogs/bundle/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Bundle),
        ),
        (
            format!("catalogs/recovery/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Recovery),
        ),
        (
            format!("catalogs/audit/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Audit),
        ),
        (
            format!("catalogs/reclamation/{DIGEST}.pb"),
            V2KeyKind::Catalog(CatalogKind::Reclamation),
        ),
        (
            format!("receipts/results/{UUID}.pb"),
            V2KeyKind::ReceiptResult,
        ),
        (format!("events/results/{UUID}.pb"), V2KeyKind::EventResult),
        (
            format!("events/archive/{UUID}/{DIGEST}.pb"),
            V2KeyKind::EventArchive,
        ),
        (
            format!("events/watermarks/{SEQUENCE}/{DIGEST}.pb"),
            V2KeyKind::EventArchiveWatermark,
        ),
        (
            format!("checkpoints/{SEQUENCE}/{DIGEST}.pb"),
            V2KeyKind::Checkpoint,
        ),
        (
            format!("recovery/{UUID}/journal/{SEQUENCE}.pb"),
            V2KeyKind::RecoveryJournal,
        ),
        (
            format!("recovery/{UUID}/mapping/{SEQUENCE}.pb"),
            V2KeyKind::RecoveryMapping,
        ),
        (
            format!("recovery/{UUID}/catalog/{SEQUENCE}.pb"),
            V2KeyKind::RecoveryCatalog,
        ),
        (
            format!("recovery/{UUID}/payload/{SEQUENCE}.pb"),
            V2KeyKind::RecoveryPayloadReference,
        ),
        (format!("git/packs/{DIGEST}.pack"), V2KeyKind::GitPack),
        (format!("lfs/{DIGEST}.bin"), V2KeyKind::LfsObject),
        (format!("bundles/{DIGEST}.bundle"), V2KeyKind::Bundle),
        (
            format!("tmp/git-pack-upload/{UUID}/{SEQUENCE}.bin"),
            V2KeyKind::TemporaryGitPackUpload,
        ),
        (
            format!("tmp/lfs-upload/{UUID}/{SEQUENCE}.bin"),
            V2KeyKind::TemporaryLfsUpload,
        ),
        (
            format!("tmp/bundle-upload/{UUID}/{SEQUENCE}.bin"),
            V2KeyKind::TemporaryBundleUpload,
        ),
        (
            format!("tmp/catalog-candidate/{UUID}/{SEQUENCE}.pb"),
            V2KeyKind::TemporaryCatalogCandidate,
        ),
        (
            format!("tmp/recovery-copy/{UUID}/{SEQUENCE}.bin"),
            V2KeyKind::TemporaryRecoveryCopy,
        ),
    ];
    for (suffix, expected) in cases {
        let parsed = parse_key(&prefix, format!("{root}{suffix}").as_bytes()).unwrap();
        assert_eq!(parsed.kind, expected, "{suffix}");
        assert_eq!(
            parsed.repository,
            Some(RepositoryKeyIdentity {
                repository_uuid: UUID_BYTES,
                generation: 1,
            })
        );
    }
}

#[test]
fn every_global_leaf_has_one_closed_kind() {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let cases = [
        (
            "v2/control/cutover_control.pb".to_string(),
            V2KeyKind::CutoverControl,
        ),
        (
            "v2/control/credential_control.pb".to_string(),
            V2KeyKind::CredentialControl,
        ),
        (
            "v2/control/bucket_admin_control.pb".to_string(),
            V2KeyKind::BucketAdminControl,
        ),
        (
            format!("v2/control/key-rings/{DIGEST}.cose"),
            V2KeyKind::VerificationKeyRing,
        ),
        (
            "v2/capacity/capacity_control.pb".to_string(),
            V2KeyKind::CapacityControl,
        ),
        (
            format!("v2/capacity/catalogs/tenant/{DIGEST}.pb"),
            V2KeyKind::TenantCapacityCatalog,
        ),
        (
            "v2/capacity/shards/ff/capacity_shard.pb".to_string(),
            V2KeyKind::CapacityShard,
        ),
        (
            "v2/recovery/recovery_control.pb".to_string(),
            V2KeyKind::RecoveryControl,
        ),
        (
            format!("v2/leases/by-id/{UUID}/g{SEQUENCE}/writer_lease.pb"),
            V2KeyKind::WriterLease,
        ),
        (
            format!("v2/host_control/by-path/{DIGEST}.pb"),
            V2KeyKind::HostByPath,
        ),
        (
            format!("v2/host_control/by-id/{UUID}/g{SEQUENCE}.pb"),
            V2KeyKind::HostByIdentity,
        ),
    ];
    for (suffix, expected) in cases {
        assert_eq!(
            parse_key(&prefix, format!("prod/{suffix}").as_bytes())
                .unwrap()
                .kind,
            expected,
            "{suffix}"
        );
    }
}

#[test]
fn rejects_unlisted_ambiguous_or_noncanonical_keys() {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let invalid = [
        format!("prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/catalogs/unknown/{DIGEST}.pb"),
        format!(
            "prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/git/packs/{}.pack",
            DIGEST.to_uppercase()
        ),
        format!("prod/v2/repositories/by-id/{UUID}/g1/git/packs/{DIGEST}.pack"),
        format!("prod/v2/repositories/by-id/{UUID}/g0000000000000000/git/packs/{DIGEST}.pack"),
        format!("prod/v2/repositories/by-id/{UUID}/g0000000000000002/git/packs/{DIGEST}.pack"),
        format!("prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/git/packs/{DIGEST}.idx"),
        format!(
            "prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/receipts/results/11111111111111111111111111111111.pb"
        ),
        "prod/v2/control/other.pb".to_string(),
        "other/v2/control/cutover_control.pb".to_string(),
    ];
    for key in invalid {
        assert!(
            parse_key(&prefix, key.as_bytes()).is_err(),
            "accepted {key}"
        );
    }
}

#[test]
fn repository_root_is_uuid_and_fixed_generation_hex() {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let identity = RepositoryKeyIdentity {
        repository_uuid: UUID_BYTES,
        generation: 1,
    };
    assert_eq!(
        identity.root(&prefix).unwrap(),
        format!("prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}/")
    );
    assert_eq!(
        RepositoryKeyIdentity {
            repository_uuid: UUID_BYTES,
            generation: 2,
        }
        .root(&prefix)
        .unwrap_err(),
        KeyError::InvalidGeneration
    );
}

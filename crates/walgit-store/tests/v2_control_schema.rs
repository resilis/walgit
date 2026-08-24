use bytes::Bytes;
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, GrantRole, InlineGrants, InlinePackRoots, Lifecycle,
    ObjectFormat, QuotaState, ReclamationPhase, ReclamationState, RepoControl, RepositoryGrant,
    RepositoryIdentity, Visibility, WalState, WriterFence, decode_repo_control,
    encode_repo_control,
    keys::{CanonicalPathDigest, DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::{GrantRepresentation, PackRepresentation},
};
use walgit_store::{ObjectStoreExt, PutMode, memory::MemoryStore};

#[tokio::test]
async fn only_the_control_cas_changes_visible_repository_semantics() {
    let store = MemoryStore::new();
    let mut control = sample_control();
    let key = std::str::from_utf8(&control.repo_control_key).unwrap();
    let first_bytes = encode_repo_control(&control).unwrap();
    let first = store
        .put_bytes(key, first_bytes.clone(), PutMode::Create)
        .await
        .unwrap();
    let first_version = first.object_version_id.clone().unwrap();
    assert_ne!(first.version.as_str(), first_version.as_str());

    let candidate_key = format!(
        "prod/v2/repositories/by-id/{}/g0000000000000001/catalogs/audit/{}.pb",
        "01890f4776447b8b9d7a876543210abd",
        "aa".repeat(32)
    );
    store
        .put_bytes(
            &candidate_key,
            b"unpublished candidate".to_vec(),
            PutMode::Create,
        )
        .await
        .unwrap();
    let (_, current_bytes) = store.get_bytes(key).await.unwrap().unwrap();
    assert_eq!(
        decode_repo_control(&current_bytes)
            .unwrap()
            .control_revision,
        1
    );

    control.control_revision = 2;
    control.last_internal_mutation_id =
        Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abf").unwrap());
    let second = store
        .put_bytes(
            key,
            encode_repo_control(&control).unwrap(),
            PutMode::Update(first.version.clone()),
        )
        .await
        .unwrap();
    assert_ne!(second.version, first.version);
    assert_ne!(second.object_version_id.as_ref(), Some(&first_version));

    let historical = store
        .get_version(key, &first_version, None)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(historical.as_ref(), first_bytes.as_slice());
    assert_eq!(
        decode_repo_control(&historical).unwrap().control_revision,
        1
    );
    let (_, current_bytes) = store.get_bytes(key).await.unwrap().unwrap();
    assert_eq!(
        decode_repo_control(&current_bytes)
            .unwrap()
            .control_revision,
        2
    );
}

fn sample_control() -> RepoControl {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let path = Bytes::from_static(b"tenant/project/repo");
    let canonical = CanonicalPathDigest::of(&path);
    let routing = RoutingDigest::of(&path).unwrap();
    RepoControl {
        schema_version: 2,
        identity: Some(RepositoryIdentity {
            tenant_id: Bytes::from_static(b"tenant-1"),
            project_id: Bytes::from_static(b"project-1"),
            repository_uuid: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abd").unwrap()),
            generation: 1,
            canonical_path: path,
            canonical_path_digest: Bytes::copy_from_slice(canonical.as_bytes()),
            routing_digest: Bytes::copy_from_slice(routing.as_bytes()),
        }),
        create_intent_id: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abc").unwrap()),
        create_intent_digest: Bytes::from(
            hex::decode("25c45a88b53645d3ce1bef07ee554a616c0ab425efbc7c95a8387914156912a6")
                .unwrap(),
        ),
        create_intent_cose: Bytes::from_static(b"cose"),
        repo_control_key: Bytes::from(repo_control_key(&prefix, routing).unwrap()),
        object_format: ObjectFormat::Sha1 as i32,
        lifecycle: Lifecycle::Active as i32,
        visibility: Visibility::Private as i32,
        control_revision: 1,
        cutover_generation: 1,
        writer: Some(WriterFence {
            holder: Bytes::from_static(b"writer-1"),
            epoch: 1,
        }),
        authorization_epoch: 1,
        quota: Some(QuotaState {
            logical_quota_bytes: 1_000_000,
            charged_git_bytes: 0,
            charged_lfs_bytes: 0,
        }),
        capacity: Some(CapacityBinding {
            allocation_epoch: 1,
            shard: 193,
            shard_key: Bytes::from_static(b"prod/v2/capacity/shards/c1/capacity_shard.pb"),
            shard_object_version_id: Bytes::from_static(b"capacity-version-1"),
            shard_budget_bytes: 2_000_000,
            tenant_slice_bytes: 1_000_000,
            shard_digest: Bytes::from(vec![0x34; 32]),
            shard_size: 4096,
        }),
        bucket_safety: Some(BucketSafetyBinding {
            epoch: 1,
            safety_digest: Bytes::from(vec![0x33; 32]),
        }),
        inline_settings: Bytes::new(),
        inline_policy: Bytes::new(),
        wal: Some(WalState::default()),
        reclamation: Some(ReclamationState {
            phase: ReclamationPhase::Idle as i32,
            pass_objects: 0,
            pass_bytes: 0,
        }),
        last_internal_mutation_id: Bytes::from(
            hex::decode("01890f4776447b8b9d7a876543210abe").unwrap(),
        ),
        receipt_catalog: None,
        event_catalog: None,
        pin_catalog: None,
        git_ownership_catalog: None,
        lfs_ownership_catalog: None,
        bundle_catalog: None,
        recovery_catalog: None,
        audit_catalog: None,
        reclamation_catalog: None,
        pack_representation: Some(PackRepresentation::InlinePacks(InlinePackRoots {
            roots: Vec::new(),
        })),
        grant_representation: Some(GrantRepresentation::InlineGrants(InlineGrants {
            grants: vec![RepositoryGrant {
                issuer: Bytes::from_static(b"cloud-core"),
                subject: Bytes::from_static(b"admin-1"),
                role: GrantRole::Administrator as i32,
            }],
        })),
    }
}

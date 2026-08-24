use bytes::Bytes;
use sha2::{Digest, Sha256};
use walgit_proto::v2::{
    BucketSafetyBinding, CapacityBinding, GrantRole, InlineGrants, InlinePackRoots, Lifecycle,
    ObjectFormat, QuotaState, ReclamationPhase, ReclamationState, RepoControl, RepositoryGrant,
    RepositoryIdentity, Visibility, WalState, WriterFence,
    keys::{CanonicalPathDigest, DeploymentPrefix, RoutingDigest, repo_control_key},
    repo_control::{GrantRepresentation, PackRepresentation},
};

pub fn sample_control() -> RepoControl {
    let prefix = DeploymentPrefix::parse("prod/").unwrap();
    let canonical_path = Bytes::from_static(b"tenant/project/repo");
    let canonical = CanonicalPathDigest::of(&canonical_path);
    let routing = RoutingDigest::of(&canonical_path).unwrap();
    let identity = RepositoryIdentity {
        tenant_id: Bytes::from_static(b"tenant-1"),
        project_id: Bytes::from_static(b"project-1"),
        repository_uuid: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abd").unwrap()),
        generation: 1,
        canonical_path,
        canonical_path_digest: Bytes::copy_from_slice(canonical.as_bytes()),
        routing_digest: Bytes::copy_from_slice(routing.as_bytes()),
    };
    let create_intent_cose = Bytes::from_static(b"deterministic-cose-sign1");
    let create_intent_digest = Bytes::copy_from_slice(&Sha256::digest(&create_intent_cose));
    RepoControl {
        schema_version: 2,
        identity: Some(identity),
        create_intent_id: Bytes::from(hex::decode("01890f4776447b8b9d7a876543210abc").unwrap()),
        create_intent_digest,
        create_intent_cose,
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
        wal: Some(WalState {
            head_sequence: 0,
            minimum_sequence: 0,
            checkpoint: None,
            tail: Vec::new(),
        }),
        reclamation: Some(ReclamationState {
            phase: ReclamationPhase::Idle as i32,
            cursor: Bytes::new(),
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

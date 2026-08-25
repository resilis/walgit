//! Closed store-data traffic classification shared by provider backends.

use walgit_proto::v2::keys::{DeploymentPrefix, V2KeyKind, parse_key};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataTraffic {
    Control,
    Bulk,
}

pub(crate) fn normalized_store_prefix(prefix: &str) -> String {
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    }
}

/// Classify one physical object key for a byte-moving operation.
///
/// Unknown, malformed, future, and wrong-prefix keys are bulk. A new control
/// encoding must be added to the closed grammar before it can use the control
/// transport. Range reads are forced to bulk by each provider before calling
/// this classifier.
pub(crate) fn classify_data_key(key: &str, physical_prefix: &str) -> DataTraffic {
    let Some(relative) = key.strip_prefix(physical_prefix) else {
        return DataTraffic::Bulk;
    };

    if let Ok(prefix) = DeploymentPrefix::parse(physical_prefix.to_owned())
        && let Ok(parsed) = parse_key(&prefix, key.as_bytes())
    {
        return match parsed.kind {
            V2KeyKind::GitPack
            | V2KeyKind::LfsObject
            | V2KeyKind::Bundle
            | V2KeyKind::TemporaryGitPackUpload
            | V2KeyKind::TemporaryLfsUpload
            | V2KeyKind::TemporaryBundleUpload
            | V2KeyKind::TemporaryRecoveryCopy => DataTraffic::Bulk,
            V2KeyKind::RepoControl
            | V2KeyKind::Catalog(_)
            | V2KeyKind::ReceiptResult
            | V2KeyKind::EventResult
            | V2KeyKind::EventArchive
            | V2KeyKind::EventArchiveWatermark
            | V2KeyKind::Checkpoint
            | V2KeyKind::RecoveryJournal
            | V2KeyKind::RecoveryMapping
            | V2KeyKind::RecoveryCatalog
            | V2KeyKind::RecoveryPayloadReference
            | V2KeyKind::TemporaryCatalogCandidate
            | V2KeyKind::CutoverControl
            | V2KeyKind::CredentialControl
            | V2KeyKind::BucketAdminControl
            | V2KeyKind::VerificationKeyRing
            | V2KeyKind::CapacityControl
            | V2KeyKind::TenantCapacityCatalog
            | V2KeyKind::CapacityShard
            | V2KeyKind::RecoveryControl
            | V2KeyKind::WriterLease
            | V2KeyKind::HostByPath
            | V2KeyKind::HostByIdentity => DataTraffic::Control,
        };
    }

    if is_v1_control_key(relative) {
        DataTraffic::Control
    } else {
        DataTraffic::Bulk
    }
}

fn is_v1_control_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').collect();
    match parts.as_slice() {
        ["meta", "repos.pb"] => true,
        ["maintain", leaf] => control_leaf(leaf, ".pb"),
        [
            "repos",
            owner,
            repo,
            "manifest.pb" | "fsck.pb" | "policy.json",
        ] => repository_parts(owner, repo),
        ["repos", owner, repo, "log", leaf] => {
            repository_parts(owner, repo) && sequence_leaf(leaf, ".pb")
        }
        [
            "repos",
            owner,
            repo,
            "checkpoints",
            sequence,
            "checkpoint.pb" | "refs.pb",
        ] => repository_parts(owner, repo) && lower_hex(sequence, 16),
        ["repos", owner, repo, "leases", leaf] => {
            repository_parts(owner, repo) && control_leaf(leaf, ".pb")
        }
        ["repos", owner, repo, "bundles", "list.pb"] => repository_parts(owner, repo),
        ["repos", owner, repo, "cache", "api", "v1", leaf] => {
            repository_parts(owner, repo)
                && leaf
                    .strip_suffix(".json")
                    .is_some_and(|digest| lower_hex(digest, 40))
        }
        _ => false,
    }
}

fn repository_parts(owner: &str, repo: &str) -> bool {
    !owner.is_empty() && !repo.is_empty()
}

fn control_leaf(leaf: &str, suffix: &str) -> bool {
    leaf.strip_suffix(suffix)
        .is_some_and(|stem| !stem.is_empty())
}

fn sequence_leaf(leaf: &str, suffix: &str) -> bool {
    leaf.strip_suffix(suffix)
        .is_some_and(|sequence| lower_hex(sequence, 16))
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const UUID: &str = "018f4b2a7c1d7e89a123456789abcdef";
    const SEQUENCE: &str = "0000000000000001";

    #[test]
    fn v1_control_grammar_is_closed_and_unknown_defaults_bulk() {
        for key in [
            "meta/repos.pb",
            "maintain/host-1.pb",
            "repos/o/r/manifest.pb",
            "repos/o/r/fsck.pb",
            "repos/o/r/policy.json",
            "repos/o/r/log/0000000000000001.pb",
            "repos/o/r/checkpoints/0000000000000001/checkpoint.pb",
            "repos/o/r/checkpoints/0000000000000001/refs.pb",
            "repos/o/r/leases/compact.pb",
            "repos/o/r/bundles/list.pb",
            "repos/o/r/cache/api/v1/0123456789abcdef0123456789abcdef01234567.json",
        ] {
            assert_eq!(classify_data_key(key, ""), DataTraffic::Control, "{key}");
            assert_eq!(
                classify_data_key(&format!("prod/{key}"), "prod/"),
                DataTraffic::Control,
                "prefixed {key}"
            );
        }

        for key in [
            "repos/o/r/wal/abc.pack",
            "repos/o/r/wal/abc.idx",
            "repos/o/r/wal/abc.rev",
            "repos/o/r/wal/abc.bitmap",
            "repos/o/r/wal/abc.commit-graph",
            "repos/o/r/checkpoints/0000000000000001/abc.bundle",
            "repos/o/r/bundles/weekly/abc.bundle",
            "repos/o/r/lfs/objects/ab/cd/abcd",
            "repos/o/r/future.pb",
            "repos/o/r/cache/api/v1/unknown.bin",
            "repos/o/r/cache/api/v1/tree/0123456789abcdef0123456789abcdef01234567.json",
            "future/control-looking.pb",
            "",
        ] {
            assert_eq!(classify_data_key(key, ""), DataTraffic::Bulk, "{key}");
        }
        assert_eq!(
            classify_data_key("other/repos/o/r/manifest.pb", "prod/"),
            DataTraffic::Bulk
        );
    }

    #[test]
    fn every_frozen_v2_raw_kind_is_bulk_and_control_kind_is_control() {
        let root = format!("prod/v2/repositories/by-id/{UUID}/g{SEQUENCE}");
        let control = [
            format!("prod/v2/repositories/by-path/{DIGEST}/repo_control.pb"),
            format!("{root}/catalogs/pack/{DIGEST}.pb"),
            format!("{root}/receipts/results/018f4b2a7c1d7e89a123456789abcdef.pb"),
            format!("{root}/events/results/018f4b2a7c1d7e89a123456789abcdef.pb"),
            format!("{root}/checkpoints/{SEQUENCE}/{DIGEST}.pb"),
            format!("{root}/tmp/catalog-candidate/{UUID}/{SEQUENCE}.pb"),
            "prod/v2/control/cutover_control.pb".into(),
            format!("prod/v2/control/key-rings/{DIGEST}.cose"),
            "prod/v2/capacity/capacity_control.pb".into(),
            format!("prod/v2/leases/by-id/{UUID}/g{SEQUENCE}/writer_lease.pb"),
        ];
        for key in control {
            assert_eq!(
                classify_data_key(&key, "prod/"),
                DataTraffic::Control,
                "{key}"
            );
        }

        for key in [
            format!("{root}/git/packs/{DIGEST}.pack"),
            format!("{root}/lfs/{DIGEST}.bin"),
            format!("{root}/bundles/{DIGEST}.bundle"),
            format!("{root}/tmp/git-pack-upload/{UUID}/{SEQUENCE}.bin"),
            format!("{root}/tmp/lfs-upload/{UUID}/{SEQUENCE}.bin"),
            format!("{root}/tmp/bundle-upload/{UUID}/{SEQUENCE}.bin"),
            format!("{root}/tmp/recovery-copy/{UUID}/{SEQUENCE}.bin"),
        ] {
            assert_eq!(classify_data_key(&key, "prod/"), DataTraffic::Bulk, "{key}");
        }
    }

    #[test]
    fn malformed_or_future_v2_keys_are_bulk() {
        for key in [
            "prod/v2/future/control.pb",
            "prod/v2/repositories/by-path/not-a-digest/repo_control.pb",
            "prod/v2/repositories/by-id/018f4b2a7c1d7e89a123456789abcdef/g0000000000000001/git/packs/future.part",
            "prod//v2/control/cutover_control.pb",
        ] {
            assert_eq!(classify_data_key(key, "prod/"), DataTraffic::Bulk, "{key}");
        }
    }
}

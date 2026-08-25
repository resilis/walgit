# Behavior preservation matrix

Status: traceable preservation matrix for production gate PR1. The named
commands are individually executable, but this change does not yet provide one
matrix-wide aggregator. A row is preserved only when its command passes or the
named evidence has been reviewed. Later gates can replace an evidence-only row
with a dedicated test. This matrix does not make untested provider claims.

Run the repository-wide checks with `just warnings`, `just test`, `just e2e`,
and `just ci`. Run `just test-s3` against the local disposable store. Run
`just test-s3-provider` against the exact selected S3-compatible provider only
after setting
the required `WALGIT_TEST_S3_*` environment variables for an approved
disposable bucket and unique prefix. Run
`just test-gcs <bucket>` only against an approved disposable bucket and unique
prefix for development or non-production evidence. Production exact-provider
primitive conformance runs only against the selected S3-compatible provider and
is a PR2 merge gate. Full-scale recovery and production-candidate evidence
remain later PR3 gates. PR1 does not implement the V5.9 control, identity,
signing, event, recovery, or cutover contracts.

| Surface | Owner | Entrypoint | PR1 preservation decision | Test or evidence |
|---|---|---|---|---|
| SHA-1 repositories | `walgit-git` | `LocalRepo`, smart HTTP | Preserve | `just test`; `tests/e2e.sh` |
| SHA-256 repositories | `walgit-git` | `ObjectFormat::Sha256` | Preserve | `cargo test -p walgit-git`; `crates/walgit-server/tests/e2e.rs` |
| Smart HTTP v0/v2 | `walgit-server` / `walgit-git` | `info/refs`, upload-pack, receive-pack | Preserve protocol and capability advertisements | `just e2e` |
| Git errors and real 401 | `walgit-server` | `smart.rs`, auth middleware | Preserve pkt-line errors and invalid-credential 401 | `just e2e`; `tests/lib-auth.sh` |
| Static `HEAD` | `walgit-server` | `static_object.rs`, Git/static routes | Preserve metadata without body | `cargo test -p walgit-server --test static_http` |
| Range, If-Range, 416 | `walgit-server` / stores | immutable static routes, `ObjectStore::get` | Preserve half-open internal ranges and HTTP static contract | `cargo test -p walgit-store --test contract`; `cargo test -p walgit-server --test static_http` |
| ETag and cache rules | server / stores | static and ref-dependent responses | Preserve strong version and immutable or SWR cache policy | `cargo test -p walgit-server --test static_http --test web_api` |
| LFS batch/basic transfer | `walgit-server` | `lfs.rs` | Preserve batch, PUT, GET, verify and 16 GiB configured limit | `just e2e`; `rg -n "16GiB|lfs" walgit.example.toml crates/walgit-server/src/lfs.rs` |
| LFS upstream/read-through | `walgit-server` | `lfs_upstream.rs` | Preserve authenticated read-through and persistence | `cargo test -p walgit-server --test lfs_upstream` |
| Receive size | `walgit-server` / store | receive-pack ingest and pack PUT | Preserve 64 GiB configured limit and streaming; no 4 GiB limit | `rg -n "64GiB|receive" walgit.example.toml crates`; S3 contract large-object plan |
| Bundle-uri | `walgit-bundle` / server | v2 command, `bundles/list`, `bundles/catchup` | Preserve clone/catch-up families and narration | `cargo test -p walgit-bundle`; `just e2e` |
| 30 GiB+ packs/bundles | bundle / store | compose, multipart PUT/copy | Preserve streaming and multipart; no local materialization or 4 GiB cap | `cargo test -p walgit-store --test contract`; exact-provider >5 GiB gate remains required |
| Upstream follow | server / Git / WAL | `follow.rs`, maintainer loop | Preserve same publish path and fast-forward rule | `cargo test -p walgit-server --test follow` |
| Mirror CLI | `walgit-cli` | `walgit mirror` | Preserve HTTP mirror behavior | `cargo test -p walgit-cli`; CLI help inspection |
| Remote reader | `walgit-wal` / Git | `remote.rs`, `upload_gix.rs` | Preserve range-backed bases and bounded cache | `cargo test -p walgit-git --test upload_gix_remote`; `cargo test -p walgit-server --test web_api` |
| Browser UI | web / server | repository SPA routes | Preserve bundled UI behavior | `cd web && pnpm run build`; `cargo test -p walgit-server --test web_ui` |
| `repos.js` IIFE SDK | web | `/repos.js` | Preserve open SDK and one API mapping | `cd web && pnpm run build`; `cargo test -p walgit-server --test static_http` |
| `repos.mjs` ESM SDK | web | `/repos.mjs` | Preserve open ESM SDK | `cd web && pnpm run build`; `cargo test -p walgit-server --test static_http` |
| Setup recipes | server | `/services/setup.json`, Clone menu | Preserve one recipe source | `cargo test -p walgit-server --test web_api --test web_ui` |
| Installer | server | `/services/public/install.sh` | Preserve POSIX, idempotent, data-free lane | `just e2e`; `tests/lib-auth.sh` |
| Credential helper | installer | host-derived helper and token file | Preserve 0600 token and scoped Git config | `just e2e`; `tests/lib-auth.sh` |
| Policy | server / WAL | `policy.json`, policy API/CLI | Preserve rule language and fail-before-publish behavior | `cargo test -p walgit-server --test policy` |
| Repository settings | server / WAL / CLI | settings API and `walgit repo settings` | Preserve WAL publication and inline effective config | `cargo test -p walgit-server --test web_api`; CLI tests |
| Effective settings secrecy | server | `/{o}/{r}/api/settings/effective` | Preserve route for PR1; secret-redaction hardening is PR2 and remains a production blocker | Route/code review; future auth gate |
| Auth `none` | config / server | `server.auth.mode=none` | Preserve loopback-only validation | `cargo test -p walgit-config` |
| Auth `token` | config / server | bearer/basic static tokens | Preserve current mode; repo grants and constant-time secrets are PR2 blockers | `just e2e`; future auth gate |
| Auth `oidc` | config / server | discovery, browser session, `wgt_` token | Preserve current allowlist and validation | auth unit/e2e tests; future auth gate |
| WAL operator CLI | `walgit-cli` / WAL | `walgit wal ls/show/materialize` | Preserve provenance and `--at-seq` | CLI unit tests; CLI help inspection |
| Import CLI | `walgit-cli` | `walgit import` | Preserve direct/staged import behavior | `cargo test -p walgit-cli`; `docs/INTEGRITY.md` review |
| Repair and fsck | CLI / Git / maintainer | `fsck`, `repair` units | Preserve connectivity audit and upstream repair | `cargo test -p walgit-server --test maintain`; `docs/INTEGRITY.md` review |
| Versioned recovery | future global recovery authority / repository control / store | `recovery_control`, exact object versions, recovery catalogs and final control CAS | Not implemented by PR1; V5.9 adds the exact global CAS fence, credential drain, crash recovery, and terminal release; exact-version primitives gate PR2, while end-to-end restore and the bounded fault model gate PR3 | Future recovery-state, missing-control, credential-drain, exact-provider version, and terminal-release tests |
| Repository create/delete | server / WAL | `PUT` / `DELETE` repo root | Preserve current routes in PR1; identity/lifecycle/reclamation move to PR2 | `just e2e`; future control gate |
| V2 direct repository identity | future control / Cloud Core | canonical transport path to routing-digest-derived `repo_control`; UUID/generation payload namespace | Not implemented by PR1; V2 keeps `SHA-256(C)` as the canonical identity digest, uses a separate domain-separated routing digest for keys, and enforces binary global uniqueness plus a non-reusable tombstone while preserving current PR1 routes until the hard cut. V5.9 defines authoritative keys as full physical `P`-prefixed keys and one adapter that validates and strips `P` exactly once for configured prefixed-store calls, then restores it exactly once on returned keys | Future shared transport corpus, both-digest derivation and binding, independent identity/routing collision errors, empty/non-empty prefix round trips, no-`P || P` namespace, and tombstone gate |
| V2 bounded control schema | future protobuf / control | `repo_control`, typed inline state, immutable catalog roots | Not implemented by PR1; every variable field, message, repeated field, and catalog uses the exact V5.9 numeric bound, exhaustive physical leaf grammar, exact digest preimage, and compact-or-reject behavior; immutable bodies never require their own store identity, parent references carry exact target roots, and standard raw Git/LFS/bundle payloads stay unmodified | Future descriptor-linter, decoder-allocation, key-grammar, parent/child root, byte-digest, raw-payload, watermark/proof boundary, inline/catalog `oneof`, and backpressure gate |
| V2 normal-read authority | future control / `walgit-store::v2_control` | one routing-digest-derived strict control GET, then exact rooted catalog versions only when required | PR2 adds a dormant load/Create/exact-CAS adapter that validates full physical keys, strips the configured prefix exactly once, preserves distinct CAS/version bindings, validates exact successors, and classifies ambiguous outcomes with one fresh strict GET. It is not activated by any V1 or runtime path. Only the control CAS can publish semantics; immutable candidates and mutable auxiliary state stay non-authoritative. Future runtime authorization must match the exact grant issuer/subject pair in current control. Capacity, receipts, authorization, fencing, catalogs, and runtime activation remain later slices. | `cargo test -p walgit-store --test v2_control_store`; `cargo test -p walgit-proto --test v2_codec`; future exact-root, exact-grant, capacity, fencing, cold-ref, stale-host-index, and side-state non-publication gate |
| Mutation receipt settlement | future repository control / immutable results | closed `NONE` / `CAPACITY` / `EVENT` obligations | Not implemented by PR1; settlement roots the result through one control CAS, the result identifies the landed `repo_control` version rather than itself, and settlement waits only for exact obligations whose tags are present | Future lost-CAS, later-CAS, all tagged-union cells, absent-obligation, max-key/max-`ObjectVersionID` 64-subscriber archive-watermark, reclamation, and no-recursive-receipt gate |
| Finite capacity allocation | future global capacity authority / shards | `capacity_control`, tenant catalog, exactly 256 capacity shards | Not implemented by PR1; V5.9 gives every shard an epoch-bound immutable budget, enforces tenant slices and the global sum, and fences redistribution until all shards have zero nonterminal reservations | Future cross-shard exhaustion, tenant/global oversubscription, redistribution, mixed-epoch, and crash-resume gate |
| Typed reclamation | future repository control / store | current and transitive roots plus retained obligations | Not implemented by PR1; protection does not retain every historical catalog forever, but exact-version deletion remains fenced, bounded, and impossible while any current or retained obligation reaches the target | Future superseded-catalog eligibility, live-root closure, receipt/event/capacity/pin/recovery retention, pagination, and refund gate |
| Signed create and capabilities | future Cloud Core / control | deterministic CBOR, untagged COSE Sign1, Ed25519 verification ring | Not implemented by PR1; V5.9 freezes exact data/root `kid` headers, required capability grant issuer/subject keys 35/36, the PENDING/ACTIVE/RETIRING/REVOKED slot matrix, same-control-key replay, Cloud Core global intent-ID uniqueness before signing, deterministic `CredentialControl` and `VerificationRingRoot` tags and evolution, checked linear ring epochs and prior digests, permanent identity non-reuse, bounded root-signed verifier-set and member-signed acknowledgement-set preimages, and a non-self-referential pinned-root-signed credential-transition proof | Future cross-language ring/control/verifier-set/acknowledgement/proof vectors, exact bootstrap, member bounds/order/signatures and digest recomputation, every grant-purpose/role and slot/state cell, malformed-CBOR, rollback/fork/skip/overflow/retired-key-reuse rejection, projection and predecessor corruption, proof replay, skew/lifetime, binding-CAS, stale-ring, rotation, and 30-second revocation gate |
| Bucket administrative safety | future global control / selected S3 provider | `bucket_admin_control`, safety digest, credential epoch, global writer fence | Not implemented by PR1; production requires `PREPARING`, runtime write denial and old-credential revocation, acknowledged drain, exact revalidation, and a new loaded epoch before publication resumes | Future versioning/lifecycle/KMS/encryption/IAM/provider-policy drift, paused-writer, credential-epoch, and drain gate |
| Durable webhook delivery | future event / Cloud Core | bounded inline event, HTTPS POST, canonical HMAC tuple, replay cache, archive watermark | Not implemented by PR1; V5.9 caps an atomic transaction at 256 changes, active subscribers at 64, every precomputed deterministic body at 1 MiB, and the watermark at 524,288 bytes with at most 64 exact archive refs of at most 4,096 bytes each; it preserves HMAC rotation, causal retention, and exact parent-rooted archives | Future size/subscriber/max-reference boundaries, pre-publication rejection, HMAC vectors, replay, key rotation, fanout crash, retention, settlement, reclamation, and watermark gate |
| Exact build pins | future Cloud Core build intent / repository control | durable `PREPARING -> READY` intent, standing named exact-SHA pins, primary and named build pins, exact outbox | Not implemented by PR1; the event CAS preserves the primary 120-day floor, but every exact pin and the one READY/outbox transaction must land by `ready_deadline` or terminal no-build permanently rejects late pin, READY, outbox, and enqueue; named exact-SHA configuration is event-eligible only while its standing fenced Git/LFS pin covers the last event horizon | Future deadline-stall, late-action denial, partial-pin compensation, standing-pin activation/removal/renewal, exact-SHA/current-ref resolution, ref-move/reclamation, and maximum-horizon gate |
| No-production-data V2 hard cut | future cutover / selected S3-compatible provider | conditional `OPEN`, `PREPARING`, bounded creation plan, exclusive fence, two scans with two shared S3 traversals each, and one inline signed proof | Not implemented by PR1; every initial control object is planned before Create and batch-resolved into the cutover graph; after revocation and the bounded admission wait, each scan uses one version traversal for three sets and one multipart traversal, with canonical presence-aware cursors and exact entry, cursor-chain, set, scan, deterministic-CBOR, and Ed25519 proof encodings | Future ordering, plan boundaries, lost-Create resolution, policy convergence, high-watermark, cursor presence/continuity/repetition, page-split/same-key version/delete-marker, byte-vector, corruption/replay, double-scan, graph/history, IAM-race, V1-rejection, and no-fallback gate |
| Placement | config / server | serve/maintain include/exclude | Preserve prefix routing and explicit placement | `cargo test -p walgit-server --test routing_prefix --test maintain` |
| Push broker | server | forwarding and trusted principal | Preserve broker fallback and opaque client credential lane | `just e2e`; config/code review |
| Drain | server / maintainer | SIGTERM phases, `/readyz` | Preserve serving during phase 1 and refusal in phase 2 | `cargo test -p walgit-server --test drain` |
| Compaction | maintainer / WAL | geometric and base compaction | Preserve leases, live-pack rules and CAS publication | `cargo test -p walgit-server --test maintain`; simulation suite |
| Checkpoint | WAL / maintainer | checkpoint thresholds and manifest CAS | Preserve refs snapshot, tail replay and request budget | `cargo test -p walgit-server --test sim` |
| Edge capabilities | server | `X-Walgit-Capabilities` | Preserve per-request opt-in for auth and byte offload | routing/static tests; nginx config review |
| TLS and CA | server / installer | off, self-signed, files; `ca.pem` | Preserve in-process TLS and public CA lane | TLS unit/e2e tests; standalone config review |
| CORS | server | `/api-browser` | Preserve allowlisted credentialed browser lane | `cargo test -p walgit-server --test web_api` |
| Gzip requests | server | smart HTTP middleware | Preserve streaming decompression and limits | `just e2e` |
| HTTP/2 | server | h2c or TLS ALPN | Preserve direct standalone support | server/config code review; later runtime probe |
| Standalone | CLI / server | `walgit-server --config`, one binary | Preserve no-edge operation and self-signed default shape | `walgit config check --config walgit.standalone.toml`; `just e2e` |
| Memory store | `walgit-store` | `MemoryStore` | Preserve full object-store contract | `cargo test -p walgit-store --test contract -- memory_contract` |
| GCS store | `walgit-store` | `GcsStore` | Preserve GCS behavior and native conditional compose for development and non-production only; exact-delete tests require Object Versioning enabled and soft-delete retention zero, but GCS is production-ineligible because it cannot prove all resumable sessions and delete markers | memory/unit gates; `just test-gcs <approved-disposable-bucket>` when authorized; future production-ineligibility gate |
| S3 store | `walgit-store` | `S3Store` | Harden default credentials, exact lengths, retry mapping, atomic final conditions, bounds and cleanup | unit tests; protected CI against disposable local RustFS via `just test-s3`; PR2 exact-provider primitive gate |
| S3 credentials | `walgit-store` | SDK chain or configured env names | Empty override names preserve the refreshable default chain and temporary credentials; complete custom access/secret and optional session token override it; incoherent partial overrides fail without printing values | `cargo test -p walgit-store --lib` |
| S3 endpoint/region/addressing | config / store | endpoint, region, path/virtual style | Preserve exact configured values; make contract test parameters explicit | required `WALGIT_TEST_S3_*` environment plus `just test-s3-provider` |
| S3 multipart cleanup | store | create/upload/complete/abort | Abort on read, upload, condition, and completion failures; max 10,000 parts; require provider `AbortIncompleteMultipartUpload` lifecycle cleanup | unit/contract tests; exact-provider cleanup gate |
| CI and supply chain | repository | `.github/workflows` | PR1 delivers pinned PR/main quality and audit jobs, a protected disposable RustFS contract, and signed development/main images built only from the exact successful main CI SHA; PR forks never publish, and no PR1 image is production-deployable. Future gates require `timeout-minutes <= 15` on every required PR/provider/evidence/recovery/cutover/promotion job, provider test work `<= 12` minutes, cleanup reserve `>= 3` minutes, workflow cap `<= 30` minutes, and promotion of one tested digest | actionlint and timeout-budget linter; branch protection, timing, cleanup, exact-provider, recovery, signature, attestation, and exact-digest promotion remain later evidence |

## Bounded dependency advisory exception

The audit gate ignores only `RUSTSEC-2026-0253`. `aws-sdk-s3` 1.143 constrains
`lru` to the affected 0.16 line for its S3 Express identity cache. WalGit uses
configured standard S3-compatible buckets. The upstream cache key is `String`,
whose `Drop` implementation does not panic, so the advisory preconditions do
not occur in this use. Remove the exception as soon as the AWS SDK permits
`lru` 0.18.2 or newer. All other advisories remain denied as warnings.

## Future provider, recovery, and production evidence

Before PR2 merges, run the S3 contract against the selected S3-compatible
provider with its real endpoint, region, addressing mode, credential mode,
temporary bucket, and unique prefix. Prove credential rotation, a payload
larger than 5 GiB, the calculated 10,000-part boundary, concurrent conditional
Create and Update, conditional multipart completion, failed and abandoned
multipart cleanup, Range/HEAD/ETag behavior, mandatory versioning, stable
`ObjectVersionID` results, paginated version enumeration, exact-version
HEAD/GET/delete, and delete-marker behavior. Prove that conditional `OPEN` and
its CAS to `PREPARING` occur before the IAM or administrative fence and every
other external cutover effect. After runtime credential revocation, prove
provider-policy convergence, the at-most-300-second admission horizon, writer
drain, and the stable last-admitted-mutating-request watermark; LIST, HEAD, and
GET proof reads must not advance it. Each scan must use exactly one shared
`ListObjectVersions` traversal for current objects, noncurrent versions, and
delete markers, and one `ListMultipartUploads` traversal for active uploads.
Prove exact presence-aware cursor bytes, truncated/terminal rules, response-next
to next-request continuity, repetition rejection, page counts, cursor-chain and
set/scan digests, matching counts, zero repository data, and only the exact
allowlisted control-plane graph. Prove every initial control Create has a prior exact plan
row and that a lost Create is resolved into the graph rather than orphaned.
Prove exclusive-IAM denial of a concurrent writer and rejection of unplanned
control history without cleanup. Prove bucket-safety drift
detection and denial of a writer resumed after validation. Run the primitive
simulation only in an approved disposable prefix, never against a production
data prefix.

GCS contract tests remain development and non-production evidence. When they
exercise exact deletion, they require Object Versioning enabled and soft-delete
retention zero. They also prove that GCS fails production eligibility because
it cannot enumerate every resumable upload session and delete marker required
by the bootstrap proof. GCS evidence cannot satisfy the production provider
gate.

The later V2 bootstrap gate runs only against the authorized fresh production
prefix on the selected S3-compatible provider. It proves conditional `OPEN`,
then the CAS to `PREPARING`, before every external cutover effect. It then
installs the exclusive IAM and administrative fence, revokes and drains writers,
waits the bounded provider admission horizon, and binds two matching complete
scans, versioning, lifecycle, encryption, KMS, provider policy, all four
repository-data zero counts, the complete resolved 262-row creation plan and
allowlisted control-plane graph, job image, and the deterministic-CBOR inline
proof signed by the dedicated pinned Ed25519 bootstrap key before `PREPARED`.
Shared byte vectors cover the 4,404-byte computed scan maximum under its 8,192-
byte cap and the 23,650-byte computed proof maximum under its 65,536-byte cap.
They also cover corruption, page splits, many versions and delete markers for
one key, cursor presence/continuity/repetition, classification, ordering,
duplicate, signature, prior-control, and session/generation replay failures.
Any unexpected object, version, delete
marker, multipart upload, V1 state, or unresolved writer fails the hard cut
without cleanup. V2 has no legacy adoption migration.

PR3 must separately prove production-scale object counts, throughput,
retention, event replay and fanout, exact build pins, recovery, and the stated
fault model on the exact selected S3-compatible provider. Every result must
bind the one production candidate image digest. Promotion must attest that same
digest without a rebuild or mutable-tag substitution. These future jobs follow
the 15-minute required-job limit and 30-minute provider-workflow cap. Each
provider job reserves at least 3 of its 15 minutes for fail-closed cleanup and
gives test work at most 12 minutes. The horizon job uses at most 5 test minutes
for `H` and leaves at least 7 for convergence and two scans. Missing or
incomplete cleanup and evidence fail closed.

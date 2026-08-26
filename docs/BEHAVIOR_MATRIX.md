# Behavior preservation matrix

Status: traceable preservation matrix for production gate PR1. The named
commands are individually executable, but this change does not yet provide one
matrix-wide aggregator. A row is preserved only when its command passes or the
named evidence has been reviewed. Later gates can replace an evidence-only row
with a dedicated test. This matrix does not make untested provider claims.

Run the repository-wide checks with `just warnings`, `just test`, `just e2e`,
and `just ci`. Run `just test-s3` against the local disposable store. Run
`just test-s3-provider` against the exact selected provider only after setting
the required `WALGIT_TEST_S3_*` environment variables for an approved
disposable bucket and unique prefix. Run
`just test-gcs <bucket>` only against an approved disposable bucket and unique
prefix. Exact-provider primitive conformance is a PR2 merge gate. Full-scale
recovery and production-candidate evidence remain later PR3 gates. PR1 does
not implement the V5.3 control, event, recovery, or cutover contracts.

| Surface | Owner | Entrypoint | PR1 preservation decision | Test or evidence |
|---|---|---|---|---|
| SHA-1 repositories | `walgit-git` | `LocalRepo`, smart HTTP | Preserve | `just test`; `tests/e2e.sh` |
| SHA-256 repositories | `walgit-git` | `ObjectFormat::Sha256` | Preserve | `cargo test -p walgit-git`; `crates/walgit-server/tests/e2e.rs` |
| Smart HTTP v0/v2 | `walgit-server` / `walgit-git` | `info/refs`, upload-pack, receive-pack | Preserve protocol and capability advertisements | `just e2e` |
| Git errors and real 401 | `walgit-server` | `smart.rs`, auth middleware | Preserve pkt-line errors and invalid-credential 401 | `just e2e`; `tests/lib-auth.sh` |
| Static `HEAD` | `walgit-server` | `static_object.rs`, Git/static routes | Preserve metadata without body | `cargo test -p walgit-server --test static_http` |
| Range, If-Range, 416 | `walgit-server` / stores | immutable static routes, `ObjectStore::get` | Preserve half-open internal ranges and HTTP static contract | `cargo test -p walgit-store --test contract`; `cargo test -p walgit-server --test static_http` |
| ETag and cache rules | server / stores | static and ref-dependent responses | Preserve strong versions, HEAD, Range and immutable/SWR policy; authenticated proxy bytes are private, explicitly anonymous proxy bytes remain public, all S3 signed URLs are private, and authenticated GCS tenants cannot use public-cacheable signed URLs | `cargo test -p walgit-server --test static_http --test web_api`; config tests |
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
| Effective settings secrecy | server | settings HTTP API | Return only safe repository settings sections, hide raw upstream settings from non-operators, preserve operator-owned upstream settings across ordinary edits/clears, reject credentials in upstream URLs, and reserve upstream overrides for principals that are both tenant admins and platform operators | Settings/auth tests and route review |
| Auth `none` | config / server | `server.auth.mode=none` | Preserve loopback-only validation | `cargo test -p walgit-config` |
| Auth `token` | config / server | bearer/basic static tokens | Preserve credential transport; require principal-to-tenant reader/writer/admin grants | auth unit tests; tenant isolation e2e |
| Auth `oidc` | config / server | discovery, browser session, `wgt_` token | Preserve allowlist and validation; resolve the same tenant grants after identity verification | auth unit/e2e tests; tenant isolation e2e |
| WAL operator CLI | `walgit-cli` / WAL | `walgit wal ls/show/materialize` | Preserve provenance and `--at-seq` | CLI unit tests; CLI help inspection |
| Import CLI | `walgit-cli` | `walgit import` | Preserve direct/staged import behavior | `cargo test -p walgit-cli`; `docs/INTEGRITY.md` review |
| Repair and fsck | CLI / Git / maintainer | `fsck`, `repair` units | Preserve connectivity audit and upstream repair | `cargo test -p walgit-server --test maintain`; `docs/INTEGRITY.md` review |
| Versioned recovery | future control / store | exact object versions, recovery catalogs and final control CAS | Not implemented by PR1; exact-version primitives gate PR2, while end-to-end restore and the bounded fault model gate PR3 production approval | Future exact-provider version tests and recovery vertical acceptance in `docs/PRODUCTION_ARCHITECTURE.md` |
| Repository create/delete | server / WAL | `PUT` / `DELETE` repo root | Tenant Admin only; auto-create on push also requires Admin while Writer can push existing repositories | tenant isolation e2e |
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
| GCS store | `walgit-store` | `GcsStore` | Preserve GCS behavior and native conditional compose | memory/unit gates; `just test-gcs <approved-disposable-bucket>` when authorized |
| S3 store | `walgit-store` | `S3Store` | Harden default credentials, exact lengths, retry mapping, atomic final conditions, bounds and cleanup | unit tests; protected CI against disposable local RustFS via `just test-s3`; PR2 exact-provider primitive gate |
| S3 credentials | `walgit-store` | SDK chain or configured env names | Empty override names preserve the refreshable default chain and temporary credentials; complete custom access/secret and optional session token override it; incoherent partial overrides fail without printing values | `cargo test -p walgit-store --lib` |
| S3 endpoint/region/addressing | config / store | endpoint, region, path/virtual style | Preserve exact configured values; make contract test parameters explicit | required `WALGIT_TEST_S3_*` environment plus `just test-s3-provider` |
| S3 multipart cleanup | store | create/upload/complete/abort | Abort on read, upload, condition, and completion failures; max 10,000 parts; require provider `AbortIncompleteMultipartUpload` lifecycle cleanup | unit/contract tests; exact-provider cleanup gate |
| CI and supply chain | repository | `.github/workflows` | PR1 delivers pinned PR/main quality and audit jobs, a protected disposable RustFS contract, and signed development/main images built only from the exact successful main CI SHA; PR forks never publish, and no PR1 image is production-deployable. Future gates require critical PR jobs at 15-minute P95, parallel provider jobs capped at 15 minutes, a fail-closed provider workflow capped at 30 minutes, and promotion of the one tested digest without rebuild or mutable tags | actionlint and workflow review; branch protection, timing, exact-provider, recovery, signature, attestation, and exact-digest promotion remain later evidence |

## Bounded dependency advisory exception

The audit gate ignores only `RUSTSEC-2026-0253`. `aws-sdk-s3` 1.143 constrains
`lru` to the affected 0.16 line for its S3 Express identity cache. WalGit uses
configured standard S3-compatible buckets. The upstream cache key is `String`,
whose `Drop` implementation does not panic, so the advisory preconditions do
not occur in this use. Remove the exception as soon as the AWS SDK permits
`lru` 0.18.2 or newer. All other advisories remain denied as warnings.

## Future provider, recovery, and production evidence

Before PR2 merges, run the S3 contract against the selected provider with its
real endpoint, region, addressing mode, credential mode, temporary bucket, and
unique prefix. Prove credential rotation, a payload larger than 5 GiB, the
calculated 10,000-part boundary, concurrent conditional Create and Update,
conditional multipart completion, failed and abandoned multipart cleanup,
Range/HEAD/ETag behavior, mandatory versioning, stable `ObjectVersionID`
results, paginated version enumeration, exact-version HEAD/GET/delete, and
delete-marker behavior. Never run these checks against a production data
prefix.

PR3 must separately prove production-scale object counts, throughput,
retention, event replay and fanout, exact build pins, recovery, and the stated
fault model on the exact selected provider. Every result must bind the one
production candidate image digest. Promotion must attest that same digest
without a rebuild or mutable-tag substitution. These future jobs follow the
15-minute per-job and 30-minute provider-workflow budgets in the production
charter and fail closed when cleanup or evidence is incomplete.

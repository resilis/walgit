# walgit cross-crate contract

Context: **the original cross-crate interface contract (2026-08-18/19, written so eight owners could build the
crates in parallel)**, kept as the reference for names and shapes. Rule still in force: *extend, do not rename*
— a type or function listed here is relied on by another crate. **Where this file and the code disagree, the
code is right and this file is stale**; verify with `rg`/`cargo doc` before relying on a signature. Known
supersessions (2026-08-20 sweep): `RepoHandle::sync()` is now the *Serve* level of the sync-level family
(`sync_refs` / `sync` = Serve / `sync_full` / `sync_objects`, `AGENTS.md §2.3`); auth is Google identities only
(`AGENTS.md §1.3`, no "admin token"); the server router is `web/API.md` + `AGENTS.md D15/D20/D26/D27`; bundle
schedule/retention semantics are specified only by `docs/BUNDLE_URI_DESIGN.md §3–§4` (calendar slots,
slot-epoch tokens, contiguous-chain retention, main-only refs). Read when you touch a crate boundary; update
the relevant block when you extend one.

Shared interfaces between crates. Implement exactly these names/shapes; extend freely, do not rename.
Original owners (parallel batch): StoreS3, StoreGcs, StoreCoord, GitEngine, Wal, Server, Bundle, Cli.
Read `AGENTS.md` first (design §1–§2, decisions §3; the original layout/phases/config draft is the measurement log).

## Existing (do not rewrite; extend only)
- `walgit-proto`: prost types from `proto/walgit/v1/wal.proto` (Manifest, LogSegmentRef, LogEntry, PackRef,
  RefTransaction/RefUpdate, Checkpoint(+Ref), RefSnapshot/Ref, Lease, BundleList/BundleEntry); `keys::*`;
  `frame::{encode_entries,decode_entries}` (uvarint-framed log encoding); `time::*`; `keys::POLICY` / `policy_key` (`policy.json` rule language, `docs/POLICY.md`).
- `walgit-proto::v2`: dormant additive `RepoControl`, `VerificationRingRoot`,
  and `CredentialControl` types from `proto/walgit/v2/control.proto`;
  descriptor-visible message, byte, and count bounds from
  `proto/walgit/v2/options.proto`; the strict
  `v2::{encode_repo_control,decode_repo_control,preflight_repo_control}` and
  `v2::{encode_credential_control,decode_credential_control,preflight_credential_control}`
  codecs; the dormant capacity
  `v2::{encode,decode,preflight}_{tenant_capacity_catalog_page,capacity_shard,capacity_control}`
  codec families; distinct canonical-path, routing, protobuf-object, raw-payload,
  signed-envelope, and verification-ring digest types; and the exhaustive
  `v2::keys` grammar with a closed key-kind-to-digest mapping from the frozen
  V5.9 production architecture. Credential encode and decode plus
  `v2::validate_credential_control` take the validated configured
  `DeploymentPrefix`; local semantic validation binds each full physical ring
  key to that prefix, its lower-hex digest leaf, root metadata field bounds,
  slot cardinality and epochs, the exact bootstrap values, and the sorted
  permanent deny set. Raw preflight runs before generated decode and rejects
  unknown, duplicate, reordered, non-canonical, or unbounded protobuf input
  while preserving explicit optional signed timestamp zero.
  `validate_credential_control_transition_structure` checks only the locally
  visible shape of the six non-bootstrap successor kinds: install-next,
  promote-next, retire-previous, revoke-kid, verifier-set-update, and
  acknowledgement-update. It is not transition authorization. Ring lineage,
  UUID and key non-reuse, prior-ring digest, exact retirement union, bound-key
  revocation, retirement timing, verifier-set evolution, and acknowledgement
  proof requirements need verified immutable-ring and signed-proof evidence;
  future runtime code must fail closed when that evidence is absent. V2 is not
  read or written by the V1 registry, WAL, server, CLI, bundle, policy, or
  coordination paths. These dormant types and APIs do not create a production
  V2 object, activate a mutation path, or create a legacy-adoption migration.

  The dormant capacity schema is version 1. One immutable flat tenant page is
  binary-sorted and unique, with at most 4,096 rows and 524,288 exact encoded
  bytes. Each allocation has exactly 256 positive slices whose checked sum
  equals its finite total. `CapacityObjectRef` is the distinct global exact
  key/`ObjectVersionID`/digest/size reference; it never reuses the
  repository-scoped `TargetObjectRef`. Capacity controls and shards are at most
  1 MiB. A stable control binds a positive global budget, an exact tenant page,
  exactly 256 sorted positive shard budgets, and exact epoch-start shard
  proofs. The checked budget sum cannot exceed the global budget. The pure
  cross-object validator exact-binds loaded current and target pages, computes
  all 256 checked tenant-slice column sums, and requires each column to fit its
  shard budget and the aggregate to fit the global budget.

  A shard has at most 4,096 sorted retained reservations and 4,096 sorted
  current tenant accounts. Every non-`ABORTED` byte is checked against the
  shard budget and the one non-extraneous current account for its tenant.
  Historical terminal rows keep their original epoch and slice across
  redistribution. `RESERVED` and `COMMITTING` must use the current shard epoch;
  terminal rows can use a nonzero earlier epoch. `RESERVED` has an explicit
  checked lifetime of at most 900 seconds. `COMMITTING` is non-expiring and
  uses a closed predecessor: `CREATE` requires explicit `NONE`; every other
  non-settlement mutation requires the exact prior control CAS token and
  object version. `ABORTED` has separate expiry and conflicting-commit proof
  arms. Commit mutation IDs are unique per repository across retained rows. A
  public successor validator accepts only a byte-exact retry or one legal
  reservation transition with shard revision `+1`. It freezes the shard,
  epoch, budget, immutable reservation fields, untouched rows, and unaffected
  accounts. The caller supplies observed `now`: creation requires
  `created_at <= now < expires_at`, `RESERVED -> COMMITTING` requires the same
  live window, and expiry repeats the original window and records that exact
  `now >= expires_at`. Terminal rows cannot change.

  The retained-shard-budget object validator exact-binds an epoch-start body
  to the matching `CapacityShardBudget.shard_object` for both STABLE and the
  retained prior plan in either PREPARING phase. A separate mutable-shard
  object validator exact-binds the current body to caller-observed provider
  metadata, then compares shard, current control epoch, and budget without
  equating that metadata to the historical epoch-start proof. The pure
  current-shard-view validator composes the mutable object gate and requires
  every tenant account to equal the exact current page slice. Every current-
  epoch non-`ABORTED` reservation must repeat that exact slice; older terminal
  proof rows keep their historical slice. The admission wrapper requires
  STABLE. Publication uses the composed STABLE successor gate so a new row
  cannot bypass the exact current page, account, epoch, budget, object, or
  caller-observed time checks. PREPARING publication uses the separate
  DRAINING gate, which permits only an expiry, charge, or conflict abort.
  Lower-level object and successor helpers are not publication gates.
  Before CHARGED or conflicting-commit ABORTED is accepted, the future
  controller must run the state-specific composition gate. Both gates exact-
  bind the prior COMMITTING shard and prepared `CapacityObligation`. CHARGED
  also exact-binds the current `RepoControl` and its rooted receipt catalog;
  conflict exact-binds a typed current GET and catalog, proves the prepared
  mutation is absent, and proves the conflicting current mutation is present.
  `CREATE_CONTROL_EXISTS` accepts any exact control at the by-path key.
  `SAME_WRITER_VERSION_ADVANCED` requires a different object version at epoch
  `E`; `WRITER_EPOCH_ADVANCED` requires a different object version at an exact
  typed-current writer epoch strictly greater than `E`. This includes `E+1`
  and later epochs after successive takeovers. All arms match canonical body
  key/digest/size and the current catalog's represented last mutation. The
  controller obtains the conflicting proof from a typed current GET at the
  abort decision; the durable proof can later exact-load that object version.
  Proto validation cannot prove provider currentness by itself.

  Redistribution has only `STABLE`, `PREPARING/DRAINING`, and
  `PREPARING/APPLYING` cells. DRAINING retains the exact prior stable plan and
  binds the target plan plus writer/admission fence. APPLYING additionally
  binds all 256 exact current drained baselines. Their provider metadata can be
  newer than the historical epoch-start proofs, but shard, prior epoch, budget,
  and key stay fixed. The exported APPLYING current-shard gate exact-loads the
  current and target pages plus the rooted drained baseline. It accepts only
  that exact baseline object or its deterministic target successor, which
  preserves terminal reservation bytes and replaces only current accounts
  from the target page. The future global controller must use this gate for
  advance and recovery across all 256 shards.
  The dormant store and domain controller below implement only RESERVED
  admission and RESERVED expiry. Provider-specific operations, V1
  compatibility, routes, configuration, migration, runtime activation, and
  the global redistribution controller remain absent. This is a greenfield
  hard-cut contract; the deferred multilevel 65,536-row topology requires a
  later explicit phase.
- `walgit-identity`: dormant pure V2 credential verification. It depends only
  on `walgit-proto` plus bounded hash, Ed25519, and error utilities. Its strict
  cursor rejects unknown, duplicate, reordered, non-minimal, indefinite,
  tagged, text-valued, floating, simple, trailing, and oversized CBOR before
  allocation. Envelope-specific APIs accept only attached untagged
  `COSE_Sign1`; bind exact rooted ring objects and the full slot/state/deny
  matrix; authenticate create intents and capabilities; and verify the exact
  verifier-set, acknowledgement-set, projection, predecessor/bootstrap, and
  transition-proof chain through one all-or-nothing result. Data-key validity
  uses signed `issued_at` without key skew. Envelope time uses explicit `now`
  with the frozen 30-second skew and checked `expiry - issued_at` lifetime.
  Ring and verifier-set IDs require UUIDv7 form but no timestamp proximity.
  Data and acknowledgement kids are opaque; only the root kid is derived.
  `AuthenticatedCapability` is not repository authorization. No V1, server,
  store, configuration, CLI, route, or runtime path calls this crate.
- `walgit-store`: `CasToken` is the opaque conditional-write identity. `ObjectVersionId` is the distinct
  immutable history identity carried by `ObjectMeta::object_version_id`
  and `GetOptions::object_version_id`. `ObjectStore` provides exact-version GET/HEAD/delete and bounded opaque
  `list_versions` pagination over objects and provider delete markers. `ComposeSource` pins each input by key,
  size, CAS token, and object-version ID. `ObjectStoreExt`, `Prefixed`, `memory::MemoryStore`, and
  `util::{collect,once,file_stream,backoff,retry}` preserve the shared implementation surface.
- `walgit-store::v2_control`: dormant strict persistence for the V2 repository
  authority. `ControlStore` receives a store that is already scoped to the
  configured `DeploymentPrefix`. It validates the full persisted
  `repo_control_key`, removes that prefix exactly once for store calls, and
  returns an opaque `StoredRepoControl` with a `ControlBinding` containing the
  full key, distinct `CasToken` and `ObjectVersionId`, exact protobuf digest,
  and size. `load` performs one strict GET. `create` permits only ACTIVE
  revision one and uses `PutMode::Create`. `compare_and_swap` accepts one
  exact stored snapshot, validates the exact successor, and uses only that
  snapshot's `CasToken`. The successor freezes identity, create binding, key,
  object format, and cutover generation; advances the revision by one; uses a
  new mutation ID; and follows `ACTIVE -> DELETING -> TOMBSTONED`.

  A successful write returns its provider binding without another read. A 412
  or ambiguous response permits exactly one fresh strict GET and returns a
  typed committed, exact-replay, conflict, not-committed, or indeterminate
  outcome. After a 412 update, an exact current successor is committed and any
  other strict current value is a conflict. Only an ambiguous update that still
  observes its exact prior CAS/version binding can be not-committed; an absent
  key after an ambiguous Create stays indeterminate. The adapter never retries,
  rebases, calls `coord::cas_update`, or uses LIST. An indeterminate outcome
  fences the caller from another CAS until later receipt settlement resolves
  it. No V1 registry, WAL, server, CLI, route, or runtime path constructs this
  adapter yet.
- `walgit-store::v2_capacity`: dormant strict persistence for exact capacity
  reads and transition-specific shard writes. It loads current
  `CapacityControl`, exact rooted tenant pages by `ObjectVersionId`, and
  current or exact `CapacityShard` bodies. Each load checks the configured
  prefix exactly once, strict canonical bytes, provider key, separate bounded
  `CasToken` and `ObjectVersionId`, digest, and size. The public write surface
  contains only RESERVED admission and RESERVED expiry CAS methods. Each uses
  one conditional PUT against the exact loaded shard and at most one strict
  current GET after a 412, ambiguous error, or unusable success response. It
  returns committed, conflict, not-committed, or indeterminate and never
  retries, rebases, uses HEAD/LIST, or falls back from an exact catalog version
  to current state.
- `walgit-control`: dormant V2 repository authorization and mutation domain.
  Authorization consumes only an `AuthenticatedCapability`, compares every
  sealed repository/control binding including the current stored-control
  `ObjectVersionId`, requires the exact inline issuer/subject grant, applies
  the closed purpose/role matrix, and fails closed on grant catalogs. The
  public controller supports only `SETTINGS`, `GRANTS`, and receiptless
  `INTERNAL_SETTLEMENT`. `WRITER_TAKEOVER` stays unavailable to administrator
  capabilities until a future sealed lease/writer coordination authority is
  specified. Every ordinary mutation roots an
  `UNRESOLVED` receipt. No later ordinary CAS is admitted until the exact
  landed-control result is materialized and a settlement CAS preserves the
  row as `SETTLED`, with the exact settlement mutation ID and result. The flat
  catalog has both a 4,096-item cap and a 512 KiB
  encoded cap. Either cap can apply earlier, and admission reserves the
  maximum valid settled-result space before publish. The crate uses the
  real `walgit-store::v2_control` adapter and remains disconnected from V1,
  server routes, providers, credentials, and deployment.
  Its separate dormant `capacity` module implements only new `RESERVED`
  admission and `RESERVED -> ABORTED(expired)`. Both start from an exact strict
  `StoredRepoControl`; callers cannot supply tenant, repository identity,
  shard, epoch, budget, slice, or key. Admission derives them from the exact
  ACTIVE repository identity, current STABLE capacity control, exact rooted
  tenant page, and current hashed shard. Expiry accepts an exact strict ACTIVE,
  DELETING, or TOMBSTONED repository-control snapshot so retained RESERVED rows
  cannot block repository reclamation or capacity drainage. The request supplies a UUIDv7 reservation
  ID, positive bytes, explicit creation, expiry, and observed time. Their
  checked lifetime must be `1..=900` seconds. The request also supplies the
  closed domain-only purpose `GitWrite | LfsFinalize`. Purpose is not persisted in
  RESERVED and does not authorize work; the future runtime/COMMITTING slice
  must bind it to capability purpose and `MutationKind`. Expiry receives
  explicit `now` and repeats the exact stored window. A new expiry transition
  runs only in STABLE or PREPARING/DRAINING. After a valid current-view load,
  an exact already-expired replay returns the rooted shard without a PUT in
  APPLYING or a later STABLE epoch. APPLYING replay exact-loads the rooted
  drained baseline and target page when they differ from the already-loaded
  current objects, then accepts only the baseline or its deterministic target
  successor. This slice does not implement CREATE admission,
  COMMITTING, CHARGED, conflict abort, capacity-control/catalog writes, or the
  cross-key global admission fence.
- `walgit-config`: `Config` for walgit.toml (+ `WALGIT__` env overrides, `PORT`); `Config::with_settings` accepts
  only `[bundles]`, `[maintenance]`, `[compaction]`, and `[upstream]` in repo-scoped settings. Public settings
  serialization uses the closed `EffectiveSettingsView`; diagnostic config dumps use the separate
  credential-safe `SafeConfigView`. Neither boundary serializes `Config` directly.

## walgit-git (owner: GitEngine)

```rust
pub struct RepoId { owner: String, name: String }
// FromStr("owner/name" | "owner/name.git"), Display "owner/name". Validation: each part ASCII [A-Za-z0-9._-],
// no leading '.', not "..", 1..=100 chars. fn owner(), name(), store_prefix() (walgit_proto::keys::repo_prefix),
// local_dir(root:&Path)->PathBuf (= root/owner/name.git).
pub enum ObjectFormat { Sha1, Sha256 } // From<walgit_config::ObjectFormat>, <-> gix_hash::Kind, as_str()

/// Bare git repo on local disk in standard layout (objects/pack/*.{pack,idx}, loose refs + packed-refs, HEAD,
/// config with repositoryformatversion / extensions.objectformat) readable by gix AND upstream git.
/// Clone-able handle (Arc inside), thread-safe.
pub struct LocalRepo;
impl LocalRepo {
  pub fn init(root: &Path, id: &RepoId, format: ObjectFormat) -> Result<Self, GitError>;
  pub fn open(root: &Path, id: &RepoId) -> Result<Option<Self>, GitError>;
  pub fn id(&self) -> &RepoId; pub fn path(&self) -> &Path; pub fn object_format(&self) -> ObjectFormat;
  pub fn gix(&self) -> gix::Repository;          // per-thread handle from shared ThreadSafeRepository
  pub fn refresh(&self) -> Result<(), GitError>;  // re-read odb/refs after pack/ref changes

  // ---- packs
  /// = git index-pack: stream in, write objects/pack/pack-<checksum>.{pack,idx}; thin packs resolved against
  /// the odb (--fix-thin); verify checksum; opts.fsck => object-level validation. Empty input => Ok(None).
  pub async fn ingest_pack<R: tokio::io::AsyncRead + Unpin + Send + 'static>(&self, pack: R, opts: IngestOptions)
      -> Result<Option<IngestedPack>, GitError>;
  pub struct IngestOptions { pub fsck: bool, pub max_bytes: Option<u64>, pub thin: bool }
  pub struct IngestedPack { pub checksum: gix_hash::ObjectId, pub pack_path: PathBuf, pub idx_path: PathBuf,
      pub pack_size: u64, pub idx_size: u64, pub object_count: u64 }
  /// Atomically move downloaded files into objects/pack/ (rename), then refresh.
  pub async fn install_pack(&self, pack: &Path, idx: &Path, extra: &[PathBuf]) -> Result<(), GitError>;
  /// Delete .pack/.idx/.rev/.bitmap. Caller guarantees no readers (wal holds a lock).
  pub fn remove_pack(&self, checksum: &gix_hash::oid) -> Result<(), GitError>;
  pub fn packs(&self) -> Result<Vec<PackInfo>, GitError>;
  pub struct PackInfo { pub checksum: gix_hash::ObjectId, pub pack_size: u64, pub idx_size: u64,
      pub object_count: u64, pub has_rev: bool, pub has_bitmap: bool }
  pub fn pack_path(&self, checksum: &gix_hash::oid) -> PathBuf; // objects/pack/pack-<hex>.pack (idx: set_extension)

  // ---- refs
  /// All refs sorted by name incl. peeled tags + HEAD symbolic target. `From` both ways with
  /// walgit_proto::v1::RefSnapshot.
  pub fn refs(&self) -> Result<RefSnapshotData, GitError>;
  /// Atomic all-or-nothing. check_old => verify old_oid (zero = must not exist). Supports HEAD symbolic update.
  /// Error GitError::RefConflict{name, expected, actual}.
  pub fn apply_ref_txn(&self, txn: &walgit_proto::v1::RefTransaction, check_old: bool) -> Result<(), GitError>;
  /// Replace ALL refs + HEAD (write packed-refs directly; must be fast for 500k refs).
  pub fn load_ref_snapshot(&self, snap: &walgit_proto::v1::RefSnapshot) -> Result<(), GitError>;
  pub fn pack_refs(&self) -> Result<(), GitError>;

  // ---- objects
  pub fn has_object(&self, oid: &gix_hash::oid) -> bool;
  /// Every object reachable from tips exists. `stop_at_existing_refs` => stop at objects reachable from
  /// current refs (rev-list --objects <tips> --not --all). Error GitError::MissingObject{oid}.
  pub fn check_connectivity(&self, tips: &[gix_hash::ObjectId], stop_at_existing_refs: bool) -> Result<(), GitError>;

  // ---- protocol, server side
  /// protocol v2 `fetch`: parsed args in, pkt-line response out (acknowledgments, shallow-info, wanted-refs,
  /// packfile-uris (empty), packfile with sideband) per git protocol-v2 doc. Pack via gix_pack::data::output
  /// (count + entries with delta reuse from on-disk packs). Engine selectable (UploadPackEngine::{Gix,Git}).
  pub async fn upload_pack<W: tokio::io::AsyncWrite + Unpin + Send>(&self, req: UploadPackRequest, out: W)
      -> Result<UploadPackStats, GitError>;
  /// Raw passthrough: spawns `git upload-pack --stateless-rpc` (GIT_PROTOCOL set) — used for v0 and for
  /// engine=Git.
  pub async fn upload_pack_raw<R, W>(&self, protocol: Protocol, body: R, out: W) -> Result<(), GitError>;
  /// v2 ls-refs from the ref snapshot; efficient prefix filtering.
  pub fn ls_refs(&self, args: &LsRefsArgs) -> Result<Vec<LsRefsLine>, GitError>;
  pub struct LsRefsArgs { pub ref_prefixes: Vec<String>, pub symrefs: bool, pub peel: bool, pub unborn: bool }
  /// v0 advertisement with capabilities.
  pub fn advertise_refs_v0(&self, service: Service, out: &mut Vec<u8>) -> Result<(), GitError>;
  pub enum Service { UploadPack, ReceivePack }  // FromStr("git-upload-pack"|"git-receive-pack")

  // ---- upstream git helpers
  pub async fn git(&self, args: &[&str]) -> Result<std::process::Output, GitError>; // cwd=repo, GIT_DIR set
  pub async fn repack(&self, opts: RepackOptions) -> Result<RepackResult, GitError>;
  pub struct RepackOptions { pub mode: RepackMode /* Geometric{factor} | Full */, pub write_bitmap: bool,
      pub write_midx: bool, pub keep: Vec<gix_hash::ObjectId> }
  pub struct RepackResult { pub new_packs: Vec<PackInfo>, pub removed: Vec<gix_hash::ObjectId> }
  /// `git bundle create`.
  pub async fn write_bundle(&self, out: &Path, refs: &[String], exclude: &[gix_hash::ObjectId])
      -> Result<BundleInfo, GitError>;
  pub struct BundleInfo { pub size: u64, pub pack_offset: u64 }
}
/// Bundle header ("# v2 git bundle\n" [+ "-<oid> prereq\n"]* + "<oid> <ref>\n"* + "\n") so a full bundle
/// can be rendered as header + existing pack bytes without git.
pub fn bundle_header(refs: &RefSnapshotData, prerequisites: &[gix_hash::ObjectId], format: ObjectFormat) -> Vec<u8>;

pub mod pkt;      // pkt-line read/write, flush/delim/response-end, sideband encode; Protocol::{V0,V2} from
                  // GIT_PROTOCOL header; command/arg parsing for v2 (ls-refs, fetch, object-info, bundle-uri)
pub mod receive;  // parse receive-pack request: caps + commands ("old new refname\0caps"), push-options,
                  // => (walgit_proto::v1::RefTransaction, ReceiveCaps{report_status_v2, side_band_64k,
                  // atomic, quiet, push_options, agent, object_format}); pack bytes follow in the same body.
                  // `report_status(caps, unpack: Result, per_ref: &[(name, Result<(),String>)], out)` writer
                  // producing report-status(-v2), sideband-framed when requested.
pub enum GitError { Io, Gix(Box<dyn Error+Send+Sync>), Pack, RefConflict{name,expected,actual}, MissingObject{oid},
                    Fsck(String), Subprocess{cmd,status,stderr}, InvalidInput(String), Protocol(String) }
```

## walgit-store::coord (owner: StoreCoord)

```rust
/// Generic read-modify-write CAS loop on a protobuf object. `f(None)` when absent. Returning `None` from `f`
/// aborts with Ok(None). Retries on PreconditionFailed (re-reading) up to `max_retries`, on Retryable with
/// backoff. Returns the written meta + value.
pub async fn cas_update<T: prost::Message + Default, F>(store: &dyn ObjectStore, key: &str, max_retries: u32, f: F)
    -> Result<Option<(ObjectMeta, T)>, CoordError>
  where F: FnMut(Option<&T>) -> Result<Option<T>, CoordError>;
/// Read a protobuf object with its version. Ok(None) if absent.
pub async fn get_message<T: prost::Message + Default>(store: &dyn ObjectStore, key: &str)
    -> Result<Option<(ObjectMeta, T)>, CoordError>;
pub async fn get_message_if_changed<T>(store, key, known: &CasToken) -> Result<Option<(ObjectMeta, T)>, CoordError>;

/// Lease = walgit_proto::v1::Lease at `key`, acquired by Create or by Update over an expired lease.
pub struct LeaseGuard; // holds store handle, key, holder id, current CasToken; Drop => best-effort release
impl LeaseGuard {
  pub async fn heartbeat(&mut self, ttl: Duration) -> Result<(), CoordError>;      // CAS-extend expires_at
  pub async fn release(self) -> Result<(), CoordError>;                            // CAS delete
  pub fn spawn_heartbeat(self: Arc<Mutex<Self>>, every: Duration, ttl: Duration) -> tokio::task::JoinHandle<()>;
  pub fn holder(&self) -> &str; pub fn expires_at(&self) -> SystemTime;
}
pub async fn try_acquire(store: DynStore, key: &str, holder: &str, purpose: &str, ttl: Duration)
    -> Result<Option<LeaseGuard>, CoordError>;   // None = held by someone else and not expired
pub async fn acquire(store, key, holder, purpose, ttl, wait_up_to: Duration) -> Result<Option<LeaseGuard>, CoordError>;
pub fn instance_id() -> &'static str; // explicit instance name/id, hostname+pid, or uuid; computed once
pub enum CoordError { Store(StoreError), Decode(prost::DecodeError), Aborted, RetriesExhausted{key, attempts}, Other }
```

## walgit-store backends (owners: StoreS3, StoreGcs)

```rust
// s3.rs
pub struct S3Store; impl S3Store { pub async fn new(cfg: &walgit_config::StoreConfig) -> anyhow::Result<Self>; }
// gcs.rs
pub struct GcsStore; impl GcsStore { pub async fn new(cfg: &walgit_config::StoreConfig) -> anyhow::Result<Self>; }
// lib.rs
pub async fn open_store(cfg: &walgit_config::Config) -> anyhow::Result<DynStore>; // by cfg.store.backend, applies Prefixed(cfg.store_prefix())
```
S3 and GCS constructors fail closed unless bucket versioning is enabled. GCS
also requires soft-delete retention to be absent or exactly zero so an exact
generation delete is permanent. WalGit verifies these prerequisites but never
changes bucket policy.

S3 credential selection is closed before any credential or network access.
`default_chain` requires empty custom variable names and delegates only to the
refreshable AWS SDK chain. `explicit_env` requires bounded portable access and
secret variable names plus an optional session-token name; every named value
must resolve non-empty or construction fails without falling back or exposing
the value. The same static validator also closes region, DNS-compatible bucket,
deployment-prefix, multipart-part-size, and endpoint syntax. The endpoint is
required and bound explicitly so ambient AWS endpoint configuration cannot
select the provider. It uses exact canonical origin syntax with no path or
trailing slash, and non-loopback endpoints require HTTPS. `Config::validate`
and `S3Store::new` call this validator before credential or network access.
S3 SDK diagnostics retain only the internal operation, transport category,
numeric status, and an allowlisted service code. Raw SDK/provider messages,
request URLs, credential values, bucket names, prefixes, and unknown service
codes are not included in errors or provider-contract banners.

Contract tests: `crates/walgit-store/tests/contract.rs` with a `run_contract(store: DynStore)` suite executed for
memory always, for S3 when `WALGIT_TEST_S3_ENDPOINT` is set (endpoint, region, bucket, prefix, addressing mode,
and closed default-chain/explicit-env credentials are parameterized with `WALGIT_TEST_S3_*`; the exact configured
deployment prefix is validated and every run writes only below a unique child key),
for gcs when `WALGIT_TEST_GCS_BUCKET` set.

S3 large writes and compose use multipart completion as the destination's
atomic Create/Update point. Every part is length checked, operations stay
within the 5 TiB/10,000-part service bounds, and every post-create failure
attempts AbortMultipartUpload. Providers that do not implement conditional
multipart completion fail their contract run; no HEAD-then-write emulation is
allowed. Small writes remain one conditional PutObject. Every S3 deployment
must also configure an `AbortIncompleteMultipartUpload` bucket lifecycle rule
with a short retention window. Runtime abort is best effort and cannot clean
uploads left by process death or a provider outage.

## walgit-wal (owner: Wal)

```rust
pub struct Registry;   // one per process: DynStore + Arc<Config> + cache_root; DashMap<RepoId, Arc<RepoHandle>>
impl Registry {
  pub fn new(store: DynStore, cfg: Arc<walgit_config::Config>) -> Arc<Self>;
  /// Open existing (materialize local copy lazily). Err(WalError::NotFound) if manifest.pb absent.
  pub async fn open(&self, id: &RepoId) -> Result<Arc<RepoHandle>, WalError>;
  /// CAS-create manifest.pb (PutMode::Create). Err(WalError::AlreadyExists).
  pub async fn create(&self, id: &RepoId, format: ObjectFormat) -> Result<Arc<RepoHandle>, WalError>;
  pub async fn open_or_create(&self, id: &RepoId, format: ObjectFormat) -> Result<Arc<RepoHandle>, WalError>;
  pub async fn list(&self) -> Result<Vec<RepoId>, WalError>;   // list "repos/" prefix (delimiter-less scan is ok v1)
  pub fn store(&self) -> &DynStore; pub fn config(&self) -> &Arc<Config>;
  /// Disk cache maintenance: evict idle repos beyond cache.max_bytes / evict_idle_after.
  pub async fn evict_idle(&self) -> Result<EvictReport, WalError>;
}
pub struct RepoHandle;
impl RepoHandle {
  pub fn id(&self) -> &RepoId;
  pub fn local(&self) -> &LocalRepo;
  pub fn store(&self) -> &Prefixed;                       // repo-scoped
  pub fn manifest(&self) -> Arc<walgit_proto::v1::Manifest>;   // last known
  pub fn manifest_version(&self) -> Option<CasToken>;
  /// Freshness check (conditional GET on manifest.pb; honors wal.freshness_ttl) + catch-up (download new
  /// packs, apply log entries after our seq, apply COMPACT: install new pack, remove superseded). Returns a
  /// read guard; while any guard is alive no pack is removed locally. Every request calls this first.
  pub async fn sync(&self) -> Result<ReadGuard<'_>, WalError>;
  /// Force full re-materialize from store (repair).
  pub async fn rematerialize(&self) -> Result<(), WalError>;
  /// Publish a push. `pack` was produced by LocalRepo::ingest_pack on this handle's local repo (already on
  /// disk). Steps: upload pack+idx to wal/<sha>.{pack,idx} (skip if exists) ‖ verify txn old values against
  /// synced refs; then CAS: append LogEntry to log (new segment object per batch on regional buckets),
  /// cas_update manifest (head_seq+1, packs+=, log_segments+=); on PreconditionFailed: re-sync, re-verify
  /// old values (RefConflict per ref → whole push rejected unless !atomic and per-ref reporting), retry.
  /// Then apply refs locally. Coalesces concurrent publishes on this handle (wal.batch_window/max_batch).
  pub async fn publish_push(&self, pack: Option<IngestedPack>, txn: RefTransaction, meta: HashMap<String,String>)
      -> Result<PublishResult, WalError>;
  pub struct PublishResult { pub seq: u64, pub per_ref: Vec<(String, Result<(), RefError>)> }
  pub async fn publish_ref_update(&self, txn: RefTransaction, meta) -> Result<PublishResult, WalError>;
  /// COMPACT entry: new pack (already local, e.g. from LocalRepo::repack) superseding `supersedes`.
  pub async fn publish_compact(&self, new_pack: PackInfo, supersedes: Vec<gix_hash::ObjectId>, tier: u32)
      -> Result<u64, WalError>;
  /// Write checkpoint at current head (refs snapshot + pack set), then CAS manifest (checkpoint=, min_seq=,
  /// log_segments trimmed). Idempotent.
  pub async fn write_checkpoint(&self) -> Result<CheckpointRef, WalError>;
  /// Read log entries [from_seq, to_seq] from the store (provenance/rewind tooling).
  pub async fn read_log(&self, from_seq: u64, to_seq: Option<u64>) -> Result<Vec<LogEntry>, WalError>;
  pub fn last_access(&self) -> Instant;  pub fn touch(&self);
}
pub enum WalError { NotFound, AlreadyExists, RefConflict{name, expected, actual}, Store(StoreError),
                    Coord(CoordError), Git(GitError), Corrupt(String), Retry{attempts}, Io(std::io::Error) }
pub enum RefError { NonFastForward, Conflict{expected,actual}, Rejected(String), Missing }
```

## walgit-server (owner: Server)

```rust
pub struct AppState { pub cfg: Arc<Config>, pub store: DynStore, pub registry: Arc<walgit_wal::Registry>,
                      pub bundles: Arc<walgit_bundle::Bundler>, pub auth: Arc<auth::Authenticator> }
pub fn router(state: Arc<AppState>) -> axum::Router;
/// Bind, serve (HTTP/1.1 + h2c), graceful shutdown on SIGTERM/SIGINT/`shutdown` future.
pub async fn serve(state: Arc<AppState>, shutdown: impl Future<Output=()> + Send) -> anyhow::Result<()>;
// Routes (all under /{owner}/{repo}[.git]):
//   GET  /info/refs?service=git-upload-pack|git-receive-pack   (v0 advert or v2 capability advert per Git-Protocol)
//   POST /git-upload-pack   POST /git-receive-pack   (Content-Encoding: gzip supported; streaming both ways)
//   GET  /HEAD  GET /objects/info/packs (404 unless dumb enabled)
//   POST /info/lfs/objects/batch  PUT/GET /info/lfs/objects/{oid}  POST /info/lfs/verify
//   GET  /bundles/list  GET /bundles/{strategy}/{name}    (bundle-uri targets; ETag/Range/immutable caching)
//   PUT  /  (create repo, write permission)   DELETE / (write permission)
// Non-repo: GET /healthz /readyz /metrics ; GET / (list repos, text/plain)
// Auth: verified Google identity; writes require write permission. Sync level depends on the endpoint
// (Refs, Serve, Full, or Objects; AGENTS.md §2.3).
```

## walgit-bundle (owner: Bundle)

```rust
pub struct Bundler; impl Bundler {
  pub fn new(registry: Arc<Registry>, cfg: Arc<Config>) -> Arc<Self>;
  /// Evaluate all strategies for `id` at `now`; build those due (leased per repo+strategy), upload
  /// bundles/<strategy>/<ts>-<sha>.bundle, cas_update bundles/list.pb, prune keep=N. Returns built entries.
  pub async fn run_due(&self, id: &RepoId, now: SystemTime) -> Result<Vec<BundleEntry>, BundleError>;
  pub async fn build(&self, id: &RepoId, strategy: &str) -> Result<BundleEntry, BundleError>;
  pub async fn list(&self, id: &RepoId) -> Result<Option<BundleList>, BundleError>;
  /// git bundle-list text (bundle.version=1, bundle.mode, bundle.heuristic=creationToken, bundle.<id>.uri/
  /// creationToken); uri = `{base_url}/{owner}/{repo}/bundles/{strategy}/{name}` or signed URL per config.
  pub async fn render_list(&self, id: &RepoId, base_url: &str) -> Result<Option<String>, BundleError>;
  /// v2 `bundle-uri` command response lines (key=value pkt-lines).
  pub async fn protocol_v2_lines(&self, id, base_url) -> Result<Vec<String>, BundleError>;
  pub async fn run_all_due(&self, now) -> Result<(), BundleError>; // every repo in registry.list()
}

/// Abstraction over the registry; `walgit_wal::Registry` implements it and tests may use any impl.
#[async_trait]
pub trait BundleSource: Send + Sync + 'static {
  async fn open_repo(&self, id: &RepoId) -> Result<BundleRepoHandle, BundleError>;
  async fn list_repos(&self) -> Result<Vec<RepoId>, BundleError>;
}
pub struct BundleRepoHandle {
  pub local: walgit_git::LocalRepo,
  pub store: walgit_store::Prefixed,
  pub head_seq: u64,
}
/// `Bundler::new_with_source(source: Arc<dyn BundleSource>, cfg)` accepts custom sources;
/// `Bundler::new(registry: Arc<Registry>, cfg)` delegates to it.
pub use walgit_git::RepoId; // re-exported
pub enum BundleError { Store, Decode, Git, StrategyNotFound, RepoNotFound, InvalidRepoId,
  InvalidSchedule, Io, BundleNotFound, NoRefs, NoNewObjects, RetriesExhausted, Other }
```

### Proto addition (owner: Bundle)
`BundleEntry` gains `repeated Ref tips = 11;` — the ref tips (name+oid+peeled) a
bundle contains. For incremental bundles, the base bundle's tips are the
prerequisites. Backward compatible (field 11 was unused).

### Schedule / retention semantics
Normative rules live in `docs/BUNDLE_URI_DESIGN.md §3–§4`: six-field UTC calendar slots, WAL state as of each
slot, slot-epoch creation tokens, oldest-first backfill, contiguous-chain retention, and main-only selection
where configured. Do not derive scheduling behavior from this interface catalog.

## walgit-cli (owner: Cli)
`walgit --config walgit.toml <cmd>`: `serve` | `compact [owner/name|--all] [--once]` | `bundle run [--repo] [--strategy]` |
`repo create|list|info` | `wal ls|show|materialize --at-seq` | `synth --out DIR --size s|m|l [--commits N --files M]`
| `import --from GITDIR owner/name` | `config check|dump`. Also `Containerfile`, `compose.yaml` (rustfs +
walgit), `justfile`, `walgit.example.toml`, `tests/e2e.sh` (real git vs. server on memory store and on rustfs).

//! `walgit.toml` — the only configuration surface. Environment overrides use
//! `WALGIT__SECTION__KEY=value` (double underscore = nesting), applied after
//! the file is parsed. `PORT` (a serverless host) overrides `server.listen` port.

mod views;

pub use views::{EffectiveSettingsView, SafeConfigView};

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
pub use bytesize::ByteSize;
use serde::{Deserialize, Serialize};
pub use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub store: StoreConfig,
    pub cache: CacheConfig,
    pub wal: WalConfig,
    pub compaction: CompactionConfig,
    pub bundles: BundlesConfig,
    pub maintenance: MaintenanceConfig,
    pub placement: PlacementConfig,
    pub lfs: LfsConfig,
    pub git: GitConfig,
    pub upstream: UpstreamConfig,
    /// Links to the systems around a repository (per repo via settings).
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    pub events: EventsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub http2: bool,
    pub max_concurrent_requests: usize,
    /// Per-repo cap on concurrent upload-pack/receive-pack processes.
    pub max_concurrent_per_repo: usize,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// Graceful drain after SIGTERM: new object work (fetch/push/LFS) is
    /// refused with 503 + Retry-After and `/readyz` turns 503 at once; in-flight
    /// requests and the running maintenance unit get this long to finish
    /// before they are interrupted. Keep it below the process supervisor's stop
    /// grace; longer SSD-host jobs should be resumable rather than relying on drain.
    #[serde(with = "humantime_serde")]
    pub drain_timeout: Duration,
    /// Max size of a single pushed pack accepted over HTTP.
    pub max_push_bytes: ByteSize,
    /// Roles this instance performs. a serverless host: fronts get ["serve"], the
    /// single maintenance instance ["maintain"] (checkpoint / bundle / compact
    /// loops over every repo; `compact` and `bundle` are its sub-roles). Empty = all.
    pub roles: Vec<Role>,
    pub auth: AuthConfig,
    /// Public base URL used when rendering absolute URIs (bundle lists, LFS).
    pub public_url: Option<String>,
    /// Create a repo on the first receive-pack push if it does not exist.
    pub auto_create_on_push: bool,
    /// Honour `X-Walgit-Capabilities: accel-redirect` from an nginx edge
    /// (`deploy/nginx.conf.example`): static objects (bundles, LFS) are answered with
    /// `X-Accel-Redirect: /_store/` + `X-Walgit-Store-Url` (and `-Authorization`) and no
    /// body, so nginx streams (and caches) the bytes itself. Only turn it on behind an
    /// edge that strips the capability header from clients: the answer carries a store
    /// credential. Off by default.
    pub accel_redirect: bool,
    /// Browser origins allowed to call `/api/*` cross-origin with credentials
    /// (the `repos.js` browser lane from other sites). Exact origins or one
    /// leading `*.` wildcard per entry, e.g. `["https://*.docs.example.com"]`.
    /// Empty (default) = no cross-origin lane and no CORS headers. Non-empty:
    /// CORS with credentials for matching origins only, and state-changing
    /// methods require a matching `Origin` when one is sent. Browser identity
    /// is the app session cookie.
    pub cors_origins: Vec<String>,
    /// TLS terminated by walgit itself (standalone, D39). A reverse proxy may terminate
    /// TLS and use `mode = "off"` (h2c); a standalone host serves
    /// `https://` directly so git, browsers and the SDK see one origin with no edge.
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    pub mode: TlsMode,
    /// `files` mode: PEM certificate chain and PKCS#8/PKCS#1 private key.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// `self_signed` mode: subject alternative names. Empty = `localhost`, `*.localhost`,
    /// `127.0.0.1`, `::1` and the host of `server.public_url`. The certificate is written
    /// once to `<cache.dir>/tls/{cert,key}.pem` and regenerated when this set changes;
    /// clients fetch it at `/services/public/ca.pem` (the installer pins it for git).
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plain HTTP/1.1 + h2c (behind an edge that terminates TLS).
    #[default]
    Off,
    /// A self-signed certificate walgit generates and keeps under `cache.dir`.
    SelfSigned,
    /// `cert` + `key` from disk.
    Files,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            mode: TlsMode::Off,
            cert: None,
            key: None,
            hostnames: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Serve,
    Compact,
    Bundle,
    /// Background maintenance loop: checkpoint-if-due (refs-level), bundles-if-
    /// due, geometric compaction for repos whose pack set fits. Implies
    /// `Compact` + `Bundle`.
    Maintain,
    /// The events bridge (`docs/EVENTS.md`): tails every repo's WAL from a
    /// per-repo cursor and publishes `ref` events to the bus sinks (webhook,
    /// pubsub). Woken by `POST /_events/notify` (GCS notifications via Pub/Sub
    /// push) and a periodic sweep. A small separate service in production.
    Events,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    /// Allow unauthenticated read (upload-pack, bundles, web UI) when mode != none.
    pub anonymous_read: bool,
    /// Static tokens (`token` mode, and accepted in `oidc` mode too — for robots): token → principal.
    /// Presented as `Authorization: Bearer <token>` or as the password of HTTP Basic.
    pub tokens: Vec<StaticToken>,
    /// Repository-owner authorization. The existing `owner` path component is the tenant key.
    /// A principal or tenant of `*` is a wildcard; wildcard principals never match anonymous
    /// requests. Multiple entries combine by taking the strongest matching role.
    pub tenant_grants: Vec<TenantGrant>,
    /// Exact authenticated principals allowed to use platform-wide endpoints such as `/metrics`
    /// and `/_events/notify`. Operator status never grants repository access.
    pub platform_operators: Vec<String>,
    /// OIDC issuer (`oidc` mode). Discovery at `<issuer>/.well-known/openid-configuration`
    /// supplies the JWKS, authorization and token endpoints. Any compliant provider works
    /// (Google, Microsoft Entra, Okta, Auth0, Keycloak, Dex, GitLab, ...).
    pub issuer: String,
    /// Email domains accepted by `oidc` (the `email` claim, `email_verified` required).
    pub allowed_domains: Vec<String>,
    /// Individual identities accepted by `oidc` (exact `email` match).
    pub allowed_emails: Vec<String>,
    /// Accepted `aud` values of ID tokens sent as `Authorization: Bearer` (CLI/CI clients that
    /// mint ID tokens themselves). `oauth_client_id` is always accepted. Empty = only the
    /// web client.
    pub audiences: Vec<String>,
    /// Domains permitted to write. If unset, all allowed domains may write.
    pub write_domains: Option<Vec<String>>,
    /// Principals allowed to forward an end-user identity (`X-Walgit-Principal`) to this
    /// server — the host that fronts a push broker. Names as they authenticate here (a static
    /// token's `principal`, or an email).
    pub trusted_forwarders: Vec<String>,
    /// HMAC key for the browser session cookie and for walgit-issued access tokens
    /// (`oidc` mode). Unset = cookie sessions and issued tokens off. When set, must be ≥ 32
    /// bytes; shared by every host that answers a browser.
    pub session_secret: Option<String>,
    /// Session cookie lifetime (default 30 d). Sliding: a response to a request whose
    /// session is older than a quarter of this re-issues the cookie.
    #[serde(with = "humantime_serde")]
    pub session_ttl: Duration,
    /// Lifetime of access tokens minted at `/_auth/tokens` for git and scripts (default 90 d).
    /// Tokens are stateless (HMAC over principal + expiry); rotating `session_secret` revokes
    /// every one of them.
    #[serde(with = "humantime_serde")]
    pub access_token_ttl: Duration,
    /// OAuth client for `/_auth/login` → issuer → `/_auth/callback` (authorization code flow).
    /// Pair with `oauth_client_secret`; both or neither.
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
}

/// Prefix of access tokens walgit mints itself (`/_auth/tokens`): recognisable in logs and
/// secret scanners, never confused with an ID token.
pub const ACCESS_TOKEN_PREFIX: &str = "wgt_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Everyone is `anon` with write. Loopback experiments only.
    #[default]
    None,
    /// Static tokens from the config (`tokens`), bearer or basic.
    Token,
    /// OpenID Connect: browser sign-in through the issuer, ID tokens as bearers, plus
    /// walgit-issued access tokens for git — and `tokens` for robots.
    Oidc,
}

/// A principal's authority inside one tenant (`RepoId.owner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Reader,
    Writer,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantGrant {
    /// Exact authenticated principal, or `*` for every authenticated principal.
    pub principal: String,
    /// Exact repository owner, or `*` for every owner.
    pub tenant: String,
    pub role: TenantRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticToken {
    pub principal: String,
    /// Read from env var if set, else literal.
    pub token: String,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default = "default_true")]
    pub write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StoreConfig {
    pub backend: StoreBackend,
    pub bucket: String,
    /// Global key prefix inside the bucket (no leading slash; trailing slash added).
    pub prefix: String,
    pub gcs: GcsConfig,
    pub s3: S3Config,
    pub max_retries: u32,
    /// Objects larger than this use resumable/multipart upload.
    pub multipart_threshold: ByteSize,
    pub multipart_part_size: ByteSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StoreBackend {
    #[default]
    Gcs,
    S3,
    /// Tests only.
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GcsConfig {
    /// gRPC endpoint.
    pub endpoint: String,
    pub direct_connectivity: bool,
    /// Service account for signed URLs; None = ADC/IAM signBlob.
    pub signing_service_account: Option<String>,
    /// Separate data clients (own channels) for bulk traffic — pack/idx/side-
    /// file/bundle/LFS bytes and ranged reads — so the control plane
    /// (manifest, log, checkpoint, lease GETs/PUTs) never queues behind a
    /// multi-GB download on a shared HTTP/2 connection.
    #[serde(default = "default_bulk_clients")]
    pub bulk_clients: usize,
    /// Max concurrent bulk requests per process (stripes + range reads).
    #[serde(default = "default_bulk_concurrency")]
    pub bulk_concurrency: usize,
}

fn default_bulk_clients() -> usize {
    4
}
fn default_bulk_concurrency() -> usize {
    32
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    /// Selects exactly one credential source. `default_chain` delegates to
    /// the refreshable AWS SDK chain. `explicit_env` requires every named
    /// credential variable to be present and never falls back.
    pub credential_mode: S3CredentialMode,
    /// Custom environment-variable name for an explicit access key. Empty
    /// unless `credential_mode = "explicit_env"`.
    pub access_key_env: String,
    /// Custom environment-variable name for an explicit secret key. This and
    /// `access_key_env` are both required in `explicit_env` mode.
    pub secret_key_env: String,
    /// Optional custom environment-variable name for the session token that
    /// accompanies deliberately configured temporary explicit credentials.
    pub session_token_env: String,
    pub force_path_style: bool,
    /// Independent AWS SDK and HTTP connection pools for pack, bundle, LFS,
    /// temporary raw-payload, and ranged traffic.
    #[serde(default = "default_bulk_clients")]
    pub bulk_clients: usize,
    /// Per-process cap for bulk operations. Control traffic never acquires
    /// these permits.
    #[serde(default = "default_bulk_concurrency")]
    pub bulk_concurrency: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum S3CredentialMode {
    #[default]
    DefaultChain,
    ExplicitEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Local directory holding materialized repositories.
    pub dir: PathBuf,
    /// `budget` (tmpfs: `max_bytes` caps everything on disk; too-large
    /// repos are served remotely/linked) or `disk` (the SSD host, D25: the cache
    /// dir is a real disk — no budget, every repo fully local, eviction only on
    /// disk pressure at `disk_high_watermark`). `auto` = `disk` when
    /// `maintenance.disk = "ssd"`, else `budget`.
    pub mode: CacheMode,
    /// Budget for everything on disk in `budget` mode. Ignored in `disk` mode.
    pub max_bytes: ByteSize,
    /// `disk` mode: evict idle repos (oldest first) when the filesystem holding
    /// `dir` is fuller than this fraction (0 = never evict on pressure).
    pub disk_high_watermark: f64,
    #[serde(with = "humantime_serde")]
    pub evict_idle_after: Duration,
    /// Repos to warm at startup ("owner/name"): refs, then objects (packs when
    /// they fit, otherwise the remote pack indexes) and the default branch's
    /// root tree, so the first request on a fresh instance is not the one that
    /// pays for it. Each runs as a `prewarm` task.
    pub prewarm: Vec<String>,
    pub prewarm_parallelism: usize,
    /// `/readyz` answers 503 until every prewarm finished or this much time
    /// passed (0 = never block readiness). With a serverless host startup probe on
    /// /readyz, traffic only reaches an instance that is already warm.
    #[serde(with = "humantime_serde")]
    pub prewarm_ready_timeout: Duration,
    /// Max entries in the ref advertisement cache (per rendered ls-refs / v0 advert).
    pub ref_advert_entries: usize,
    /// Max entries in the object-info (size/has) cache.
    pub object_info_entries: usize,
    /// Max entries in the bundle list render cache.
    pub bundle_list_entries: usize,
    /// Process-wide LRU of pack data blocks (1 MiB range reads) used when a
    /// repo's pack set does not fit `max_bytes` and objects are read straight
    /// from the object store.
    pub remote_block_bytes: ByteSize,
    /// Per-repo LRU of decoded objects (delta bases) for the remote reader.
    pub remote_object_bytes: ByteSize,
    /// Mirror rendered sha-addressed web API responses into the object store
    /// (`repos/<o>/<r>/cache/api/...`) so every instance shares one render
    /// cache. Only consulted when objects are read remotely (local renders are
    /// cheaper than a store round trip).
    pub shared_render_cache: bool,
    /// Read-only mount of the object-store bucket (gcsfuse, s3fs, rclone, etc.),
    /// e.g. `/mnt/store`. When set, the "Serve" sync level
    /// never copies tier-2 base packs onto tmpfs: their side-files
    /// (idx/rev/bitmap/commit-graph) are downloaded and `pack-<sha>.pack` is a
    /// symlink to `<store_mount>/<store.prefix>repos/<o>/<r>/wal/<sha>.pack`,
    /// so stock git can still read any base object (slowly) while everything
    /// hot (refs, recent packs, indexes, commit-graph) is local.
    pub store_mount: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WalConfig {
    /// Coalesce concurrent publishes to one repo within this window into one index CAS.
    #[serde(with = "humantime_serde")]
    pub batch_window: Duration,
    pub max_batch: usize,
    /// Route receive-pack writes through a single stateless broker when set.
    pub push_broker_url: Option<String>,
    /// Static token this host presents to the broker (`Authorization: Bearer`); the broker
    /// lists it in `server.auth.tokens` and its principal in `trusted_forwarders`.
    /// `WALGIT_BROKER_TOKEN` in the environment overrides it.
    pub push_broker_token: Option<String>,
    /// Maximum receive-pack body retained for a safe broker-to-local fallback.
    pub push_broker_buffer_bytes: ByteSize,
    /// Checkpoint (ref snapshot + pack set, log folded) when this many entries
    /// accumulated since the last one (0 = never by count).
    pub snapshot_every_entries: u64,
    /// ... or when the last checkpoint is older than this (0 = never by age).
    /// Cold readers load checkpoint + tail, so the tail stays short.
    #[serde(with = "humantime_serde")]
    pub checkpoint_interval: Duration,
    /// ... or when the log tail after the checkpoint exceeds this many bytes
    /// (0 = never by size).
    pub checkpoint_tail_bytes: ByteSize,
    pub cas_max_retries: u32,
    /// Verify pushed objects (fsck-level) before publish.
    pub fsck_objects: bool,
    /// Require every pushed ref tip to be connected to existing objects + the pack.
    pub check_connectivity: bool,
    /// Skip the index freshness GET if the last check was younger than this (0 = always check).
    #[serde(with = "humantime_serde")]
    pub freshness_ttl: Duration,
    /// After a refs-only sync (info/refs, ls-refs, bundle-uri, web refs) on a
    /// copy whose packs are not yet reconciled, start downloading the packs in
    /// the background so the first fetch does not pay for it.
    pub prefetch_packs: bool,
    /// Upper bound on what `prefetch_packs` pulls unasked: a pack set whose serving copy would
    /// put more than this on local disk is materialized only when a request needs it (fetch,
    /// push, web object work — narrated, CPU allocated), never because someone opened the
    /// repository page. 2026-08-22: an overview view made a front download acme/large's single
    /// 11.9 GB pack in the background for 5 min (nothing asked for its objects) while the runtime
    /// watchdog fired 11×. 0 = no bound.
    pub prefetch_max_bytes: ByteSize,
    /// When the live pack set exceeds `cache.max_bytes`, serve object reads
    /// (web API) straight from the store: pack indexes local, pack data by
    /// range read. Off => such repos answer 503 for object work.
    pub remote_objects: bool,
}

/// The `maintain` role's loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MaintenanceConfig {
    /// Pause between passes over the assigned repositories.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Checkpoint repos whose trigger fired (see `wal.snapshot_every_entries`,
    /// `wal.checkpoint_interval`, `wal.checkpoint_tail_bytes`).
    pub checkpoints: bool,
    /// Declared capacity: the largest pack set (bytes) this host can hold as a
    /// local copy for a unit that needs one (full repack, incremental cut on a
    /// local copy). 0 = use `cache.max_bytes`. A unit whose need exceeds it is
    /// plan state `wrong-host` — visible, never an error.
    pub max_pack_bytes: ByteSize,
    /// `tmpfs` (a serverless host: disk is memory) | `ssd` (a VM: can repack bases).
    #[serde(default)]
    pub disk: MaintainerDisk,
    /// Heartbeat object name (`maintain/<host>.pb`): who maintains what and
    /// whether that host is alive. Default: the instance id.
    #[serde(default)]
    pub host: Option<String>,
    /// Connectivity audit cadence: `git fsck --connectivity-only` over a complete
    /// local copy, result at `repos/<o>/<r>/fsck.pb` (missing objects →
    /// `walgit_repo_missing_objects{repo}` and the `repair` unit). Lowest
    /// priority unit; only on hosts that hold the whole pack set. 0 = off.
    #[serde(with = "humantime_serde")]
    pub fsck_interval: Duration,
    /// How often the upstream-follow loop (`upstream.follow`, ingress, its own
    /// loop next to the priority loop so a long unit never delays it) fetches
    /// each assigned repository's followed refs. 0 = off on this host.
    #[serde(with = "humantime_serde")]
    pub follow_interval: Duration,
}

/// D25: how the local cache is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Follow `maintenance.disk`: `ssd` ⇒ `disk`, else `budget`.
    #[default]
    Auto,
    /// `cache.max_bytes` is the budget (tmpfs).
    Budget,
    /// No budget: real disk, full materialization, watermark eviction.
    Disk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaintainerDisk {
    #[default]
    Tmpfs,
    Ssd,
}

fn default_all_repos() -> Vec<String> {
    vec!["*".into()]
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        MaintenanceConfig {
            interval: Duration::from_secs(60),
            checkpoints: true,
            max_pack_bytes: ByteSize::b(0),
            disk: MaintainerDisk::Tmpfs,
            host: None,
            fsck_interval: Duration::from_secs(7 * 24 * 3600),
            follow_interval: Duration::from_secs(30),
        }
    }
}

/// Which repositories this host attends to. Two independent roles, each a
/// glob list minus an exclude list (`owner/name` | `owner/*` | `*`):
/// * **serve**: object work — `git-upload-pack`, `git-receive-pack`, LFS transfer. A
///   host that does not serve a repo answers those with 503 + `Retry-After` (+ a band-3
///   line naming the host that does) *before* any sync or materialize; refs-level
///   reads (info/refs, the API via the remote reader, UI, bundle list) stay available
///   everywhere, so the edge's read-only fallback (D29) works.
/// * **maintain**: the maintainer loop's units (checkpoints, bundles, compaction,
///   fsck/repair) — only on hosts with the `maintain` role.
/// Placement is by rule, not by capacity: a repo is either this host's or not.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PlacementConfig {
    pub serve: Vec<String>,
    pub serve_exclude: Vec<String>,
    pub maintain: Vec<String>,
    pub maintain_exclude: Vec<String>,
}

impl Default for PlacementConfig {
    fn default() -> Self {
        PlacementConfig {
            serve: default_all_repos(),
            serve_exclude: Vec::new(),
            maintain: default_all_repos(),
            maintain_exclude: Vec::new(),
        }
    }
}

impl PlacementConfig {
    /// Object work for `owner/name` happens on this host.
    pub fn serves(&self, owner: &str, name: &str) -> bool {
        repo_listed(&self.serve, owner, name) && !repo_listed(&self.serve_exclude, owner, name)
    }
    /// Maintenance units for `owner/name` run on this host (given the role).
    pub fn maintains(&self, owner: &str, name: &str) -> bool {
        repo_listed(&self.maintain, owner, name)
            && !repo_listed(&self.maintain_exclude, owner, name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CompactionConfig {
    pub enabled: bool,
    /// Geometric factor between tiers.
    pub factor: u32,
    /// Compact when this many fresh (tier 0) packs exist.
    pub trigger_packs: usize,
    /// Or when fresh pack bytes exceed this.
    pub trigger_bytes: ByteSize,
    #[serde(with = "humantime_serde")]
    pub lease_ttl: Duration,
    /// Keep superseded packs and old index generations for this long (provenance/rewind).
    #[serde(with = "humantime_serde")]
    pub retention_superseded: Duration,
    /// Use upstream git for delta compression (`git repack`); gix does not delta-compress.
    pub engine: RepackEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RepackEngine {
    #[default]
    Git,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BundlesConfig {
    pub enabled: bool,
    pub strategy: Vec<BundleStrategy>,
    /// Minimum-size gate for **incremental** slots: a slot whose content
    /// (commits on the bundle's refs since its base bundle's tips) has fewer
    /// commits than this is not built (plan state `too-small`; the next slot of
    /// the strategy is built on the same base, so nothing is lost). Fulls are
    /// never gated. 0 = no gate. Per-strategy `min_commits` overrides.
    #[serde(default = "default_min_commits")]
    pub min_commits: u64,
    /// Optional second guard: skip incrementals whose pack would be smaller
    /// than this (0 = off).
    #[serde(default)]
    pub min_bytes: ByteSize,
    pub serve_via: BundleServe,
    #[serde(with = "humantime_serde")]
    pub signed_url_ttl: Duration,
    /// Advertise `bundle-uri` in protocol v2 capabilities.
    pub advertise: bool,
    /// Put the filtered families INTO the plain `bundles/list` and the v2
    /// advertisement (with their `bundle.<id>.filter` lines) instead of only
    /// at `bundles/list?filter=…`. Only for clients whose git matches
    /// `bundle.<id>.filter` against the clone's filter (a patched Git client
    /// patch, `docs/patches/`): stock git ignores the key and a full clone
    /// would swallow the blobless bundles (design §6b). Default false.
    #[serde(default)]
    pub advertise_filtered: bool,
    /// Repositories (`owner/name`, or `owner/*`) whose clones **must** go
    /// through bundle-uri: a fetch with zero `have`s gets a pkt ERR / band-3
    /// message with the exact fix instead of an impossible full pack. Fetches
    /// with haves proceed normally.
    #[serde(default)]
    pub require: Vec<String>,
    /// Repositories (`owner/name` | `owner/*`) whose bundle URIs are always
    /// signed store URLs regardless of `serve_via`: clone bytes of the biggest
    /// repos bypass the fronts entirely.
    #[serde(default)]
    pub signed_url_for: Vec<String>,
    /// Default ref set of a bundle when a strategy has no `refs`: `HEAD` +
    /// `refs/heads/main` when true (branches are tiny per-fetch deltas on top
    /// of main; bundling every branch makes rebased branches *slower* to
    /// fetch, not faster), `refs/heads/*` + `refs/tags/*` + `HEAD` when false.
    #[serde(default = "default_true")]
    pub main_only: bool,
    /// Extra ref globs added to every bundle's default ref set (e.g. `refs/tags/v*`).
    #[serde(default)]
    pub extra_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BundleServe {
    #[default]
    Proxy,
    SignedUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleStrategy {
    pub name: String,
    pub kind: BundleKind,
    /// Cron expression (6 or 7 fields, `cron` crate syntax) or "@hourly"/"@daily"/"@weekly".
    pub schedule: String,
    /// For incremental: name of the strategy this one is based on.
    #[serde(default)]
    pub base: Option<String>,
    /// Full strategies only: how many newest fulls stay listed (>= 1). Incrementals have
    /// no knob — always the 2 newest whose base is kept (`walgit_bundle::slots::INCREMENTALS_KEPT`,
    /// D21 amended 2026-08-22); setting `keep` on one is a configuration error.
    #[serde(default)]
    pub keep: usize,
    /// Ref globs included in the bundle. Default: see `bundles.main_only`.
    #[serde(default)]
    pub refs: Vec<String>,
    /// Backfill horizon: how many missing slots (oldest first) one maintainer
    /// pass may build for this strategy (0 = unlimited). Keeps a long outage
    /// from turning into hours of catch-up in one pass.
    #[serde(default)]
    pub backfill_max: usize,
    /// Override of `bundles.min_commits` for this strategy (None = inherit).
    #[serde(default)]
    pub min_commits: Option<u64>,
    /// Object filter of the bundles this strategy builds (`"blob:none"` is the
    /// only supported value): a **blobless family** for `--filter=blob:none`
    /// clones. A full strategy with a filter composes the D18 history pack
    /// (commits + trees) under a `@filter=blob:none` header; incrementals pack
    /// with `--filter=blob:none`. Whole chains share one filter. Filtered
    /// bundles are advertised only at `bundles/list?filter=blob:none` — never
    /// in the protocol-advertised list: git (2.47 … master) does not match
    /// `bundle.<id>.filter` against the clone's filter, so a full clone would
    /// swallow them and end up with promisor packs it cannot complete.
    #[serde(default)]
    pub filter: Option<String>,
    /// Incrementals only. `false` (default, D21): every slot is cut on its **base** (a daily on the
    /// weekly, an hourly on the newest daily), so the newest one subsumes the older ones and only the
    /// 2 newest are listed — a fresh clone is 5 downloads, a catch-up ≤ 2, bytes overlap.
    /// `true`: a slot is cut on this strategy's **own previous bundle** when that one is newer than
    /// the newest base bundle at or before the slot (dailies chain from the weekly, hourlies restart
    /// from each daily); every slot since the base is listed (≤ 7 dailies, ≤ 24 hourlies) and each
    /// carries exactly its delta — more downloads, no overlapping bytes, a catch-up is exactly the
    /// slots missed. `walgit_bundle::slots` is the one place that knows either rule.
    #[serde(default)]
    pub chain: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LfsConfig {
    pub enabled: bool,
    pub serve_via: BundleServe,
    #[serde(with = "humantime_serde")]
    pub signed_url_ttl: Duration,
    pub max_object_bytes: ByteSize,
}

/// Where a repository's history lives when it is not (all) here: a repository
/// imported from GitHub keeps its LFS objects there, and a hole in the imported
/// pack set (the original large-repository measurements: 1,952 blobs) is repaired from there. Per
/// repository via D24 settings (`[upstream]`); one token for both.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamConfig {
    /// Git remote URL (`https://github.com/acme/monorepo.git`): source for the
    /// maintainer's `repair` unit (fetches exactly the objects `fsck` found
    /// missing; GitHub serves blob/tree wants by SHA).
    pub git: Option<String>,
    /// LFS endpoint (`https://github.com/acme/monorepo.git/info/lfs`): read-through
    /// for LFS objects this store lacks — batch `upload` reports them present
    /// (no actions) so pushes proceed; `download`/GET stream through and persist
    /// after a complete sha256-verified read. Unset = missing objects are 404.
    pub lfs: Option<String>,
    /// Name of an environment variable on the maintaining host that holds the token
    /// (settings live in the bucket, so never the token itself); sent as HTTP Basic
    /// `x-access-token:<token>` (GitHub). Unset = unauthenticated.
    pub token_env: Option<String>,
    /// Refs kept equal to the upstream's (`["refs/heads/main"]`): the host that
    /// maintains the repository (D28: its writer) fetches the delta from `git`
    /// every `maintenance.follow_interval` and publishes it through the WAL as
    /// an ordinary push (fast-forward only; a rewound upstream is refused and
    /// logged until a human decides). Empty = off.
    pub follow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GitConfig {
    /// Path to the upstream git binary (repack, bundle, optional upload-pack engine).
    pub binary: PathBuf,
    pub upload_pack_engine: UploadPackEngine,
    pub allow_filter: bool,
    pub allow_any_sha1_in_want: bool,
    /// Default object format for new repos.
    pub object_format: ObjectFormat,
    /// Maintain a split commit-graph chain per local repo: tier-2 packs that
    /// publish a commit-graph layer install it as the chain base; every other
    /// installed pack is folded in incrementally (`commit-graph write --split`).
    /// History walks then never touch base pack data.
    #[serde(default = "default_true")]
    pub commit_graph: bool,
    /// Compute changed-path Bloom filters for incremental layers (`git log --
    /// path` speed-up). Diffs new commits against parent trees, so it needs
    /// the parents' tree data reachable (local or mounted base pack).
    #[serde(default)]
    pub commit_graph_changed_paths: bool,
    /// At a base rebuild, also publish a **history pack** (commits + trees of
    /// the base, `pack-objects --filter=blob:none`) that instances keep as a
    /// real local pack next to a linked/remote base (D18).
    #[serde(default = "default_true")]
    pub history_pack: bool,
    /// Refuse a v2 `fetch` asking for more than this many objects (0 = no bound). A blobless clone
    /// without `--sparse`/`--no-checkout` makes git fetch every blob of HEAD's tree in one lazy
    /// request right after cloning (a large repository: 1.47 M wants, 49 GB RSS, > 12 min on the SSD host); the
    /// refusal names the fix. Ordinary fetches want a handful of tips; a `--sparse` checkout fetches
    /// its cone's blobs, a few thousand at most. Set it per host above the largest honest request.
    #[serde(default)]
    pub max_wants: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UploadPackEngine {
    /// In-process gitoxide engine (`walgit-git/src/upload_gix.rs`): commit-graph walks,
    /// tree-diff enumeration, streaming, base objects faulted by range when the base is
    /// remote-served. Best for commit fetches and filtered/shallow clones.
    Gix,
    /// `git upload-pack --stateless-rpc` subprocess: delta reuse + bitmaps; best for
    /// many-blob wants (a partial clone's lazy checkout) and full unfiltered clones.
    Git,
    /// Per request: gix for commit wants, git when the wants are blobs/trees (lazy
    /// checkout). Default since 2026-08-20 (the original A/B/C measurements).
    #[default]
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFormat {
    #[default]
    Sha1,
    Sha256,
}

/// Events (`docs/EVENTS.md`): the bridge (`Role::Events`) tails every repo's
/// WAL from a durable cursor and publishes `ref` events to the webhook. Only the
/// bridge reads this section; nothing on the push path does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EventsConfig {
    /// Where ref events go: each batch is `POST`ed as a JSON array (`docs/EVENTS.md`).
    /// Unset = the events role has nothing to do.
    pub webhook_url: Option<String>,
    /// Shared secret for `X-Walgit-Signature: sha256=<HMAC-SHA256 of the body>`. Unset = unsigned.
    pub webhook_secret: Option<String>,
    /// Catch-all sweep over every repo (a `list` + one conditional manifest
    /// GET per repo), the backstop behind store notifications; the bridge
    /// warns when a sweep finds unpublished entries. `0` = off.
    #[serde(with = "humantime_serde")]
    pub sweep_interval: Duration,
}

impl Default for EventsConfig {
    fn default() -> Self {
        EventsConfig {
            webhook_url: None,
            webhook_secret: None,
            sweep_interval: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// `json` (Cloud Logging) or `pretty`.
    pub log_format: LogFormat,
    pub log_filter: String,
    /// Prometheus scrape endpoint on the main listener (`/metrics`).
    pub metrics: bool,
    /// GCP project id for Cloud Logging trace correlation.
    /// Falls back to env `GOOGLE_CLOUD_PROJECT` then the metadata server.
    pub trace_project: Option<String>,
    /// A wait on a per-repository lock or a store permit on a request path (`RepoHandle::rw`,
    /// `sync_mutex`, `pack_mutex`, the GCS bulk permits) longer than this is logged as a WARN
    /// `lock wait` line with `lock`, `repo`, `wait_ms` (+ the request's id from the span); every
    /// wait that was not immediately satisfied lands in `walgit_lock_wait_seconds{lock}`. D19's
    /// incident (a queued writer starving readers for 60–680 s) is what this makes visible.
    #[serde(with = "humantime_serde")]
    pub lock_wait_warn: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Json,
    Pretty,
}

fn default_min_commits() -> u64 {
    25
}
fn default_true() -> bool {
    true
}

/// D24: the top-level sections a repository's settings may override.
pub const SETTINGS_SECTIONS: &[&str] = &["bundles", "maintenance", "compaction", "upstream"];
const SETTINGS_BUNDLES_FIELDS: &[&str] = &[
    "enabled",
    "strategy",
    "min_commits",
    "min_bytes",
    "serve_via",
    "signed_url_ttl",
    "advertise",
    "advertise_filtered",
    "require",
    "signed_url_for",
    "main_only",
    "extra_refs",
];
const SETTINGS_BUNDLE_STRATEGY_FIELDS: &[&str] = &[
    "name",
    "kind",
    "schedule",
    "base",
    "keep",
    "refs",
    "backfill_max",
    "min_commits",
    "filter",
    "chain",
];
const SETTINGS_MAINTENANCE_FIELDS: &[&str] = &[
    "interval",
    "checkpoints",
    "max_pack_bytes",
    "disk",
    "host",
    "fsck_interval",
    "follow_interval",
];
const SETTINGS_COMPACTION_FIELDS: &[&str] = &[
    "enabled",
    "factor",
    "trigger_packs",
    "trigger_bytes",
    "lease_ttl",
    "retention_superseded",
    "engine",
];
const SETTINGS_UPSTREAM_FIELDS: &[&str] = &["git", "lfs", "token_env", "follow"];
/// D24: maximum size of a settings document.
pub const SETTINGS_MAX_BYTES: usize = 16 * 1024;

fn settings_section_fields(section: &str) -> Option<&'static [&'static str]> {
    match section {
        "bundles" => Some(SETTINGS_BUNDLES_FIELDS),
        "maintenance" => Some(SETTINGS_MAINTENANCE_FIELDS),
        "compaction" => Some(SETTINGS_COMPACTION_FIELDS),
        "upstream" => Some(SETTINGS_UPSTREAM_FIELDS),
        _ => None,
    }
}

fn ensure_settings_fields(table: &toml::Table, path: &str, allowed: &[&str]) -> Result<()> {
    for key in table.keys() {
        anyhow::ensure!(
            allowed.contains(&key.as_str()),
            "settings: key {path}.{key} may not be set per repository"
        );
    }
    Ok(())
}

fn reject_settings_child_keys(value: &toml::Value, path: &str) -> Result<()> {
    match value {
        toml::Value::Table(table) => {
            if let Some(key) = table.keys().next() {
                anyhow::bail!("settings: key {path}.{key} may not be set per repository");
            }
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_settings_child_keys(item, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_settings_strategy(table: &toml::Table, path: &str) -> Result<()> {
    ensure_settings_fields(table, path, SETTINGS_BUNDLE_STRATEGY_FIELDS)?;
    for (key, value) in table {
        reject_settings_child_keys(value, &format!("{path}.{key}"))?;
    }
    Ok(())
}

fn validate_settings_fields(overrides: &toml::Table) -> Result<()> {
    for (section, value) in overrides {
        let Some(allowed) = settings_section_fields(section) else {
            anyhow::bail!(
                "settings: section [{section}] may not be set per repository (allowed: {})",
                SETTINGS_SECTIONS.join(", ")
            );
        };
        let Some(table) = value.as_table() else {
            continue;
        };
        ensure_settings_fields(table, section, allowed)?;
        for (key, value) in table {
            if section != "bundles" || key != "strategy" {
                reject_settings_child_keys(value, &format!("{section}.{key}"))?;
            }
        }
        if section == "bundles"
            && let Some(strategy) = table.get("strategy")
        {
            match strategy {
                toml::Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        if let Some(item) = item.as_table() {
                            validate_settings_strategy(
                                item,
                                &format!("bundles.strategy[{index}]"),
                            )?;
                        } else {
                            reject_settings_child_keys(
                                item,
                                &format!("bundles.strategy[{index}]"),
                            )?;
                        }
                    }
                }
                toml::Value::Table(item) => validate_settings_strategy(item, "bundles.strategy")?,
                _ => {}
            }
        }
    }
    Ok(())
}

impl Config {
    /// D24: the effective configuration for one repository = this (the host's
    /// walgit.toml ⊕ env) with the repository's settings TOML merged on top.
    /// Only [`SETTINGS_SECTIONS`] may appear; the result is validated like a
    /// config file. Empty settings = `self` unchanged.
    pub fn with_settings(&self, settings_toml: &str) -> Result<Config> {
        if settings_toml.trim().is_empty() {
            return Ok(self.clone());
        }
        anyhow::ensure!(
            settings_toml.len() <= SETTINGS_MAX_BYTES,
            "settings document larger than {SETTINGS_MAX_BYTES} bytes"
        );
        let overrides: toml::Table = settings_toml
            .parse()
            .map_err(|error| source_free_toml_error("settings: invalid TOML", error))?;
        validate_settings_fields(&overrides)?;
        let mut doc: toml::Table = toml::Table::try_from(self).context("serializing config")?;
        fn merge(into: &mut toml::Table, from: &toml::Table) {
            for (k, v) in from {
                match (into.get_mut(k), v) {
                    (Some(toml::Value::Table(a)), toml::Value::Table(b)) => merge(a, b),
                    _ => {
                        into.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        merge(&mut doc, &overrides);
        let cfg: Config = doc.try_into().map_err(|error| {
            source_free_toml_error("settings: invalid effective configuration", error)
        })?;
        cfg.validate()
            .context("settings: validating the effective config")?;
        anyhow::ensure!(
            cfg.bundles.signed_url_ttl <= self.bundles.signed_url_ttl,
            "settings: bundles.signed_url_ttl may not exceed the host maximum ({:?})",
            self.bundles.signed_url_ttl
        );
        Ok(cfg)
    }

    /// D25: the effective on-disk budget — `cache.max_bytes` in budget mode,
    /// **0 = unlimited** in disk mode (the SSD host: `maintenance.disk = "ssd"` or
    /// `cache.mode = "disk"`). Every fits/plan decision goes through this.
    pub fn cache_budget_bytes(&self) -> u64 {
        if self.cache_is_disk() {
            0
        } else {
            self.cache.max_bytes.as_u64()
        }
    }
    /// Whether the cache is a real disk (no budget; watermark eviction).
    pub fn cache_is_disk(&self) -> bool {
        match self.cache.mode {
            CacheMode::Disk => true,
            CacheMode::Budget => false,
            CacheMode::Auto => self.maintenance.disk == MaintainerDisk::Ssd,
        }
    }
    /// Bundle strategies form chains of calendar slots (docs/BUNDLE_URI_DESIGN.md §4):
    /// every `schedule` is a 6-field UTC cron (or an `@alias`) that parses; an
    /// incremental names a `base` that exists and whose chain ends in a full
    /// strategy; each chain has exactly one full root; `keep >= 1` on fulls.
    fn validate_bundle_strategies(&self) -> Result<()> {
        use std::collections::HashMap;
        let strategies = &self.bundles.strategy;
        let by_name: HashMap<&str, &BundleStrategy> =
            strategies.iter().map(|s| (s.name.as_str(), s)).collect();
        anyhow::ensure!(
            by_name.len() == strategies.len(),
            "bundles.strategy: duplicate strategy names"
        );
        for s in strategies {
            let expr = s.schedule.trim();
            let fields = expr.split_whitespace().count();
            anyhow::ensure!(
                expr.starts_with('@') || fields == 6 || fields == 7,
                "bundles.strategy {}: schedule {:?} must be a 6-field UTC cron (sec min hour dom mon dow) or @hourly/@daily/@weekly",
                s.name,
                s.schedule
            );
            cron::Schedule::from_str(expr).map_err(|e| {
                anyhow::anyhow!(
                    "bundles.strategy {}: schedule {:?} does not parse: {e}",
                    s.name,
                    s.schedule
                )
            })?;
            if let Some(f) = &s.filter {
                anyhow::ensure!(
                    f == "blob:none",
                    "bundles.strategy {}: filter {f:?} is not supported (only \"blob:none\")",
                    s.name
                );
            }
            match s.kind {
                BundleKind::Full => {
                    anyhow::ensure!(
                        s.base.is_none(),
                        "bundles.strategy {}: a full strategy has no base",
                        s.name
                    );
                    anyhow::ensure!(
                        !s.chain,
                        "bundles.strategy {}: `chain` is an incremental knob",
                        s.name
                    );
                    anyhow::ensure!(
                        s.keep >= 1,
                        "bundles.strategy {}: keep must be >= 1 on a full strategy",
                        s.name
                    );
                }
                BundleKind::Incremental => {
                    anyhow::ensure!(
                        s.keep == 0,
                        "bundles.strategy {}: `keep` is not a knob on an incremental strategy — the 2 newest whose base is kept are always listed (D21, 2026-08-22); remove it",
                        s.name
                    );
                    let mut cur = s;
                    let mut hops = 0;
                    loop {
                        let base = cur.base.as_deref().ok_or_else(|| {
                            anyhow::anyhow!("bundles.strategy {}: incremental needs base", cur.name)
                        })?;
                        let b = by_name.get(base).ok_or_else(|| {
                            anyhow::anyhow!(
                                "bundles.strategy {}: base {base} is not a strategy",
                                cur.name
                            )
                        })?;
                        anyhow::ensure!(
                            b.filter == s.filter,
                            "bundles.strategy {}: filter {:?} differs from its base {}'s {:?} (a chain shares one filter)",
                            s.name,
                            s.filter,
                            b.name,
                            b.filter
                        );
                        if b.kind == BundleKind::Full {
                            break;
                        }
                        cur = b;
                        hops += 1;
                        anyhow::ensure!(
                            hops < 16,
                            "bundles.strategy {}: base chain has a cycle",
                            s.name
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// `owner/name` matches an entry of `list` (`owner/name`, `owner/*`, `*`; `.git` tolerated).
/// The `placement` table as the env overrides alone set it (None when no
/// `WALGIT__PLACEMENT__*` variable was present).
fn env_placement_overrides(doc: &toml::Table, vars_seen: &[String]) -> Option<toml::Value> {
    let keys: Vec<String> = vars_seen
        .iter()
        .filter_map(|k| k.strip_prefix("WALGIT__PLACEMENT__"))
        .map(|k| k.to_ascii_lowercase())
        .collect();
    if keys.is_empty() {
        return None;
    }
    let table = doc.get("placement")?.as_table()?;
    let mut out = toml::Table::new();
    for k in keys {
        if let Some(v) = table.get(&k) {
            out.insert(k, v.clone());
        }
    }
    Some(toml::Value::Table(out))
}

pub fn repo_listed(list: &[String], owner: &str, name: &str) -> bool {
    list.iter().any(|r| {
        let r = r.trim().trim_end_matches(".git");
        r == format!("{owner}/{name}") || r == format!("{owner}/*") || r == "*"
    })
}

fn valid_repo_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != ".."
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig::default(),
            store: StoreConfig::default(),
            cache: CacheConfig::default(),
            wal: WalConfig::default(),
            compaction: CompactionConfig::default(),
            maintenance: MaintenanceConfig::default(),
            bundles: BundlesConfig::default(),
            placement: PlacementConfig::default(),
            lfs: LfsConfig::default(),
            upstream: UpstreamConfig::default(),
            git: GitConfig::default(),
            telemetry: TelemetryConfig::default(),
            events: EventsConfig::default(),
        }
    }
}
impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            http2: true,
            max_concurrent_requests: 512,
            max_concurrent_per_repo: 64,
            request_timeout: Duration::from_secs(3600),
            drain_timeout: Duration::from_secs(20),
            max_push_bytes: ByteSize::gib(64),
            roles: vec![],
            auth: AuthConfig::default(),
            public_url: None,
            auto_create_on_push: false,
            accel_redirect: false,
            cors_origins: vec![],
            tls: TlsConfig::default(),
        }
    }
}
impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            mode: AuthMode::None,
            anonymous_read: true,
            tokens: vec![],
            tenant_grants: vec![],
            platform_operators: vec![],
            issuer: "https://accounts.google.com".into(),
            allowed_domains: vec![],
            allowed_emails: vec![],
            audiences: vec![],
            write_domains: None,
            trusted_forwarders: vec![],
            session_secret: None,
            session_ttl: Duration::from_secs(30 * 24 * 3600),
            access_token_ttl: Duration::from_secs(90 * 24 * 3600),
            oauth_client_id: None,
            oauth_client_secret: None,
        }
    }
}
impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            backend: StoreBackend::Gcs,
            bucket: "walgit".into(),
            prefix: String::new(),
            gcs: GcsConfig::default(),
            s3: S3Config::default(),
            max_retries: 8,
            multipart_threshold: ByteSize::mib(64),
            multipart_part_size: ByteSize::mib(32),
        }
    }
}
impl Default for GcsConfig {
    fn default() -> Self {
        GcsConfig {
            endpoint: "https://storage.googleapis.com".into(),
            direct_connectivity: true,
            signing_service_account: None,
            bulk_clients: 4,
            bulk_concurrency: 32,
        }
    }
}
impl Default for S3Config {
    fn default() -> Self {
        S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            credential_mode: S3CredentialMode::DefaultChain,
            access_key_env: String::new(),
            secret_key_env: String::new(),
            session_token_env: String::new(),
            force_path_style: true,
            bulk_clients: 4,
            bulk_concurrency: 32,
        }
    }
}
impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            dir: PathBuf::from("/tmp/walgit"),
            mode: CacheMode::Auto,
            max_bytes: ByteSize::gib(20),
            disk_high_watermark: 0.9,
            evict_idle_after: Duration::from_secs(6 * 3600),
            prewarm: vec![],
            prewarm_parallelism: 2,
            prewarm_ready_timeout: Duration::ZERO,
            ref_advert_entries: 256,
            object_info_entries: 4096,
            bundle_list_entries: 128,
            remote_block_bytes: ByteSize::gib(1),
            remote_object_bytes: ByteSize::mib(256),
            shared_render_cache: true,
            store_mount: None,
        }
    }
}
impl Default for WalConfig {
    fn default() -> Self {
        WalConfig {
            batch_window: Duration::from_millis(5),
            max_batch: 64,
            push_broker_url: None,
            push_broker_token: None,
            push_broker_buffer_bytes: ByteSize::mib(64),
            snapshot_every_entries: 256,
            checkpoint_interval: Duration::from_secs(3600),
            checkpoint_tail_bytes: ByteSize::mib(8),
            cas_max_retries: 16,
            fsck_objects: true,
            check_connectivity: true,
            freshness_ttl: Duration::ZERO,
            prefetch_packs: true,
            prefetch_max_bytes: ByteSize::gib(1),
            remote_objects: true,
        }
    }
}
impl Default for CompactionConfig {
    fn default() -> Self {
        CompactionConfig {
            enabled: true,
            factor: 2,
            trigger_packs: 16,
            trigger_bytes: ByteSize::gib(1),
            lease_ttl: Duration::from_secs(600),
            retention_superseded: Duration::from_secs(7 * 24 * 3600),
            engine: RepackEngine::Git,
        }
    }
}
impl Default for BundlesConfig {
    fn default() -> Self {
        BundlesConfig {
            enabled: true,
            strategy: vec![
                BundleStrategy {
                    name: "weekly".into(),
                    kind: BundleKind::Full,
                    // Sunday 23:00 UTC (slot = fire time; backfilled when missed).
                    schedule: "0 0 23 * * Sun".into(),
                    base: None,
                    keep: 2,
                    refs: vec![],
                    backfill_max: 0,
                    min_commits: None,
                    filter: None,
                    chain: false,
                },
                BundleStrategy {
                    name: "daily".into(),
                    kind: BundleKind::Incremental,
                    schedule: "0 0 23 * * *".into(),
                    base: Some("weekly".into()),
                    keep: 0,
                    refs: vec![],
                    backfill_max: 0,
                    min_commits: None,
                    filter: None,
                    chain: true,
                },
                BundleStrategy {
                    name: "hourly".into(),
                    kind: BundleKind::Incremental,
                    schedule: "@hourly".into(),
                    base: Some("daily".into()),
                    keep: 0,
                    refs: vec![],
                    backfill_max: 0,
                    min_commits: None,
                    filter: None,
                    chain: false,
                },
            ],
            serve_via: BundleServe::Proxy,
            signed_url_ttl: Duration::from_secs(3600),
            advertise: true,
            advertise_filtered: false,
            require: Vec::new(),
            signed_url_for: Vec::new(),
            main_only: true,
            extra_refs: Vec::new(),
            min_commits: 25,
            min_bytes: ByteSize::b(0),
        }
    }
}
impl Default for LfsConfig {
    fn default() -> Self {
        LfsConfig {
            enabled: true,
            serve_via: BundleServe::Proxy,
            signed_url_ttl: Duration::from_secs(3600),
            max_object_bytes: ByteSize::gib(16),
        }
    }
}
impl Default for GitConfig {
    fn default() -> Self {
        GitConfig {
            binary: PathBuf::from("git"),
            upload_pack_engine: UploadPackEngine::Auto,
            allow_filter: true,
            allow_any_sha1_in_want: false,
            object_format: ObjectFormat::Sha1,
            commit_graph: true,
            commit_graph_changed_paths: false,
            history_pack: true,
            max_wants: 0,
        }
    }
}
impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig {
            log_format: LogFormat::Json,
            log_filter: "info,walgit=debug".into(),
            metrics: true,
            trace_project: None,
            lock_wait_warn: Duration::from_secs(1),
        }
    }
}

fn authority_contains_userinfo(raw: &str) -> bool {
    raw.split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn validated_http_url(field: &str, raw: &str, allow_query: bool) -> Result<url::Url> {
    anyhow::ensure!(
        raw.starts_with("http://") || raw.starts_with("https://"),
        "{field} must use exact http:// or https:// URL syntax"
    );
    anyhow::ensure!(!raw.contains('\\'), "{field} must not contain a backslash");
    let parsed = url::Url::parse(raw).with_context(|| format!("{field} must be a valid URL"))?;
    anyhow::ensure!(parsed.host_str().is_some(), "{field} must include a host");
    anyhow::ensure!(
        !authority_contains_userinfo(raw)
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "{field} must not contain userinfo"
    );
    anyhow::ensure!(
        allow_query || parsed.query().is_none(),
        "{field} must not contain a query"
    );
    anyhow::ensure!(
        parsed.fragment().is_none(),
        "{field} must not contain a fragment"
    );
    Ok(parsed)
}

fn validated_cors_origin(raw: &str) -> Result<()> {
    anyhow::ensure!(
        raw.matches('*').count() <= 1 && (!raw.contains('*') || raw.starts_with("https://*.")),
        "server.cors_origins entries allow at most one leading https wildcard"
    );
    let normalized = raw
        .strip_prefix("https://*.")
        .map(|rest| format!("https://walgit-wildcard.{rest}"))
        .unwrap_or_else(|| raw.to_string());
    let parsed = validated_http_url("server.cors_origins", &normalized, false)?;
    anyhow::ensure!(
        parsed.path() == "/",
        "server.cors_origins entries must be origins without a path"
    );
    anyhow::ensure!(
        parsed.scheme() == "https"
            || (parsed.scheme() == "http" && parsed.host_str() == Some("localhost")),
        "server.cors_origins entries must use https (http is allowed only for localhost)"
    );
    Ok(())
}

pub(crate) fn diagnostic_url(raw: &str) -> Option<String> {
    if !(raw.starts_with("http://") || raw.starts_with("https://")) || raw.contains('\\') {
        return None;
    }
    let mut parsed = url::Url::parse(raw).ok()?;
    parsed.host_str()?;
    parsed.set_password(None).ok()?;
    parsed.set_username("").ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    if parsed.path() != "/" {
        parsed.set_path("/_path_redacted_");
    }
    Some(parsed.into())
}

pub(crate) fn diagnostic_cors_origin(raw: &str) -> Option<String> {
    let wildcard = raw.strip_prefix("https://*.");
    let normalized = wildcard
        .map(|rest| format!("https://walgit-wildcard.{rest}"))
        .unwrap_or_else(|| raw.to_string());
    let sanitized = diagnostic_url(&normalized)?;
    Some(if wildcard.is_some() {
        sanitized.replacen("walgit-wildcard.", "*.", 1)
    } else {
        sanitized
    })
}

fn config_env_vars(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Result<Vec<(String, String)>> {
    let mut config_vars = Vec::new();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        if key != "PORT" && !key.starts_with("WALGIT__") {
            continue;
        }
        let key = key.to_string();
        let value = value.into_string().map_err(|_| {
            anyhow::anyhow!("environment variable {key} contains a non-Unicode value")
        })?;
        config_vars.push((key, value));
    }
    Ok(config_vars)
}

/// Map TOML deserialization failures without retaining parser messages or
/// source snippets. `toml::de::Error` can contain the complete attacker- or
/// operator-authored line, including credential-bearing URL paths.
fn source_free_toml_error(category: &'static str, _error: toml::de::Error) -> anyhow::Error {
    anyhow::anyhow!(category)
}

impl Config {
    pub fn parse(toml_text: &str) -> Result<Config> {
        let mut cfg: Config = toml::from_str(toml_text)
            .map_err(|error| source_free_toml_error("config: invalid TOML", error))?;
        cfg.apply_env(config_env_vars(std::env::vars_os())?.into_iter())?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text)
    }

    /// Apply `WALGIT__a__b=v` overrides (values parsed as TOML values, falling back to string)
    /// and a serverless host's `PORT`.
    ///
    /// Config and image are released independently (the ssd-host host follows
    /// the serving image's version): an override for a key **unknown to this build**
    /// (or with an unparsable value) is **ignored with a WARN**, never a
    /// startup failure (2026-08-21: `unknown field disk_high_watermark`
    /// crash-looped a host running the previous image). The ignored keys are
    /// returned by [`apply_env_report`].
    pub fn apply_env(&mut self, vars: impl Iterator<Item = (String, String)>) -> Result<()> {
        let ignored = self.apply_env_report(vars)?;
        for (k, why) in &ignored {
            tracing::warn!(key = %k, reason = %why, "ignoring {k}: unknown in this build");
        }
        Ok(())
    }

    /// [`apply_env`] returning the `(key, reason)` pairs it had to ignore.
    pub fn apply_env_report(
        &mut self,
        vars: impl Iterator<Item = (String, String)>,
    ) -> Result<Vec<(String, String)>> {
        let mut vars_seen: Vec<String> = Vec::new();
        let mut doc: toml::Table = toml::Table::try_from(&*self).context("serializing config")?;
        let mut touched = false;
        let mut ignored = Vec::new();
        let mut port_override = None;
        for (k, v) in vars {
            if k == "PORT" {
                port_override = v.parse::<u16>().ok();
                continue;
            }
            let Some(rest) = k.strip_prefix("WALGIT__") else {
                continue;
            };
            vars_seen.push(k.clone());
            let path: Vec<String> = rest.split("__").map(|s| s.to_ascii_lowercase()).collect();
            if path.is_empty() || path.iter().any(|p| p.is_empty()) {
                continue;
            }
            let value: toml::Value = v
                .parse::<toml::Value>()
                .unwrap_or(toml::Value::String(v.clone()));
            // Apply into a copy and type-check it alone: a bad/unknown key is
            // dropped (WARN) instead of failing every other override with it.
            let mut trial = doc.clone();
            let bad = {
                fn set(
                    cur: &mut toml::Table,
                    path: &[String],
                    value: toml::Value,
                ) -> std::result::Result<(), String> {
                    if path.len() == 1 {
                        cur.insert(path[0].clone(), value);
                        return Ok(());
                    }
                    let next = cur
                        .entry(path[0].clone())
                        .or_insert_with(|| toml::Value::Table(Default::default()))
                        .as_table_mut()
                        .ok_or_else(|| format!("{} is not a table", path[0]))?;
                    set(next, &path[1..], value)
                }
                match set(&mut trial, &path, value) {
                    Err(why) => Some(why),
                    Ok(()) => trial.clone().try_into::<Config>().err().map(|error| {
                        source_free_toml_error("invalid configuration override", error).to_string()
                    }),
                }
            };
            match bad {
                Some(why) => ignored.push((k, why)),
                None => {
                    doc = trial;
                    touched = true;
                }
            }
        }
        // `[placement]` is a host fact set as a GROUP: any WALGIT__PLACEMENT__* override
        // replaces the whole section (unset keys = the section's defaults), never
        // merges with the baked file's. 2026-08-21 07:00Z: the image's toml carried
        // the serverless host shape (serve_exclude = ["acme/monorepo"]); the SSD host's env set only
        // MAINTAIN* and inherited the exclude — it refused its own repo for 12 min.
        if let Some(toml::Value::Table(env_placement)) = env_placement_overrides(&doc, &vars_seen) {
            let mut fresh: toml::Table =
                toml::Table::try_from(PlacementConfig::default()).context("placement defaults")?;
            for (k, v) in env_placement {
                fresh.insert(k, v);
            }
            doc.insert("placement".into(), toml::Value::Table(fresh));
            touched = true;
        }
        if touched {
            *self = doc
                .try_into()
                .map_err(|error| source_free_toml_error("invalid environment overrides", error))?;
        }
        if let Some(port) = port_override {
            self.server.listen.set_port(port);
            // Standalone / `dev server`: public_url is the origin the browser hits. Keep its
            // port in lockstep with PORT. A real public_url is left alone.
            if let Some(u) = self.server.public_url.as_mut() {
                if origin_is_loopback(u) {
                    *u = rewrite_origin_port(u, port);
                }
            }
        }
        Ok(ignored)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.store.bucket.is_empty(), "store.bucket must be set");
        // Validate inactive credential selectors too: the safe diagnostic
        // view includes them, so arbitrary strings must not become an output
        // channel merely because another backend is selected.
        self.store.validate_s3_credential_selector()?;
        if self.store.backend == StoreBackend::S3 {
            self.store.validate_s3()?;
        }
        let t = &self.server.tls;
        match t.mode {
            TlsMode::Files => anyhow::ensure!(
                t.cert.is_some() && t.key.is_some(),
                "server.tls.cert and server.tls.key must both be set in files mode"
            ),
            TlsMode::Off | TlsMode::SelfSigned => anyhow::ensure!(
                t.cert.is_none() && t.key.is_none(),
                "server.tls.cert/key are only read in files mode (got mode = {:?})",
                t.mode
            ),
        }
        if t.mode != TlsMode::SelfSigned {
            anyhow::ensure!(
                t.hostnames.is_empty(),
                "server.tls.hostnames only applies to self_signed mode"
            );
        }
        if let Some(u) = &self.server.public_url {
            validated_http_url("server.public_url", u, false)?;
        }
        for (field, endpoint) in [
            ("store.gcs.endpoint", self.store.gcs.endpoint.as_str()),
            ("store.s3.endpoint", self.store.s3.endpoint.as_str()),
        ] {
            if !endpoint.is_empty() {
                validated_http_url(field, endpoint, false)?;
            }
        }
        if let Some(url) = &self.wal.push_broker_url {
            validated_http_url("wal.push_broker_url", url, false)?;
        }
        self.validate_bundle_strategies()?;
        // You cannot maintain what you refuse to serve: a host with the serve role
        // whose maintain rules name a repository its serve rules exclude is a config
        // error (the SSD host 2026-08-21 07:00Z: maintain = ["acme/monorepo"], inherited
        // serve_exclude = ["acme/monorepo"] → refused its own repo). Checked on the
        // literal names in `maintain` (globs are not expanded).
        if self.has_role(Role::Serve) {
            for m in &self.placement.maintain {
                if let Some((o, n)) = m.split_once('/')
                    && !n.contains('*')
                    && !o.contains('*')
                    && !self.placement.serves(o, n)
                    && self.placement.maintains(o, n)
                {
                    anyhow::bail!(
                        "placement: this host maintains {m} but its serve rules exclude it (serve = {:?}, serve_exclude = {:?}) — you cannot maintain what you refuse to serve",
                        self.placement.serve,
                        self.placement.serve_exclude
                    );
                }
            }
        }
        for (key, u) in [
            ("upstream.git", &self.upstream.git),
            ("upstream.lfs", &self.upstream.lfs),
        ] {
            if let Some(u) = u {
                let parsed = validated_http_url(key, u, false)?;
                let is_https = u.starts_with("https://");
                let is_local_http = u.starts_with("http://")
                    && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1"));
                anyhow::ensure!(
                    is_https || is_local_http,
                    "{key} must be an https:// URL (http is allowed only for localhost or 127.0.0.1)"
                );
                anyhow::ensure!(
                    !parsed.path().ends_with('/'),
                    "{key} path must not end with '/'"
                );
            }
        }
        if !self.upstream.follow.is_empty() {
            anyhow::ensure!(
                self.upstream.git.is_some(),
                "upstream.follow needs upstream.git (the host to follow)"
            );
            for r in &self.upstream.follow {
                anyhow::ensure!(
                    r.starts_with("refs/") && !r.ends_with('/') && !r.contains('*'),
                    "upstream.follow entries are full ref names (refs/heads/main), got {r:?}"
                );
            }
        }
        for origin in &self.server.cors_origins {
            validated_cors_origin(origin)?;
        }
        if self.store.backend == StoreBackend::Gcs && self.server.auth.mode != AuthMode::None {
            anyhow::ensure!(
                self.lfs.serve_via != BundleServe::SignedUrl
                    && self.bundles.serve_via != BundleServe::SignedUrl
                    && self.bundles.signed_url_for.is_empty(),
                "authenticated GCS tenants must serve LFS and bundles through the proxy because GCS signed URLs inherit public object cache metadata"
            );
        }
        for o in &self.server.cors_origins {
            let host = o
                .strip_prefix("https://")
                .or_else(|| o.strip_prefix("http://localhost").map(|_| "localhost"))
                .filter(|h| !h.is_empty() && !h.contains('/'));
            anyhow::ensure!(
                host.is_some()
                    && o.matches('*').count() <= 1
                    && (!o.contains('*') || o.contains("://*.")),
                "server.cors_origins entries must be https origins (or http://localhost[:port]) with at most one leading `*.` wildcard, got {o:?}"
            );
        }
        // Security contract: identity modes fail closed.
        let a = &self.server.auth;
        let issuer = if a.issuer.is_empty() {
            None
        } else {
            Some(validated_http_url("server.auth.issuer", &a.issuer, false)?)
        };
        if a.mode == AuthMode::Token {
            anyhow::ensure!(
                !a.tokens.is_empty(),
                "server.auth.tokens must list at least one token in token mode"
            );
        }
        for (index, t) in a.tokens.iter().enumerate() {
            anyhow::ensure!(
                !t.principal.is_empty() && !t.principal.eq_ignore_ascii_case("anonymous"),
                "server.auth.tokens[{index}].principal must be non-empty and may not be the reserved anonymous identity"
            );
            if let Some(name) = &t.token_env {
                anyhow::ensure!(
                    !name.is_empty(),
                    "server.auth.tokens[{index}].token_env must not be empty"
                );
                anyhow::ensure!(
                    !name.contains(['=', '\0']),
                    "server.auth.tokens[{index}].token_env is not a valid environment variable name"
                );
            }
            anyhow::ensure!(
                !t.token.is_empty() || t.token_env.is_some(),
                "server.auth.tokens[{index}] needs `token` or `token_env`"
            );
        }
        for grant in &a.tenant_grants {
            anyhow::ensure!(
                !grant.principal.trim().is_empty(),
                "server.auth.tenant_grants[].principal must not be empty"
            );
            anyhow::ensure!(
                grant.tenant == "*" || valid_repo_part(&grant.tenant),
                "server.auth.tenant_grants[] tenant {:?} must be `*` or an owner name using ASCII [A-Za-z0-9._-] without a leading dot",
                grant.tenant
            );
            anyhow::ensure!(
                !grant.principal.eq_ignore_ascii_case("anonymous")
                    || grant.role == TenantRole::Reader,
                "server.auth.tenant_grants[] for anonymous must use the reader role"
            );
        }
        for principal in &a.platform_operators {
            anyhow::ensure!(
                !principal.trim().is_empty()
                    && principal != "*"
                    && !principal.eq_ignore_ascii_case("anonymous"),
                "server.auth.platform_operators entries must be exact non-anonymous principals"
            );
        }
        if let Some(secret) = a.session_secret.as_deref().filter(|s| !s.is_empty()) {
            anyhow::ensure!(
                secret.len() >= 32,
                "server.auth.session_secret must be at least 32 bytes when set"
            );
        }
        if a.mode == AuthMode::Oidc {
            anyhow::ensure!(
                issuer.as_ref().is_some_and(|url| url.scheme() == "https")
                    && !a.issuer.ends_with('/'),
                "server.auth.issuer must be a non-empty https URL without a trailing slash"
            );
            anyhow::ensure!(
                !a.anonymous_read,
                "server.auth.anonymous_read must be false in oidc mode"
            );
            anyhow::ensure!(
                !a.allowed_domains.is_empty() || !a.allowed_emails.is_empty(),
                "server.auth.allowed_domains (or allowed_emails) must be set in oidc mode"
            );
            let oauth_id = a.oauth_client_id.as_deref().is_some_and(|v| !v.is_empty());
            let oauth_secret = a
                .oauth_client_secret
                .as_deref()
                .is_some_and(|v| !v.is_empty());
            anyhow::ensure!(
                oauth_id == oauth_secret,
                "server.auth.oauth_client_id and oauth_client_secret must be set together (browser sign-in) or both left unset"
            );
            anyhow::ensure!(
                oauth_id || !a.audiences.is_empty(),
                "oidc mode needs a way in: server.auth.oauth_client_id/oauth_client_secret (browser sign-in + issued tokens) and/or server.auth.audiences (ID tokens minted by clients)"
            );
            anyhow::ensure!(
                !oauth_id || a.session_secret.as_deref().is_some_and(|s| !s.is_empty()),
                "server.auth.session_secret is required with oauth_client_id (it signs sessions and access tokens)"
            );
        }
        if a.mode != AuthMode::None {
            anyhow::ensure!(
                !a.tenant_grants.is_empty() || !a.platform_operators.is_empty(),
                "server.auth.tenant_grants or server.auth.platform_operators must list at least one authorization in token or oidc mode"
            );
        }
        if a.mode == AuthMode::Token && a.anonymous_read {
            anyhow::ensure!(
                a.tenant_grants
                    .iter()
                    .any(|grant| grant.principal.eq_ignore_ascii_case("anonymous")),
                "server.auth.anonymous_read requires an explicit anonymous tenant reader grant"
            );
        }
        anyhow::ensure!(
            self.compaction.factor >= 2,
            "compaction.factor must be >= 2"
        );
        anyhow::ensure!(self.wal.max_batch >= 1, "wal.max_batch must be >= 1");
        let names: std::collections::HashSet<&str> = self
            .bundles
            .strategy
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        anyhow::ensure!(
            names.len() == self.bundles.strategy.len(),
            "bundle strategy names must be unique"
        );
        for s in &self.bundles.strategy {
            match (s.kind, &s.base) {
                (BundleKind::Incremental, None) => {
                    anyhow::bail!("bundle strategy {} is incremental but has no base", s.name)
                }
                (BundleKind::Incremental, Some(b)) => {
                    anyhow::ensure!(
                        names.contains(b.as_str()),
                        "bundle strategy {} base {b} does not exist",
                        s.name
                    )
                }
                (BundleKind::Full, Some(_)) => {
                    anyhow::bail!("bundle strategy {} is full but has a base", s.name)
                }
                _ => {}
            }
            if matches!(s.kind, BundleKind::Full) {
                anyhow::ensure!(
                    s.keep >= 1,
                    "bundle strategy {}: keep must be >= 1 on a full strategy",
                    s.name
                );
            }
        }
        if let Some(u) = &self.events.webhook_url {
            validated_http_url("events.webhook_url", u, true)?;
        }
        Ok(())
    }

    /// Store prefix normalized to either "" or "something/".
    pub fn store_prefix(&self) -> String {
        let p = self.store.prefix.trim_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("{p}/")
        }
    }

    /// Whether `owner/name` is listed in `bundles.require` (exact or `owner/*`).
    pub fn bundles_required(&self, owner: &str, name: &str) -> bool {
        repo_listed(&self.bundles.require, owner, name)
    }

    /// How `owner/name`'s bundle URIs are served: `bundles.serve_via`, or
    /// signed URLs when listed in `bundles.signed_url_for`.
    pub fn bundle_serve_via(&self, owner: &str, name: &str) -> BundleServe {
        if repo_listed(&self.bundles.signed_url_for, owner, name) {
            BundleServe::SignedUrl
        } else {
            self.bundles.serve_via
        }
    }

    /// Whether this process terminates TLS itself (D39 standalone shape).
    pub fn tls_enabled(&self) -> bool {
        self.server.tls.mode != TlsMode::Off
    }

    /// Where the self-signed certificate lives: `<cache.dir>/tls/`.
    pub fn tls_dir(&self) -> PathBuf {
        self.cache.dir.join("tls")
    }

    /// Subject alternative names for a self-signed certificate: the configured
    /// `server.tls.hostnames`, else localhost forms plus `public_url`'s host.
    pub fn tls_hostnames(&self) -> Vec<String> {
        if !self.server.tls.hostnames.is_empty() {
            return self.server.tls.hostnames.clone();
        }
        let mut v: Vec<String> = ["localhost", "*.localhost", "127.0.0.1", "::1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(u) = &self.server.public_url {
            let host = u
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .trim_start_matches('[');
            let host = host
                .rsplit_once(']')
                .map(|(h, _)| h)
                .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
            if !host.is_empty() && !v.iter().any(|h| h == host) {
                v.push(host.to_string());
            }
        }
        v
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.server.roles.is_empty()
            || self.server.roles.contains(&role)
            || (matches!(role, Role::Compact | Role::Bundle)
                && self.server.roles.contains(&Role::Maintain))
    }
}

impl StoreConfig {
    /// Validate the complete static S3 selector before credential or network
    /// access. `S3Store::new` also calls this so direct construction cannot
    /// bypass the same fail-closed contract as `Config::validate`.
    pub fn validate_s3(&self) -> Result<()> {
        self.validate_s3_credential_selector()?;
        let valid_bucket = self.bucket.len() >= 3
            && self.bucket.len() <= 63
            && self.bucket.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            && self
                .bucket
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && self
                .bucket
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && !self.bucket.contains("..")
            && self.bucket.split('.').all(|label| {
                label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && label
                        .bytes()
                        .last()
                        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
            && self.bucket.parse::<std::net::Ipv4Addr>().is_err();
        anyhow::ensure!(
            valid_bucket,
            "store.bucket must be a 3-63 byte DNS-compatible S3 bucket name"
        );
        let prefix_segments: Vec<&str> = if self.prefix.is_empty() {
            Vec::new()
        } else {
            self.prefix.split('/').collect()
        };
        let valid_prefix = self.prefix.len() <= 256
            && prefix_segments.len() <= 4
            && prefix_segments.iter().all(|segment| {
                segment.len() <= 63
                    && segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
                    && !matches!(*segment, "." | "..")
            });
        anyhow::ensure!(
            valid_prefix,
            "store.prefix must be empty or 1-4 canonical S3 key segments totaling at most 256 bytes"
        );
        anyhow::ensure!(
            !self.s3.endpoint.is_empty(),
            "store.s3.endpoint must be set explicitly"
        );
        let endpoint = validated_http_url("store.s3.endpoint", &self.s3.endpoint, false)?;
        anyhow::ensure!(
            self.s3.endpoint == endpoint.origin().ascii_serialization(),
            "store.s3.endpoint must use exact canonical origin syntax without a path or trailing slash"
        );
        let loopback = endpoint.host().is_some_and(|host| match host {
            url::Host::Domain(domain) => domain == "localhost",
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
        });
        anyhow::ensure!(
            endpoint.scheme() == "https" || (endpoint.scheme() == "http" && loopback),
            "store.s3.endpoint must use https (http is allowed only for a loopback development store)"
        );

        const S3_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
        const S3_MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
        anyhow::ensure!(
            (S3_MIN_PART_SIZE..=S3_MAX_PART_SIZE).contains(&self.multipart_part_size.as_u64()),
            "store.multipart_part_size must be between 5MiB and 5GiB for S3"
        );

        Ok(())
    }

    fn validate_s3_credential_selector(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=16).contains(&self.s3.bulk_clients),
            "store.s3.bulk_clients must be in 1..=16"
        );
        anyhow::ensure!(
            (1..=256).contains(&self.s3.bulk_concurrency),
            "store.s3.bulk_concurrency must be in 1..=256"
        );
        anyhow::ensure!(
            !self.s3.region.is_empty()
                && self.s3.region.len() <= 64
                && self
                    .s3
                    .region
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "store.s3.region must be 1-64 ASCII letters, digits, '.', '_', or '-'"
        );
        let valid_env_name = |name: &str| {
            name.len() <= 128
                && name
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        };
        match self.s3.credential_mode {
            S3CredentialMode::DefaultChain => anyhow::ensure!(
                self.s3.access_key_env.is_empty()
                    && self.s3.secret_key_env.is_empty()
                    && self.s3.session_token_env.is_empty(),
                "store.s3 default_chain credential mode does not accept explicit environment-variable names"
            ),
            S3CredentialMode::ExplicitEnv => {
                anyhow::ensure!(
                    valid_env_name(&self.s3.access_key_env)
                        && valid_env_name(&self.s3.secret_key_env),
                    "store.s3 explicit_env credential mode requires valid access_key_env and secret_key_env names"
                );
                anyhow::ensure!(
                    self.s3.session_token_env.is_empty()
                        || valid_env_name(&self.s3.session_token_env),
                    "store.s3.session_token_env is not a valid environment-variable name"
                );
            }
        }
        Ok(())
    }
}

fn origin_host(origin: &str) -> &str {
    let rest = origin
        .trim_end_matches('/')
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(origin);
    if let Some(inside) = rest.strip_prefix('[') {
        return inside.split_once(']').map(|(h, _)| h).unwrap_or(inside);
    }
    rest.split([':', '/']).next().unwrap_or(rest)
}

fn origin_is_loopback(origin: &str) -> bool {
    let host = origin_host(origin);
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "::1"
}

fn rewrite_origin_port(origin: &str, port: u16) -> String {
    let origin = origin.trim_end_matches('/');
    let Some((scheme, rest)) = origin.split_once("://") else {
        return origin.to_string();
    };
    let host = if rest.starts_with('[') {
        rest.split_once(']')
            .map(|(h, _)| format!("{h}]"))
            .unwrap_or_else(|| rest.to_string())
    } else {
        rest.split([':', '/']).next().unwrap_or(rest).to_string()
    };
    let default = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    if port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn config_env_filter_ignores_unrelated_non_unicode_entries() {
        use std::os::unix::ffi::OsStringExt;

        let vars = config_env_vars(
            vec![
                (
                    std::ffi::OsString::from("CUSTOM_TOKEN_ENV"),
                    std::ffi::OsString::from_vec(b"token-value-sentinel-\xff".to_vec()),
                ),
                (
                    std::ffi::OsString::from_vec(b"UNRELATED_KEY_\xff".to_vec()),
                    std::ffi::OsString::from_vec(b"unrelated-value-sentinel-\xff".to_vec()),
                ),
                (
                    std::ffi::OsString::from("PORT"),
                    std::ffi::OsString::from("9000"),
                ),
                (
                    std::ffi::OsString::from("WALGIT__WAL__MAX_BATCH"),
                    std::ffi::OsString::from("17"),
                ),
            ]
            .into_iter(),
        )
        .expect("unrelated non-Unicode environment entries are not config overrides");
        assert_eq!(
            vars,
            vec![
                ("PORT".to_string(), "9000".to_string()),
                ("WALGIT__WAL__MAX_BATCH".to_string(), "17".to_string())
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_env_filter_rejects_non_unicode_override_values_without_leaking_them() {
        use std::os::unix::ffi::OsStringExt;

        for key in ["PORT", "WALGIT__WAL__MAX_BATCH"] {
            let err = config_env_vars(
                vec![(
                    std::ffi::OsString::from(key),
                    std::ffi::OsString::from_vec(
                        format!("override-value-sentinel-for-{key}-")
                            .into_bytes()
                            .into_iter()
                            .chain([0xff])
                            .collect(),
                    ),
                )]
                .into_iter(),
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains(key), "missing override key in error: {err}");
            assert!(
                !err.contains("override-value-sentinel"),
                "non-Unicode override value leaked in error: {err}"
            );
        }
    }

    #[test]
    fn defaults_parse_and_validate() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.server.listen.port(), 8080);
        assert_eq!(c.bundles.strategy.len(), 3);
        c.validate().unwrap();
        // Round trip through TOML.
        let text = toml::to_string(&c).unwrap();
        let back = Config::parse(&text).unwrap();
        assert_eq!(back.store.bucket, c.store.bucket);
    }

    #[test]
    fn s3_default_chain_rejects_explicit_variable_names() {
        let mut cfg = Config::default();
        cfg.store.s3.access_key_env = "CUSTOM_ACCESS".into();
        cfg.store.s3.secret_key_env = "CUSTOM_SECRET".into();

        for backend in [StoreBackend::Gcs, StoreBackend::S3] {
            cfg.store.backend = backend;
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("default_chain"), "{error}");
            assert!(!error.contains("CUSTOM_ACCESS"), "{error}");
            assert!(!error.contains("CUSTOM_SECRET"), "{error}");
        }
    }

    #[test]
    fn s3_explicit_env_requires_closed_portable_selectors() {
        let mut cfg = Config::default();
        cfg.store.backend = StoreBackend::S3;
        cfg.store.s3.credential_mode = S3CredentialMode::ExplicitEnv;

        for (access, secret, token) in [
            ("", "CUSTOM_SECRET", ""),
            ("CUSTOM_ACCESS", "", ""),
            ("lowercase", "CUSTOM_SECRET", ""),
            ("CUSTOM=ACCESS", "CUSTOM_SECRET", ""),
            ("CUSTOM_ACCESS", "CUSTOM_SECRET", "TOKEN-NAME"),
        ] {
            cfg.store.s3.access_key_env = access.into();
            cfg.store.s3.secret_key_env = secret.into();
            cfg.store.s3.session_token_env = token.into();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.s3"), "{error}");
            for selector in [access, secret, token] {
                if !selector.is_empty() {
                    assert!(!error.contains(selector), "selector leaked: {error}");
                }
            }
        }

        cfg.store.s3.access_key_env = "CUSTOM_ACCESS".into();
        cfg.store.s3.secret_key_env = "CUSTOM_SECRET".into();
        cfg.store.s3.session_token_env = "CUSTOM_SESSION_TOKEN".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn s3_region_is_nonempty_bounded_ascii() {
        let mut cfg = Config::default();
        cfg.store.backend = StoreBackend::S3;
        for region in [
            String::new(),
            "eu west 1".into(),
            "région".into(),
            "x".repeat(65),
        ] {
            cfg.store.s3.region = region.clone();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.s3.region"), "{error}");
            if !region.is_empty() {
                assert!(!error.contains(&region), "region leaked: {error}");
            }
        }
        cfg.store.s3.region = "eu-west-par".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn s3_static_location_and_multipart_contract_is_closed() {
        let mut cfg = Config::default();
        cfg.store.backend = StoreBackend::S3;

        for bucket in [
            "ab",
            "UPPERCASE",
            "192.0.2.1",
            "starts-.bad",
            "bad.-ends",
            "bad..dots",
        ] {
            cfg.store.bucket = bucket.into();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.bucket"), "{error}");
            assert!(!error.contains(bucket), "bucket leaked: {error}");
        }
        cfg.store.bucket = "walgit-production".into();

        for prefix in [
            "/leading",
            "trailing/",
            "too/many/prefix/segments/here",
            "UPPERCASE",
            ".",
            "valid/../invalid",
        ] {
            cfg.store.prefix = prefix.into();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.prefix"), "{error}");
            if prefix.len() > 3 {
                assert!(!error.contains(prefix), "prefix leaked: {error}");
            }
        }
        cfg.store.prefix = "production/walgit".into();
        cfg.validate().unwrap();
        cfg.store.prefix = format!("contract-{}", "a".repeat(40));
        cfg.validate()
            .expect("the protected CI deployment prefix must remain valid");

        for endpoint in [
            "",
            "http://s3.example.com",
            "https://s3.example.com/provider-path",
            "https://s3.example.com/./",
            "https://s3.example.com/provider-path/..",
            "https://s3.example.com/%2e%2e/",
            "https://S3.EXAMPLE.COM:443",
            "https://s3.example.com?query=sentinel",
        ] {
            cfg.store.s3.endpoint = endpoint.into();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.s3.endpoint"), "{error}");
            assert!(!error.contains("sentinel"), "endpoint leaked: {error}");
        }
        for endpoint in [
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
            "https://s3.eu-west-par.io.cloud.ovh.net",
        ] {
            cfg.store.s3.endpoint = endpoint.into();
            cfg.validate().unwrap();
        }

        cfg.store.multipart_part_size = ByteSize::mib(4);
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("multipart_part_size")
        );
        cfg.store.multipart_part_size = ByteSize::gib(6);
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("multipart_part_size")
        );
        cfg.store.multipart_part_size = ByteSize::mib(32);
        cfg.validate().unwrap();

        for bulk_clients in [0, 17] {
            cfg.store.s3.bulk_clients = bulk_clients;
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.s3.bulk_clients"), "{error}");
        }
        cfg.store.s3.bulk_clients = 4;

        for bulk_concurrency in [0, 257] {
            cfg.store.s3.bulk_concurrency = bulk_concurrency;
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("store.s3.bulk_concurrency"), "{error}");
        }
        cfg.store.s3.bulk_concurrency = 32;
        cfg.validate().unwrap();
    }

    #[test]
    fn config_parse_errors_are_source_free() {
        const SENTINEL: &str = "config-malformed-webhook-path-sentinel";
        let source = format!("[events]\nwebhook_url = \"https://hooks.example/{SENTINEL}\n");
        let err = Config::parse(&source).unwrap_err().to_string();
        assert_eq!(err, "config: invalid TOML");
        assert!(!err.contains(SENTINEL), "config error leaked source: {err}");
        assert!(!err.contains("webhook_url ="), "{err}");
    }

    #[test]
    fn env_overrides() {
        let mut c = Config::default();
        c.apply_env(
            vec![
                ("WALGIT__STORE__BACKEND".to_string(), "s3".to_string()),
                (
                    "WALGIT__STORE__S3__ENDPOINT".to_string(),
                    "http://rustfs:9000".to_string(),
                ),
                (
                    "WALGIT__STORE__S3__BULK_CLIENTS".to_string(),
                    "6".to_string(),
                ),
                (
                    "WALGIT__STORE__S3__BULK_CONCURRENCY".to_string(),
                    "24".to_string(),
                ),
                ("WALGIT__WAL__MAX_BATCH".to_string(), "7".to_string()),
                ("PORT".to_string(), "9090".to_string()),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(c.store.backend, StoreBackend::S3);
        assert_eq!(c.store.s3.endpoint, "http://rustfs:9000");
        assert_eq!(c.store.s3.bulk_clients, 6);
        assert_eq!(c.store.s3.bulk_concurrency, 24);
        assert_eq!(c.wal.max_batch, 7);
        assert_eq!(c.server.listen.port(), 9090);
    }

    #[test]
    fn port_rewrites_loopback_public_url_only() {
        let mut c = Config::default();
        c.server.public_url = Some("https://walgit.localhost:8888".into());
        c.apply_env(vec![("PORT".to_string(), "8080".to_string())].into_iter())
            .unwrap();
        assert_eq!(c.server.listen.port(), 8080);
        assert_eq!(
            c.server.public_url.as_deref(),
            Some("https://walgit.localhost:8080")
        );

        let mut prod = Config::default();
        prod.server.public_url = Some("https://git.example.com".into());
        prod.apply_env(vec![("PORT".to_string(), "8080".to_string())].into_iter())
            .unwrap();
        assert_eq!(
            prod.server.public_url.as_deref(),
            Some("https://git.example.com")
        );
    }

    /// `[placement]` is set as a group: one PLACEMENT env key replaces the whole
    /// section (unset keys = defaults), never merges with the file's values.
    /// The SSD host 2026-08-21 07:00Z: the baked toml's serve_exclude = ["acme/monorepo"]
    /// leaked under an env that set only MAINTAIN* → the host refused its own repo.
    #[test]
    fn env_placement_override_replaces_the_whole_section() {
        let mut c = Config::default();
        c.placement.serve_exclude = vec!["acme/monorepo".into()]; // the baked a serverless host shape
        c.placement.maintain_exclude = vec!["acme/monorepo".into()];
        c.apply_env(
            vec![(
                "WALGIT__PLACEMENT__MAINTAIN".to_string(),
                "[\"acme/monorepo\"]".to_string(),
            )]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(c.placement.maintain, vec!["acme/monorepo"]);
        assert!(
            c.placement.serve_exclude.is_empty(),
            "the file's exclude must not survive an env group override: {:?}",
            c.placement.serve_exclude
        );
        assert!(c.placement.maintain_exclude.is_empty());
        assert_eq!(c.placement.serve, vec!["*"]);
        assert!(c.placement.serves("acme", "monorepo"));
        // No PLACEMENT env at all: the file's section stands.
        let mut c = Config::default();
        c.placement.serve_exclude = vec!["acme/monorepo".into()];
        c.apply_env(vec![("WALGIT__WAL__MAX_BATCH".to_string(), "7".to_string())].into_iter())
            .unwrap();
        assert_eq!(c.placement.serve_exclude, vec!["acme/monorepo"]);
    }

    /// You cannot maintain what you refuse to serve.
    #[test]
    fn validate_refuses_maintaining_a_repo_the_host_does_not_serve() {
        let mut c = Config::default();
        c.store.bucket = "b".into();
        c.server.roles = vec![Role::Serve, Role::Maintain];
        c.placement.maintain = vec!["acme/monorepo".into()];
        c.placement.serve_exclude = vec!["acme/monorepo".into()];
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("cannot maintain what you refuse to serve"),
            "{err}"
        );
        // A maintain-only host may well refuse to serve (it is not a front).
        c.server.roles = vec![Role::Maintain];
        c.validate().unwrap();
        // And the prod shapes are fine: broker excludes a large repository from both; the SSD host serves + maintains it.
        c.server.roles = vec![Role::Serve, Role::Maintain];
        c.placement.maintain = vec!["*".into()];
        c.placement.maintain_exclude = vec!["acme/monorepo".into()];
        c.validate().unwrap();
        c.placement = PlacementConfig {
            serve: vec!["acme/monorepo".into()],
            serve_exclude: vec![],
            maintain: vec!["acme/monorepo".into()],
            maintain_exclude: vec![],
        };
        c.validate().unwrap();
    }

    /// Config and image release independently: an override for a key this
    /// build does not know (or a value it cannot parse) is ignored and
    /// reported, the known ones still apply, startup continues.
    #[test]
    fn env_override_unknown_key_is_ignored_not_fatal() {
        let mut c = Config::default();
        let ignored = c
            .apply_env_report(
                vec![
                    (
                        "WALGIT__CACHE__NOT_A_KEY_YET".to_string(),
                        "0.9".to_string(),
                    ),
                    (
                        "WALGIT__WAL__MAX_BATCH".to_string(),
                        "not-a-number".to_string(),
                    ),
                    ("WALGIT__NOSUCHSECTION__X".to_string(), "1".to_string()),
                    ("WALGIT__WAL__BATCH_WINDOW".to_string(), "30ms".to_string()),
                ]
                .into_iter(),
            )
            .unwrap();
        assert_eq!(
            c.wal.batch_window,
            Duration::from_millis(30),
            "known override still applied"
        );
        let keys: Vec<&str> = ignored.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "WALGIT__CACHE__NOT_A_KEY_YET",
                "WALGIT__WAL__MAX_BATCH",
                "WALGIT__NOSUCHSECTION__X"
            ]
        );
        assert_eq!(ignored[0].1, "invalid configuration override");
        assert_eq!(ignored[1].1, "invalid configuration override");
        assert_eq!(ignored[2].1, "invalid configuration override");
        // Plain apply_env is the same, just warns.
        let mut c2 = Config::default();
        c2.apply_env(
            vec![("WALGIT__CACHE__NOT_A_KEY_YET".to_string(), "1".to_string())].into_iter(),
        )
        .unwrap();
    }

    #[test]
    fn env_override_type_errors_do_not_echo_values() {
        const SENTINEL: &str = "env-override-value-sentinel";
        let mut config = Config::default();
        let ignored = config
            .apply_env_report(
                vec![(
                    "WALGIT__WAL__MAX_BATCH".to_string(),
                    format!("\"{SENTINEL}\""),
                )]
                .into_iter(),
            )
            .unwrap();
        assert_eq!(
            ignored,
            vec![(
                "WALGIT__WAL__MAX_BATCH".to_string(),
                "invalid configuration override".to_string()
            )]
        );
        assert!(!ignored[0].1.contains(SENTINEL));
    }

    #[test]
    fn settings_merge_over_config_and_are_restricted() {
        let mut base = Config::default();
        base.store.bucket = "b".into();
        let eff = base
            .with_settings(
                r#"
[bundles]
min_commits = 3
main_only = false
[maintenance]
checkpoints = false
"#,
            )
            .unwrap();
        assert_eq!(eff.bundles.min_commits, 3);
        assert!(!eff.bundles.main_only);
        assert!(!eff.maintenance.checkpoints);
        assert_eq!(
            eff.bundles.strategy.len(),
            base.bundles.strategy.len(),
            "untouched keys keep the host's values"
        );
        // Forbidden section.
        let e = base
            .with_settings(
                "[server]
listen = \"0.0.0.0:1\"\n",
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("[server]"), "{e}");
        // Unknown key inside an allowed section.
        assert!(base.with_settings("[bundles]\nnope = 1\n").is_err());
        // Invalid effective config (incremental without a base).
        let e = base
            .with_settings("[[bundles.strategy]]\nname = \"x\"\nkind = \"incremental\"\nschedule = \"@hourly\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("settings"), "{e}");
        let e = base
            .with_settings("[bundles]\nsigned_url_ttl = \"2h\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("host maximum"), "{e}");
        for upstream in [
            "https://user:secret@example.com/repo.git",
            "https://example.com/repo.git?token=secret",
        ] {
            let e = base
                .with_settings(&format!("[upstream]\ngit = {upstream:?}\n"))
                .unwrap_err();
            let e = format!("{e:#}");
            assert!(e.contains("upstream.git"), "{e}");
            assert!(!e.contains(upstream), "{e}");
            assert!(!e.contains("secret"), "{e}");
        }
        assert_eq!(
            base.with_settings("  ").unwrap().bundles.min_commits,
            base.bundles.min_commits
        );
    }

    #[test]
    fn settings_parse_and_type_errors_are_source_free() {
        let mut base = Config::default();
        base.store.bucket = "b".into();

        const MALFORMED_SENTINEL: &str = "settings-malformed-path-sentinel";
        let malformed = format!("[upstream]\ngit = \"https://example.test/{MALFORMED_SENTINEL}\n");
        let err = base.with_settings(&malformed).unwrap_err().to_string();
        assert_eq!(err, "settings: invalid TOML");
        assert!(!err.contains(MALFORMED_SENTINEL), "{err}");
        assert!(!err.contains("git ="), "{err}");

        const TYPE_SENTINEL: &str = "settings-type-value-sentinel";
        let invalid_type = format!("[bundles]\nmin_commits = \"{TYPE_SENTINEL}\"\n");
        let err = base.with_settings(&invalid_type).unwrap_err().to_string();
        assert_eq!(err, "settings: invalid effective configuration");
        assert!(!err.contains(TYPE_SENTINEL), "{err}");
        assert!(!err.contains("min_commits ="), "{err}");
    }

    #[test]
    fn settings_closed_input_allowlist_accepts_every_current_field() {
        let mut base = Config::default();
        base.store.bucket = "b".into();
        let effective = base
            .with_settings(
                r#"
[bundles]
enabled = true
min_commits = 3
min_bytes = "1.0 KiB"
serve_via = "proxy"
signed_url_ttl = "30m"
advertise = true
advertise_filtered = true
require = ["acme/*"]
signed_url_for = ["acme/large"]
main_only = false
extra_refs = ["refs/tags/v*"]

[[bundles.strategy]]
name = "filtered-full"
kind = "full"
schedule = "@weekly"
keep = 2
refs = ["refs/heads/main"]
backfill_max = 1
min_commits = 4
filter = "blob:none"
chain = false

[[bundles.strategy]]
name = "filtered-incremental"
kind = "incremental"
schedule = "@daily"
base = "filtered-full"
keep = 0
refs = ["refs/heads/main"]
backfill_max = 2
min_commits = 5
filter = "blob:none"
chain = true

[maintenance]
interval = "2m"
checkpoints = false
max_pack_bytes = "2.0 GiB"
disk = "tmpfs"
host = "maintainer.example"
fsck_interval = "2days"
follow_interval = "45s"

[compaction]
enabled = true
factor = 3
trigger_packs = 9
trigger_bytes = "3.0 GiB"
lease_ttl = "11m"
retention_superseded = "8days"
engine = "git"

[upstream]
git = "https://upstream.example/repo.git"
lfs = "https://upstream.example/repo.git/info/lfs"
token_env = "UPSTREAM_TOKEN"
follow = ["refs/heads/main"]
"#,
            )
            .expect("every current repository setting remains allowed");

        assert_eq!(effective.bundles.strategy.len(), 2);
        assert_eq!(
            effective.maintenance.host.as_deref(),
            Some("maintainer.example")
        );
        assert_eq!(effective.compaction.factor, 3);
        assert_eq!(
            effective.upstream.token_env.as_deref(),
            Some("UPSTREAM_TOKEN")
        );
    }

    #[test]
    fn settings_closed_input_allowlist_rejects_unknown_paths_without_values() {
        let mut base = Config::default();
        base.store.bucket = "b".into();
        for (document, path, sentinel) in [
            (
                "[bundles]\nfuture_field = \"bundles-value-sentinel\"\n",
                "bundles.future_field",
                "bundles-value-sentinel",
            ),
            (
                "[maintenance]\nfuture_field = \"maintenance-value-sentinel\"\n",
                "maintenance.future_field",
                "maintenance-value-sentinel",
            ),
            (
                "[compaction]\nfuture_field = \"compaction-value-sentinel\"\n",
                "compaction.future_field",
                "compaction-value-sentinel",
            ),
            (
                "[upstream]\nfuture_field = \"upstream-value-sentinel\"\n",
                "upstream.future_field",
                "upstream-value-sentinel",
            ),
            (
                "[[bundles.strategy]]\nfuture_field = \"strategy-value-sentinel\"\n",
                "bundles.strategy[0].future_field",
                "strategy-value-sentinel",
            ),
            (
                "[bundles.min_commits]\nfuture_field = \"nested-value-sentinel\"\n",
                "bundles.min_commits.future_field",
                "nested-value-sentinel",
            ),
            (
                "[[bundles.strategy]]\nname = { future_field = \"strategy-nested-value-sentinel\" }\n",
                "bundles.strategy[0].name.future_field",
                "strategy-nested-value-sentinel",
            ),
        ] {
            let err = base.with_settings(document).unwrap_err().to_string();
            assert_eq!(
                err,
                format!("settings: key {path} may not be set per repository")
            );
            assert!(
                !err.contains(sentinel),
                "settings error leaked value {sentinel}: {err}"
            );
        }
    }

    #[test]
    fn auth_modes_validate_fail_closed() {
        let multiple = Config::parse(
            r#"
[server.auth]
audiences = ["walgit-cli", "https://git.example.com"]
"#,
        )
        .unwrap();
        assert_eq!(
            multiple.server.auth.audiences,
            vec![
                "walgit-cli".to_string(),
                "https://git.example.com".to_string()
            ]
        );
        // token mode needs tokens.
        let err = Config::parse("[store]\nbucket = \"b\"\n[server.auth]\nmode = \"token\"\n")
            .unwrap_err();
        assert!(err.to_string().contains("tokens"), "{err}");
        let err = Config::parse(
            "[store]\nbucket = \"b\"\n[server.auth]\nmode = \"token\"\ntokens = [{ principal = \"ci\", token = \"secret\" }]\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("tenant_grants"), "{err}");
        // oidc: anonymous_read off, an allowlist, and a way in.
        let err = Config::parse("[store]\nbucket = \"b\"\n[server.auth]\nmode = \"oidc\"\nanonymous_read = false\nallowed_domains = [\"example.com\"]\n").unwrap_err();
        assert!(err.to_string().contains("way in"), "{err}");
        let err = Config::parse("[store]\nbucket = \"b\"\n[server.auth]\nmode = \"oidc\"\nanonymous_read = false\nallowed_domains = [\"example.com\"]\noauth_client_id = \"x\"\noauth_client_secret = \"y\"\n").unwrap_err();
        assert!(err.to_string().contains("session_secret"), "{err}");
        let ok = Config::parse("[store]\nbucket = \"b\"\n[server.auth]\nmode = \"oidc\"\nissuer = \"https://login.example.com\"\nanonymous_read = false\nallowed_domains = [\"example.com\"]\noauth_client_id = \"x\"\noauth_client_secret = \"y\"\nsession_secret = \"0123456789abcdef0123456789abcdef\"\n[[server.auth.tenant_grants]]\nprincipal = \"*\"\ntenant = \"acme\"\nrole = \"reader\"\n").unwrap();
        assert_eq!(ok.server.auth.issuer, "https://login.example.com");
        assert_eq!(ok.server.auth.tenant_grants[0].tenant, "acme");
        assert_eq!(
            ok.server.auth.access_token_ttl,
            Duration::from_secs(90 * 86400)
        );
        let mut token = ok.clone();
        token.server.auth.mode = AuthMode::Token;
        token.server.auth.tokens = vec![StaticToken {
            principal: "ci".into(),
            token: "secret".into(),
            token_env: None,
            write: true,
        }];
        for (mode, authenticated) in [("token", token), ("oidc", ok.clone())] {
            for (control, configure) in [
                (
                    "lfs.serve_via",
                    (|cfg: &mut Config| cfg.lfs.serve_via = BundleServe::SignedUrl)
                        as fn(&mut Config),
                ),
                ("bundles.serve_via", |cfg: &mut Config| {
                    cfg.bundles.serve_via = BundleServe::SignedUrl
                }),
                ("bundles.signed_url_for", |cfg: &mut Config| {
                    cfg.bundles.signed_url_for = vec!["acme/*".into()]
                }),
            ] {
                let mut unsafe_gcs = authenticated.clone();
                unsafe_gcs.store.backend = StoreBackend::Gcs;
                configure(&mut unsafe_gcs);
                let err = unsafe_gcs.validate().unwrap_err();
                assert!(
                    err.to_string().contains("authenticated GCS tenants"),
                    "{mode} {control}: {err}"
                );
            }
        }

        let mut unauthenticated_gcs = ok;
        unauthenticated_gcs.server.auth.mode = AuthMode::None;
        unauthenticated_gcs.store.backend = StoreBackend::Gcs;
        unauthenticated_gcs.lfs.serve_via = BundleServe::SignedUrl;
        unauthenticated_gcs.bundles.serve_via = BundleServe::SignedUrl;
        unauthenticated_gcs.bundles.signed_url_for = vec!["acme/*".into()];
        unauthenticated_gcs.validate().unwrap();
    }

    #[test]
    fn upstream_urls_reject_credential_and_suffix_channels() {
        let mut cfg = Config::default();
        cfg.store.bucket = "b".into();
        for (key, url) in [
            ("userinfo", "https://user:pass@example.com/repo.git"),
            ("empty userinfo", "https://@example.com/repo.git"),
            ("query", "https://example.com/repo.git?token=secret"),
            ("empty query", "https://example.com/repo.git?"),
            ("fragment", "https://example.com/repo.git#credential"),
            ("empty fragment", "https://example.com/repo.git#"),
            (
                "lookalike localhost",
                "http://localhost.example.com/repo.git",
            ),
            ("opaque https syntax", "https:example.com/repo.git"),
            ("parsed trailing slash", "https://example.com/repo.git/"),
            ("backslash suffix", "https://example.com/repo.git\\"),
        ] {
            cfg.upstream.git = Some(url.into());
            let err = cfg.validate().unwrap_err().to_string();
            assert!(
                err.contains("upstream.git"),
                "{key} rejection named the wrong field: {err}"
            );
        }
        for url in [
            "https://example.com/repo.git",
            "http://localhost/repo.git",
            "http://localhost:8080/repo.git",
            "http://127.0.0.1:8080/repo.git",
        ] {
            cfg.upstream.git = Some(url.into());
            cfg.validate()
                .unwrap_or_else(|e| panic!("valid URL {url} rejected: {e}"));
        }
        cfg.upstream.git = None;
        cfg.upstream.lfs = Some("https://user@example.com/repo.git/info/lfs".into());
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("upstream.lfs")
        );
    }

    #[test]
    fn static_token_env_names_are_nonempty_and_lookup_safe() {
        for env_name in ["", "TOKEN=VALUE", "TOKEN\0VALUE"] {
            let mut cfg = Config::default();
            cfg.store.bucket = "b".into();
            cfg.server.auth.tokens = vec![StaticToken {
                principal: "robot".into(),
                token: "literal-fallback".into(),
                token_env: Some(env_name.into()),
                write: true,
            }];
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("token_env"), "{err}");
            assert!(
                !err.contains("literal-fallback"),
                "literal token leaked in validation error: {err}"
            );
        }

        let mut cfg = Config::default();
        cfg.store.bucket = "b".into();
        cfg.server.auth.mode = AuthMode::Token;
        cfg.server.auth.anonymous_read = false;
        cfg.server.auth.issuer.clear();
        cfg.server.auth.tokens = vec![StaticToken {
            principal: "robot".into(),
            token: "literal-fallback".into(),
            token_env: Some("ROBOT_TOKEN".into()),
            write: true,
        }];
        cfg.server.auth.tenant_grants = vec![TenantGrant {
            principal: "robot".into(),
            tenant: "*".into(),
            role: TenantRole::Writer,
        }];
        cfg.validate().expect("named env with literal fallback");
        cfg.server.auth.tokens[0].token_env = None;
        cfg.validate().expect("literal-only fallback");
        cfg.server.auth.tokens[0].token.clear();
        cfg.server.auth.tokens[0].token_env = Some("ROBOT_TOKEN".into());
        cfg.validate()
            .expect("valid named env without literal fallback");
    }

    #[test]
    fn configured_urls_are_parsed_and_errors_never_echo_input() {
        fn assert_invalid(field: &str, configure: impl FnOnce(&mut Config), sentinels: &[&str]) {
            let mut cfg = Config::default();
            cfg.store.bucket = "b".into();
            configure(&mut cfg);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(field), "{field}: {err}");
            for sentinel in sentinels {
                assert!(
                    !err.contains(sentinel),
                    "{field} leaked URL input sentinel {sentinel}: {err}"
                );
            }
        }

        assert_invalid(
            "server.public_url",
            |cfg| {
                cfg.server.public_url =
                    Some("https://public-user:public-pass@public.example/base?public-query#public-fragment".into())
            },
            &[
                "public-user",
                "public-pass",
                "public-query",
                "public-fragment",
            ],
        );
        assert_invalid(
            "server.auth.issuer",
            |cfg| {
                cfg.server.auth.issuer =
                    "https://issuer-user:issuer-pass@issuer.example/tenant?issuer-query#issuer-fragment".into()
            },
            &[
                "issuer-user",
                "issuer-pass",
                "issuer-query",
                "issuer-fragment",
            ],
        );
        assert_invalid(
            "store.gcs.endpoint",
            |cfg| {
                cfg.store.gcs.endpoint =
                    "https://gcs-user:gcs-pass@gcs.example/storage?gcs-query#gcs-fragment".into()
            },
            &["gcs-user", "gcs-pass", "gcs-query", "gcs-fragment"],
        );
        assert_invalid(
            "store.s3.endpoint",
            |cfg| {
                cfg.store.s3.endpoint =
                    "https://s3-user:s3-pass@s3.example/storage?s3-query#s3-fragment".into()
            },
            &["s3-user", "s3-pass", "s3-query", "s3-fragment"],
        );
        assert_invalid(
            "wal.push_broker_url",
            |cfg| {
                cfg.wal.push_broker_url = Some(
                    "https://broker-user:broker-pass@broker.example/push?broker-query#broker-fragment"
                        .into(),
                )
            },
            &[
                "broker-user",
                "broker-pass",
                "broker-query",
                "broker-fragment",
            ],
        );
        assert_invalid(
            "server.cors_origins",
            |cfg| {
                cfg.server.cors_origins =
                    vec!["https://cors-user:cors-pass@cors.example?cors-query#cors-fragment".into()]
            },
            &["cors-user", "cors-pass", "cors-query", "cors-fragment"],
        );
        assert_invalid(
            "events.webhook_url",
            |cfg| {
                cfg.events.webhook_url = Some(
                    "https://hooks.example/services/webhook-path?webhook-query#webhook-fragment"
                        .into(),
                )
            },
            &["webhook-query", "webhook-fragment"],
        );

        let mut valid = Config::default();
        valid.store.bucket = "b".into();
        valid.server.cors_origins = vec!["https://*.docs.example.com".into()];
        valid.events.webhook_url =
            Some("https://hooks.example/services/secret-path?token=secret-query".into());
        valid
            .validate()
            .expect("documented URL shapes remain valid");
    }

    #[test]
    fn effective_settings_projection_is_an_exact_closed_allowlist() {
        use std::collections::BTreeSet;

        fn keys(table: &toml::Table) -> BTreeSet<&str> {
            table.keys().map(String::as_str).collect()
        }

        fn field_set<'a>(fields: &'a [&'a str]) -> BTreeSet<&'a str> {
            fields.iter().copied().collect()
        }

        let mut cfg = Config::default();
        cfg.server.auth.session_secret = Some("settings-session-secret-sentinel".repeat(2));
        cfg.server.auth.oauth_client_secret = Some("settings-oauth-secret-sentinel".into());
        cfg.events.webhook_secret = Some("settings-webhook-secret-sentinel".into());
        cfg.wal.push_broker_token = Some("settings-broker-secret-sentinel".into());
        cfg.bundles.strategy[0].base = Some("projection-base".into());
        cfg.bundles.strategy[0].min_commits = Some(7);
        cfg.bundles.strategy[0].filter = Some("blob:none".into());
        cfg.maintenance.host = Some("projection-host".into());
        cfg.upstream.git = Some("https://example.com/repo.git".into());
        cfg.upstream.lfs = Some("https://example.com/repo.git/info/lfs".into());
        cfg.upstream.token_env = Some("UPSTREAM_TOKEN".into());
        cfg.upstream.follow = vec!["refs/heads/main".into()];

        let view = cfg.effective_settings_view();
        let table = view.to_toml_table().unwrap();
        assert_eq!(keys(&table), field_set(SETTINGS_SECTIONS));
        assert_eq!(
            keys(table["bundles"].as_table().unwrap()),
            field_set(SETTINGS_BUNDLES_FIELDS)
        );
        assert_eq!(
            keys(table["maintenance"].as_table().unwrap()),
            field_set(SETTINGS_MAINTENANCE_FIELDS)
        );
        assert_eq!(
            keys(table["compaction"].as_table().unwrap()),
            field_set(SETTINGS_COMPACTION_FIELDS)
        );
        assert_eq!(
            keys(table["upstream"].as_table().unwrap()),
            field_set(&["git", "lfs", "follow"])
        );
        let strategy = table["bundles"]["strategy"].as_array().unwrap()[0]
            .as_table()
            .unwrap();
        assert_eq!(keys(strategy), field_set(SETTINGS_BUNDLE_STRATEGY_FIELDS));
        let text = view.to_toml_string().unwrap();
        assert!(!text.contains("token_env"), "{text}");
        assert!(!text.contains("UPSTREAM_TOKEN"), "{text}");
        for sentinel in [
            "settings-session-secret-sentinel",
            "settings-oauth-secret-sentinel",
            "settings-webhook-secret-sentinel",
            "settings-broker-secret-sentinel",
        ] {
            assert!(
                !text.contains(sentinel),
                "effective projection leaked {sentinel}"
            );
        }
    }

    #[test]
    fn safe_config_projection_keeps_diagnostics_without_secret_values() {
        let mut cfg = Config::default();
        cfg.store.bucket = "diagnostic-bucket".into();
        cfg.server.auth.tokens = vec![StaticToken {
            principal: "deploy-bot".into(),
            token: "safe-view-static-token-sentinel".into(),
            token_env: Some("DEPLOY_BOT_TOKEN".into()),
            write: true,
        }];
        cfg.server.auth.session_secret = Some("safe-view-session-secret-sentinel".repeat(2));
        cfg.server.auth.oauth_client_secret = Some("safe-view-oauth-secret-sentinel".into());
        cfg.wal.push_broker_token = Some("safe-view-broker-token-sentinel".into());
        cfg.events.webhook_secret = Some("safe-view-webhook-secret-sentinel".into());
        cfg.server.public_url = Some(
            "https://public-user:public-pass@public.example/public-path?public-query#public-fragment"
                .into(),
        );
        cfg.server.auth.issuer =
            "https://issuer-user:issuer-pass@issuer.example/issuer-path?issuer-query#issuer-fragment"
                .into();
        cfg.server.cors_origins = vec![
            "https://cors-user:cors-pass@cors.example/cors-path?cors-query#cors-fragment".into(),
        ];
        cfg.store.gcs.endpoint =
            "https://gcs-user:gcs-pass@gcs.example/gcs-path?gcs-query#gcs-fragment".into();
        cfg.store.s3.endpoint =
            "https://s3-user:s3-pass@s3.example/s3-path?s3-query#s3-fragment".into();
        cfg.store.s3.bulk_clients = 7;
        cfg.store.s3.bulk_concurrency = 19;
        cfg.wal.push_broker_url = Some(
            "https://broker-user:broker-pass@broker.example/broker-path?broker-query#broker-fragment"
                .into(),
        );
        cfg.upstream.git =
            Some("https://git-user:git-pass@git.example/git-path?git-query#git-fragment".into());
        cfg.upstream.lfs =
            Some("https://lfs-user:lfs-pass@lfs.example/lfs-path?lfs-query#lfs-fragment".into());
        cfg.events.webhook_url = Some(
            "https://webhook-user:webhook-pass@hooks.example/webhook-path-sentinel?webhook-query#webhook-fragment"
                .into(),
        );

        let text = cfg.safe_view().to_toml_string().unwrap();
        assert!(text.contains("diagnostic-bucket"), "{text}");
        assert!(text.contains("deploy-bot"), "{text}");
        assert!(text.contains("DEPLOY_BOT_TOKEN"), "{text}");
        assert!(text.contains("session_secret_configured = true"), "{text}");
        assert!(
            text.contains("push_broker_token_configured = true"),
            "{text}"
        );
        assert!(text.contains("webhook_secret_configured = true"), "{text}");
        assert!(text.contains("webhook_url_configured = true"), "{text}");
        assert!(text.contains("bulk_clients = 7"), "{text}");
        assert!(text.contains("bulk_concurrency = 19"), "{text}");
        for diagnostic in [
            "public.example/_path_redacted_",
            "issuer.example/_path_redacted_",
            "cors.example/_path_redacted_",
            "gcs.example/_path_redacted_",
            "s3.example/_path_redacted_",
            "broker.example/_path_redacted_",
            "git.example/_path_redacted_",
            "lfs.example/_path_redacted_",
        ] {
            assert!(
                text.contains(diagnostic),
                "missing sanitized URL {diagnostic}: {text}"
            );
        }
        for sentinel in [
            "safe-view-static-token-sentinel",
            "safe-view-session-secret-sentinel",
            "safe-view-oauth-secret-sentinel",
            "safe-view-broker-token-sentinel",
            "safe-view-webhook-secret-sentinel",
            "public-user",
            "public-pass",
            "public-path",
            "public-query",
            "public-fragment",
            "issuer-user",
            "issuer-pass",
            "issuer-path",
            "issuer-query",
            "issuer-fragment",
            "cors-user",
            "cors-pass",
            "cors-path",
            "cors-query",
            "cors-fragment",
            "gcs-user",
            "gcs-pass",
            "gcs-path",
            "gcs-query",
            "gcs-fragment",
            "s3-user",
            "s3-pass",
            "s3-path",
            "s3-query",
            "s3-fragment",
            "broker-user",
            "broker-pass",
            "broker-path",
            "broker-query",
            "broker-fragment",
            "git-user",
            "git-pass",
            "git-path",
            "git-query",
            "git-fragment",
            "lfs-user",
            "lfs-pass",
            "lfs-path",
            "lfs-query",
            "lfs-fragment",
            "webhook-user",
            "webhook-pass",
            "webhook-path-sentinel",
            "webhook-query",
            "webhook-fragment",
        ] {
            assert!(
                !text.contains(sentinel),
                "safe config projection leaked {sentinel}"
            );
        }
        cfg.events.webhook_url = None;
        let without_webhook = cfg.safe_view().to_toml_string().unwrap();
        assert!(
            without_webhook.contains("webhook_url_configured = false"),
            "{without_webhook}"
        );
    }

    #[test]
    fn safe_config_projection_redacts_paths_from_valid_urls_exactly() {
        let mut cfg = Config::default();
        cfg.store.bucket = "diagnostic-bucket".into();
        cfg.server.public_url =
            Some("https://public.example:8443/public-capability-sentinel".into());
        cfg.server.auth.issuer = "https://issuer.example:9443/issuer-capability-sentinel".into();
        cfg.server.cors_origins = vec!["https://cors.example:9444".into()];
        cfg.store.gcs.endpoint = "https://gcs.example:4443/gcs-capability-sentinel".into();
        cfg.store.s3.endpoint = "https://s3.example:5443/s3-capability-sentinel".into();
        cfg.wal.push_broker_url =
            Some("https://broker.example:6443/broker-capability-sentinel".into());
        cfg.upstream.git = Some("https://git.example:7443/git-capability-sentinel".into());
        cfg.upstream.lfs = Some("https://lfs.example:8444/lfs-capability-sentinel".into());
        cfg.events.webhook_url =
            Some("https://hooks.example/webhook-capability-sentinel?webhook-query-sentinel".into());
        cfg.validate().expect("valid path-bearing URLs");

        let text = cfg.safe_view().to_toml_string().unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        for (actual, expected) in [
            (
                table["server"]["public_url"].as_str(),
                "https://public.example:8443/_path_redacted_",
            ),
            (
                table["server"]["auth"]["issuer"].as_str(),
                "https://issuer.example:9443/_path_redacted_",
            ),
            (
                table["store"]["gcs"]["endpoint"].as_str(),
                "https://gcs.example:4443/_path_redacted_",
            ),
            (
                table["store"]["s3"]["endpoint"].as_str(),
                "https://s3.example:5443/_path_redacted_",
            ),
            (
                table["wal"]["push_broker_url"].as_str(),
                "https://broker.example:6443/_path_redacted_",
            ),
            (
                table["upstream"]["git"].as_str(),
                "https://git.example:7443/_path_redacted_",
            ),
            (
                table["upstream"]["lfs"].as_str(),
                "https://lfs.example:8444/_path_redacted_",
            ),
        ] {
            assert_eq!(actual, Some(expected), "{text}");
        }
        assert_eq!(
            table["server"]["cors_origins"][0].as_str(),
            Some("https://cors.example:9444/")
        );
        assert_eq!(
            table["events"]["webhook_url_configured"].as_bool(),
            Some(true)
        );
        for sentinel in [
            "public-capability-sentinel",
            "issuer-capability-sentinel",
            "gcs-capability-sentinel",
            "s3-capability-sentinel",
            "broker-capability-sentinel",
            "git-capability-sentinel",
            "lfs-capability-sentinel",
            "webhook-capability-sentinel",
            "webhook-query-sentinel",
        ] {
            assert!(!text.contains(sentinel), "safe dump leaked {sentinel}");
        }
    }

    #[test]
    fn events_section_parses_and_validates() {
        let c = Config::parse(
            r#"
[events]
sweep_interval = "1m"
webhook_url = "https://hooks.example.com/walgit"
webhook_secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(c.events.sweep_interval, Duration::from_secs(60));
        assert_eq!(c.events.webhook_secret.as_deref(), Some("s"));
        let err = Config::parse("[events]\nwebhook_url = \"ftp://x\"\n").unwrap_err();
        assert!(err.to_string().contains("webhook_url"), "{err}");
    }

    #[test]
    fn rejects_bad_bundle_graph() {
        let text = r#"
[[bundles.strategy]]
name = "daily"
kind = "incremental"
schedule = "@daily"
keep = 3
"#;
        assert!(Config::parse(text).is_err());
    }
}

#[cfg(test)]
mod bundle_strategy_validation {
    use super::*;

    fn base() -> Config {
        let mut c = Config::default();
        c.store.bucket = "b".into();
        c
    }

    #[test]
    fn defaults_validate() {
        base().validate().unwrap();
    }

    #[test]
    fn bad_schedule_incremental_without_full_root_and_keep_zero_are_rejected() {
        let mut c = base();
        c.bundles.strategy[2].schedule = "every hour".into();
        assert!(c.validate().unwrap_err().to_string().contains("schedule"));
        let mut c = base();
        c.bundles.strategy[1].base = Some("nope".into());
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("not a strategy")
        );
        let mut c = base();
        c.bundles.strategy[0].keep = 0;
        assert!(c.validate().unwrap_err().to_string().contains("keep"));
        let mut c = base();
        c.bundles.strategy[2].keep = 28;
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("not a knob on an incremental")
        );
        let mut c = base();
        c.bundles.strategy[1].base = Some("hourly".into());
        c.bundles.strategy[2].base = Some("daily".into());
        assert!(c.validate().unwrap_err().to_string().contains("cycle"));
    }
}

//! Explicit serialization boundaries for configuration exposed to users.
//!
//! `Config` is an internal runtime type. Public responses and diagnostic dumps
//! serialize only the closed projections in this module, so a future `Config`
//! field cannot cross a boundary until it is deliberately added here.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    AuthMode, BundleKind, BundleServe, ByteSize, CacheMode, Config, LogFormat, MaintainerDisk,
    ObjectFormat, RepackEngine, Role, StoreBackend, TlsMode, UploadPackEngine,
    diagnostic_cors_origin, diagnostic_url,
};

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveSettingsView {
    pub bundles: EffectiveBundlesView,
    pub maintenance: EffectiveMaintenanceView,
    pub compaction: EffectiveCompactionView,
    pub upstream: EffectiveUpstreamView,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveBundlesView {
    pub enabled: bool,
    pub strategy: Vec<EffectiveBundleStrategyView>,
    pub min_commits: u64,
    pub min_bytes: ByteSize,
    pub serve_via: BundleServe,
    #[serde(with = "humantime_serde")]
    pub signed_url_ttl: Duration,
    pub advertise: bool,
    pub advertise_filtered: bool,
    pub require: Vec<String>,
    pub signed_url_for: Vec<String>,
    pub main_only: bool,
    pub extra_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveBundleStrategyView {
    pub name: String,
    pub kind: BundleKind,
    pub schedule: String,
    pub base: Option<String>,
    pub keep: usize,
    pub refs: Vec<String>,
    pub backfill_max: usize,
    pub min_commits: Option<u64>,
    pub filter: Option<String>,
    pub chain: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveMaintenanceView {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub checkpoints: bool,
    pub max_pack_bytes: ByteSize,
    pub disk: MaintainerDisk,
    pub host: Option<String>,
    #[serde(with = "humantime_serde")]
    pub fsck_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub follow_interval: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveCompactionView {
    pub enabled: bool,
    pub factor: u32,
    pub trigger_packs: usize,
    pub trigger_bytes: ByteSize,
    #[serde(with = "humantime_serde")]
    pub lease_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub retention_superseded: Duration,
    pub engine: RepackEngine,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveUpstreamView {
    pub git: Option<String>,
    pub lfs: Option<String>,
    pub follow: Vec<String>,
}

impl EffectiveSettingsView {
    pub fn from_config(config: &Config) -> Self {
        Self {
            bundles: EffectiveBundlesView {
                enabled: config.bundles.enabled,
                strategy: config
                    .bundles
                    .strategy
                    .iter()
                    .map(|strategy| EffectiveBundleStrategyView {
                        name: strategy.name.clone(),
                        kind: strategy.kind,
                        schedule: strategy.schedule.clone(),
                        base: strategy.base.clone(),
                        keep: strategy.keep,
                        refs: strategy.refs.clone(),
                        backfill_max: strategy.backfill_max,
                        min_commits: strategy.min_commits,
                        filter: strategy.filter.clone(),
                        chain: strategy.chain,
                    })
                    .collect(),
                min_commits: config.bundles.min_commits,
                min_bytes: config.bundles.min_bytes,
                serve_via: config.bundles.serve_via,
                signed_url_ttl: config.bundles.signed_url_ttl,
                advertise: config.bundles.advertise,
                advertise_filtered: config.bundles.advertise_filtered,
                require: config.bundles.require.clone(),
                signed_url_for: config.bundles.signed_url_for.clone(),
                main_only: config.bundles.main_only,
                extra_refs: config.bundles.extra_refs.clone(),
            },
            maintenance: EffectiveMaintenanceView {
                interval: config.maintenance.interval,
                checkpoints: config.maintenance.checkpoints,
                max_pack_bytes: config.maintenance.max_pack_bytes,
                disk: config.maintenance.disk,
                host: config.maintenance.host.clone(),
                fsck_interval: config.maintenance.fsck_interval,
                follow_interval: config.maintenance.follow_interval,
            },
            compaction: EffectiveCompactionView {
                enabled: config.compaction.enabled,
                factor: config.compaction.factor,
                trigger_packs: config.compaction.trigger_packs,
                trigger_bytes: config.compaction.trigger_bytes,
                lease_ttl: config.compaction.lease_ttl,
                retention_superseded: config.compaction.retention_superseded,
                engine: config.compaction.engine,
            },
            upstream: EffectiveUpstreamView {
                git: config.upstream.git.clone(),
                lfs: config.upstream.lfs.clone(),
                follow: config.upstream.follow.clone(),
            },
        }
    }

    pub fn to_toml_table(&self) -> Result<toml::Table> {
        toml::Table::try_from(self).context("serializing effective settings projection")
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing effective settings projection")
    }
}

/// Safe diagnostic form used by `walgit config dump`.
///
/// Secret values are replaced by configured-state booleans. Environment
/// variable names remain visible because operators need them to diagnose the
/// selected credential channel.
#[derive(Debug, Clone, Serialize)]
pub struct SafeConfigView {
    pub server: SafeServerView,
    pub store: SafeStoreView,
    pub cache: SafeCacheView,
    pub wal: SafeWalView,
    pub compaction: SafeCompactionView,
    pub bundles: SafeBundlesView,
    pub maintenance: SafeMaintenanceView,
    pub placement: SafePlacementView,
    pub lfs: SafeLfsView,
    pub git: SafeGitView,
    pub upstream: SafeUpstreamView,
    pub telemetry: SafeTelemetryView,
    pub events: SafeEventsView,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeServerView {
    pub listen: SocketAddr,
    pub http2: bool,
    pub max_concurrent_requests: usize,
    pub max_concurrent_per_repo: usize,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub drain_timeout: Duration,
    pub max_push_bytes: ByteSize,
    pub roles: Vec<Role>,
    pub auth: SafeAuthView,
    pub public_url: Option<String>,
    pub auto_create_on_push: bool,
    pub accel_redirect: bool,
    pub cors_origins: Vec<String>,
    pub tls: SafeTlsView,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeTlsView {
    pub mode: TlsMode,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeAuthView {
    pub mode: AuthMode,
    pub anonymous_read: bool,
    pub tokens: Vec<SafeStaticTokenView>,
    pub managed_tokens: Option<SafeManagedTokensView>,
    pub issuer: Option<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    pub audiences: Vec<String>,
    pub write_domains: Option<Vec<String>>,
    pub trusted_forwarders: Vec<String>,
    pub session_secret_configured: bool,
    #[serde(with = "humantime_serde")]
    pub session_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub access_token_ttl: Duration,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret_configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeManagedTokensView {
    pub issuer: String,
    pub audience: String,
    pub key_ids: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeStaticTokenView {
    pub principal: String,
    pub token_env: Option<String>,
    pub literal_token_configured: bool,
    pub write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeStoreView {
    pub backend: StoreBackend,
    pub bucket: String,
    pub prefix: String,
    pub gcs: SafeGcsView,
    pub s3: SafeS3View,
    pub max_retries: u32,
    pub multipart_threshold: ByteSize,
    pub multipart_part_size: ByteSize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeGcsView {
    pub endpoint: Option<String>,
    pub direct_connectivity: bool,
    pub signing_service_account: Option<String>,
    pub bulk_clients: usize,
    pub bulk_concurrency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeS3View {
    pub endpoint: Option<String>,
    pub region: String,
    pub credential_mode: super::S3CredentialMode,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub session_token_env: String,
    pub force_path_style: bool,
    pub bulk_clients: usize,
    pub bulk_concurrency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCacheView {
    pub dir: PathBuf,
    pub mode: CacheMode,
    pub max_bytes: ByteSize,
    pub disk_high_watermark: f64,
    #[serde(with = "humantime_serde")]
    pub evict_idle_after: Duration,
    pub prewarm: Vec<String>,
    pub prewarm_parallelism: usize,
    #[serde(with = "humantime_serde")]
    pub prewarm_ready_timeout: Duration,
    pub ref_advert_entries: usize,
    pub object_info_entries: usize,
    pub bundle_list_entries: usize,
    pub remote_block_bytes: ByteSize,
    pub remote_object_bytes: ByteSize,
    pub shared_render_cache: bool,
    pub store_mount: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeWalView {
    #[serde(with = "humantime_serde")]
    pub batch_window: Duration,
    pub max_batch: usize,
    pub push_broker_url: Option<String>,
    pub push_broker_token_configured: bool,
    pub push_broker_buffer_bytes: ByteSize,
    pub snapshot_every_entries: u64,
    #[serde(with = "humantime_serde")]
    pub checkpoint_interval: Duration,
    pub checkpoint_tail_bytes: ByteSize,
    pub cas_max_retries: u32,
    pub fsck_objects: bool,
    pub check_connectivity: bool,
    #[serde(with = "humantime_serde")]
    pub freshness_ttl: Duration,
    pub prefetch_packs: bool,
    pub prefetch_max_bytes: ByteSize,
    pub remote_objects: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCompactionView {
    pub enabled: bool,
    pub factor: u32,
    pub trigger_packs: usize,
    pub trigger_bytes: ByteSize,
    #[serde(with = "humantime_serde")]
    pub lease_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub retention_superseded: Duration,
    pub engine: RepackEngine,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeBundlesView {
    pub enabled: bool,
    pub strategy: Vec<SafeBundleStrategyView>,
    pub min_commits: u64,
    pub min_bytes: ByteSize,
    pub serve_via: BundleServe,
    #[serde(with = "humantime_serde")]
    pub signed_url_ttl: Duration,
    pub advertise: bool,
    pub advertise_filtered: bool,
    pub require: Vec<String>,
    pub signed_url_for: Vec<String>,
    pub main_only: bool,
    pub extra_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeBundleStrategyView {
    pub name: String,
    pub kind: BundleKind,
    pub schedule: String,
    pub base: Option<String>,
    pub keep: usize,
    pub refs: Vec<String>,
    pub backfill_max: usize,
    pub min_commits: Option<u64>,
    pub filter: Option<String>,
    pub chain: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeMaintenanceView {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub checkpoints: bool,
    pub max_pack_bytes: ByteSize,
    pub disk: MaintainerDisk,
    pub host: Option<String>,
    #[serde(with = "humantime_serde")]
    pub fsck_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub follow_interval: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafePlacementView {
    pub serve: Vec<String>,
    pub serve_exclude: Vec<String>,
    pub maintain: Vec<String>,
    pub maintain_exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLfsView {
    pub enabled: bool,
    pub serve_via: BundleServe,
    #[serde(with = "humantime_serde")]
    pub signed_url_ttl: Duration,
    pub max_object_bytes: ByteSize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeGitView {
    pub binary: PathBuf,
    pub upload_pack_engine: UploadPackEngine,
    pub allow_filter: bool,
    pub allow_any_sha1_in_want: bool,
    pub object_format: ObjectFormat,
    pub commit_graph: bool,
    pub commit_graph_changed_paths: bool,
    pub history_pack: bool,
    pub max_wants: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeUpstreamView {
    pub git: Option<String>,
    pub lfs: Option<String>,
    pub token_env: Option<String>,
    pub follow: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeTelemetryView {
    pub log_format: LogFormat,
    pub log_filter: String,
    pub metrics: bool,
    pub trace_project: Option<String>,
    #[serde(with = "humantime_serde")]
    pub lock_wait_warn: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeEventsView {
    pub webhook_url_configured: bool,
    pub webhook_secret_configured: bool,
    #[serde(with = "humantime_serde")]
    pub sweep_interval: Duration,
}

impl SafeConfigView {
    pub fn from_config(config: &Config) -> Self {
        let auth = &config.server.auth;
        Self {
            server: SafeServerView {
                listen: config.server.listen,
                http2: config.server.http2,
                max_concurrent_requests: config.server.max_concurrent_requests,
                max_concurrent_per_repo: config.server.max_concurrent_per_repo,
                request_timeout: config.server.request_timeout,
                drain_timeout: config.server.drain_timeout,
                max_push_bytes: config.server.max_push_bytes,
                roles: config.server.roles.clone(),
                auth: SafeAuthView {
                    mode: auth.mode,
                    anonymous_read: auth.anonymous_read,
                    tokens: auth
                        .tokens
                        .iter()
                        .map(|token| SafeStaticTokenView {
                            principal: token.principal.clone(),
                            token_env: token.token_env.clone(),
                            literal_token_configured: !token.token.is_empty(),
                            write: token.write,
                        })
                        .collect(),
                    managed_tokens: auth.managed_tokens.as_ref().map(|managed| {
                        SafeManagedTokensView {
                            issuer: managed.issuer.clone(),
                            audience: managed.audience.clone(),
                            key_ids: managed.keys.iter().map(|key| key.kid.clone()).collect(),
                            max_ttl: managed.max_ttl,
                        }
                    }),
                    issuer: diagnostic_url(&auth.issuer),
                    allowed_domains: auth.allowed_domains.clone(),
                    allowed_emails: auth.allowed_emails.clone(),
                    audiences: auth.audiences.clone(),
                    write_domains: auth.write_domains.clone(),
                    trusted_forwarders: auth.trusted_forwarders.clone(),
                    session_secret_configured: auth
                        .session_secret
                        .as_deref()
                        .is_some_and(|secret| !secret.is_empty()),
                    session_ttl: auth.session_ttl,
                    access_token_ttl: auth.access_token_ttl,
                    oauth_client_id: auth.oauth_client_id.clone(),
                    oauth_client_secret_configured: auth
                        .oauth_client_secret
                        .as_deref()
                        .is_some_and(|secret| !secret.is_empty()),
                },
                public_url: config.server.public_url.as_deref().and_then(diagnostic_url),
                auto_create_on_push: config.server.auto_create_on_push,
                accel_redirect: config.server.accel_redirect,
                cors_origins: config
                    .server
                    .cors_origins
                    .iter()
                    .filter_map(|origin| diagnostic_cors_origin(origin))
                    .collect(),
                tls: SafeTlsView {
                    mode: config.server.tls.mode,
                    cert: config.server.tls.cert.clone(),
                    key: config.server.tls.key.clone(),
                    hostnames: config.server.tls.hostnames.clone(),
                },
            },
            store: SafeStoreView {
                backend: config.store.backend,
                bucket: config.store.bucket.clone(),
                prefix: config.store.prefix.clone(),
                gcs: SafeGcsView {
                    endpoint: diagnostic_url(&config.store.gcs.endpoint),
                    direct_connectivity: config.store.gcs.direct_connectivity,
                    signing_service_account: config.store.gcs.signing_service_account.clone(),
                    bulk_clients: config.store.gcs.bulk_clients,
                    bulk_concurrency: config.store.gcs.bulk_concurrency,
                },
                s3: SafeS3View {
                    endpoint: diagnostic_url(&config.store.s3.endpoint),
                    region: config.store.s3.region.clone(),
                    credential_mode: config.store.s3.credential_mode,
                    access_key_env: config.store.s3.access_key_env.clone(),
                    secret_key_env: config.store.s3.secret_key_env.clone(),
                    session_token_env: config.store.s3.session_token_env.clone(),
                    force_path_style: config.store.s3.force_path_style,
                    bulk_clients: config.store.s3.bulk_clients,
                    bulk_concurrency: config.store.s3.bulk_concurrency,
                },
                max_retries: config.store.max_retries,
                multipart_threshold: config.store.multipart_threshold,
                multipart_part_size: config.store.multipart_part_size,
            },
            cache: SafeCacheView {
                dir: config.cache.dir.clone(),
                mode: config.cache.mode,
                max_bytes: config.cache.max_bytes,
                disk_high_watermark: config.cache.disk_high_watermark,
                evict_idle_after: config.cache.evict_idle_after,
                prewarm: config.cache.prewarm.clone(),
                prewarm_parallelism: config.cache.prewarm_parallelism,
                prewarm_ready_timeout: config.cache.prewarm_ready_timeout,
                ref_advert_entries: config.cache.ref_advert_entries,
                object_info_entries: config.cache.object_info_entries,
                bundle_list_entries: config.cache.bundle_list_entries,
                remote_block_bytes: config.cache.remote_block_bytes,
                remote_object_bytes: config.cache.remote_object_bytes,
                shared_render_cache: config.cache.shared_render_cache,
                store_mount: config.cache.store_mount.clone(),
            },
            wal: SafeWalView {
                batch_window: config.wal.batch_window,
                max_batch: config.wal.max_batch,
                push_broker_url: config
                    .wal
                    .push_broker_url
                    .as_deref()
                    .and_then(diagnostic_url),
                push_broker_token_configured: config
                    .wal
                    .push_broker_token
                    .as_deref()
                    .is_some_and(|token| !token.is_empty()),
                push_broker_buffer_bytes: config.wal.push_broker_buffer_bytes,
                snapshot_every_entries: config.wal.snapshot_every_entries,
                checkpoint_interval: config.wal.checkpoint_interval,
                checkpoint_tail_bytes: config.wal.checkpoint_tail_bytes,
                cas_max_retries: config.wal.cas_max_retries,
                fsck_objects: config.wal.fsck_objects,
                check_connectivity: config.wal.check_connectivity,
                freshness_ttl: config.wal.freshness_ttl,
                prefetch_packs: config.wal.prefetch_packs,
                prefetch_max_bytes: config.wal.prefetch_max_bytes,
                remote_objects: config.wal.remote_objects,
            },
            compaction: SafeCompactionView {
                enabled: config.compaction.enabled,
                factor: config.compaction.factor,
                trigger_packs: config.compaction.trigger_packs,
                trigger_bytes: config.compaction.trigger_bytes,
                lease_ttl: config.compaction.lease_ttl,
                retention_superseded: config.compaction.retention_superseded,
                engine: config.compaction.engine,
            },
            bundles: SafeBundlesView {
                enabled: config.bundles.enabled,
                strategy: config
                    .bundles
                    .strategy
                    .iter()
                    .map(|strategy| SafeBundleStrategyView {
                        name: strategy.name.clone(),
                        kind: strategy.kind,
                        schedule: strategy.schedule.clone(),
                        base: strategy.base.clone(),
                        keep: strategy.keep,
                        refs: strategy.refs.clone(),
                        backfill_max: strategy.backfill_max,
                        min_commits: strategy.min_commits,
                        filter: strategy.filter.clone(),
                        chain: strategy.chain,
                    })
                    .collect(),
                min_commits: config.bundles.min_commits,
                min_bytes: config.bundles.min_bytes,
                serve_via: config.bundles.serve_via,
                signed_url_ttl: config.bundles.signed_url_ttl,
                advertise: config.bundles.advertise,
                advertise_filtered: config.bundles.advertise_filtered,
                require: config.bundles.require.clone(),
                signed_url_for: config.bundles.signed_url_for.clone(),
                main_only: config.bundles.main_only,
                extra_refs: config.bundles.extra_refs.clone(),
            },
            maintenance: SafeMaintenanceView {
                interval: config.maintenance.interval,
                checkpoints: config.maintenance.checkpoints,
                max_pack_bytes: config.maintenance.max_pack_bytes,
                disk: config.maintenance.disk,
                host: config.maintenance.host.clone(),
                fsck_interval: config.maintenance.fsck_interval,
                follow_interval: config.maintenance.follow_interval,
            },
            placement: SafePlacementView {
                serve: config.placement.serve.clone(),
                serve_exclude: config.placement.serve_exclude.clone(),
                maintain: config.placement.maintain.clone(),
                maintain_exclude: config.placement.maintain_exclude.clone(),
            },
            lfs: SafeLfsView {
                enabled: config.lfs.enabled,
                serve_via: config.lfs.serve_via,
                signed_url_ttl: config.lfs.signed_url_ttl,
                max_object_bytes: config.lfs.max_object_bytes,
            },
            git: SafeGitView {
                binary: config.git.binary.clone(),
                upload_pack_engine: config.git.upload_pack_engine,
                allow_filter: config.git.allow_filter,
                allow_any_sha1_in_want: config.git.allow_any_sha1_in_want,
                object_format: config.git.object_format,
                commit_graph: config.git.commit_graph,
                commit_graph_changed_paths: config.git.commit_graph_changed_paths,
                history_pack: config.git.history_pack,
                max_wants: config.git.max_wants,
            },
            upstream: SafeUpstreamView {
                git: config.upstream.git.as_deref().and_then(diagnostic_url),
                lfs: config.upstream.lfs.as_deref().and_then(diagnostic_url),
                token_env: config.upstream.token_env.clone(),
                follow: config.upstream.follow.clone(),
            },
            telemetry: SafeTelemetryView {
                log_format: config.telemetry.log_format,
                log_filter: config.telemetry.log_filter.clone(),
                metrics: config.telemetry.metrics,
                trace_project: config.telemetry.trace_project.clone(),
                lock_wait_warn: config.telemetry.lock_wait_warn,
            },
            events: SafeEventsView {
                webhook_url_configured: config.events.webhook_url.is_some(),
                webhook_secret_configured: config
                    .events
                    .webhook_secret
                    .as_deref()
                    .is_some_and(|secret| !secret.is_empty()),
                sweep_interval: config.events.sweep_interval,
            },
        }
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing safe configuration projection")
    }
}

impl Config {
    pub fn effective_settings_view(&self) -> EffectiveSettingsView {
        EffectiveSettingsView::from_config(self)
    }

    pub fn safe_view(&self) -> SafeConfigView {
        SafeConfigView::from_config(self)
    }
}

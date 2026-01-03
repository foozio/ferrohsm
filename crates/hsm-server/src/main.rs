mod auth;
mod pqc;
mod retention;
mod tls;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use clap::{Parser, ValueEnum};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tera::Tera;
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{signal, time::MissedTickBehavior};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::tls::TlsSetup;
use auth::AuthVerifier;
use hsm_core::{
    ApprovalStore, AuditEvent, AuditLog, AuthContext, CheckpointScheduler, DefaultPolicyEngine,
    FileApprovalStore, FileAuditLog, HsmError, KeyAlgorithm, KeyGenerationRequest, KeyManager,
    KeyRotationScheduler, KeyState, KeyStore, KeyUsage, OperationContext, PendingApprovalInfo,
    PolicyEngine, RbacAuthorizer, Role, SqliteApprovalStore, SqliteAuditLog, SqliteKeyStore,
    TamperStatus, retention::RetentionLedger, storage::FileKeyStore,
};
use retention::RetentionScheduler;

#[derive(Parser, Debug)]
#[command(
    name = "hsm-server",
    version,
    about = "FerroHSM secure services daemon"
)]
struct Args {
    /// Bind address for the HTTPS listener.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// TLS provisioning mode (`manual` uses provided certs, `acme` provisions automatically).
    #[arg(long, value_enum, default_value_t = TlsMode::Manual)]
    tls_mode: TlsMode,

    /// Directory for sealed key material.
    #[arg(long, default_value = "data/keys")]
    key_dir: PathBuf,

    /// Key store backend (filesystem or sqlite).
    #[arg(long, value_enum, default_value_t = StoreBackend::Filesystem)]
    key_store: StoreBackend,

    /// SQLite database path (used when --key-store=sqlite).
    #[arg(long, default_value = "data/keys.sqlite")]
    sqlite_path: PathBuf,

    /// Audit store backend (file or sqlite).
    #[arg(long, value_enum, default_value_t = AuditStoreBackend::File)]
    audit_store: AuditStoreBackend,

    /// Audit log file path (used when --audit-store=file).
    #[arg(long, default_value = "data/audit.log")]
    audit_log: PathBuf,

    /// SQLite audit database path (used when --audit-store=sqlite).
    #[arg(long, default_value = "data/audit.sqlite")]
    audit_sqlite_path: PathBuf,

    /// Approval store backend (file or sqlite).
    #[arg(long, value_enum, default_value_t = ApprovalStoreBackend::File)]
    approval_store: ApprovalStoreBackend,

    /// Directory for pending approval records (used when --approval-store=file).
    #[arg(long, default_value = "data/approvals")]
    approval_dir: PathBuf,

    /// SQLite approvals database path (used when --approval-store=sqlite).
    #[arg(long, default_value = "data/approvals.sqlite")]
    approval_sqlite_path: PathBuf,

    /// TLS certificate chain in PEM format (required in manual TLS mode).
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key in PEM format (required in manual TLS mode).
    #[arg(long)]
    key: Option<PathBuf>,

    /// Optional OCSP response in DER format to staple for manual TLS deployments.
    #[arg(long)]
    ocsp_response: Option<PathBuf>,

    /// Interval in seconds to reload certificates and OCSP data when using manual TLS.
    #[arg(long, default_value_t = 3600)]
    cert_reload_interval_secs: u64,

    /// Interval in seconds between OCSP staple refresh attempts in manual TLS mode.
    #[arg(long, default_value_t = 14400)]
    ocsp_refresh_interval_secs: u64,

    /// Optional client CA bundle for mutual TLS.
    #[arg(long)]
    client_ca: Option<PathBuf>,

    /// Domains to request certificates for when ACME mode is enabled (repeat flag or comma-delimited list).
    #[arg(long = "acme-domain", value_delimiter = ',', num_args = 0..)]
    acme_domains: Vec<String>,

    /// Contact emails for ACME account registration (repeat flag). `mailto:` prefix is added automatically if omitted.
    #[arg(long = "acme-contact", value_delimiter = ',', num_args = 0..)]
    acme_contacts: Vec<String>,

    /// Directory to cache ACME account and certificate material.
    #[arg(long, default_value = "data/acme")]
    acme_cache_dir: PathBuf,

    /// Override ACME directory URL (defaults to Let's Encrypt staging unless --acme-use-production is provided).
    #[arg(long)]
    acme_directory_url: Option<String>,

    /// Use Let's Encrypt production directory (rate limited) instead of staging.
    #[arg(long, default_value_t = false)]
    acme_use_production: bool,

    /// 32-byte master key encoded as base64 (env: FERROHSM_MASTER_KEY).
    #[arg(long, env = "FERROHSM_MASTER_KEY")]
    master_key: Option<String>,

    /// 32-byte HMAC key encoded as base64 (env: FERROHSM_HMAC_KEY).
    #[arg(long, env = "FERROHSM_HMAC_KEY")]
    hmac_key: Option<String>,

    /// JWT secret (base64 or utf-8) used to validate bearer tokens.
    #[arg(long, env = "FERROHSM_JWT_SECRET")]
    auth_jwt_secret: Option<String>,

    /// Optional JWT configuration file (JSON or YAML) describing algorithms and key rotation.
    #[arg(long, env = "FERROHSM_JWT_CONFIG")]
    auth_jwt_config: Option<PathBuf>,

    /// Expected JWT issuer when using a shared secret.
    #[arg(long, env = "FERROHSM_JWT_ISSUER")]
    auth_jwt_issuer: Option<String>,

    /// Interval, in seconds, between JWT config reload checks.
    #[arg(long, default_value_t = 30)]
    auth_jwt_reload_secs: u64,

    /// Allowed requests per second per remote identity.
    #[arg(long, default_value_t = 100)]
    rate_limit_per_second: u64,

    /// Rate limiting burst capacity.
    #[arg(long, default_value_t = 200)]
    rate_limit_burst: u64,

    /// TTL in seconds for key listing cache entries.
    #[arg(long, default_value_t = 5)]
    list_cache_ttl_secs: u64,

    /// Retention policy configuration file (YAML or JSON).
    #[arg(long, default_value = "config/retention.yaml")]
    retention_config: PathBuf,

    /// Ledger file capturing purge attestations.
    #[arg(long, default_value = "data/retention-ledger.log")]
    retention_ledger: PathBuf,

    /// Interval in seconds between retention sweeps.
    #[arg(long, default_value_t = 3600)]
    retention_interval_secs: u64,

    /// Grace period in seconds after approval before purge executes.
    #[arg(long, default_value_t = 86400)]
    retention_grace_secs: u64,

    /// Audit retention window in days (sqlite backend only).
    #[arg(long, default_value_t = 365)]
    audit_retention_days: u64,

    /// Interval in seconds between audit retention sweeps.
    #[arg(long, default_value_t = 86400)]
    audit_retention_interval_secs: u64,

    /// Approval retention window in days (sqlite backend only for approved records).
    #[arg(long, default_value_t = 90)]
    approval_retention_days: u64,

    /// Interval in seconds between approval retention sweeps.
    #[arg(long, default_value_t = 86400)]
    approval_retention_interval_secs: u64,

    /// Interval in seconds between audit checkpoint verifications.
    #[arg(long, default_value_t = 3600)]
    checkpoint_interval_secs: u64,

    /// Interval in seconds between audit signing key rotation checks.
    #[arg(long, default_value_t = 86400)]
    key_rotation_interval_secs: u64,
}

#[derive(Clone, Debug, ValueEnum)]
enum TlsMode {
    Manual,
    Acme,
}

#[derive(Clone, Debug, ValueEnum)]
enum StoreBackend {
    Filesystem,
    Sqlite,
}

#[derive(Clone, Debug, ValueEnum)]
enum AuditStoreBackend {
    File,
    Sqlite,
}

#[derive(Clone, Debug, ValueEnum)]
enum ApprovalStoreBackend {
    File,
    Sqlite,
}

struct AppState<P: PolicyEngine + 'static> {
    manager: Arc<KeyManager<dyn KeyStore, dyn AuditLog, P>>,
    templates: Arc<Tera>,
    auth: Arc<AuthVerifier>,
    rate_limiter: Arc<RateLimiter>,
    key_cache: Arc<KeyCache>,
    audit_view: AuditView,
    metrics_handle: PrometheusHandle,
    startup: Instant,
}

impl<P: PolicyEngine + 'static> Clone for AppState<P> {
    fn clone(&self) -> Self {
        Self {
            manager: Arc::clone(&self.manager),
            templates: Arc::clone(&self.templates),
            auth: Arc::clone(&self.auth),
            rate_limiter: Arc::clone(&self.rate_limiter),
            key_cache: Arc::clone(&self.key_cache),
            audit_view: self.audit_view.clone(),
            metrics_handle: self.metrics_handle.clone(),
            startup: self.startup,
        }
    }
}

fn authenticate_request<P: PolicyEngine>(
    state: &AppState<P>,
    headers: &HeaderMap,
    remote_addr: IpAddr,
) -> Result<AuthContext, AppError> {
    let authn = state.auth.authenticate(headers, Some(remote_addr))?;
    state.rate_limiter.check(authn.throttle_key())?;
    Ok(authn.into_context())
}

#[derive(Clone)]
enum AuditView {
    File(Arc<FileAuditLog>),
    Sqlite(Arc<SqliteAuditLog>),
}

impl AuditView {
    fn recent_events(&self, limit: usize) -> Vec<AuditEventSummary> {
        let events = match self {
            Self::File(file) => file.tail(limit).unwrap_or_default(),
            Self::Sqlite(db) => db.tail(limit).unwrap_or_default(),
        };
        events.into_iter().map(AuditEventSummary::from).collect()
    }
}

#[derive(Debug, Serialize)]
struct AuditEventSummary {
    actor_id: String,
    action: String,
    key_id: Option<String>,
    message: String,
    hash: String,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
}

impl From<AuditEvent> for AuditEventSummary {
    fn from(event: AuditEvent) -> Self {
        Self {
            actor_id: event.record.actor_id,
            action: event.record.action.to_string(),
            key_id: event.record.key_id,
            message: event.record.message,
            hash: event.hash,
            timestamp: event.record.timestamp,
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct MetricsSnapshot {
    rate_allowed: u64,
    rate_blocked: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_stores: u64,
}

impl MetricsSnapshot {
    fn from_prometheus(text: &str) -> Self {
        Self {
            rate_allowed: Self::extract_counter(text, "ferrohsm_rate_limit_allowed_total"),
            rate_blocked: Self::extract_counter(text, "ferrohsm_rate_limit_blocked_total"),
            cache_hits: Self::extract_counter(text, "ferrohsm_key_cache_hit_total"),
            cache_misses: Self::extract_counter(text, "ferrohsm_key_cache_miss_total"),
            cache_stores: Self::extract_counter(text, "ferrohsm_key_cache_store_total"),
        }
    }

    fn extract_counter(text: &str, metric: &str) -> u64 {
        text.lines()
            .find(|line| line.starts_with(metric))
            .and_then(|line| line.split_whitespace().last())
            .and_then(|value| value.parse::<f64>().ok())
            .map(|val| val as u64)
            .unwrap_or(0)
    }
}

const RATE_LIMITER_MAX_BUCKETS: usize = 4096;
const RATE_LIMITER_IDLE_TTL: Duration = Duration::from_secs(300);

struct RateLimiter {
    buckets: Mutex<BucketStore>,
    capacity: u64,
    per_second: u64,
    refill_per_sec: f64,
    max_buckets: usize,
    idle_ttl: Duration,
}

struct BucketStore {
    map: HashMap<String, TokenBucket>,
    order: VecDeque<String>,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

#[derive(Debug, Serialize)]
struct RateLimiterStats {
    per_second: u64,
    burst: u64,
    active_buckets: usize,
}

impl RateLimiter {
    fn new(per_second: u64, burst: u64) -> Self {
        let per_second = per_second.max(1);
        let burst = burst.max(1);
        Self {
            buckets: parking_lot::Mutex::new(BucketStore::new()),
            capacity: burst,
            per_second,
            refill_per_sec: per_second as f64,
            max_buckets: RATE_LIMITER_MAX_BUCKETS,
            idle_ttl: RATE_LIMITER_IDLE_TTL,
        }
    }

    fn check(&self, bucket_id: &str) -> Result<(), AppError> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        buckets.evict_stale(now, self.idle_ttl);
        let bucket = buckets.get_or_insert(bucket_id, self.capacity, now, self.max_buckets);
        bucket.refill(now, self.refill_per_sec, self.capacity);
        if bucket.consume(1.0) {
            metrics::counter!("ferrohsm_rate_limit_allowed_total").increment(1);
            Ok(())
        } else {
            metrics::counter!("ferrohsm_rate_limit_blocked_total").increment(1);
            Err(AppError::too_many_requests())
        }
    }

    fn stats(&self) -> RateLimiterStats {
        let buckets = self.buckets.lock();
        RateLimiterStats {
            per_second: self.per_second,
            burst: self.capacity,
            active_buckets: buckets.len(),
        }
    }
}

impl BucketStore {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn get_or_insert(
        &mut self,
        actor: &str,
        capacity: u64,
        now: Instant,
        max_buckets: usize,
    ) -> &mut TokenBucket {
        if self.map.contains_key(actor) {
            self.touch(actor);
            return self
                .map
                .get_mut(actor)
                .expect("bucket must exist after touch");
        }
        self.insert(actor, TokenBucket::new(capacity, now), max_buckets)
    }

    fn insert(&mut self, actor: &str, bucket: TokenBucket, max_buckets: usize) -> &mut TokenBucket {
        self.touch(actor);
        self.map.insert(actor.to_string(), bucket);
        self.enforce_limit(max_buckets);
        self.map.get_mut(actor).expect("bucket just inserted")
    }

    fn touch(&mut self, actor: &str) {
        if let Some(pos) = self.order.iter().position(|entry| entry == actor) {
            self.order.remove(pos);
        }
        self.order.push_back(actor.to_string());
    }

    fn enforce_limit(&mut self, max_buckets: usize) {
        while self.map.len() > max_buckets {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn evict_stale(&mut self, now: Instant, ttl: Duration) {
        while let Some(actor) = self.order.front() {
            let remove = self
                .map
                .get(actor)
                .map(|bucket| now.saturating_duration_since(bucket.last_seen) >= ttl)
                .unwrap_or(true);
            if remove {
                let oldest = self.order.pop_front().expect("front exists");
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

impl TokenBucket {
    fn new(capacity: u64, now: Instant) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: now,
            last_seen: now,
        }
    }

    fn refill(&mut self, now: Instant, rate: f64, capacity: u64) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let added = elapsed.as_secs_f64() * rate;
        self.tokens = (self.tokens + added).min(capacity as f64);
        self.last_seen = now;
    }

    fn consume(&mut self, amount: f64) -> bool {
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct KeyCacheKey {
    actor: String,
    algorithm: Option<KeyAlgorithm>,
    state: Option<KeyState>,
    tags: Vec<String>,
    page: u32,
    per_page: u32,
}

impl KeyCacheKey {
    fn new(actor: String, query: &hsm_core::KeyListQuery) -> Self {
        let mut tags = query.policy_tags.clone();
        tags.sort();
        Self {
            actor,
            algorithm: query.algorithm,
            state: query.state.clone(),
            tags,
            page: query.page,
            per_page: query.per_page,
        }
    }
}

struct CacheEntry {
    inserted_at: Instant,
    value: PaginatedKeys,
}

const KEY_CACHE_MAX_ENTRIES: usize = 2048;

struct KeyCache {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<CacheStore>,
}

struct CacheStore {
    map: HashMap<KeyCacheKey, CacheEntry>,
    order: VecDeque<KeyCacheKey>,
}

impl KeyCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: KEY_CACHE_MAX_ENTRIES,
            entries: Mutex::new(CacheStore::new()),
        }
    }

    fn get(&self, key: &KeyCacheKey) -> Option<PaginatedKeys> {
        let mut entries = self.entries.lock();
        entries.evict_expired(self.ttl);
        if let Some(result) = entries.get(key, self.ttl) {
            metrics::counter!("ferrohsm_key_cache_hit_total").increment(1);
            return Some(result);
        }
        metrics::counter!("ferrohsm_key_cache_miss_total").increment(1);
        None
    }

    fn put(&self, key: KeyCacheKey, value: PaginatedKeys) {
        let mut entries = self.entries.lock();
        entries.evict_expired(self.ttl);
        entries.insert(key, value, self.max_entries);
        metrics::counter!("ferrohsm_key_cache_store_total").increment(1);
    }

    fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

impl CacheStore {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn evict_expired(&mut self, ttl: Duration) {
        while let Some(key) = self.order.front() {
            let remove = self
                .map
                .get(key)
                .map(|entry| entry.inserted_at.elapsed() > ttl)
                .unwrap_or(true);
            if remove {
                let oldest = self.order.pop_front().expect("front exists");
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn get(&mut self, key: &KeyCacheKey, ttl: Duration) -> Option<PaginatedKeys> {
        let should_return = self
            .map
            .get(key)
            .filter(|entry| entry.inserted_at.elapsed() <= ttl)
            .map(|entry| entry.value.clone());

        if let Some(value) = should_return {
            self.touch(key.clone());
            return Some(value);
        }

        if self.map.remove(key).is_some()
            && let Some(pos) = self.order.iter().position(|existing| existing == key)
        {
            self.order.remove(pos);
        }
        None
    }

    fn insert(&mut self, key: KeyCacheKey, value: PaginatedKeys, max_entries: usize) {
        if self.map.contains_key(&key)
            && let Some(pos) = self.order.iter().position(|existing| existing == &key)
        {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
        self.map.insert(
            key,
            CacheEntry {
                inserted_at: Instant::now(),
                value,
            },
        );
        self.enforce_limit(max_entries);
    }

    fn enforce_limit(&mut self, max_entries: usize) {
        while self.map.len() > max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn touch(&mut self, key: KeyCacheKey) {
        if let Some(pos) = self.order.iter().position(|existing| existing == &key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize OpenTelemetry tracing
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| anyhow::anyhow!("failed to initialize OpenTelemetry: {e}"))?;

    // Set up tracing subscriber with OpenTelemetry
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let args = Args::parse();
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|err| anyhow::anyhow!("failed to install metrics recorder: {err}"))?;
    let startup = Instant::now();
    let master_key = decode_or_error(args.master_key.as_deref(), "master")?;
    let hmac_key = decode_or_error(args.hmac_key.as_deref(), "hmac")?;

    let storage: Arc<dyn KeyStore> = match args.key_store {
        StoreBackend::Filesystem => Arc::new(FileKeyStore::new(&args.key_dir)?),
        StoreBackend::Sqlite => Arc::new(SqliteKeyStore::new(&args.sqlite_path)?),
    };

    let (audit_log, audit_sqlite, audit_view): (
        Arc<dyn AuditLog>,
        Option<Arc<SqliteAuditLog>>,
        AuditView,
    ) = match args.audit_store {
        AuditStoreBackend::File => {
            let file = Arc::new(FileAuditLog::new(&args.audit_log)?);
            (file.clone(), None, AuditView::File(file))
        }
        AuditStoreBackend::Sqlite => {
            let sqlite = Arc::new(SqliteAuditLog::new(&args.audit_sqlite_path)?);
            (
                sqlite.clone(),
                Some(sqlite.clone()),
                AuditView::Sqlite(sqlite),
            )
        }
    };

    let approval_sqlite: Option<Arc<SqliteApprovalStore>> = match args.approval_store {
        ApprovalStoreBackend::File => None,
        ApprovalStoreBackend::Sqlite => Some(Arc::new(SqliteApprovalStore::new(
            &args.approval_sqlite_path,
        )?)),
    };
    let approval_store: Arc<dyn ApprovalStore> = match &approval_sqlite {
        Some(sqlite) => sqlite.clone(),
        None => Arc::new(FileApprovalStore::new(&args.approval_dir)?),
    };
    let policy = DefaultPolicyEngine::new(
        RbacAuthorizer::default(),
        HashSet::new(),
        approval_store.clone(),
    );
    let manager: Arc<KeyManager<dyn KeyStore, dyn AuditLog, _>> = Arc::new(KeyManager::new(
        Arc::clone(&storage),
        Arc::clone(&audit_log),
        policy,
        master_key,
        hmac_key,
    ));
    let retention_ledger = Arc::new(RetentionLedger::new(&args.retention_ledger)?);
    let templates = Arc::new(load_templates("web/templates/**/*")?);
    let auth = if let Some(config_path) = args.auth_jwt_config.clone() {
        AuthVerifier::from_config_file(config_path, Duration::from_secs(args.auth_jwt_reload_secs))?
    } else if let Some(secret) = args.auth_jwt_secret.as_deref() {
        AuthVerifier::from_secret(secret, args.auth_jwt_issuer.clone())?
    } else {
        anyhow::bail!("provide --auth-jwt-secret or --auth-jwt-config");
    };
    let auth = Arc::new(auth);
    let rate_limiter = Arc::new(RateLimiter::new(
        args.rate_limit_per_second,
        args.rate_limit_burst,
    ));
    let key_cache = Arc::new(KeyCache::new(Duration::from_secs(args.list_cache_ttl_secs)));
    let retention_grace_secs = i64::try_from(args.retention_grace_secs)
        .map_err(|_| anyhow::anyhow!("retention_grace_secs exceeds supported range"))?;
    let retention_scheduler = RetentionScheduler::new(
        Arc::clone(&manager),
        approval_store.clone(),
        Arc::clone(&retention_ledger),
        args.retention_config.clone(),
        Duration::from_secs(args.retention_interval_secs),
        time::Duration::seconds(retention_grace_secs),
    );
    let state = AppState {
        manager,
        templates,
        auth,
        rate_limiter,
        key_cache,
        audit_view: audit_view.clone(),
        metrics_handle: metrics_handle.clone(),
        startup,
    };

    tokio::spawn(retention_scheduler.run());

    // Spawn checkpoint scheduler
    let checkpoint_interval = Duration::from_secs(args.checkpoint_interval_secs.max(60));
    if let AuditView::File(file_audit_log) = audit_view.clone() {
        let checkpoint_scheduler =
            CheckpointScheduler::new(Arc::clone(&file_audit_log), checkpoint_interval);
        tokio::spawn(async move { checkpoint_scheduler.run().await });

        // Spawn key rotation scheduler
        let key_rotation_interval = Duration::from_secs(args.key_rotation_interval_secs.max(60));
        let key_rotation_scheduler =
            KeyRotationScheduler::new(file_audit_log, key_rotation_interval);
        tokio::spawn(async move { key_rotation_scheduler.run().await });
    }

    let audit_interval = Duration::from_secs(args.audit_retention_interval_secs.max(60));
    if let Some(sqlite) = audit_sqlite {
        let retention_days = i64::try_from(args.audit_retention_days)
            .map_err(|_| anyhow::anyhow!("audit_retention_days exceeds supported range"))?;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(audit_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let cutoff = OffsetDateTime::now_utc() - TimeDuration::days(retention_days);
                let store = sqlite.clone();
                match tokio::task::spawn_blocking(move || store.purge_older_than(cutoff)).await {
                    Ok(Ok(pruned)) if pruned > 0 => {
                        info!(pruned = pruned, "audit retention purge completed")
                    }
                    Ok(Err(err)) => error!(?err, "audit retention purge failed"),
                    Err(err) => error!(?err, "audit retention task join error"),
                    _ => {}
                }
            }
        });
    }

    let approval_interval = Duration::from_secs(args.approval_retention_interval_secs.max(60));
    if let Some(sqlite) = approval_sqlite {
        let retention_days = i64::try_from(args.approval_retention_days)
            .map_err(|_| anyhow::anyhow!("approval_retention_days exceeds supported range"))?;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(approval_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let cutoff = OffsetDateTime::now_utc() - TimeDuration::days(retention_days);
                let store = sqlite.clone();
                match tokio::task::spawn_blocking(move || store.purge_older_than(cutoff)).await {
                    Ok(Ok(pruned)) if pruned > 0 => {
                        info!(pruned = pruned, "approval retention purge completed")
                    }
                    Ok(Err(err)) => error!(?err, "approval retention purge failed"),
                    Err(err) => error!(?err, "approval retention task join error"),
                    _ => {}
                }
            }
        });
    }

    let router = Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics_endpoint))
        .route("/.well-known/jwks.json", get(jwks_endpoint))
        .route("/api/v1/keys", get(list_keys).post(create_key))
        .route("/api/v1/keys/:id", get(describe_key))
        .route("/api/v1/keys/:id/rotate", post(rotate_key))
        .route("/api/v1/keys/:id/versions", get(list_key_versions))
        .route("/api/v1/keys/:id/rollback", post(rollback_key))
        .route("/api/v1/keys/:id/sign", post(sign_payload))
        .route("/api/v1/keys/:id/encrypt", post(encrypt_payload))
        .route("/api/v1/keys/:id/decrypt", post(decrypt_payload))
        .route("/api/v1/approvals", get(list_approvals))
        .route(
            "/api/v1/approvals/:id/approve",
            post(approve_pending_action),
        )
        .route("/api/v1/approvals/:id/deny", post(deny_pending_action))
        .route("/ui", get(render_dashboard))
        .route("/ui/approvals/:id/approve", post(approve_approval_ui))
        .route("/ui/approvals/:id/deny", post(deny_approval_ui))
        .nest_service("/static", ServeDir::new("web/static"));

    let app = pqc::register_routes(router)
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let tls_setup = crate::tls::configure(&args).await?;
    let server_handle = axum_server::Handle::new();

    info!(mode = ?args.tls_mode, "FerroHSM listening on https://{}", args.bind);

    match (tls_setup, app) {
        (TlsSetup::Manual(config), app) => {
            let shutdown_handle = server_handle.clone();
            let server = axum_server::bind_rustls(args.bind, config)
                .handle(server_handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => result?,
                _ = shutdown_signal() => {
                    shutdown_handle.graceful_shutdown(None);
                    server.await?;
                }
            }
        }
        (TlsSetup::Acme { acceptor }, app) => {
            let shutdown_handle = server_handle.clone();
            let server = axum_server::Server::bind(args.bind)
                .acceptor(acceptor)
                .handle(server_handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => result?,
                _ = shutdown_signal() => {
                    shutdown_handle.graceful_shutdown(None);
                    server.await?;
                }
            }
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_seconds: u64,
    cache_entries: usize,
    rate_limit_per_second: u64,
    rate_limit_burst: u64,
    active_rate_limiters: usize,
}

async fn health<P: PolicyEngine>(
    State(state): State<AppState<P>>,
) -> Result<Json<HealthResponse>, AppError> {
    info!("Health check called");
    let stats = state.rate_limiter.stats();
    let uptime_seconds = state.startup.elapsed().as_secs();

    // Perform basic storage health check
    let storage_healthy = tokio::task::spawn_blocking(move || {
        // Try to list keys to check storage connectivity
        state.manager.list_keys(&AuthContext {
            actor_id: "health-check".to_string(),
            session_id: uuid::Uuid::new_v4(),
            roles: vec![Role::Administrator], // Use admin role for health check
            client_fingerprint: None,
            source_ip: None,
        }).is_ok()
    }).await.map_err(|_| AppError::internal("health check task failed"))?;

    Ok(Json(HealthResponse {
        status: if storage_healthy { "ok" } else { "degraded" },
        uptime_seconds,
        cache_entries: state.key_cache.len(),
        rate_limit_per_second: stats.per_second,
        rate_limit_burst: stats.burst,
        active_rate_limiters: stats.active_buckets,
    }))
}

async fn metrics_endpoint<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let _ = authenticate_request(&state, &headers, addr.ip())?;
    match Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(state.metrics_handle.render()))
    {
        Ok(response) => Ok(response),
        Err(error) => {
            error!("failed to render metrics: {error}");
            Err(AppError::internal("failed to render metrics"))
        }
    }
}

async fn jwks_endpoint<P: PolicyEngine>(
    State(state): State<AppState<P>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let jwks = state.auth.jwks()?;
    Ok(Json(jwks))
}

fn parse_algorithm(input: &str) -> Result<KeyAlgorithm, AppError> {
    match input.to_lowercase().as_str() {
        "aes256gcm" | "aes-256-gcm" | "aes" => Ok(KeyAlgorithm::Aes256Gcm),
        "rsa2048" | "rsa-2048" | "rsa" => Ok(KeyAlgorithm::Rsa2048),
        "rsa4096" | "rsa-4096" => Ok(KeyAlgorithm::Rsa4096),
        "p256" | "secp256r1" | "nistp256" => Ok(KeyAlgorithm::P256),
        "p384" | "secp384r1" | "nistp384" => Ok(KeyAlgorithm::P384),
        other => Err(AppError::bad_request(format!(
            "unsupported algorithm filter: {other}"
        ))),
    }
}

fn parse_state(input: &str) -> Result<KeyState, AppError> {
    match input.to_lowercase().as_str() {
        "staged" => Ok(KeyState::Staged),
        "active" => Ok(KeyState::Active),
        "revoked" => Ok(KeyState::Revoked),
        "purge_scheduled" | "purge-scheduled" | "scheduled" => Ok(KeyState::PurgeScheduled),
        "destroyed" => Ok(KeyState::Destroyed),
        other => Err(AppError::bad_request(format!(
            "unsupported state filter: {other}"
        ))),
    }
}

async fn list_keys<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Query(params): Query<ListKeysParams>,
) -> Result<Json<PaginatedKeys>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let mut query = hsm_core::KeyListQuery::default();

    if let Some(page) = params.page {
        if page == 0 {
            return Err(AppError::bad_request("page must be >= 1"));
        }
        query.page = page;
    }

    if let Some(per_page) = params.per_page {
        if per_page == 0 {
            return Err(AppError::bad_request("per_page must be >= 1"));
        }
        query.per_page = per_page.min(1000);
    }

    if let Some(algorithm) = params.algorithm {
        query.algorithm = Some(parse_algorithm(&algorithm)?);
    }

    if let Some(state_param) = params.state {
        query.state = Some(parse_state(&state_param)?);
    }

    if let Some(tags) = params.tags {
        let tags_vec = tags
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect::<Vec<_>>();
        query.policy_tags = tags_vec;
    }

    let cache_key = KeyCacheKey::new(ctx.actor_id.clone(), &query);
    if let Some(cached) = state.key_cache.get(&cache_key) {
        return Ok(Json(cached));
    }

    let page = state.manager.list_keys_with_query(&ctx, &query)?;
    let payload = PaginatedKeys::from(page);
    state.key_cache.put(cache_key, payload.clone());
    Ok(Json(payload))
}

async fn create_key<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(payload): Json<CreateKeyRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let req = KeyGenerationRequest {
        algorithm: payload.algorithm,
        usage: payload.usage,
        policy_tags: payload.policy_tags,
        description: payload.description,
    };
    let meta = state.manager.generate_key(req, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

async fn describe_key<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let meta = state.manager.describe_key(&id, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

async fn rotate_key<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let meta = state.manager.rotate_key(&id, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

async fn list_key_versions<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Vec<KeySummary>>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let versions = state.manager.list_key_versions(&id, &ctx)?;
    Ok(Json(versions.into_iter().map(KeySummary::from).collect()))
}

async fn rollback_key<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<RollbackRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let meta = state.manager.rollback_key(&id, payload.version, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

async fn sign_payload<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    let start = std::time::Instant::now();
    let result = async {
        let ctx = authenticate_request(&state, &headers, addr.ip())?;
        // Validate payload size before decoding to prevent resource exhaustion
        if payload.payload_b64.len() > 10_000_000 {
            // 10MB limit
            return Err(AppError::bad_request("payload too large"));
        }

        let data = B64
            .decode(&payload.payload_b64)
            .map_err(|_| AppError::bad_request("invalid base64 payload"))?;

        // Additional validation for decoded data size
        if data.len() > 1_000_000 {
            // 1MB limit for decoded data
            return Err(AppError::bad_request("decoded payload too large"));
        }
        let operation = hsm_core::CryptoOperation::Sign { payload: data };
        let result = state
            .manager
            .perform_operation(&id, operation, &ctx, &OperationContext::new())?;
        if let hsm_core::KeyOperationResult::Signature { signature } = result {
            Ok(Json(SignResponse {
                signature_b64: B64.encode(signature),
            }))
        } else {
            Err(AppError::internal("unexpected operation result"))
        }
    }.await;
    let duration = start.elapsed();
    metrics::histogram!("ferrohsm_operation_duration_seconds", "operation" => "sign").record(duration.as_secs_f64());
    if result.is_err() {
        metrics::counter!("ferrohsm_operation_errors_total", "operation" => "sign").increment(1);
    }
    result
}

async fn encrypt_payload<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, AppError> {
    let start = std::time::Instant::now();
    let result = async {
        let ctx = authenticate_request(&state, &headers, addr.ip())?;
        // Validate payload size before decoding to prevent resource exhaustion
        if payload.plaintext_b64.len() > 10_000_000 {
            // 10MB limit
            return Err(AppError::bad_request("plaintext too large"));
        }

        let plaintext = B64
            .decode(&payload.plaintext_b64)
            .map_err(|_| AppError::bad_request("invalid base64 plaintext"))?;

        // Additional validation for decoded data size
        if plaintext.len() > 1_000_000 {
            // 1MB limit for decoded data
            return Err(AppError::bad_request("plaintext too large"));
        }
        let mut op_ctx = OperationContext::new();
        if let Some(aad) = payload.associated_data_b64 {
            // Validate AAD size
            if aad.len() > 1_000_000 {
                // 1MB limit for AAD
                return Err(AppError::bad_request("associated data too large"));
            }

            let decoded_aad = B64
                .decode(&aad)
                .map_err(|_| AppError::bad_request("invalid associated data"))?;

            // Additional validation for decoded AAD size
            if decoded_aad.len() > 100_000 {
                // 100KB limit for decoded AAD
                return Err(AppError::bad_request("associated data too large"));
            }

            op_ctx.associated_data = Some(decoded_aad);
        }
        let result = state.manager.perform_operation(
            &id,
            hsm_core::CryptoOperation::Encrypt {
                plaintext: plaintext.clone(),
            },
            &ctx,
            &op_ctx,
        )?;

        if let hsm_core::KeyOperationResult::Encrypted { ciphertext, nonce } = result {
            Ok(Json(EncryptResponse {
                ciphertext_b64: B64.encode(ciphertext),
                nonce_b64: B64.encode(nonce),
            }))
        } else {
            Err(AppError::internal("unexpected operation result"))
        }
    }.await;
    let duration = start.elapsed();
    metrics::histogram!("ferrohsm_operation_duration_seconds", "operation" => "encrypt").record(duration.as_secs_f64());
    if result.is_err() {
        metrics::counter!("ferrohsm_operation_errors_total", "operation" => "encrypt").increment(1);
    }
    result
}

async fn decrypt_payload<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, AppError> {
    let start = std::time::Instant::now();
    let result = async {
        let ctx = authenticate_request(&state, &headers, addr.ip())?;
        // Validate payload sizes before decoding
        if payload.ciphertext_b64.len() > 10_000_000 {
            // 10MB limit
            return Err(AppError::bad_request("ciphertext too large"));
        }
        if payload.nonce_b64.len() > 1_000 {
            // Nonce should be small
            return Err(AppError::bad_request("nonce too large"));
        }

        let ciphertext = B64
            .decode(&payload.ciphertext_b64)
            .map_err(|_| AppError::bad_request("invalid base64 ciphertext"))?;
        let nonce = B64
            .decode(&payload.nonce_b64)
            .map_err(|_| AppError::bad_request("invalid base64 nonce"))?;

        // Additional validation for decoded data sizes
        if ciphertext.len() > 1_000_000 {
            // 1MB limit for decoded ciphertext
            return Err(AppError::bad_request("ciphertext too large"));
        }
        if nonce.len() > 100 {
            // Nonce should be very small
            return Err(AppError::bad_request("nonce too large"));
        }
        let mut op_ctx = OperationContext::new();
        let associated = if let Some(aad) = payload.associated_data_b64 {
            // Validate AAD size
            if aad.len() > 1_000_000 {
                // 1MB limit for AAD
                return Err(AppError::bad_request("associated data too large"));
            }

            let decoded = B64
                .decode(&aad)
                .map_err(|_| AppError::bad_request("invalid associated data"))?;

            // Additional validation for decoded AAD size
            if decoded.len() > 100_000 {
                // 100KB limit for decoded AAD
                return Err(AppError::bad_request("associated data too large"));
            }

            op_ctx.associated_data = Some(decoded.clone());
            Some(decoded)
        } else {
            None
        };
        let result = state.manager.perform_operation(
            &id,
            hsm_core::CryptoOperation::Decrypt {
                ciphertext,
                nonce,
                associated_data: associated,
            },
            &ctx,
            &op_ctx,
        )?;
        if let hsm_core::KeyOperationResult::Decrypted { plaintext } = result {
            Ok(Json(DecryptResponse {
                plaintext_b64: B64.encode(plaintext),
            }))
        } else {
            Err(AppError::internal("unexpected operation result"))
        }
    }.await;
    let duration = start.elapsed();
    metrics::histogram!("ferrohsm_operation_duration_seconds", "operation" => "decrypt").record(duration.as_secs_f64());
    if result.is_err() {
        metrics::counter!("ferrohsm_operation_errors_total", "operation" => "decrypt").increment(1);
    }
    result
}

async fn list_approvals<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApprovalResponse>>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let approvals = state.manager.list_pending_approvals(&ctx)?;
    let payload = approvals.into_iter().map(ApprovalResponse::from).collect();
    Ok(Json(payload))
}

async fn approve_pending_action<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let approval_id =
        Uuid::parse_str(&id).map_err(|_| AppError::bad_request("invalid approval identifier"))?;
    state.manager.approve_pending(approval_id, &ctx)?;
    Ok(Json(serde_json::json!({
        "status": "approved",
        "approval_id": approval_id,
    })))
}

async fn deny_pending_action<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let approval_id =
        Uuid::parse_str(&id).map_err(|_| AppError::bad_request("invalid approval identifier"))?;
    state.manager.deny_pending(approval_id, &ctx)?;
    Ok(Json(serde_json::json!({
        "status": "denied",
        "approval_id": approval_id,
    })))
}

async fn approve_approval_ui<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Redirect, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let approval_id =
        Uuid::parse_str(&id).map_err(|_| AppError::bad_request("invalid approval identifier"))?;
    state.manager.approve_pending(approval_id, &ctx)?;
    Ok(Redirect::to("/ui"))
}

async fn deny_approval_ui<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Redirect, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let approval_id =
        Uuid::parse_str(&id).map_err(|_| AppError::bad_request("invalid approval identifier"))?;
    state.manager.deny_pending(approval_id, &ctx)?;
    Ok(Redirect::to("/ui"))
}

fn format_duration_compact(duration: Duration) -> String {
    let mut remaining = duration.as_secs();
    let days = remaining / 86_400;
    remaining %= 86_400;
    let hours = remaining / 3_600;
    remaining %= 3_600;
    let minutes = remaining / 60;
    let seconds = remaining % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if parts.is_empty() || seconds > 0 {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

async fn render_dashboard<P: PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    let keys = state.manager.list_keys(&ctx)?;
    let (approvals, approvals_allowed) = match state.manager.list_pending_approvals(&ctx) {
        Ok(list) => (
            list.into_iter()
                .map(ApprovalResponse::from)
                .collect::<Vec<_>>(),
            true,
        ),
        Err(HsmError::Authorization(_)) | Err(HsmError::PolicyDenied) => (Vec::new(), false),
        Err(err) => return Err(AppError::from(err)),
    };
    let can_view_audit = ctx.has_role(&Role::Administrator) || ctx.has_role(&Role::Auditor);
    let audit_events = if can_view_audit {
        state.audit_view.recent_events(10)
    } else {
        Vec::new()
    };
    let metrics_snapshot = MetricsSnapshot::from_prometheus(&state.metrics_handle.render());
    let rate_stats = state.rate_limiter.stats();
    let uptime = format_duration_compact(state.startup.elapsed());
    let mut tera_ctx = tera::Context::new();
    tera_ctx.insert(
        "keys",
        &keys
            .into_iter()
            .map(KeySummary::from)
            .collect::<Vec<KeySummary>>(),
    );
    tera_ctx.insert("approvals", &approvals);
    tera_ctx.insert("approvals_allowed", &approvals_allowed);
    tera_ctx.insert("audit_events", &audit_events);
    tera_ctx.insert("can_view_audit", &can_view_audit);
    tera_ctx.insert("metrics", &metrics_snapshot);
    tera_ctx.insert("rate_stats", &rate_stats);
    tera_ctx.insert("uptime", &uptime);
    let rendered = state
        .templates
        .render("dashboard.html", &tera_ctx)
        .map_err(|e| AppError::internal(format!("template error: {e}")))?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(rendered.into())
        .map_err(|e| AppError::internal(format!("response building error: {e}")))
}

fn decode_or_error(value: Option<&str>, label: &str) -> anyhow::Result<[u8; 32]> {
    let raw = value.ok_or_else(|| {
        anyhow::anyhow!(
            "--{label}-key (or FERROHSM_{}_KEY) is required and must be a 32-byte value",
            label.to_uppercase()
        )
    })?;

    let bytes = match B64.decode(raw) {
        Ok(bytes) => bytes,
        Err(_) => raw.as_bytes().to_vec(),
    };

    if bytes.len() != 32 {
        anyhow::bail!(
            "invalid {label} key length (expected 32 bytes, got {})",
            bytes.len()
        );
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn load_templates(pattern: &str) -> anyhow::Result<Tera> {
    let mut tera = Tera::new(pattern)?;
    tera.autoescape_on(vec!["html"]);
    Ok(tera)
}

#[derive(Clone, Debug, Serialize)]
struct KeySummary {
    id: String,
    algorithm: KeyAlgorithm,
    version: u32,
    state: KeyState,
    usage: KeyUsage,
    description: Option<String>,
    policy_tags: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
    tamper_status: TamperStatus,
}

impl From<hsm_core::KeyMetadata> for KeySummary {
    fn from(value: hsm_core::KeyMetadata) -> Self {
        Self {
            id: value.id,
            algorithm: value.algorithm,
            version: value.version,
            state: value.state,
            usage: value.usage,
            description: value.description,
            policy_tags: value.policy_tags,
            created_at: value.created_at,
            tamper_status: value.tamper_status,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct PaginatedKeys {
    items: Vec<KeySummary>,
    total: usize,
    page: u32,
    per_page: u32,
    has_more: bool,
}

impl From<hsm_core::KeyListPage> for PaginatedKeys {
    fn from(value: hsm_core::KeyListPage) -> Self {
        Self {
            items: value.items.into_iter().map(KeySummary::from).collect(),
            total: value.total,
            page: value.page,
            per_page: value.per_page,
            has_more: value.has_more,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateKeyRequest {
    algorithm: KeyAlgorithm,
    usage: KeyUsage,
    policy_tags: Vec<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignRequest {
    payload_b64: String,
}

#[derive(Debug, Serialize)]
struct SignResponse {
    signature_b64: String,
}

#[derive(Debug, Deserialize)]
struct EncryptRequest {
    plaintext_b64: String,
    associated_data_b64: Option<String>,
}

#[derive(Debug, Serialize)]
struct EncryptResponse {
    ciphertext_b64: String,
    nonce_b64: String,
}

#[derive(Debug, Deserialize)]
struct DecryptRequest {
    ciphertext_b64: String,
    nonce_b64: String,
    associated_data_b64: Option<String>,
}

#[derive(Debug, Serialize)]
struct DecryptResponse {
    plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
struct RollbackRequest {
    version: u32,
}

#[derive(Debug, Default, Deserialize)]
struct ListKeysParams {
    page: Option<u32>,
    #[serde(rename = "per_page")]
    per_page: Option<u32>,
    algorithm: Option<String>,
    state: Option<String>,
    tags: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApprovalResponse {
    id: String,
    action: String,
    subject: String,
    requester: String,
    created_at: String,
    approved_by: Option<String>,
    approved_at: Option<String>,
}

impl From<PendingApprovalInfo> for ApprovalResponse {
    fn from(value: PendingApprovalInfo) -> Self {
        let PendingApprovalInfo {
            id,
            action,
            subject,
            requester,
            created_at,
            approved_by,
            approved_at,
        } = value;

        let created_at = created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| created_at.to_string());
        let approved_at =
            approved_at.map(|stamp| stamp.format(&Rfc3339).unwrap_or_else(|_| stamp.to_string()));

        Self {
            id: id.to_string(),
            action: action.to_string(),
            subject,
            requester,
            created_at,
            approved_by,
            approved_at,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub(crate) fn too_many_requests() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
        }));
        (self.status, body).into_response()
    }
}

impl From<hsm_core::HsmError> for AppError {
    fn from(value: hsm_core::HsmError) -> Self {
        match value {
            hsm_core::HsmError::PolicyDenied | hsm_core::HsmError::Authorization(_) => {
                Self::new(StatusCode::FORBIDDEN, value.to_string())
            }
            hsm_core::HsmError::KeyNotFound(_) => {
                Self::new(StatusCode::NOT_FOUND, value.to_string())
            }
            hsm_core::HsmError::KeyInactive(_) => {
                Self::new(StatusCode::CONFLICT, value.to_string())
            }
            hsm_core::HsmError::ApprovalRequired { approval_id } => Self::new(
                StatusCode::ACCEPTED,
                format!("dual-control approval required: {approval_id}"),
            ),
            _ => {
                error!("internal error: {value:?}");
                Self::internal("internal server error")
            }
        }
    }
}

//! Database config loader with incremental polling.
//!
//! **Incremental polling strategy**:
//! 1. Admin and import write paths append durable `config_changes` records in
//!    the same transaction as SQL resource mutations.
//! 2. Pollers read ordered change records after their accepted sequence cursor,
//!    collapse each resource to its final operation in the batch, and point-load
//!    only changed resource IDs. Consumer changes force an authoritative full
//!    reload so credentials stripped from the published snapshot by runtime
//!    quarantine can be rehydrated after a repair.
//! 3. Deletes are delivered from durable delete records; normal incremental
//!    polling does not scan every resource ID or rely on wall-clock timestamps.
//!
//! On startup, a transaction-scoped full load seeds the initial config and
//! accepted sequence cursor. Full loads use deterministic keyset pagination
//! (`id > last_id`) so mutable tables cannot shift under `OFFSET`. If an
//! incremental poll fails or the cursor is older than retained change history,
//! the loop falls back to a full reload and reseeds the accepted sequence.
//!
//! **Key implementation details**:
//! - Postgres `?` → `$N` placeholder rewrite via `q()` method (sqlx `Any` uses `?`)
//! - `>500` IN-clause threshold switches to full-table fetch + in-memory filter
//! - `ArcSwap`-based pool swap enables zero-downtime DNS re-resolution on failover
//! - Batch chunking (`BATCH_CHUNK_SIZE`) for large imports to stay within DB limits

use crate::config::types::{
    AuthMode, BackendScheme, CircuitBreakerConfig, Consumer, DispatchKind, GatewayConfig,
    HealthCheckConfig, LoadBalancerAlgorithm, PluginAssociation, PluginConfig, PluginScope, Proxy,
    ResponseBodyMode, RetryConfig, ServiceDiscoveryConfig, Upstream, UpstreamTarget,
};
use crate::config::validation_pipeline::{
    ConfigValidationRejection, ValidationAction, ValidationPipeline,
    collect_rejecting_runtime_config_errors, validate_plugin_file_dependencies_off_thread,
};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::Executor;
use sqlx::Row;
use sqlx::{AnyPool, any::AnyPoolOptions, any::AnyRow};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Re-export trait types so existing `use crate::config::db_loader::{IncrementalResult, ...}` works.
#[allow(unused_imports)]
pub use crate::config::db_backend::{
    ApiSpecListFilter, ApiSpecSortBy, BatchConfigWriteMode, DatabaseBackend, FullConfigLoadPurpose,
    IncrementalResult, MtlsDnsAdmissionUnavailable, MtlsDnsIdentityConflict,
    NamespaceConfigAdmissionLeaseBackend, NamespaceResourceCounts, NamespacedResourceId,
    PROXY_ROUTE_CONFLICT_ERROR, PaginatedResult, SnapshotDataIntegrityError, SortOrder,
    TcpConnectionThrottleAttachmentConflict, extract_db_hostname, redact_url,
};

const CONFIG_ADMISSION_LEASE_DURATION_MILLIS: i64 = 120_000;
pub(crate) const MYSQL_MTLS_DNS_ADMISSION_LOCK_INSERT_SQL: &str = "INSERT INTO mtls_dns_admission_locks \
     (namespace, updated_at) VALUES (?, ?) \
     ON DUPLICATE KEY UPDATE updated_at = mtls_dns_admission_locks.updated_at";
pub(crate) const MYSQL_CONFIG_CHANGE_LOCK_INSERT_SQL: &str = "INSERT INTO config_change_locks \
     (lock_name, updated_at) VALUES (?, ?) \
     ON DUPLICATE KEY UPDATE updated_at = config_change_locks.updated_at";
pub(crate) const MYSQL_PROXY_ROUTE_LOCK_INSERT_SQL: &str = "INSERT INTO proxy_route_locks \
     (namespace, route_key_hash, created_at) VALUES (?, ?, ?) \
     ON DUPLICATE KEY UPDATE created_at = proxy_route_locks.created_at";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FullLoadPurpose {
    Runtime,
    RestoreSnapshot,
}

impl FullLoadPurpose {
    fn operation(self) -> &'static str {
        match self {
            Self::Runtime => "load_full_config",
            Self::RestoreSnapshot => "load_namespace_snapshot",
        }
    }

    fn map_row_error(
        self,
        resource_type: &'static str,
        resource_id: Option<String>,
        error: anyhow::Error,
    ) -> anyhow::Error {
        if self == Self::RestoreSnapshot {
            anyhow::Error::new(SnapshotDataIntegrityError::new(
                resource_type,
                resource_id,
                error,
            ))
        } else {
            error
        }
    }
}

struct PluginConfigRef {
    id: String,
    scope: PluginScope,
    proxy_id: Option<String>,
}

type ProxyPluginAssociations = HashMap<String, Vec<PluginAssociation>>;
type PluginConfigRefs = HashMap<String, PluginConfigRef>;

#[derive(Debug)]
pub(crate) struct ProxyPluginAssociationLoadError {
    message: String,
    source: Option<sqlx::Error>,
}

impl ProxyPluginAssociationLoadError {
    fn new(message: String) -> Self {
        Self {
            message,
            source: None,
        }
    }

    fn with_source(message: String, source: sqlx::Error) -> Self {
        Self {
            message,
            source: Some(source),
        }
    }
}

impl std::fmt::Display for ProxyPluginAssociationLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProxyPluginAssociationLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

pub(crate) fn is_proxy_plugin_association_load_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ProxyPluginAssociationLoadError>()
        .is_some()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConsumerCredentialIndexEntry {
    credential_type: &'static str,
    credential_hash: String,
}

pub(crate) fn credential_value_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical_mtls_identity(identity: &str) -> &str {
    identity.trim()
}

fn consumer_credential_index_entries(consumer: &Consumer) -> Vec<ConsumerCredentialIndexEntry> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for entry in consumer.credential_entries("keyauth") {
        if let Some(key) = entry.get("key").and_then(|value| value.as_str()) {
            let indexed = ConsumerCredentialIndexEntry {
                credential_type: "keyauth",
                credential_hash: credential_value_hash(key),
            };
            if seen.insert(indexed.clone()) {
                entries.push(indexed);
            }
        }
    }

    for entry in consumer.credential_entries("mtls_auth") {
        if let Some(identity) = entry.get("identity").and_then(|value| value.as_str()) {
            let indexed = ConsumerCredentialIndexEntry {
                credential_type: "mtls_auth",
                credential_hash: credential_value_hash(canonical_mtls_identity(identity)),
            };
            if seen.insert(indexed.clone()) {
                entries.push(indexed);
            }
        }
    }

    // HMAC secrets are hashed before entering the index: the composite primary
    // key is the cross-process uniqueness backstop, while the stored index
    // never contains the credential itself. Namespace remains part of that
    // primary key, so separate tenants may intentionally reuse a secret.
    for entry in consumer.credential_entries("hmac_auth") {
        if let Some(secret) = entry.get("secret").and_then(|value| value.as_str()) {
            let indexed = ConsumerCredentialIndexEntry {
                credential_type: "hmac_auth",
                credential_hash: credential_value_hash(secret),
            };
            if seen.insert(indexed.clone()) {
                entries.push(indexed);
            }
        }
    }

    entries
}

/// Deduped set of identity values a consumer claims within its namespace:
/// id, username, and custom_id (when present). Deduped because
/// self-collisions — a consumer whose own custom_id equals its own id or
/// username — are explicitly allowed (matching
/// `GatewayConfig::validate_unique_consumer_identities`); only cross-consumer
/// collisions must trip the `consumer_identity_index` primary key.
fn consumer_identity_values(consumer: &Consumer) -> Vec<&str> {
    let mut values = vec![consumer.id.as_str(), consumer.username.as_str()];
    if let Some(custom_id) = consumer.custom_id.as_deref() {
        values.push(custom_id);
    }
    values.sort_unstable();
    values.dedup();
    values
}

pub(crate) fn proxy_route_key_hash(listen_path: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    match listen_path {
        Some(path) => {
            hasher.update(b"path\0");
            hasher.update(path.as_bytes());
        }
        None => hasher.update(b"host-only\0"),
    }
    hex::encode(hasher.finalize())
}

fn format_consumer_identity_conflict(
    candidate_field: &str,
    candidate_value: &str,
    existing_field: &str,
    existing_id: &str,
) -> String {
    match (candidate_field, existing_field) {
        ("username", "username") => format!(
            "A consumer with username '{}' already exists (consumer '{}')",
            candidate_value, existing_id
        ),
        ("custom_id", "custom_id") => format!(
            "A consumer with custom_id '{}' already exists (consumer '{}')",
            candidate_value, existing_id
        ),
        ("username", "custom_id") => format!(
            "Consumer username '{}' conflicts with custom_id of consumer '{}'",
            candidate_value, existing_id
        ),
        ("custom_id", "username") => format!(
            "Consumer custom_id '{}' conflicts with username of consumer '{}'",
            candidate_value, existing_id
        ),
        _ => format!(
            "Consumer {} '{}' conflicts with {} of consumer '{}'",
            candidate_field, candidate_value, existing_field, existing_id
        ),
    }
}

fn mesh_route_dispatch_references_upstream_id(plugin: &PluginConfig, upstream_id: &str) -> bool {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return false;
    }
    MeshRouteDispatchConfig::from_value(&plugin.config)
        .is_ok_and(|config| config.references_upstream_id(upstream_id))
}

fn mesh_route_dispatch_referenced_upstream(
    plugin: &PluginConfig,
    upstream_ids: &HashSet<String>,
) -> Option<String> {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return None;
    }
    let config = MeshRouteDispatchConfig::from_value(&plugin.config).ok()?;
    config
        .rules
        .iter()
        .filter_map(|rule| rule.destination.upstream_id.as_deref())
        .find(|upstream_id| upstream_ids.contains(*upstream_id))
        .map(ToOwned::to_owned)
}

fn upstream_backend_tls_san_allow_list_json(
    upstream: &Upstream,
) -> Result<Option<String>, anyhow::Error> {
    if upstream.backend_tls_san_allow_list.is_empty() {
        Ok(None)
    } else {
        serde_json::to_string(&upstream.backend_tls_san_allow_list)
            .map(Some)
            .map_err(Into::into)
    }
}

fn store_canonical_resource_hash(
    bundle: &crate::admin::api_specs::ExtractedBundle,
) -> Result<String, anyhow::Error> {
    let mut proxy = bundle.proxy.clone();
    proxy.normalize_fields();
    let upstream = bundle.upstream.clone().map(|mut upstream| {
        upstream.normalize_fields();
        upstream
    });
    let mut plugins = bundle.plugins.clone();
    for plugin in &mut plugins {
        plugin.normalize_fields();
    }
    crate::admin::api_specs::hash_resource_bundle(&crate::admin::api_specs::ExtractedBundle {
        proxy,
        upstream,
        plugins,
    })
}

#[derive(Debug)]
struct ConfigChangeRecord {
    sequence: u64,
    resource_type: String,
    resource_id: String,
    operation: String,
}

/// Database connection pool tuning parameters.
///
/// These are exposed via `FERRUM_DB_POOL_*` environment variables and applied
/// to all SQLx pools (primary, failover, and read replica).
#[derive(Debug, Clone)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    /// Maximum time (seconds) for each SQL pool *creation* attempt (initial
    /// connect, failover, replica, reconnect, migrate). Default: 10.
    ///
    /// Enforced by [`await_pool_connect_with_timeout`] around sqlx
    /// `AnyPoolOptions::connect` — sqlx 0.8's native PG/MySQL drivers ignore a
    /// `connect_timeout` URL query parameter, so Ferrum must bound the future
    /// itself. Separate from [`Self::acquire_timeout_seconds`], which still
    /// covers in-pool checkout wait + connect. `0` disables the bound.
    pub connect_timeout_seconds: u64,
    /// Maximum execution time (seconds) for any single SQL statement. Default:
    /// 30, max 3600 (clamped at `EnvConfig` parse time). Set via
    /// `SET statement_timeout` (PostgreSQL) or `SET SESSION max_execution_time`
    /// (MySQL) on every new connection. Prevents runaway queries from holding
    /// connections indefinitely. 0 = disabled (no per-statement timeout).
    /// Ignored for SQLite.
    pub statement_timeout_seconds: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 32,
            min_connections: 1,
            acquire_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 10,
            statement_timeout_seconds: 30,
        }
    }
}

/// Await a SQL pool-connect future with the configured per-attempt bound.
///
/// Centralized so initial, failover, replica, reconnect, and migrate paths
/// cannot drift. `timeout_seconds == 0` leaves the future unbounded (OS /
/// `acquire_timeout` still apply inside sqlx). On expiry the connect future is
/// dropped — no detached attempt — and the error is a typed
/// `sqlx::Error::Io(TimedOut)` with a non-secret message so failover / backup
/// classification stays transient without embedding the DSN.
pub(crate) async fn await_pool_connect_with_timeout<F, T>(
    timeout_seconds: u64,
    connect: F,
) -> Result<T, sqlx::Error>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    if timeout_seconds == 0 {
        return connect.await;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_seconds), connect).await {
        Ok(result) => result,
        Err(_elapsed) => Err(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("database pool connect timed out after {timeout_seconds}s"),
        ))),
    }
}

/// Connect an `AnyPool` under [`await_pool_connect_with_timeout`].
///
/// Does not mutate the URL: TLS / DSN query parameters are left untouched, and
/// no ignored `connect_timeout=` query parameter is appended.
pub(crate) async fn connect_any_pool_with_timeout(
    options: AnyPoolOptions,
    url: &str,
    db_type: &str,
    connect_timeout_seconds: u64,
) -> Result<AnyPool, sqlx::Error> {
    await_pool_connect_with_timeout(
        effective_pool_connect_timeout_seconds(db_type, connect_timeout_seconds),
        options.connect(url),
    )
    .await
}

/// Keep the SQL pool knob scoped to network database connects.
///
/// SQLite is local file I/O and the previous implementation deliberately did
/// not append a driver timeout for it. Preserve that contract while replacing
/// the ineffective PostgreSQL/MySQL URL parameter with a real future bound.
pub(crate) fn effective_pool_connect_timeout_seconds(
    db_type: &str,
    configured_seconds: u64,
) -> u64 {
    if db_type == "sqlite" {
        0
    } else {
        configured_seconds
    }
}

/// Build the `SET` SQL for per-statement timeouts, or `None` when disabled.
///
/// Returns:
/// - PostgreSQL: `SET statement_timeout = <ms>` (unquoted numeric)
/// - MySQL: `SET SESSION max_execution_time = <ms>`
/// - SQLite / `timeout_seconds == 0`: `None`
///
/// The caller is responsible for clamping `timeout_seconds` before calling
/// (enforced at `EnvConfig` parse time, 0..=3600).
pub(crate) fn statement_timeout_sql(
    timeout_seconds: u64,
    is_postgres: bool,
    is_mysql: bool,
) -> Option<String> {
    if timeout_seconds == 0 {
        return None;
    }
    let timeout_ms = timeout_seconds * 1000;
    if is_postgres {
        Some(format!("SET statement_timeout = {timeout_ms}"))
    } else if is_mysql {
        Some(format!("SET SESSION max_execution_time = {timeout_ms}"))
    } else {
        None
    }
}

/// Database configuration store.
///
/// The inner pool is wrapped in `ArcSwap` so it can be atomically replaced
/// when DNS re-resolution detects that the database FQDN now points to a
/// different IP. All readers (query methods, transactions) take a cheap
/// `Arc` clone of the current pool, so in-flight queries finish on the old
/// pool while new queries go to the freshly connected one.
#[derive(Clone)]
pub struct DatabaseStore {
    pool: Arc<ArcSwap<AnyPool>>,
    read_replica_url: Option<String>,
    read_replica_pool: Arc<ArcSwapOption<AnyPool>>,
    /// Read replicas belong to the configured primary topology. While the
    /// active write/runtime pool points at a failover URL, admin reads must
    /// stay on that same active pool rather than crossing into a replica of
    /// the unavailable primary topology.
    primary_topology_active: Arc<AtomicBool>,
    db_type: String,
    failover_urls: Vec<String>,
    pool_config: DbPoolConfig,
    slow_query_threshold_ms: Option<u64>,
    /// Maximum rows fetched per query during full config loading.
    /// Configurable via `FERRUM_DB_FULL_LOAD_PAGE_SIZE`. Default: 10000.
    full_load_page_size: i64,
    cert_expiry_warning_days: u64,
    backend_allow_ips: crate::config::BackendEgressPolicy,
    /// Set to `true` when the store was created via
    /// [`DatabaseStore::connect_offline_with_pool_config`] — the lazy pool
    /// never ran migrations because the DB was unreachable at startup.
    /// Cleared once migrations succeed against a recovered DB. `reconnect()`
    /// checks this flag and runs migrations on the first successful reconnect
    /// so the polling loop does not loop forever on a missing schema.
    /// Shared via `Arc<AtomicBool>` so all clones of the store observe the
    /// same cleared-state after recovery.
    migrations_pending: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminReadSource {
    Primary,
    ReadReplica,
}

struct AdminReadPool {
    pool: AnyPool,
    source: AdminReadSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DatabaseTopology {
    Primary,
    Failover,
}

fn is_transient_failover_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<sqlx::Error>())
        .is_some_and(is_transient_sqlx_error)
}

/// Marker carried by a database-initialization/reconnect error that a
/// failover or backup caller must treat as permanent (non-transient). Attached
/// under the human-readable context so the message is unchanged while the
/// classification stays discoverable via `anyhow`'s chained downcast.
#[derive(Debug)]
struct NonTransientDbInitError;

impl std::fmt::Display for NonTransientDbInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("non-transient database initialization error")
    }
}

impl std::error::Error for NonTransientDbInitError {}

/// Wrap a non-transient failure with the [`NonTransientDbInitError`] marker
/// and an outer message that folds in the redacted driver cause.
///
/// `main` logs fatal startup/reconnect errors with `{}` (Display), which for an
/// `anyhow::Error` renders only the outermost context. Attaching just a static
/// explanation would therefore hide the actionable driver cause (bad password,
/// missing table, constraint failure, ...). We render the cause chain now —
/// before the marker/context are attached — redact any connection URLs in
/// `secrets`, and append it to the outer message so operators see what to fix.
/// The marker is kept below the message so it stays discoverable via `anyhow`'s
/// chained downcast.
fn mark_non_transient(
    error: anyhow::Error,
    context: impl std::fmt::Display,
    secrets: &[&str],
) -> anyhow::Error {
    let cause = crate::config::db_backend::redact_error_text(format!("{error:#}"), secrets);
    let message = format!("{context}: {cause}");
    error.context(NonTransientDbInitError).context(message)
}

/// Returns true when an error chain contains a transient database
/// connectivity/resource failure from SQL or MongoDB.
///
/// Full-config loading uses this to decide whether an on-disk backup is safe to
/// serve. Restore also uses it when the pre-snapshot namespace guard cannot be
/// acquired, so a pool/network outage retains the same operator-facing
/// `failure_class: connectivity` contract as a snapshot query outage. Schema
/// drift, decode, query, authentication, and validation failures return false.
pub(crate) fn is_transient_database_error(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        if let Some(sqlx_err) = source.downcast_ref::<sqlx::Error>() {
            return is_transient_sqlx_error(sqlx_err);
        }
        if let Some(mongo_err) = source.downcast_ref::<mongodb::error::Error>() {
            return is_transient_mongo_load_error(mongo_err);
        }
        false
    })
}

fn is_transient_config_load_error(error: &anyhow::Error) -> bool {
    is_transient_database_error(error)
}

/// MongoDB counterpart to [`is_transient_sqlx_error`] for the full-config load
/// path: network I/O, connection-pool, server-selection, DNS, and retryable
/// topology command failures are transient. Other command/write/auth/decode
/// failures are non-transient.
pub(crate) fn is_transient_mongo_load_error(error: &mongodb::error::Error) -> bool {
    match error.kind.as_ref() {
        mongodb::error::ErrorKind::Io(_)
        | mongodb::error::ErrorKind::ConnectionPoolCleared { .. }
        | mongodb::error::ErrorKind::ServerSelection { .. }
        | mongodb::error::ErrorKind::DnsResolve { .. } => true,
        mongodb::error::ErrorKind::Command(command_error) => {
            // Prefer retryability labels supplied/derived by the driver, then
            // cover topology command responses that may remain after its one
            // retry and do not consistently carry a label across server
            // versions.
            error.contains_label(mongodb::error::RETRYABLE_WRITE_ERROR)
                || error.contains_label(mongodb::error::RETRYABLE_ERROR)
                || error.contains_label(mongodb::error::TRANSIENT_TRANSACTION_ERROR)
                || is_transient_mongo_command_code(command_error.code)
        }
        _ => false,
    }
}

// Retryable topology codes from the MongoDB retryable-reads specification and
// the driver's retryable read/write code lists. Authentication, decode, and
// write-concern validation codes are intentionally absent.
const TRANSIENT_MONGO_COMMAND_CODES: &[i32] = &[
    6,     // HostUnreachable
    7,     // HostNotFound
    89,    // NetworkTimeout
    91,    // ShutdownInProgress
    189,   // PrimarySteppedDown
    262,   // ExceededTimeLimit
    9001,  // SocketException
    10107, // NotWritablePrimary
    11600, // InterruptedAtShutdown
    11602, // InterruptedDueToReplStateChange
    13435, // NotPrimaryNoSecondaryOk
    13436, // NotPrimaryOrSecondary
];

pub(crate) fn is_transient_mongo_command_code(code: i32) -> bool {
    TRANSIENT_MONGO_COMMAND_CODES.contains(&code)
}

fn is_transient_sqlx_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        sqlx::Error::Database(database_error) => {
            if let Some(mysql_error) =
                database_error.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                && is_transient_mysql_error_number(mysql_error.number())
            {
                return true;
            }
            let is_sqlite = database_error
                .try_downcast_ref::<sqlx::sqlite::SqliteError>()
                .is_some();
            database_error
                .code()
                .is_some_and(|code| is_transient_database_code(code.as_ref(), is_sqlite))
        }
        _ => false,
    }
}

pub(crate) fn is_transient_database_code(code: &str, is_sqlite: bool) -> bool {
    code.starts_with("08")
        || is_sqlite
            && code
                .parse::<i32>()
                .is_ok_and(|code| matches!(code & 0xff, 5 | 6 | 14))
        || matches!(
            code,
            // PostgreSQL shutdown and resource-exhaustion connection failures
            // are listed explicitly. SQLite base/extended codes are handled
            // above only when the Any-driver error downcasts to SqliteError.
            "53300" | "57P01" | "57P02" | "57P03"
        )
}

pub(crate) fn is_transient_mysql_error_number(number: u16) -> bool {
    matches!(
        number,
        // Connection/resource and network read/write failures. Query and lock
        // wait timeouts (1205/3024) stay on the active topology.
        1040
            | 1158
            | 1159
            | 1160
            | 1161
            | 1203 // ER_TOO_MANY_USER_CONNECTIONS (max_user_connections)
            | 1226 // ER_USER_LIMIT_REACHED (per-user resource quota)
            | 2002
            | 2003
            | 2006
            | 2013
    )
}

/// Fold a failed MySQL `@@transaction_isolation` read and its `@@tx_isolation`
/// fallback into one error that PRESERVES the fallback `sqlx::Error` as its
/// source.
///
/// A MySQL primary can drop mid-`configure_full_load_snapshot` while this read
/// runs; that is a transient post-connect load failure the backup path is meant
/// to cover. If we stringified both `sqlx` failures into an opaque `anyhow!`
/// message, [`is_transient_config_load_error`] would find no typed
/// `sqlx::Error` in the chain and [`DatabaseStore::classify_initial_config_load_error`]
/// would mark the outage non-transient, refusing `FERRUM_DB_CONFIG_BACKUP_PATH`.
/// Keeping the fallback error as the chained SOURCE keeps a transient disconnect
/// backup-eligible while the primary error text survives in the context.
pub(crate) fn wrap_mysql_isolation_read_error(
    primary_error: &sqlx::Error,
    fallback_error: sqlx::Error,
) -> anyhow::Error {
    anyhow::Error::new(fallback_error).context(format!(
        "failed to read MySQL transaction isolation (primary @@transaction_isolation error: {primary_error})"
    ))
}

impl DatabaseStore {
    /// Rewrite `?` placeholders to `$N` for PostgreSQL.
    ///
    /// The `sqlx::Any` driver does not automatically translate `?` bind
    /// parameters to PostgreSQL's `$1`, `$2`, ... syntax. PostgreSQL reserves
    /// `?` as a JSON "exists" operator, so unescaped `?` in a query string
    /// causes a parse error.
    ///
    /// This method is a no-op for MySQL and SQLite (which use `?` natively).
    fn q(&self, sql: &str) -> String {
        if self.db_type != "postgres" {
            return sql.to_string();
        }
        let mut result = String::with_capacity(sql.len() + 16);
        let mut n = 0u32;
        for ch in sql.chars() {
            if ch == '?' {
                n += 1;
                result.push('$');
                // Inline u32 formatting to avoid format!() overhead
                let s = n.to_string();
                result.push_str(&s);
            } else {
                result.push(ch);
            }
        }
        result
    }

    fn proxy_route_lock_insert_sql(&self) -> String {
        match self.db_type.as_str() {
            // Same S->X upgrade trap as config_change_locks / mTLS DNS
            // admission: INSERT IGNORE takes a shared duplicate-key lock, then
            // SELECT ... FOR UPDATE upgrades it. Prefer the no-op upsert so
            // MySQL holds the exclusive row lock up front.
            "mysql" => MYSQL_PROXY_ROUTE_LOCK_INSERT_SQL.to_string(),
            "sqlite" => "INSERT OR IGNORE INTO proxy_route_locks \
                 (namespace, route_key_hash, created_at) VALUES (?, ?, ?)"
                .to_string(),
            _ => self.q("INSERT INTO proxy_route_locks \
                 (namespace, route_key_hash, created_at) VALUES (?, ?, ?) \
                 ON CONFLICT (namespace, route_key_hash) DO NOTHING"),
        }
    }

    fn config_change_lock_insert_sql(&self) -> String {
        match self.db_type.as_str() {
            // Cross-namespace writers share the single 'global' row and are not
            // serialized by per-namespace admission. INSERT IGNORE + FOR UPDATE
            // deadlocks on the S->X upgrade under concurrent namespaces; the
            // no-op upsert acquires the exclusive lock immediately.
            "mysql" => MYSQL_CONFIG_CHANGE_LOCK_INSERT_SQL.to_string(),
            "sqlite" => "INSERT OR IGNORE INTO config_change_locks \
                 (lock_name, updated_at) VALUES (?, ?)"
                .to_string(),
            _ => self.q("INSERT INTO config_change_locks \
                 (lock_name, updated_at) VALUES (?, ?) \
                 ON CONFLICT (lock_name) DO NOTHING"),
        }
    }

    fn config_admission_lease_acquire_sql(&self) -> String {
        let now = self.config_admission_lease_now_sql();
        match self.db_type.as_str() {
            "mysql" => format!(
                "INSERT INTO config_admission_locks \
                 (namespace, owner, expires_at, generation) VALUES (?, ?, {now} + ?, 1) \
                 ON DUPLICATE KEY UPDATE \
                 generation = IF(\
                     expires_at <= {now} OR owner = VALUES(owner), \
                     IF(owner = VALUES(owner), generation, generation + 1), \
                     generation), \
                 owner = IF(expires_at <= {now} OR owner = VALUES(owner), VALUES(owner), owner), \
                 expires_at = IF(owner = VALUES(owner), VALUES(expires_at), expires_at)"
            ),
            _ => self.q(&format!(
                "INSERT INTO config_admission_locks \
                 (namespace, owner, expires_at, generation) VALUES (?, ?, {now} + ?, 1) \
                 ON CONFLICT (namespace) DO UPDATE SET \
                 generation = CASE \
                     WHEN config_admission_locks.owner = excluded.owner \
                     THEN config_admission_locks.generation \
                     ELSE config_admission_locks.generation + 1 END, \
                 owner = excluded.owner, expires_at = excluded.expires_at \
                 WHERE config_admission_locks.expires_at <= {now} \
                    OR config_admission_locks.owner = excluded.owner"
            )),
        }
    }

    fn config_admission_lease_now_sql(&self) -> &'static str {
        match self.db_type.as_str() {
            "mysql" => "CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(3)) * 1000 AS SIGNED)",
            "sqlite" => "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)",
            _ => "CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT)",
        }
    }

    fn config_admission_lease_renew_sql(&self) -> String {
        let now = self.config_admission_lease_now_sql();
        self.q(&format!(
            "UPDATE config_admission_locks SET expires_at = {now} + ? \
             WHERE namespace = ? AND owner = ? AND expires_at > {now}"
        ))
    }

    fn mtls_dns_admission_lock_insert_sql(&self) -> String {
        match self.db_type.as_str() {
            // INSERT IGNORE takes a shared duplicate-key lock before the
            // SELECT ... FOR UPDATE below tries to upgrade it. Two contenders
            // can deadlock on that S->X upgrade. The no-op duplicate-key UPDATE
            // acquires the row exclusively up front, so same-namespace writers
            // serialize before the SELECT instead of mutually upgrading.
            "mysql" => MYSQL_MTLS_DNS_ADMISSION_LOCK_INSERT_SQL.to_string(),
            "sqlite" => "INSERT OR IGNORE INTO mtls_dns_admission_locks \
                 (namespace, updated_at) VALUES (?, ?)"
                .to_string(),
            _ => self.q("INSERT INTO mtls_dns_admission_locks \
                 (namespace, updated_at) VALUES (?, ?) \
                 ON CONFLICT (namespace) DO NOTHING"),
        }
    }
    fn config_change_retention_upsert_sql(&self) -> String {
        match self.db_type.as_str() {
            "mysql" => "INSERT INTO config_change_retention \
                 (namespace, retained_sequence, updated_at) VALUES (?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                 retained_sequence = GREATEST(retained_sequence, VALUES(retained_sequence)), \
                 updated_at = VALUES(updated_at)"
                .to_string(),
            "sqlite" => "INSERT INTO config_change_retention \
                 (namespace, retained_sequence, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT (namespace) DO UPDATE SET \
                 retained_sequence = max(config_change_retention.retained_sequence, excluded.retained_sequence), \
                 updated_at = excluded.updated_at"
                .to_string(),
            _ => self.q("INSERT INTO config_change_retention \
                 (namespace, retained_sequence, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT (namespace) DO UPDATE SET \
                 retained_sequence = GREATEST(config_change_retention.retained_sequence, EXCLUDED.retained_sequence), \
                 updated_at = EXCLUDED.updated_at"),
        }
    }

    fn listen_path_candidate_sql(
        &self,
        listen_path: Option<&str>,
        exclude_id: Option<&str>,
    ) -> String {
        let path_filter = if listen_path.is_some() {
            "listen_path = ?"
        } else {
            "listen_path IS NULL"
        };
        let exclude_filter = if exclude_id.is_some() {
            " AND id != ?"
        } else {
            ""
        };
        self.q(&format!(
            "SELECT id, hosts FROM proxies WHERE namespace = ? \
             AND backend_scheme NOT IN ('tcp', 'tcps', 'udp', 'dtls') \
             AND {path_filter}{exclude_filter}"
        ))
    }

    async fn listen_path_candidate_rows_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        listen_path: Option<&str>,
        exclude_id: Option<&str>,
    ) -> Result<Vec<AnyRow>, anyhow::Error> {
        let sql = self.listen_path_candidate_sql(listen_path, exclude_id);
        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(path) = listen_path {
            query = query.bind(path);
        }
        if let Some(eid) = exclude_id {
            query = query.bind(eid);
        }
        Ok(query.fetch_all(&mut **tx).await?)
    }

    fn listen_path_rows_are_unique(
        listen_path: Option<&str>,
        hosts: &[String],
        rows: &[AnyRow],
    ) -> bool {
        if listen_path.is_none() && hosts.is_empty() {
            return false;
        }
        if rows.is_empty() {
            return true;
        }
        if listen_path.is_some() && hosts.is_empty() {
            return false;
        }

        for row in rows {
            let existing_hosts: Vec<String> = row
                .try_get::<String, _>("hosts")
                .ok()
                .and_then(|s| match serde_json::from_str(&s) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        warn!("Failed to parse hosts JSON during uniqueness check: {}", e);
                        None
                    }
                })
                .unwrap_or_default();

            if crate::config::types::hosts_overlap(hosts, &existing_hosts) {
                return false;
            }
        }

        true
    }

    async fn lock_proxy_route_bucket_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        listen_path: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let route_key_hash = proxy_route_key_hash(listen_path);
        let now = Utc::now().to_rfc3339();
        let insert_sql = self.proxy_route_lock_insert_sql();
        sqlx::query(&insert_sql)
            .bind(namespace)
            .bind(&route_key_hash)
            .bind(&now)
            .execute(&mut **tx)
            .await?;

        // SQLite: INSERT OR IGNORE serializes via the DB writer lock.
        // MySQL: the no-op ON DUPLICATE KEY UPDATE already holds X; a follow-up
        // SELECT ... FOR UPDATE would be redundant and reintroduce S->X races
        // if the insert shape ever regresses to INSERT IGNORE.
        // PostgreSQL: INSERT ... DO NOTHING does not lock the existing row, so
        // SELECT ... FOR UPDATE remains required.
        if self.db_type != "sqlite" && self.db_type != "mysql" {
            let lock_sql = self.q("SELECT route_key_hash FROM proxy_route_locks \
                 WHERE namespace = ? AND route_key_hash = ? FOR UPDATE");
            sqlx::query(&lock_sql)
                .bind(namespace)
                .bind(&route_key_hash)
                .fetch_optional(&mut **tx)
                .await?;
        }

        Ok(())
    }

    async fn lock_config_change_sequence_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<(), anyhow::Error> {
        // Serialize SQL change-log inserts so auto-incremented sequences become
        // visible to pollers in commit order.
        let now = Utc::now().to_rfc3339();
        let insert_sql = self.config_change_lock_insert_sql();
        sqlx::query(&insert_sql)
            .bind(Self::CONFIG_CHANGE_LOCK_NAME)
            .bind(&now)
            .execute(&mut **tx)
            .await?;

        if self.db_type == "sqlite" {
            // SQLite has no SELECT ... FOR UPDATE. This write takes the
            // database writer lock inside the same transaction that will
            // insert the change-log row.
            sqlx::query("UPDATE config_change_locks SET updated_at = ? WHERE lock_name = ?")
                .bind(Utc::now().to_rfc3339())
                .bind(Self::CONFIG_CHANGE_LOCK_NAME)
                .execute(&mut **tx)
                .await?;
        } else if self.db_type != "mysql" {
            // PostgreSQL: INSERT ... DO NOTHING does not lock the existing row.
            // MySQL: MYSQL_CONFIG_CHANGE_LOCK_INSERT_SQL already holds the
            // exclusive row lock for the rest of this transaction — do not
            // follow with SELECT ... FOR UPDATE (that was the S->X deadlock).
            let lock_sql =
                self.q("SELECT lock_name FROM config_change_locks WHERE lock_name = ? FOR UPDATE");
            sqlx::query(&lock_sql)
                .bind(Self::CONFIG_CHANGE_LOCK_NAME)
                .fetch_optional(&mut **tx)
                .await?;
        }

        Ok(())
    }

    /// Serialize every mutation that can change either consumer mTLS
    /// credentials or the effective plugin association graph, and block every
    /// namespace resource mutation while a persistent restore owner exists.
    /// The caller holds this row through candidate validation and commit.
    async fn lock_mtls_dns_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<(), anyhow::Error> {
        self.lock_mtls_dns_admission_for_owner_tx(tx, namespace, None)
            .await
    }

    async fn lock_mtls_dns_admission_for_owner_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        allowed_restore_owner: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let now = Utc::now().to_rfc3339();
        let insert_sql = self.mtls_dns_admission_lock_insert_sql();
        sqlx::query(&insert_sql)
            .bind(namespace)
            .bind(&now)
            .execute(&mut **tx)
            .await?;

        let restore_owner = if self.db_type == "sqlite" {
            // SQLite has no SELECT ... FOR UPDATE. This write takes the
            // database writer lock inside the same transaction that will
            // persist and validate the candidate.
            sqlx::query("UPDATE mtls_dns_admission_locks SET updated_at = ? WHERE namespace = ?")
                .bind(now)
                .bind(namespace)
                .execute(&mut **tx)
                .await?;
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT restore_owner FROM mtls_dns_admission_locks WHERE namespace = ?",
            )
            .bind(namespace)
            .fetch_one(&mut **tx)
            .await?
        } else {
            let lock_sql = self.q("SELECT restore_owner FROM mtls_dns_admission_locks \
                 WHERE namespace = ? FOR UPDATE");
            sqlx::query_scalar::<_, Option<String>>(&lock_sql)
                .bind(namespace)
                .fetch_one(&mut **tx)
                .await?
        };

        match (restore_owner.as_deref(), allowed_restore_owner) {
            (None, None) => {}
            (Some(actual), Some(allowed)) if actual == allowed => {}
            (Some(_), _) => {
                return Err(anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(format!(
                    "mTLS DNS admission is blocked while a guarded operation owns namespace '{namespace}'"
                )));
            }
            (None, Some(_)) => {
                return Err(
                    anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(format!(
                        "mTLS DNS admission guard ownership was lost for namespace '{namespace}'"
                    )),
                );
            }
        }

        Ok(())
    }

    async fn acquire_mtls_dns_admission_guard_inner(
        &self,
        namespace: &str,
    ) -> Result<String, anyhow::Error> {
        let owner = Uuid::new_v4().to_string();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        let result = sqlx::query(&self.q(
            "UPDATE mtls_dns_admission_locks SET restore_owner = ?, updated_at = ? \
             WHERE namespace = ? AND restore_owner IS NULL",
        ))
        .bind(&owner)
        .bind(Utc::now().to_rfc3339())
        .bind(namespace)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            anyhow::bail!("failed to claim mTLS DNS admission guard");
        }
        tx.commit().await?;
        Ok(owner)
    }

    async fn release_mtls_dns_admission_guard_inner(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<(), anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, Some(owner))
            .await?;
        let result = sqlx::query(&self.q(
            "UPDATE mtls_dns_admission_locks SET restore_owner = NULL, updated_at = ? \
             WHERE namespace = ? AND restore_owner = ?",
        ))
        .bind(Utc::now().to_rfc3339())
        .bind(namespace)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            anyhow::bail!("mTLS DNS admission guard ownership was lost");
        }
        tx.commit().await?;
        Ok(())
    }

    /// Load the proxy/plugin policy graph once while the caller holds the
    /// namespace admission lock. Combined admission checks share this exact
    /// transaction candidate instead of repeating the full graph read.
    async fn load_namespace_admission_policy_candidate_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<GatewayConfig, anyhow::Error> {
        let proxies = self
            .load_proxies_tx(namespace, FullLoadPurpose::Runtime, tx)
            .await?;
        let plugin_configs = self
            .load_plugin_configs_tx(namespace, FullLoadPurpose::Runtime, tx)
            .await?;
        let mut candidate = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            plugin_configs,
            loaded_at: Utc::now(),
            ..Default::default()
        };
        candidate.normalize_fields();
        Ok(candidate)
    }

    /// Complete an already-loaded policy candidate only when an enabled
    /// effective `san_dns` policy requires Consumer identities.
    async fn load_mtls_dns_consumers_for_candidate_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        mut candidate: GatewayConfig,
    ) -> Result<Option<GatewayConfig>, anyhow::Error> {
        if !candidate.has_effective_mtls_dns_identity_policy() {
            return Ok(None);
        }
        candidate.consumers = self
            .load_consumers_tx(namespace, FullLoadPurpose::Runtime, tx)
            .await?;
        candidate.normalize_fields();
        Ok(Some(candidate))
    }

    /// Load the policy graph first and avoid reading every Consumer when no
    /// enabled effective `san_dns` policy exists. The caller already owns the
    /// namespace lock, so the graph and optional Consumer load describe one
    /// serialized transaction candidate.
    async fn load_mtls_dns_admission_candidate_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<Option<GatewayConfig>, anyhow::Error> {
        let candidate = self
            .load_namespace_admission_policy_candidate_tx(tx, namespace)
            .await?;
        self.load_mtls_dns_consumers_for_candidate_tx(tx, namespace, candidate)
            .await
    }

    /// Validate the exact transaction candidate after its resource mutations
    /// but before its change record and commit. Because every relevant writer
    /// first holds [`Self::lock_mtls_dns_admission_tx`], the snapshot cannot be
    /// invalidated by a second admin process between this check and commit.
    async fn validate_mtls_dns_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<(), anyhow::Error> {
        let Some(candidate) = self
            .load_mtls_dns_admission_candidate_tx(tx, namespace)
            .await?
        else {
            return Ok(());
        };
        candidate
            .validate_unique_mtls_dns_identities()
            .map_err(|errors| anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)))
    }

    fn validate_tcp_connection_throttle_admission_candidate(
        candidate: &GatewayConfig,
    ) -> Result<(), anyhow::Error> {
        crate::plugin_cache::validate_tcp_connection_throttle_attachments(candidate).map_err(
            |errors| anyhow::Error::new(TcpConnectionThrottleAttachmentConflict::new(errors)),
        )
    }

    /// Re-read the namespace policy graph once and feed that exact transaction
    /// candidate to both guarded validators. The caller holds the namespace
    /// admission row through commit, so a second admin process cannot
    /// invalidate the snapshot between validation and persistence.
    async fn validate_namespace_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<(), anyhow::Error> {
        let candidate = self
            .load_namespace_admission_policy_candidate_tx(tx, namespace)
            .await?;
        Self::validate_tcp_connection_throttle_admission_candidate(&candidate)?;
        let Some(candidate) = self
            .load_mtls_dns_consumers_for_candidate_tx(tx, namespace, candidate)
            .await?
        else {
            return Ok(());
        };
        candidate
            .validate_unique_mtls_dns_identities()
            .map_err(|errors| anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)))
    }

    /// Validate the exact proxy/plugin graph produced by an API-spec restore.
    /// This is intentionally stricter than the shared admission validator:
    /// compensation must never attach a restored proxy to a pre-existing
    /// global, cross-proxy, cross-namespace, or otherwise wrong plugin row.
    async fn validate_api_spec_restore_candidate_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        restored_proxy_id: &str,
        validation_http_client: &crate::plugins::PluginHttpClient,
    ) -> Result<(), anyhow::Error> {
        let mut candidate = self
            .load_namespace_admission_policy_candidate_tx(tx, namespace)
            .await?;
        candidate.upstreams = self
            .load_upstreams_tx(namespace, FullLoadPurpose::Runtime, tx)
            .await?;
        candidate.normalize_fields();
        let recovered_graph = crate::config::db_backend::api_spec_recovered_proxy_graph(
            candidate.clone(),
            restored_proxy_id,
        )?;
        Self::reject_invalid_gateway_plugin_references(
            "restore_api_spec_bundle",
            &recovered_graph,
        )?;
        Self::reject_invalid_gateway_upstream_references(
            "restore_api_spec_bundle",
            &recovered_graph,
        )?;
        crate::config::db_backend::validate_api_spec_recovered_plugin_graph(
            &recovered_graph,
            validation_http_client,
        )
        .await?;
        Self::validate_tcp_connection_throttle_admission_candidate(&candidate)?;
        let Some(candidate) = self
            .load_mtls_dns_consumers_for_candidate_tx(tx, namespace, candidate)
            .await?
        else {
            return Ok(());
        };
        candidate
            .validate_unique_mtls_dns_identities()
            .map_err(|errors| anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)))
    }

    async fn mtls_dns_identity_conflicts_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, anyhow::Error> {
        Ok(self
            .load_mtls_dns_admission_candidate_tx(tx, namespace)
            .await?
            .map(|candidate| candidate.mtls_dns_identity_conflicts())
            .unwrap_or_default())
    }

    /// Deletes are repair-safe when every remaining ambiguity was already
    /// present with the same (or a smaller) owner set. This permits operators
    /// to remove unrelated or conflicting resources from a restored/out-of-band
    /// ambiguous namespace, while still rejecting a delete that exposes a new
    /// effective `san_dns` policy collision.
    async fn validate_mtls_dns_repair_delete_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        prior_conflicts: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(), anyhow::Error> {
        let Some(candidate) = self
            .load_mtls_dns_admission_candidate_tx(tx, namespace)
            .await?
        else {
            return Ok(());
        };
        if candidate.introduces_new_mtls_dns_identity_conflict(prior_conflicts) {
            let errors = candidate
                .validate_unique_mtls_dns_identities()
                .err()
                .unwrap_or_else(|| {
                    vec!["Mutation would introduce a new mTLS DNS identity ambiguity".to_string()]
                });
            return Err(anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)));
        }
        Ok(())
    }

    /// Validate both guarded policy contracts from one post-delete graph read,
    /// while retaining the repair-safe mTLS DNS comparison against the exact
    /// pre-mutation conflict set.
    async fn validate_namespace_repair_delete_admission_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        prior_mtls_dns_conflicts: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(), anyhow::Error> {
        let candidate = self
            .load_namespace_admission_policy_candidate_tx(tx, namespace)
            .await?;
        Self::validate_tcp_connection_throttle_admission_candidate(&candidate)?;
        let Some(candidate) = self
            .load_mtls_dns_consumers_for_candidate_tx(tx, namespace, candidate)
            .await?
        else {
            return Ok(());
        };
        if candidate.introduces_new_mtls_dns_identity_conflict(prior_mtls_dns_conflicts) {
            let errors = candidate
                .validate_unique_mtls_dns_identities()
                .err()
                .unwrap_or_else(|| {
                    vec!["Mutation would introduce a new mTLS DNS identity ambiguity".to_string()]
                });
            return Err(anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)));
        }
        Ok(())
    }

    async fn ensure_proxy_route_unique_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        proxy: &Proxy,
        exclude_id: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        if proxy.effective_scheme().is_stream() {
            return Ok(());
        }

        let listen_path = proxy.listen_path.as_deref();
        self.lock_proxy_route_bucket_tx(tx, &proxy.namespace, listen_path)
            .await?;
        let rows = self
            .listen_path_candidate_rows_tx(tx, &proxy.namespace, listen_path, exclude_id)
            .await?;
        if !Self::listen_path_rows_are_unique(listen_path, &proxy.hosts, &rows) {
            anyhow::bail!(PROXY_ROUTE_CONFLICT_ERROR);
        }

        Ok(())
    }

    async fn delete_consumer_credential_index_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        consumer_id: &str,
    ) -> Result<(), anyhow::Error> {
        // Consumer ids are only unique per namespace (composite consumers PK),
        // so the delete must be namespace-scoped or it would wipe another
        // namespace's rows for a same-id consumer.
        sqlx::query(
            &self
                .q("DELETE FROM consumer_credential_index WHERE namespace = ? AND consumer_id = ?"),
        )
        .bind(namespace)
        .bind(consumer_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn insert_consumer_credential_index_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        consumer: &Consumer,
    ) -> Result<(), anyhow::Error> {
        let sql = self.q("INSERT INTO consumer_credential_index \
             (namespace, credential_type, credential_hash, consumer_id) VALUES (?, ?, ?, ?)");
        for entry in consumer_credential_index_entries(consumer) {
            sqlx::query(&sql)
                .bind(&consumer.namespace)
                .bind(entry.credential_type)
                .bind(&entry.credential_hash)
                .bind(&consumer.id)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    async fn delete_consumer_identity_index_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        consumer_id: &str,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(
            &self.q("DELETE FROM consumer_identity_index WHERE namespace = ? AND consumer_id = ?"),
        )
        .bind(namespace)
        .bind(consumer_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Insert one `consumer_identity_index` row per identity value the
    /// consumer claims (issue #2121). The table's composite
    /// `PRIMARY KEY (namespace, identity_value)` is the persistence-level
    /// cross-field collision guard: a violation here means another consumer in
    /// the namespace already claims the value as its id, username, or
    /// custom_id. The constraint error is intentionally propagated — the admin
    /// layer maps unique-constraint text to HTTP 409.
    async fn insert_consumer_identity_index_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        consumer: &Consumer,
    ) -> Result<(), anyhow::Error> {
        let sql = self.q("INSERT INTO consumer_identity_index \
             (namespace, identity_value, consumer_id, created_at) VALUES (?, ?, ?, ?)");
        let created_at = Utc::now().to_rfc3339();
        for value in consumer_identity_values(consumer) {
            sqlx::query(&sql)
                .bind(&consumer.namespace)
                .bind(value)
                .bind(&consumer.id)
                .bind(&created_at)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    // set_slow_query_threshold, set_cert_expiry_warning_days, and
    // set_backend_allow_ips are implemented via the DatabaseBackend trait.

    /// Log a warning if the elapsed time since `start` exceeds the configured
    /// slow query threshold. No-op when the threshold is disabled.
    fn check_slow_query(&self, operation: &str, start: Instant) {
        if let Some(threshold_ms) = self.slow_query_threshold_ms {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            if elapsed_ms > threshold_ms {
                warn!(
                    "Slow database query: {} took {}ms (threshold: {}ms)",
                    operation, elapsed_ms, threshold_ms
                );
            }
        }
    }

    /// Build `AnyPoolOptions` from the stored pool configuration.
    ///
    /// Used by all pool creation paths (initial connect, reconnect, read replica)
    /// to ensure consistent tuning from `FERRUM_DB_POOL_*` env vars.
    fn build_pool_options(&self) -> AnyPoolOptions {
        Self::build_pool_options_from_config(&self.pool_config, &self.db_type)
    }

    /// Build `AnyPoolOptions` from a given pool configuration.
    fn build_pool_options_from_config(config: &DbPoolConfig, db_type: &str) -> AnyPoolOptions {
        let is_sqlite = db_type == "sqlite";
        let is_postgres = db_type == "postgres";
        let is_mysql = db_type == "mysql";
        let statement_timeout_seconds = config.statement_timeout_seconds;

        AnyPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(std::time::Duration::from_secs(
                config.acquire_timeout_seconds,
            ))
            .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_seconds))
            // Force connection cycling so new TCP connections re-resolve DNS.
            // Defence-in-depth alongside the explicit DnsCache-based reconnect.
            .max_lifetime(std::time::Duration::from_secs(config.max_lifetime_seconds))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    // SQLite per-connection PRAGMAs (not persistent across pool
                    // connections — must be set on every checkout).
                    if is_sqlite {
                        conn.execute("PRAGMA foreign_keys = ON").await?;
                        // WAL mode dramatically improves concurrent read/write
                        // performance. Unlike other PRAGMAs this persists on the
                        // database file, but setting it per-connection is a harmless
                        // no-op once applied and ensures it is always enabled even
                        // after a fresh database creation.
                        conn.execute("PRAGMA journal_mode = WAL").await?;
                        // Without busy_timeout, concurrent writes immediately fail
                        // with SQLITE_BUSY. 5 000 ms gives the WAL writer time to
                        // finish before returning an error.
                        conn.execute("PRAGMA busy_timeout = 5000").await?;
                    }
                    // Set per-statement timeout on network databases to prevent
                    // runaway queries from holding connections indefinitely.
                    //
                    // Safety: `statement_timeout_seconds` is a `u64` parsed from
                    // `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` and clamped to
                    // 0..=3600 at `EnvConfig` parse time, so the `format!()`
                    // interpolation always produces a plain integer literal.
                    // `SET` commands do not support `$1`/`?` parameterized
                    // placeholders in sqlx, hence the string interpolation.
                    if let Some(sql) =
                        statement_timeout_sql(statement_timeout_seconds, is_postgres, is_mysql)
                    {
                        conn.execute(sql.as_str()).await?;
                    }
                    Ok(())
                })
            })
    }

    /// Connect to the database with the provided pool configuration and run migrations.
    pub async fn connect_with_pool_config(
        db_type: &str,
        db_url: &str,
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        // Install all drivers
        sqlx::any::install_default_drivers();

        let pool = connect_any_pool_with_timeout(
            Self::build_pool_options_from_config(&pool_config, db_type),
            db_url,
            db_type,
            pool_config.connect_timeout_seconds,
        )
        .await?;

        let store = Self {
            pool: Arc::new(ArcSwap::from_pointee(pool)),
            read_replica_url: None,
            read_replica_pool: Arc::new(ArcSwapOption::empty()),
            primary_topology_active: Arc::new(AtomicBool::new(true)),
            db_type: db_type.to_string(),
            failover_urls: Vec::new(),
            pool_config,
            slow_query_threshold_ms: None,
            full_load_page_size: Self::DEFAULT_FULL_LOAD_PAGE_SIZE,
            cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
            backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
            migrations_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        store.run_migrations().await?;

        info!(
            "Database connected and migrations applied (type={}, max_connections={}, min_connections={})",
            db_type, store.pool_config.max_connections, store.pool_config.min_connections
        );
        Ok(store)
    }

    /// Construct a `DatabaseStore` with a lazy pool — no TCP connection is
    /// opened and no migrations run. The first query will trigger connection
    /// (and may fail). Use this only as a bootstrap fallback when eager
    /// connection has failed but a backup config is being loaded from disk:
    /// the gateway serves from cached config while the background polling
    /// loop retries the pool until the DB becomes reachable again.
    ///
    /// `failover_urls` is stored on the returned `DatabaseStore` so that the
    /// polling loop's `try_failover_reconnect()` call can probe each URL in
    /// order — a primary that stays down should not prevent recovery when a
    /// configured failover DB is healthy.
    ///
    /// The returned store has `migrations_pending=true`. The first successful
    /// `reconnect()` (primary or failover) will run migrations, because a DB
    /// that comes back with a fresh or outdated schema must be brought up to
    /// the expected version before the polling loop can read from it.
    pub fn connect_offline_with_pool_config(
        db_type: &str,
        db_url: &str,
        failover_urls: &[String],
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        sqlx::any::install_default_drivers();

        // `connect_lazy` does not attempt a connection — the pool is ready to
        // hand out connections on first query. Migrations are deferred until
        // the database becomes reachable and the polling loop drives a
        // successful `reconnect()`. Eager reconnect/failover paths apply
        // `connect_timeout_seconds` via [`connect_any_pool_with_timeout`].
        let pool =
            Self::build_pool_options_from_config(&pool_config, db_type).connect_lazy(db_url)?;

        Ok(Self {
            pool: Arc::new(ArcSwap::from_pointee(pool)),
            read_replica_url: None,
            read_replica_pool: Arc::new(ArcSwapOption::empty()),
            primary_topology_active: Arc::new(AtomicBool::new(true)),
            db_type: db_type.to_string(),
            failover_urls: failover_urls.to_vec(),
            pool_config,
            slow_query_threshold_ms: None,
            full_load_page_size: Self::DEFAULT_FULL_LOAD_PAGE_SIZE,
            cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
            backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
            migrations_pending: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
    }

    /// Run versioned schema migrations using the MigrationRunner.
    ///
    /// This replaces the old inline `CREATE TABLE IF NOT EXISTS` approach with
    /// a tracked, versioned migration system. Existing databases are automatically
    /// detected and bootstrapped into the new system.
    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        use crate::config::migrations::MigrationRunner;

        let runner = MigrationRunner::new(self.pool(), self.db_type.clone());
        let applied = runner.run_pending().await?;

        if applied.is_empty() {
            info!("Database schema is up to date");
        } else {
            info!("Applied {} migration(s)", applied.len());
        }

        Ok(())
    }

    /// If `migrations_pending` is set (only true for offline-bootstrapped
    /// stores), try to run migrations now. Returns `Ok(true)` if migrations
    /// were actually executed, `Ok(false)` if nothing was pending.
    ///
    /// Uses a CAS from `true → false` so concurrent callers don't run
    /// migrations twice: whichever caller wins the CAS is the designated
    /// runner. On failure, the flag is restored so the next caller retries.
    ///
    /// This is the canonical entry point for clearing the deferred-migration
    /// state. Call it:
    /// - At startup right after offline bootstrap (so the startup path
    ///   doesn't wait for the first polling tick to catch up).
    /// - At the end of `reconnect()` (for the failover-reconnect path).
    /// - On each successful polling-loop query (for the case where the lazy
    ///   pool happened to connect on the first query and `reconnect()` never
    ///   fired — otherwise the flag would stay `true` indefinitely).
    pub async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        // Only one caller wins the CAS and runs migrations; the rest see
        // `Ok(false)` and return early. Acquire on success ensures we see
        // the constructor's write of `true`; Release on the clear ensures
        // other CPUs observe post-migration state after we complete.
        if self
            .migrations_pending
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }

        info!("Applying deferred migrations after backup-bootstrap recovery");
        match self.run_migrations().await {
            Ok(()) => {
                info!("Deferred migrations applied — database ready for polling");
                Ok(true)
            }
            Err(e) => {
                // Restore the flag so the next caller retries. Without this,
                // a transient migration failure would silently skip forever.
                self.migrations_pending.store(true, Ordering::Release);
                Err(e)
            }
        }
    }

    fn proxy_plugin_association_query_error(
        operation: &str,
        namespace: Option<&str>,
        source: sqlx::Error,
    ) -> anyhow::Error {
        let message = match namespace {
            Some(namespace) => format!(
                "operation={} resource=proxy_plugins namespace={}: failed to query proxy/plugin associations: {}",
                operation, namespace, source
            ),
            None => format!(
                "operation={} resource=proxy_plugins: failed to query proxy/plugin associations: {}",
                operation, source
            ),
        };
        if operation == "load_namespace_snapshot" {
            // Snapshot callers must distinguish an unavailable database from a
            // row-integrity failure. Query failures are availability failures;
            // decode/dangling-association paths retain the typed marker below.
            anyhow::Error::new(source).context(message)
        } else {
            anyhow::Error::new(ProxyPluginAssociationLoadError::with_source(
                message, source,
            ))
        }
    }

    fn proxy_plugin_association_proxy_id(
        row: &AnyRow,
        operation: &str,
    ) -> Result<String, anyhow::Error> {
        row.try_get::<String, _>("proxy_id").map_err(|e| {
            anyhow::Error::new(ProxyPluginAssociationLoadError::with_source(
                format!(
                    "operation={} resource=proxy_plugins column=proxy_id: failed to decode proxy/plugin association row: {}",
                    operation, e
                ),
                e,
            ))
        })
    }

    fn proxy_plugin_association_plugin_config_id(
        row: &AnyRow,
        operation: &str,
        proxy_id: &str,
    ) -> Result<String, anyhow::Error> {
        row.try_get::<String, _>("plugin_config_id").map_err(|e| {
            anyhow::Error::new(ProxyPluginAssociationLoadError::with_source(
                format!(
                    "operation={} resource=proxy_plugins proxy_id={} column=plugin_config_id: failed to decode proxy/plugin association row: {}",
                    operation, proxy_id, e
                ),
                e,
            ))
        })
    }

    fn proxy_plugin_reference_lookup_error(
        operation: &str,
        namespace: &str,
        column: Option<&str>,
        source: sqlx::Error,
    ) -> anyhow::Error {
        let column_context = column
            .map(|column| format!(" column=plugin_configs.{column}"))
            .unwrap_or_default();
        anyhow::Error::new(ProxyPluginAssociationLoadError::with_source(
            format!(
                "operation={} resource=proxy_plugins namespace={}{}: failed to load plugin_config references for proxy/plugin association validation: {}",
                operation, namespace, column_context, source
            ),
            source,
        ))
    }

    fn push_proxy_plugin_association_row(
        associations: &mut ProxyPluginAssociations,
        row: &AnyRow,
        operation: &str,
    ) -> Result<(), anyhow::Error> {
        let proxy_id = Self::proxy_plugin_association_proxy_id(row, operation)?;
        let plugin_config_id =
            Self::proxy_plugin_association_plugin_config_id(row, operation, &proxy_id)?;
        associations
            .entry(proxy_id)
            .or_default()
            .push(PluginAssociation { plugin_config_id });
        Ok(())
    }

    fn ensure_no_unmatched_proxy_plugin_associations(
        operation: &str,
        associations: &ProxyPluginAssociations,
    ) -> Result<(), anyhow::Error> {
        if let Some(proxy_id) = associations.keys().next() {
            return Err(anyhow::Error::new(ProxyPluginAssociationLoadError::new(
                format!(
                    "operation={} resource=proxy_plugins proxy_id={}: association row references a proxy that was not present in the loaded proxy candidate",
                    operation, proxy_id
                ),
            )));
        }
        Ok(())
    }

    async fn load_proxy_plugin_associations_for_namespace_tx(
        &self,
        namespace: &str,
        operation: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<ProxyPluginAssociations, anyhow::Error> {
        let sql = self.q("SELECT pp.proxy_id, pp.plugin_config_id \
             FROM proxy_plugins pp \
             INNER JOIN proxies p ON pp.proxy_id = p.id \
             WHERE p.namespace = ?");
        let rows: Vec<AnyRow> = sqlx::query(&sql)
            .bind(namespace)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| {
                Self::proxy_plugin_association_query_error(operation, Some(namespace), e)
            })?;

        let mut associations = HashMap::with_capacity(rows.len());
        for row in &rows {
            Self::push_proxy_plugin_association_row(&mut associations, row, operation)?;
        }
        Ok(associations)
    }

    async fn load_proxy_plugin_associations_for_proxy_ids(
        &self,
        proxy_ids: &[String],
        operation: &str,
        use_primary: bool,
    ) -> Result<ProxyPluginAssociations, anyhow::Error> {
        if proxy_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let pool = if use_primary {
            self.pool()
        } else {
            self.rpool()
        };
        self.load_proxy_plugin_associations_for_proxy_ids_from_pool(proxy_ids, operation, &pool)
            .await
    }

    async fn load_proxy_plugin_associations_for_proxy_ids_from_pool(
        &self,
        proxy_ids: &[String],
        operation: &str,
        pool: &AnyPool,
    ) -> Result<ProxyPluginAssociations, anyhow::Error> {
        if proxy_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let mut associations: ProxyPluginAssociations = HashMap::new();
        for chunk in proxy_ids.chunks(Self::ASSOCIATION_LOOKUP_CHUNK_SIZE) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = self.q(&format!(
                "SELECT proxy_id, plugin_config_id FROM proxy_plugins WHERE proxy_id IN ({})",
                placeholders
            ));
            let mut query = sqlx::query(&sql);
            for id in chunk {
                query = query.bind(id);
            }
            let rows = query
                .fetch_all(pool)
                .await
                .map_err(|e| Self::proxy_plugin_association_query_error(operation, None, e))?;
            for row in &rows {
                Self::push_proxy_plugin_association_row(&mut associations, row, operation)?;
            }
        }

        Ok(associations)
    }

    async fn reject_invalid_loaded_proxy_plugin_associations(
        &self,
        operation: &str,
        proxy: &Proxy,
    ) -> Result<(), anyhow::Error> {
        let plugin_config_ids = Self::loaded_proxy_plugin_config_ids(std::slice::from_ref(proxy));
        let plugin_refs = self
            .load_plugin_config_refs(&plugin_config_ids, &proxy.namespace, operation)
            .await?;
        let errors = Self::validate_loaded_proxy_plugin_associations_with_refs(
            &proxy.id,
            &proxy.plugins,
            &plugin_refs,
        );
        if errors.is_empty() {
            return Ok(());
        }

        Err(anyhow::Error::new(ProxyPluginAssociationLoadError::new(
            format!(
                "operation={} resource=proxy_plugins proxy_id={} namespace={}: invalid proxy/plugin associations: {}",
                operation,
                proxy.id,
                proxy.namespace,
                errors.join("; ")
            ),
        )))
    }

    async fn reject_invalid_loaded_proxy_plugin_association_page(
        &self,
        operation: &str,
        namespace: &str,
        proxies: &[Proxy],
        pool: &AnyPool,
    ) -> Result<(), anyhow::Error> {
        let plugin_config_ids = Self::loaded_proxy_plugin_config_ids(proxies);
        let plugin_refs = self
            .load_plugin_config_refs_from_pool(&plugin_config_ids, namespace, operation, pool)
            .await?;
        let mut errors = Vec::new();
        for proxy in proxies {
            errors.extend(Self::validate_loaded_proxy_plugin_associations_with_refs(
                &proxy.id,
                &proxy.plugins,
                &plugin_refs,
            ));
        }
        if errors.is_empty() {
            return Ok(());
        }

        Err(anyhow::Error::new(ProxyPluginAssociationLoadError::new(
            format!(
                "operation={} resource=proxy_plugins namespace={}: invalid proxy/plugin associations: {}",
                operation,
                namespace,
                errors.join("; ")
            ),
        )))
    }

    fn loaded_proxy_plugin_config_ids(proxies: &[Proxy]) -> Vec<String> {
        let mut requested_ids = Vec::new();
        let mut seen_ids = HashSet::new();
        for proxy in proxies {
            for assoc in &proxy.plugins {
                if seen_ids.insert(assoc.plugin_config_id.as_str()) {
                    requested_ids.push(assoc.plugin_config_id.clone());
                }
            }
        }
        requested_ids
    }

    fn validate_loaded_proxy_plugin_associations_with_refs(
        proxy_id: &str,
        associations: &[PluginAssociation],
        plugin_refs: &PluginConfigRefs,
    ) -> Vec<String> {
        let mut seen_assoc_ids: HashSet<&str> = HashSet::new();
        let mut errors = Vec::new();

        for assoc in associations {
            if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                errors.push(format!(
                    "Proxy '{}' references plugin_config '{}' more than once",
                    proxy_id, assoc.plugin_config_id
                ));
            } else {
                match plugin_refs.get(assoc.plugin_config_id.as_str()) {
                    Some(plugin) => match plugin.scope {
                        PluginScope::Global => {
                            errors.push(format!(
                                "Proxy '{}' references global plugin_config '{}'",
                                proxy_id, plugin.id
                            ));
                        }
                        PluginScope::ProxyGroup => {
                            if plugin.proxy_id.is_some() {
                                errors.push(format!(
                                    "Proxy '{}' references proxy_group plugin_config '{}' with proxy_id '{}'",
                                    proxy_id,
                                    plugin.id,
                                    plugin.proxy_id.as_deref().unwrap_or("<none>")
                                ));
                            }
                        }
                        PluginScope::Proxy => {
                            if plugin.proxy_id.as_deref() != Some(proxy_id) {
                                errors.push(format!(
                                    "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                    proxy_id,
                                    plugin.id,
                                    plugin.proxy_id.as_deref().unwrap_or("<none>")
                                ));
                            }
                        }
                    },
                    None => errors.push(format!(
                        "Proxy '{}' references non-existent plugin_config '{}'",
                        proxy_id, assoc.plugin_config_id
                    )),
                }
            }
        }

        errors
    }

    fn reject_invalid_gateway_plugin_references(
        operation: &str,
        config: &GatewayConfig,
    ) -> Result<(), anyhow::Error> {
        if let Err(errors) = config.validate_plugin_references() {
            let context = format!(
                "operation={} resource=proxy_plugins: invalid proxy/plugin associations: {}",
                operation,
                errors.join("; ")
            );
            // A malformed association graph is a semantic rejection from a
            // reachable database, not a connectivity failure. Preserve the
            // operation/resource detail as outer context while carrying the
            // same typed marker used by the rest of the runtime validation
            // contract so database-mode polling keeps admin writes available
            // for in-band repair (issue #2158).
            return Err(ConfigValidationRejection {
                backend: "Database",
                errors,
            }
            .into_anyhow()
            .context(context));
        }
        Ok(())
    }

    fn reject_invalid_gateway_upstream_references(
        operation: &str,
        config: &GatewayConfig,
    ) -> Result<(), anyhow::Error> {
        if let Err(errors) = config.validate_upstream_references() {
            let context = format!(
                "operation={operation} resource=upstreams: invalid proxy/upstream references: {}",
                errors.join("; ")
            );
            return Err(ConfigValidationRejection {
                backend: "Database",
                errors,
            }
            .into_anyhow()
            .context(context));
        }
        Ok(())
    }

    /// Load the full gateway configuration from the database.
    pub async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
        self.load_full_config_for_purpose(namespace, FullConfigLoadPurpose::Runtime)
            .await
    }

    /// Load the full gateway configuration for a runtime, control-plane, or
    /// export consumer. Only runtime loads retain node-local plugin snapshots.
    pub async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        let start = Instant::now();
        // Capture timestamp before queries so the incremental polling safety
        // margin covers the full load duration.
        let loaded_at = Utc::now();
        let mut tx = self.pool().begin().await?;
        self.configure_full_load_snapshot(&mut tx).await?;

        let proxies = self
            .load_proxies_tx(namespace, FullLoadPurpose::Runtime, &mut tx)
            .await?;
        let consumers = self
            .load_consumers_tx(namespace, FullLoadPurpose::Runtime, &mut tx)
            .await?;
        let plugin_configs = self
            .load_plugin_configs_tx(namespace, FullLoadPurpose::Runtime, &mut tx)
            .await?;
        let upstreams = self
            .load_upstreams_tx(namespace, FullLoadPurpose::Runtime, &mut tx)
            .await?;
        tx.commit().await?;

        let mut config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            consumers,
            plugin_configs,
            upstreams,
            loaded_at,
            known_namespaces: Vec::new(),
            ..Default::default()
        };

        ValidationPipeline::new(&mut config)
            .normalize_fields()
            .run()?;
        Self::reject_invalid_gateway_plugin_references("load_full_config", &config)?;

        // Fail-closed consumer identity handling (issue #2121): quarantine
        // (remove) consumers whose id/username/custom_id collides with an
        // earlier-loaded consumer instead of warn-and-overwrite, which
        // mis-routes JWKS/JWT authentication. The consumer_identity_index
        // table blocks new collisions at write time; this covers pre-existing
        // rows.
        let quarantined = config.quarantine_colliding_consumer_identities();
        if !quarantined.is_empty() {
            for message in &quarantined {
                error!("{}", message);
            }
            error!(
                "Quarantined {} consumer(s) with colliding identities during full config load",
                quarantined.len()
            );
        }

        // Fail-closed hmac_auth secret policy: strip pre-existing or
        // out-of-band credentials with weak or cross-consumer duplicate
        // secrets instead of publishing them behind a warning-only
        // validation run. Admin write-time validation rejects new
        // violations; this guard covers stored rows.
        let hmac_quarantined = config.quarantine_invalid_hmac_credentials();
        if !hmac_quarantined.is_empty() {
            for message in &hmac_quarantined {
                error!("{}", message);
            }
            error!(
                "Quarantined {} hmac_auth credential(s) during full config load",
                hmac_quarantined.len()
            );
        }

        ValidationPipeline::new(&mut config)
            .resolve_upstream_tls()
            .validate_all_fields_with_ip_policy(
                self.cert_expiry_warning_days,
                &self.backend_allow_ips,
                ValidationAction::Warn,
            )
            .validate_hosts(ValidationAction::Warn)
            .run()?;

        let validation_errors = collect_rejecting_runtime_config_errors(&config);
        if !validation_errors.is_empty() {
            for message in &validation_errors {
                tracing::error!("Database config rejected — {}", message);
            }
            // Typed, downcast-discoverable rejection (parity with the Mongo
            // loader) so the database-mode poll loop classifies this as a
            // reachable-but-invalid snapshot and keeps admin writes enabled for
            // in-band repair (issue #2158), rather than treating it as a
            // connectivity outage. Still an `Err`, so caches / CP broadcast
            // fail closed.
            return Err(
                crate::config::validation_pipeline::ConfigValidationRejection {
                    backend: "Database",
                    errors: validation_errors,
                }
                .into_anyhow(),
            );
        }

        ValidationPipeline::new(&mut config)
            .validate_unique_consumer_identities(ValidationAction::Warn)
            .validate_unique_consumer_credentials(ValidationAction::Warn)
            .validate_plugin_configs(&self.backend_allow_ips, ValidationAction::Warn)
            .run()?;
        if purpose.loads_node_local_plugin_files() {
            config = validate_plugin_file_dependencies_off_thread(config, ValidationAction::Warn)
                .await?;
        }

        // Hot-path isolation: strip api_spec_id from runtime config. The row
        // mappers preserve api_spec_id so admin GET/list paths can serialise
        // it; here we ensure the gateway's in-memory `GatewayConfig` does
        // not carry the ownership tag (the runtime never reads it, and CP
        // gRPC broadcasts must not leak it to DPs). Mirrors the strip done
        // by Mongo's `load_full_config`. See the cross-backend invariant
        // test `runtime_load_strips_api_spec_id_from_resources`.
        strip_api_spec_id_from_runtime_config(&mut config);

        self.check_slow_query("load_full_config", start);
        Ok(config)
    }

    /// Load a namespace's raw resources for a rollback snapshot WITHOUT the
    /// fatal validation chain that `load_full_config` runs.
    ///
    /// Reads from the PRIMARY pool (`self.pool()`), never the read replica, so a
    /// rollback snapshot is authoritative. Runs only `normalize_fields()` (parity
    /// with admission — idempotent, infallible), NOT the regex/listen-path/
    /// upstream-reference/etc. validators. That is deliberate: restore is the
    /// tool an operator uses to *repair* an invalid-but-present config, so such a
    /// config must still snapshot (rollback stays available during the repair).
    /// Only a genuine DB/connectivity error (or unparseable rows) makes this
    /// fail, which is exactly the case where the caller must abort rather than
    /// wipe a config it cannot restore.
    pub async fn load_namespace_snapshot(
        &self,
        namespace: &str,
    ) -> Result<GatewayConfig, anyhow::Error> {
        let start = Instant::now();
        let loaded_at = Utc::now();
        // Authoritative read: the primary pool, not `admin_read_pool()`.
        let mut tx = self.pool().begin().await?;
        self.configure_full_load_snapshot(&mut tx).await?;

        let purpose = FullLoadPurpose::RestoreSnapshot;
        let proxies = self.load_proxies_tx(namespace, purpose, &mut tx).await?;
        let consumers = self.load_consumers_tx(namespace, purpose, &mut tx).await?;
        let plugin_configs = self
            .load_plugin_configs_tx(namespace, purpose, &mut tx)
            .await?;
        let upstreams = self.load_upstreams_tx(namespace, purpose, &mut tx).await?;
        tx.commit().await?;

        let mut config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            consumers,
            plugin_configs,
            upstreams,
            loaded_at,
            known_namespaces: Vec::new(),
            ..Default::default()
        };

        // Normalize like admission (hostnames/etc.) but run NO fatal validators:
        // an invalid-but-present prior config must still snapshot so restore can
        // repair it while retaining rollback capability.
        ValidationPipeline::new(&mut config)
            .normalize_fields()
            .run()?;

        // Match `load_full_config`: strip the api_spec ownership tag. A rollback
        // re-applies these resources as hand-managed; the `api_specs` rows are
        // captured separately by the caller.
        strip_api_spec_id_from_runtime_config(&mut config);

        self.check_slow_query("load_namespace_snapshot", start);
        Ok(config)
    }

    /// Count ApiSpecs from the authoritative primary pool without hydrating rows.
    pub async fn count_api_specs(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        let start = Instant::now();
        let primary_pool = self.pool();
        let row = sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM api_specs WHERE namespace = ?"))
            .bind(namespace)
            .fetch_one(&primary_pool)
            .await?;
        let count: i64 = row.try_get("cnt")?;
        self.check_slow_query("count_api_specs", start);
        u64::try_from(count).map_err(|_| anyhow::anyhow!("api_specs count cannot be negative"))
    }

    pub async fn count_namespace_resources(
        &self,
        namespace: &str,
    ) -> Result<NamespaceResourceCounts, anyhow::Error> {
        let sql = self.q("SELECT \
             (SELECT COUNT(*) FROM proxies WHERE namespace = ?) AS proxies, \
             (SELECT COUNT(*) FROM consumers WHERE namespace = ?) AS consumers, \
             (SELECT COUNT(*) FROM plugin_configs WHERE namespace = ?) AS plugin_configs, \
             (SELECT COUNT(*) FROM upstreams WHERE namespace = ?) AS upstreams, \
             (SELECT COUNT(*) FROM api_specs WHERE namespace = ?) AS api_specs");
        let row = sqlx::query(&sql)
            .bind(namespace)
            .bind(namespace)
            .bind(namespace)
            .bind(namespace)
            .bind(namespace)
            .fetch_one(&self.pool())
            .await?;
        let count = |column: &str| -> Result<u64, anyhow::Error> {
            let value: i64 = row.try_get(column)?;
            u64::try_from(value).map_err(|_| anyhow::anyhow!("{} count cannot be negative", column))
        };
        Ok(NamespaceResourceCounts {
            proxies: count("proxies")?,
            consumers: count("consumers")?,
            plugin_configs: count("plugin_configs")?,
            upstreams: count("upstreams")?,
            api_specs: count("api_specs")?,
        })
    }

    async fn configure_full_load_snapshot(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<(), anyhow::Error> {
        match self.db_type.as_str() {
            "postgres" => {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut **tx)
                    .await?;
            }
            "mysql" => {
                let isolation = Self::mysql_transaction_isolation(tx).await?;
                if !Self::is_mysql_repeatable_read(&isolation) {
                    return Err(anyhow::anyhow!(
                        "MySQL full-load transactions require REPEATABLE READ isolation; current transaction isolation is '{}'. Configure the MySQL server or Ferrum session default to REPEATABLE READ so full runtime loads fail closed instead of publishing mixed snapshots.",
                        isolation
                    ));
                }
            }
            "sqlite" => {
                // SQLite read transactions observe one database snapshot from
                // the first read.
            }
            _ => {}
        }
        Ok(())
    }

    async fn mysql_transaction_isolation(
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<String, anyhow::Error> {
        match sqlx::query_scalar::<_, String>("SELECT @@transaction_isolation")
            .fetch_one(&mut **tx)
            .await
        {
            Ok(value) => Ok(value),
            Err(primary_error) => sqlx::query_scalar::<_, String>("SELECT @@tx_isolation")
                .fetch_one(&mut **tx)
                .await
                .map_err(|fallback_error| {
                    wrap_mysql_isolation_read_error(&primary_error, fallback_error)
                }),
        }
    }

    fn is_mysql_repeatable_read(isolation: &str) -> bool {
        isolation
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-' && *ch != '_')
            .flat_map(char::to_uppercase)
            .collect::<String>()
            == "REPEATABLEREAD"
    }

    async fn load_proxies_tx(
        &self,
        namespace: &str,
        purpose: FullLoadPurpose,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<Proxy>, anyhow::Error> {
        let start = Instant::now();

        // Batch-load proxy_plugins for proxies in this namespace (eliminates N+1).
        // Association rows are part of the security/policy graph, so any
        // query or decode error rejects the whole candidate instead of
        // publishing proxies with silently empty plugin lists.
        let mut plugins_by_proxy = self
            .load_proxy_plugin_associations_for_namespace_tx(namespace, purpose.operation(), tx)
            .await
            .map_err(|error| {
                if purpose == FullLoadPurpose::RestoreSnapshot
                    && is_proxy_plugin_association_load_error(&error)
                {
                    purpose.map_row_error("proxy_plugin", None, error)
                } else {
                    error
                }
            })?;

        // Load proxies in chunks to avoid unbounded SELECT * at scale.
        let mut proxies = Vec::new();
        let mut last_id: Option<String> = None;

        loop {
            let sql = if last_id.is_some() {
                "SELECT * FROM proxies WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?"
            } else {
                "SELECT * FROM proxies WHERE namespace = ? ORDER BY id LIMIT ?"
            };
            let query_sql = self.q(sql);
            let mut query = sqlx::query(&query_sql).bind(namespace);
            if let Some(last_id) = last_id.as_deref() {
                query = query.bind(last_id);
            }
            let rows: Vec<AnyRow> = query
                .bind(self.full_load_page_size)
                .fetch_all(&mut **tx)
                .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id").map_err(|error| {
                    purpose.map_row_error("proxy", None, anyhow::Error::new(error))
                })?;
                let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
                let proxy = row_to_proxy(&row, id.clone(), plugins)
                    .map_err(|error| purpose.map_row_error("proxy", Some(id.clone()), error))?;
                proxies.push(proxy);
                last_id = Some(id);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
        }
        Self::ensure_no_unmatched_proxy_plugin_associations(purpose.operation(), &plugins_by_proxy)
            .map_err(|error| purpose.map_row_error("proxy_plugin", None, error))?;

        self.check_slow_query("load_proxies", start);
        Ok(proxies)
    }

    async fn load_consumers_tx(
        &self,
        namespace: &str,
        purpose: FullLoadPurpose,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let mut consumers = Vec::new();
        let mut last_id: Option<String> = None;

        loop {
            let sql = if last_id.is_some() {
                "SELECT * FROM consumers WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?"
            } else {
                "SELECT * FROM consumers WHERE namespace = ? ORDER BY id LIMIT ?"
            };
            let query_sql = self.q(sql);
            let mut query = sqlx::query(&query_sql).bind(namespace);
            if let Some(last_id) = last_id.as_deref() {
                query = query.bind(last_id);
            }
            let rows: Vec<AnyRow> = query
                .bind(self.full_load_page_size)
                .fetch_all(&mut **tx)
                .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id").map_err(|error| {
                    purpose.map_row_error("consumer", None, anyhow::Error::new(error))
                })?;
                consumers.push(
                    row_to_consumer(&row).map_err(|error| {
                        purpose.map_row_error("consumer", Some(id.clone()), error)
                    })?,
                );
                last_id = Some(id);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
        }

        self.check_slow_query("load_consumers", start);
        Ok(consumers)
    }

    async fn load_plugin_configs_tx(
        &self,
        namespace: &str,
        purpose: FullLoadPurpose,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let mut configs = Vec::new();
        let mut last_id: Option<String> = None;

        loop {
            let sql = if last_id.is_some() {
                "SELECT * FROM plugin_configs WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?"
            } else {
                "SELECT * FROM plugin_configs WHERE namespace = ? ORDER BY id LIMIT ?"
            };
            let query_sql = self.q(sql);
            let mut query = sqlx::query(&query_sql).bind(namespace);
            if let Some(last_id) = last_id.as_deref() {
                query = query.bind(last_id);
            }
            let rows: Vec<AnyRow> = query
                .bind(self.full_load_page_size)
                .fetch_all(&mut **tx)
                .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id").map_err(|error| {
                    purpose.map_row_error("plugin_config", None, anyhow::Error::new(error))
                })?;
                configs.push(row_to_plugin_config(&row).map_err(|error| {
                    purpose.map_row_error("plugin_config", Some(id.clone()), error)
                })?);
                last_id = Some(id);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
        }

        self.check_slow_query("load_plugin_configs", start);
        Ok(configs)
    }

    // ---- Proxy INSERT SQL helpers ----
    //
    // The column list for a proxy INSERT appears in three places:
    //   1. `create_proxy`           — direct admin POST /proxies
    //   2. `batch_create_proxies_chunk` — bulk import
    //   3. `submit_api_spec_bundle` — spec-owned INSERT (adds `api_spec_id` column)
    //
    // Sites 1 and 2 share `PROXY_INSERT_SQL` (no api_spec_id).
    // Site 3 uses `PROXY_INSERT_WITH_SPEC_SQL` (adds api_spec_id before created_at).
    //
    // IMPORTANT: when adding a new column to `proxies`, update BOTH constants and
    // the corresponding `.bind()` chains in all three call sites.  The direct-admin
    // `update_proxy` (also in this file) and `replace_api_spec_bundle` UPDATE paths
    // are separate SQL strings and must be updated independently.
    //
    // NOTE: `submit_api_spec_bundle` uses a literal multi-line query string with
    // `\` continuation rather than this const because it adds the `api_spec_id`
    // column.  The `replace_api_spec_bundle` path uses UPDATE so it is out of scope.
    // ── Drift-prevention contract for proxy INSERT call sites ────────────────
    //
    // The 45-column proxy column list is canonical and shared by THREE INSERT
    // sites and ONE UPDATE site. When you add a new column to the `proxies`
    // table, it must be added — in the same position — to ALL of:
    //
    //   1. PROXY_INSERT_SQL                         (direct admin path)
    //   2. create_proxy() bind chain                (this file, ~line 790)
    //   3. submit_api_spec_bundle() proxy INSERT    (this file, ~line 3387)
    //   4. update_proxy() SET clause + bind chain   (this file, ~line 919)
    //   5. PROXY_INSERT_PLACEHOLDER_COUNT below     (drift catcher)
    //   6. PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT below
    //
    // The two `proxy_insert_sql_*_count_matches_bind_count` tests below count
    // `?` placeholders in the SQL and assert against the constants here. If
    // you forget to update the placeholder count, the test fails and points
    // at the exact discrepancy. If you update the constant but forget to
    // bind, sqlx returns "wrong number of parameters" at execute time.
    //
    // We chose this drift-catcher pattern over a fully-generic
    // `bind_proxy_base_columns` helper because the sqlx::Any generic makes
    // such helpers verbose without meaningful runtime benefit.

    /// Number of `?` placeholders in `PROXY_INSERT_SQL` (no api_spec_id).
    /// 48 base columns + `created_at` + `updated_at` = 50.
    ///
    /// Used only by the drift-catcher tests in `proxy_insert_sql_drift_tests`;
    /// kept available outside `#[cfg(test)]` so it remains a visible
    /// drift-prevention anchor when reading the SQL definition.
    #[allow(dead_code)]
    pub(crate) const PROXY_INSERT_PLACEHOLDER_COUNT: usize = 51;

    /// Number of `?` placeholders in the `submit_api_spec_bundle` proxy
    /// INSERT statement (which adds `api_spec_id` between
    /// `stream_proxy_protocol` and `created_at`).
    /// 51 base + 1 (api_spec_id) = 52.
    #[allow(dead_code)]
    pub(crate) const PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT: usize = 52;

    /// Proxy INSERT SQL without `api_spec_id` (direct admin path and bulk import).
    ///
    /// Note: the `?` placeholder is rewritten to `$N` for PostgreSQL by `self.q()`.
    /// Any new column must be appended in the same position in `PROXY_INSERT_SQL`
    /// and the corresponding `.bind()` chain — see the drift-prevention contract
    /// block above.
    const PROXY_INSERT_SQL: &'static str = "\
        INSERT INTO proxies (id, namespace, name, hosts, listen_path, backend_scheme, \
         backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, \
         backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, \
         backend_tls_client_cert_path, backend_tls_client_key_path, \
         backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, \
         dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, \
         circuit_breaker, retry, response_body_mode, \
         pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, \
         pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, \
         pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, \
         pool_http2_initial_connection_window_size, pool_http2_adaptive_window, \
         pool_http2_max_frame_size, pool_http2_max_concurrent_streams, \
         pool_http3_connections_per_backend, pool_max_requests_per_connection, \
         listen_port, frontend_tls, passthrough, \
         udp_idle_timeout_seconds, tcp_idle_timeout_seconds, websocket_idle_timeout_seconds, \
         allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, \
         stream_proxy_protocol, \
         upstream_subset, \
         created_at, updated_at) \
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                ?, ?, ?, ?, ?, ?)";

    // ---- CRUD for Admin API ----

    pub async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let circuit_breaker_json = proxy
            .circuit_breaker
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let retry_json = proxy
            .retry
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let response_body_mode_str = match proxy.response_body_mode {
            ResponseBodyMode::Buffer => "buffer",
            ResponseBodyMode::Stream => "stream",
        };

        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &proxy.namespace)
            .await?;
        self.ensure_proxy_route_unique_tx(&mut tx, proxy, None)
            .await?;

        let hosts_json = serde_json::to_string(&proxy.hosts)?;

        sqlx::query(&self.q(Self::PROXY_INSERT_SQL))
            .bind(&proxy.id)
            .bind(&proxy.namespace)
            .bind(&proxy.name)
            .bind(&hosts_json)
            .bind(&proxy.listen_path)
            .bind(proxy.effective_scheme().to_scheme_str())
            .bind(&proxy.backend_host)
            .bind(proxy.backend_port as i32)
            .bind(&proxy.backend_path)
            .bind(if proxy.strip_listen_path { 1i32 } else { 0 })
            .bind(if proxy.preserve_host_header { 1i32 } else { 0 })
            .bind(proxy.backend_connect_timeout_ms as i64)
            .bind(proxy.backend_read_timeout_ms as i64)
            .bind(proxy.backend_write_timeout_ms as i64)
            .bind(&proxy.backend_tls_client_cert_path)
            .bind(&proxy.backend_tls_client_key_path)
            .bind(if proxy.backend_tls_verify_server_cert {
                1i32
            } else {
                0
            })
            .bind(&proxy.backend_tls_server_ca_cert_path)
            .bind(&proxy.dns_override)
            .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
            .bind(match proxy.auth_mode {
                AuthMode::Multi => "multi",
                _ => "single",
            })
            .bind(&proxy.upstream_id)
            .bind(&circuit_breaker_json)
            .bind(&retry_json)
            .bind(response_body_mode_str)
            .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                proxy
                    .pool_enable_http_keep_alive
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
            .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
            .bind(
                proxy
                    .pool_http2_keep_alive_interval_seconds
                    .map(|v| v as i64),
            )
            .bind(
                proxy
                    .pool_http2_keep_alive_timeout_seconds
                    .map(|v| v as i64),
            )
            .bind(
                proxy
                    .pool_http2_initial_stream_window_size
                    .map(|v| v as i64),
            )
            .bind(
                proxy
                    .pool_http2_initial_connection_window_size
                    .map(|v| v as i64),
            )
            .bind(
                proxy
                    .pool_http2_adaptive_window
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
            .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
            .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
            .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
            .bind(proxy.listen_port.map(|v| v as i32))
            .bind(if proxy.frontend_tls { 1i32 } else { 0 })
            .bind(if proxy.passthrough { 1i32 } else { 0 })
            .bind(proxy.udp_idle_timeout_seconds as i64)
            .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
            .bind(proxy.websocket_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                proxy
                    .allowed_methods
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(if proxy.allowed_ws_origins.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&proxy.allowed_ws_origins)?)
            })
            .bind(
                proxy
                    .udp_max_response_amplification_factor
                    .map(|v| v as f64),
            )
            .bind(
                proxy
                    .stream_proxy_protocol
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(&proxy.upstream_subset)
            .bind(proxy.created_at.to_rfc3339())
            .bind(proxy.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;

        // Persist plugin associations in the junction table
        for assoc in &proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }

        self.validate_namespace_admission_tx(&mut tx, &proxy.namespace)
            .await?;
        self.record_config_change_tx(&mut tx, &proxy.namespace, "proxy", &proxy.id, "upsert")
            .await?;
        self.compact_config_changes_tx(&mut tx, &proxy.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("create_proxy", start);
        Ok(())
    }

    pub async fn update_proxy(&self, proxy: &Proxy) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let circuit_breaker_json = proxy
            .circuit_breaker
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let retry_json = proxy
            .retry
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let response_body_mode_str = match proxy.response_body_mode {
            ResponseBodyMode::Buffer => "buffer",
            ResponseBodyMode::Stream => "stream",
        };

        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &proxy.namespace)
            .await?;
        // Existence read inside the transaction is the not-found authority —
        // not the UPDATE's rows_affected. MySQL without CLIENT_FOUND_ROWS
        // (sqlx's default) counts *changed* rows, so an update writing
        // identical values would falsely report 0 for an existing row.
        // FOR UPDATE locks the row against a concurrent delete until commit.
        let proxy_select_sql = if self.db_type == "sqlite" {
            self.q("SELECT upstream_id FROM proxies WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT upstream_id FROM proxies WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        let proxy_row: Option<AnyRow> = sqlx::query(&proxy_select_sql)
            .bind(&proxy.id)
            .bind(&proxy.namespace)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(proxy_row) = proxy_row else {
            tx.rollback().await?;
            self.check_slow_query("update_proxy", start);
            return Ok(false);
        };
        let old_upstream_id: Option<String> = proxy_row.try_get::<String, _>("upstream_id").ok();
        self.ensure_proxy_route_unique_tx(&mut tx, proxy, Some(&proxy.id))
            .await?;

        let hosts_json = serde_json::to_string(&proxy.hosts)?;

        sqlx::query(
            &self.q("UPDATE proxies SET name=?, hosts=?, listen_path=?, backend_scheme=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, dns_override=?, dns_cache_ttl_seconds=?, auth_mode=?, upstream_id=?, upstream_subset=?, circuit_breaker=?, retry=?, response_body_mode=?, pool_idle_timeout_seconds=?, pool_enable_http_keep_alive=?, pool_enable_http2=?, pool_tcp_keepalive_seconds=?, pool_http2_keep_alive_interval_seconds=?, pool_http2_keep_alive_timeout_seconds=?, pool_http2_initial_stream_window_size=?, pool_http2_initial_connection_window_size=?, pool_http2_adaptive_window=?, pool_http2_max_frame_size=?, pool_http2_max_concurrent_streams=?, pool_http3_connections_per_backend=?, pool_max_requests_per_connection=?, listen_port=?, frontend_tls=?, passthrough=?, udp_idle_timeout_seconds=?, tcp_idle_timeout_seconds=?, websocket_idle_timeout_seconds=?, allowed_methods=?, allowed_ws_origins=?, udp_max_response_amplification_factor=?, stream_proxy_protocol=?, updated_at=? WHERE id=? AND namespace=?")
        )
        .bind(&proxy.name)
        .bind(&hosts_json)
        .bind(&proxy.listen_path)
        .bind(proxy.effective_scheme().to_scheme_str())
        .bind(&proxy.backend_host)
        .bind(proxy.backend_port as i32)
        .bind(&proxy.backend_path)
        .bind(if proxy.strip_listen_path { 1i32 } else { 0 })
        .bind(if proxy.preserve_host_header { 1i32 } else { 0 })
        .bind(proxy.backend_connect_timeout_ms as i64)
        .bind(proxy.backend_read_timeout_ms as i64)
        .bind(proxy.backend_write_timeout_ms as i64)
        .bind(&proxy.backend_tls_client_cert_path)
        .bind(&proxy.backend_tls_client_key_path)
        .bind(if proxy.backend_tls_verify_server_cert { 1i32 } else { 0 })
        .bind(&proxy.backend_tls_server_ca_cert_path)
        .bind(&proxy.dns_override)
        .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
        .bind(match proxy.auth_mode { AuthMode::Multi => "multi", _ => "single" })
        .bind(&proxy.upstream_id)
        .bind(&proxy.upstream_subset)
        .bind(&circuit_breaker_json)
        .bind(&retry_json)
        .bind(response_body_mode_str)
        .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_enable_http_keep_alive.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_stream_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_connection_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_adaptive_window.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
        .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
        .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
        .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
        .bind(proxy.listen_port.map(|v| v as i32))
        .bind(if proxy.frontend_tls { 1i32 } else { 0 })
        .bind(if proxy.passthrough { 1i32 } else { 0 })
        .bind(proxy.udp_idle_timeout_seconds as i64)
        .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.websocket_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.allowed_methods.as_ref().map(serde_json::to_string).transpose()?)
        .bind(if proxy.allowed_ws_origins.is_empty() { None } else { Some(serde_json::to_string(&proxy.allowed_ws_origins)?) })
        .bind(proxy.udp_max_response_amplification_factor.map(|v| v as f64))
        .bind(proxy.stream_proxy_protocol.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.updated_at.to_rfc3339())
        .bind(&proxy.id)
        .bind(&proxy.namespace)
        .execute(&mut *tx)
        .await?;

        // Update plugin associations: remove old, insert new
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id = ?"))
            .bind(&proxy.id)
            .execute(&mut *tx)
            .await?;

        for assoc in &proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }

        // Clean up orphaned proxy_group plugin configs (no remaining associations)
        self.cleanup_orphaned_proxy_group_plugins(&mut tx, &proxy.namespace)
            .await?;

        if let Some(old_upstream_id) = old_upstream_id.as_deref()
            && proxy.upstream_id.as_deref() != Some(old_upstream_id)
        {
            self.cleanup_orphaned_upstream_tx(&mut tx, &proxy.namespace, old_upstream_id)
                .await?;
        }

        self.validate_namespace_admission_tx(&mut tx, &proxy.namespace)
            .await?;
        self.record_config_change_tx(&mut tx, &proxy.namespace, "proxy", &proxy.id, "upsert")
            .await?;
        self.compact_config_changes_tx(&mut tx, &proxy.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("update_proxy", start);
        Ok(true)
    }

    pub async fn delete_proxy(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        let prior_mtls_dns_conflicts = self
            .mtls_dns_identity_conflicts_tx(&mut tx, namespace)
            .await?;

        // Look up the proxy's current upstream_id before deleting so we can
        // cascade-delete that upstream if it becomes orphaned. Also capture the
        // api_spec row, if this proxy owns one, before the FK cascade removes it.
        // The lookup is scoped to the caller's namespace so a tenant cannot
        // reach a same-id proxy in another namespace (issue #2122).
        let proxy_select_sql = if self.db_type == "sqlite" {
            self.q("SELECT upstream_id FROM proxies WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT upstream_id FROM proxies WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        let proxy_row: Option<AnyRow> = sqlx::query(&proxy_select_sql)
            .bind(id)
            .bind(namespace)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(proxy_row) = proxy_row else {
            tx.rollback().await?;
            self.check_slow_query("delete_proxy", start);
            return Ok(false);
        };
        let upstream_id: Option<String> = proxy_row.try_get::<String, _>("upstream_id").ok();

        let spec_row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id, namespace FROM api_specs WHERE proxy_id = ?"))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let spec_owner: Option<(String, String)> = spec_row
            .as_ref()
            .map(|row| Ok::<_, anyhow::Error>((row.try_get("id")?, row.try_get("namespace")?)))
            .transpose()?;
        if let Some((ref spec_id, ref spec_namespace)) = spec_owner {
            self.ensure_no_external_spec_upstream_refs_tx(&mut tx, spec_namespace, spec_id, id)
                .await?;
        }
        let proxy_scoped_plugin_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT id, namespace FROM plugin_configs WHERE proxy_id = ?"))
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        let proxy_scoped_plugins: Vec<(String, String)> = proxy_scoped_plugin_rows
            .iter()
            .map(|row| Ok::<_, anyhow::Error>((row.try_get("id")?, row.try_get("namespace")?)))
            .collect::<Result<_, _>>()?;

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query(&self.q("DELETE FROM proxies WHERE id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            self.check_slow_query("delete_proxy", start);
            return Ok(false);
        }

        // Clean up orphaned proxy_group plugin configs (no remaining associations)
        self.cleanup_orphaned_proxy_group_plugins(&mut tx, namespace)
            .await?;

        // If this was a spec-owned proxy, delete every upstream tagged with the
        // spec id, not only the proxy's current upstream_id. Direct admin CRUD
        // can drift the pointer away from the original spec-owned upstream.
        if let Some((ref spec_id, ref spec_namespace)) = spec_owner {
            let upstream_rows: Vec<AnyRow> = sqlx::query(
                &self.q("SELECT id FROM upstreams WHERE api_spec_id = ? AND namespace = ?"),
            )
            .bind(spec_id)
            .bind(spec_namespace)
            .fetch_all(&mut *tx)
            .await?;
            let upstream_ids: Vec<String> = upstream_rows
                .iter()
                .map(|row| row.try_get("id"))
                .collect::<Result<_, _>>()?;
            sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
                .bind(spec_id)
                .bind(spec_namespace)
                .execute(&mut *tx)
                .await?;
            for upstream_id in upstream_ids {
                self.record_config_change_tx(
                    &mut tx,
                    spec_namespace,
                    "upstream",
                    &upstream_id,
                    "delete",
                )
                .await?;
            }
        }

        // Generic proxy deletion owns ordinary orphan cleanup. A spec-owned
        // proxy can drift to a hand-owned upstream, though, and that resource
        // must survive deletion of the spec graph. Spec-owned upstreams were
        // already removed explicitly above.
        if spec_owner.is_none()
            && let Some(ref uid) = upstream_id
        {
            self.cleanup_orphaned_upstream_tx(&mut tx, namespace, uid)
                .await?;
        }

        self.validate_namespace_repair_delete_admission_tx(
            &mut tx,
            namespace,
            &prior_mtls_dns_conflicts,
        )
        .await?;
        self.record_config_change_tx(&mut tx, namespace, "proxy", id, "delete")
            .await?;
        for (plugin_id, plugin_namespace) in proxy_scoped_plugins {
            self.record_config_change_tx(
                &mut tx,
                &plugin_namespace,
                "plugin_config",
                &plugin_id,
                "delete",
            )
            .await?;
            self.compact_config_changes_tx(&mut tx, &plugin_namespace)
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, namespace).await?;
        tx.commit().await?;

        self.check_slow_query("delete_proxy", start);
        Ok(true)
    }

    /// Delete proxy_group-scoped plugin configs that have no remaining proxy
    /// associations in the proxy_plugins junction table. Called within a
    /// transaction after proxy deletion or proxy update (which may remove
    /// associations).
    async fn cleanup_orphaned_proxy_group_plugins(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<(), anyhow::Error> {
        let orphaned_configs: Vec<(String, String)> = sqlx::query(&self.q(
            "SELECT pc.id, pc.namespace FROM plugin_configs pc \
                 WHERE pc.scope = 'proxy_group' AND pc.namespace = ? \
                 AND NOT EXISTS (SELECT 1 FROM proxy_plugins pp WHERE pp.plugin_config_id = pc.id)",
        ))
        .bind(namespace)
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .filter_map(|row| {
            Some((
                row.try_get::<String, _>("id").ok()?,
                row.try_get::<String, _>("namespace").ok()?,
            ))
        })
        .collect();

        for (id, namespace) in &orphaned_configs {
            info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
            sqlx::query(&self.q("DELETE FROM plugin_configs WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .execute(&mut **tx)
                .await?;
            self.record_config_change_tx(tx, namespace, "plugin_config", id, "delete")
                .await?;
            self.compact_config_changes_tx(tx, namespace).await?;
        }

        Ok(())
    }

    async fn cleanup_orphaned_upstream_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        let upstream_row: Option<AnyRow> = sqlx::query(
            &self.q("SELECT api_spec_id FROM upstreams WHERE id = ? AND namespace = ? LIMIT 1"),
        )
        .bind(upstream_id)
        .bind(namespace)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(upstream_row) = upstream_row else {
            return Ok(());
        };
        let api_spec_id: Option<String> = upstream_row.try_get("api_spec_id")?;
        if api_spec_id.is_some() {
            return Ok(());
        }

        let ref_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT id FROM proxies WHERE upstream_id = ? AND namespace = ? LIMIT 1"),
        )
        .bind(upstream_id)
        .bind(namespace)
        .fetch_all(&mut **tx)
        .await?;

        let dispatch_ref = if ref_rows.is_empty() {
            self.find_mesh_route_dispatch_upstream_ref_tx(tx, upstream_id, namespace)
                .await?
        } else {
            None
        };

        if ref_rows.is_empty() && dispatch_ref.is_none() {
            info!("Cleaning up orphaned upstream {}", upstream_id);
            sqlx::query(&self.q("DELETE FROM upstreams WHERE id = ? AND namespace = ?"))
                .bind(upstream_id)
                .bind(namespace)
                .execute(&mut **tx)
                .await?;
            self.record_config_change_tx(tx, namespace, "upstream", upstream_id, "delete")
                .await?;
            self.compact_config_changes_tx(tx, namespace).await?;
        }

        Ok(())
    }

    pub async fn get_proxy(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Proxy>, anyhow::Error> {
        let start = Instant::now();
        let proxy = self
            .load_proxy_with_associations(namespace, id, "get_proxy")
            .await?;
        if let Some(proxy) = proxy.as_ref() {
            self.reject_invalid_loaded_proxy_plugin_associations("get_proxy", proxy)
                .await?;
        }
        self.check_slow_query("get_proxy", start);
        Ok(proxy)
    }

    pub async fn get_proxy_for_write(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Proxy>, anyhow::Error> {
        let start = Instant::now();
        let proxy = self
            .load_proxy_with_associations(namespace, id, "get_proxy_for_write")
            .await?;
        self.check_slow_query("get_proxy_for_write", start);
        Ok(proxy)
    }

    async fn load_proxy_with_associations(
        &self,
        namespace: &str,
        id: &str,
        operation: &str,
    ) -> Result<Option<Proxy>, anyhow::Error> {
        // Namespace predicate keeps ID-only admin reads tenant-scoped
        // (issue #2122): a caller can never see a same-id proxy that lives in
        // another namespace.
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM proxies WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let proxy_ids = [id.to_string()];
        let mut plugins_by_proxy = self
            .load_proxy_plugin_associations_for_proxy_ids(&proxy_ids, operation, true)
            .await?;
        let plugins = plugins_by_proxy.remove(id).unwrap_or_default();
        Self::ensure_no_unmatched_proxy_plugin_associations(operation, &plugins_by_proxy)?;

        let mut proxy = row_to_proxy(&row, id.to_string(), plugins)?;
        proxy.normalize_fields();
        Ok(Some(proxy))
    }

    /// Check whether a proxy with the given ID exists in `namespace`.
    ///
    /// The `namespace` filter is required: admin-API callers must scope
    /// reference checks to the requesting tenant's namespace so that, for
    /// example, a `plugin_config.proxy_id` cannot point at a proxy that lives
    /// in a different namespace (such a config would never load at runtime
    /// because the polling path filters by namespace).
    pub async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM proxies WHERE id = ? AND namespace = ?"))
                .bind(proxy_id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;
        self.check_slow_query("check_proxy_exists", start);
        Ok(row.is_some())
    }

    pub async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &consumer.namespace)
            .await?;
        sqlx::query(
            &self.q("INSERT INTO consumers (id, namespace, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&consumer.id)
        .bind(&consumer.namespace)
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(&acl_groups_json)
        .bind(consumer.created_at.to_rfc3339())
        .bind(consumer.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        self.insert_consumer_credential_index_tx(&mut tx, consumer)
            .await?;
        // Identity rows ride the same transaction as the consumer INSERT: a
        // cross-field identity collision aborts the whole create via the
        // consumer_identity_index PK (mapped to HTTP 409 by the admin layer).
        self.insert_consumer_identity_index_tx(&mut tx, consumer)
            .await?;
        self.validate_mtls_dns_admission_tx(&mut tx, &consumer.namespace)
            .await?;
        self.record_config_change_tx(
            &mut tx,
            &consumer.namespace,
            "consumer",
            &consumer.id,
            "upsert",
        )
        .await?;
        self.compact_config_changes_tx(&mut tx, &consumer.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("create_consumer", start);
        Ok(())
    }

    async fn update_consumer_for_guard(
        &self,
        consumer: &Consumer,
        guard_owner: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_for_owner_tx(&mut tx, &consumer.namespace, guard_owner)
            .await?;
        // Existence read inside the transaction is the not-found authority —
        // not the UPDATE's rows_affected. MySQL without CLIENT_FOUND_ROWS
        // (sqlx's default) counts *changed* rows, so an update writing
        // identical values would falsely report 0 for an existing row.
        // FOR UPDATE locks the row against a concurrent delete until commit.
        let exists_sql = if self.db_type == "sqlite" {
            self.q("SELECT id FROM consumers WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT id FROM consumers WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        let existing: Option<AnyRow> = sqlx::query(&exists_sql)
            .bind(&consumer.id)
            .bind(&consumer.namespace)
            .fetch_optional(&mut *tx)
            .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("update_consumer", start);
            return Ok(false);
        }
        self.delete_consumer_credential_index_tx(&mut tx, &consumer.namespace, &consumer.id)
            .await?;
        self.delete_consumer_identity_index_tx(&mut tx, &consumer.namespace, &consumer.id)
            .await?;
        sqlx::query(&self.q(
            "UPDATE consumers SET username=?, custom_id=?, credentials=?, acl_groups=?, updated_at=? WHERE id=? AND namespace=?",
        ))
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(&acl_groups_json)
        .bind(consumer.updated_at.to_rfc3339())
        .bind(&consumer.id)
        .bind(&consumer.namespace)
        .execute(&mut *tx)
        .await?;
        self.insert_consumer_credential_index_tx(&mut tx, consumer)
            .await?;
        self.insert_consumer_identity_index_tx(&mut tx, consumer)
            .await?;
        self.validate_mtls_dns_admission_tx(&mut tx, &consumer.namespace)
            .await?;
        self.record_config_change_tx(
            &mut tx,
            &consumer.namespace,
            "consumer",
            &consumer.id,
            "upsert",
        )
        .await?;
        self.compact_config_changes_tx(&mut tx, &consumer.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("update_consumer", start);
        Ok(true)
    }

    pub async fn delete_consumer(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        let prior_mtls_dns_conflicts = self
            .mtls_dns_identity_conflicts_tx(&mut tx, namespace)
            .await?;
        // Scope the existence check to the caller's namespace (issue #2122):
        // consumer ids are only unique per namespace.
        let existing: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM consumers WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&mut *tx)
                .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("delete_consumer", start);
            return Ok(false);
        }
        // The FK cascade on both index tables covers these deletes; keep them
        // explicit for defense in depth (mirrors delete_all_resources).
        self.delete_consumer_credential_index_tx(&mut tx, namespace, id)
            .await?;
        self.delete_consumer_identity_index_tx(&mut tx, namespace, id)
            .await?;
        let result = sqlx::query(&self.q("DELETE FROM consumers WHERE id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        self.validate_mtls_dns_repair_delete_tx(&mut tx, namespace, &prior_mtls_dns_conflicts)
            .await?;
        self.record_config_change_tx(&mut tx, namespace, "consumer", id, "delete")
            .await?;
        self.compact_config_changes_tx(&mut tx, namespace).await?;
        tx.commit().await?;
        self.check_slow_query("delete_consumer", start);
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_consumer(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM consumers WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;

        let result = match row {
            Some(r) => {
                let mut consumer = row_to_consumer(&r)?;
                consumer.normalize_fields();
                Ok(Some(consumer))
            }
            None => Ok(None),
        };
        self.check_slow_query("get_consumer", start);
        result
    }

    pub async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::ProxyGroup => "proxy_group",
            PluginScope::Global => "global",
        };
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &pc.namespace)
            .await?;
        sqlx::query(
            &self.q("INSERT INTO plugin_configs (id, namespace, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&pc.id)
        .bind(&pc.namespace)
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(pc.priority_override.map(|v| v as i32))
        .bind(pc.created_at.to_rfc3339())
        .bind(pc.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        self.record_config_change_tx(&mut tx, &pc.namespace, "plugin_config", &pc.id, "upsert")
            .await?;
        if pc.scope == PluginScope::Proxy
            && let Some(proxy_id) = pc.proxy_id.as_deref()
        {
            self.record_config_change_tx(&mut tx, &pc.namespace, "proxy", proxy_id, "upsert")
                .await?;
        }
        self.validate_namespace_admission_tx(&mut tx, &pc.namespace)
            .await?;
        self.compact_config_changes_tx(&mut tx, &pc.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("create_plugin_config", start);
        Ok(())
    }

    pub async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::ProxyGroup => "proxy_group",
            PluginScope::Global => "global",
        };
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &pc.namespace)
            .await?;
        // Existence read inside the transaction is the not-found authority —
        // not the UPDATE's rows_affected. MySQL without CLIENT_FOUND_ROWS
        // (sqlx's default) counts *changed* rows, so an update writing
        // identical values would falsely report 0 for an existing row.
        // FOR UPDATE locks the row against a concurrent delete until commit.
        let exists_sql = if self.db_type == "sqlite" {
            self.q("SELECT id FROM plugin_configs WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT id FROM plugin_configs WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        let existing: Option<AnyRow> = sqlx::query(&exists_sql)
            .bind(&pc.id)
            .bind(&pc.namespace)
            .fetch_optional(&mut *tx)
            .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("update_plugin_config", start);
            return Ok(false);
        }
        sqlx::query(
            &self.q("UPDATE plugin_configs SET plugin_name=?, config=?, scope=?, proxy_id=?, enabled=?, priority_override=?, updated_at=? WHERE id=? AND namespace=?")
        )
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(pc.priority_override.map(|v| v as i32))
        .bind(pc.updated_at.to_rfc3339())
        .bind(&pc.id)
        .bind(&pc.namespace)
        .execute(&mut *tx)
        .await?;
        self.record_config_change_tx(&mut tx, &pc.namespace, "plugin_config", &pc.id, "upsert")
            .await?;
        if pc.scope == PluginScope::Proxy
            && let Some(proxy_id) = pc.proxy_id.as_deref()
        {
            self.record_config_change_tx(&mut tx, &pc.namespace, "proxy", proxy_id, "upsert")
                .await?;
        }
        self.validate_namespace_admission_tx(&mut tx, &pc.namespace)
            .await?;
        self.compact_config_changes_tx(&mut tx, &pc.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("update_plugin_config", start);
        Ok(true)
    }

    pub async fn delete_plugin_config(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        let prior_mtls_dns_conflicts = self
            .mtls_dns_identity_conflicts_tx(&mut tx, namespace)
            .await?;
        // Scope the existence check to the caller's namespace (issue #2122) so
        // a tenant cannot delete a same-id plugin config in another namespace.
        let existing: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM plugin_configs WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&mut *tx)
                .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("delete_plugin_config", start);
            return Ok(false);
        }

        let affected_proxy_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT proxy_id FROM proxy_plugins WHERE plugin_config_id = ?"))
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        let affected_proxy_ids: Vec<String> = affected_proxy_rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("proxy_id").ok())
            .collect();

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE plugin_config_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if !affected_proxy_ids.is_empty() {
            let updated_at = Utc::now().to_rfc3339();
            let sql = self.q("UPDATE proxies SET updated_at = ? WHERE id = ? AND namespace = ?");
            for proxy_id in &affected_proxy_ids {
                sqlx::query(&sql)
                    .bind(&updated_at)
                    .bind(proxy_id)
                    .bind(namespace)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        let result =
            sqlx::query(&self.q("DELETE FROM plugin_configs WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .execute(&mut *tx)
                .await?;
        self.validate_namespace_repair_delete_admission_tx(
            &mut tx,
            namespace,
            &prior_mtls_dns_conflicts,
        )
        .await?;
        self.record_config_change_tx(&mut tx, namespace, "plugin_config", id, "delete")
            .await?;
        for proxy_id in affected_proxy_ids {
            self.record_config_change_tx(&mut tx, namespace, "proxy", &proxy_id, "upsert")
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, namespace).await?;

        tx.commit().await?;

        self.check_slow_query("delete_plugin_config", start);
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_plugin_config(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM plugin_configs WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;

        let result = match row {
            Some(r) => {
                let mut plugin_config = row_to_plugin_config(&r)?;
                plugin_config.normalize_fields();
                Ok(Some(plugin_config))
            }
            None => Ok(None),
        };
        self.check_slow_query("get_plugin_config", start);
        result
    }

    // ---- Upstream CRUD ----

    async fn load_upstreams_tx(
        &self,
        namespace: &str,
        purpose: FullLoadPurpose,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let mut upstreams = Vec::new();
        let mut last_id: Option<String> = None;

        loop {
            let sql = if last_id.is_some() {
                "SELECT * FROM upstreams WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?"
            } else {
                "SELECT * FROM upstreams WHERE namespace = ? ORDER BY id LIMIT ?"
            };
            let query_sql = self.q(sql);
            let mut query = sqlx::query(&query_sql).bind(namespace);
            if let Some(last_id) = last_id.as_deref() {
                query = query.bind(last_id);
            }
            let rows: Vec<AnyRow> = query
                .bind(self.full_load_page_size)
                .fetch_all(&mut **tx)
                .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id").map_err(|error| {
                    purpose.map_row_error("upstream", None, anyhow::Error::new(error))
                })?;
                upstreams.push(
                    row_to_upstream(&row).map_err(|error| {
                        purpose.map_row_error("upstream", Some(id.clone()), error)
                    })?,
                );
                last_id = Some(id);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
        }

        self.check_slow_query("load_upstreams", start);
        Ok(upstreams)
    }

    // ---- Paginated list queries for Admin API ----

    /// List proxies with database-level LIMIT/OFFSET pagination.
    pub async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_proxies_paginated_from_admin_read(namespace, limit, offset, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_proxies_paginated", &error);
                warn!(
                    "Read replica admin query failed; retrying list_proxies_paginated against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_proxies_paginated_from_admin_read(namespace, limit, offset, &primary_pool)
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_proxies_paginated");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_proxies_paginated_from_admin_read(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM proxies WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(pool)
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM proxies WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        // Batch-load proxy_plugins for only the proxies in this page
        let proxy_ids: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect();

        let mut plugins_by_proxy = self
            .load_proxy_plugin_associations_for_proxy_ids_from_pool(
                &proxy_ids,
                "list_proxies_paginated",
                pool,
            )
            .await?;

        let mut proxies = Vec::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            let mut proxy = row_to_proxy(&row, id, plugins)?;
            proxy.normalize_fields();
            proxies.push(proxy);
        }
        Self::ensure_no_unmatched_proxy_plugin_associations(
            "list_proxies_paginated",
            &plugins_by_proxy,
        )?;
        self.reject_invalid_loaded_proxy_plugin_association_page(
            "list_proxies_paginated",
            namespace,
            &proxies,
            pool,
        )
        .await?;

        self.check_slow_query("list_proxies_paginated", start);
        Ok(PaginatedResult {
            items: proxies,
            total,
        })
    }

    /// List consumers with database-level LIMIT/OFFSET pagination.
    pub async fn list_consumers_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_consumers_paginated_from_admin_read(namespace, limit, offset, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_consumers_paginated", &error);
                warn!(
                    "Read replica admin query failed; retrying list_consumers_paginated against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_consumers_paginated_from_admin_read(
                        namespace,
                        limit,
                        offset,
                        &primary_pool,
                    )
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_consumers_paginated");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_consumers_paginated_from_admin_read(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM consumers WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(pool)
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM consumers WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let mut consumers = Vec::new();
        for row in rows {
            consumers.push(row_to_consumer(&row)?);
        }

        self.check_slow_query("list_consumers_paginated", start);
        Ok(PaginatedResult {
            items: consumers,
            total,
        })
    }

    /// List plugin configs with database-level LIMIT/OFFSET pagination.
    pub async fn list_plugin_configs_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_plugin_configs_paginated_from_admin_read(
                namespace,
                limit,
                offset,
                &admin_read.pool,
            )
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_plugin_configs_paginated", &error);
                warn!(
                    "Read replica admin query failed; retrying list_plugin_configs_paginated against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_plugin_configs_paginated_from_admin_read(
                        namespace,
                        limit,
                        offset,
                        &primary_pool,
                    )
                    .await;
                if retry.is_ok() {
                    info!(
                        "Admin read fallback to primary succeeded for list_plugin_configs_paginated"
                    );
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_plugin_configs_paginated_from_admin_read(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM plugin_configs WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(pool)
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self
                .q("SELECT * FROM plugin_configs WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let mut configs = Vec::new();
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }

        self.check_slow_query("list_plugin_configs_paginated", start);
        Ok(PaginatedResult {
            items: configs,
            total,
        })
    }

    /// List upstreams with database-level LIMIT/OFFSET pagination.
    pub async fn list_upstreams_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_upstreams_paginated_from_admin_read(namespace, limit, offset, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_upstreams_paginated", &error);
                warn!(
                    "Read replica admin query failed; retrying list_upstreams_paginated against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_upstreams_paginated_from_admin_read(
                        namespace,
                        limit,
                        offset,
                        &primary_pool,
                    )
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_upstreams_paginated");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_upstreams_paginated_from_admin_read(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM upstreams WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(pool)
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM upstreams WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let mut upstreams = Vec::new();
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }

        self.check_slow_query("list_upstreams_paginated", start);
        Ok(PaginatedResult {
            items: upstreams,
            total,
        })
    }

    pub async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        // algo_json is quoted like "\"round_robin\"", strip the quotes
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let service_discovery_json = upstream
            .service_discovery
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let subsets_json = upstream
            .subsets
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(upstream)?;

        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &upstream.namespace)
            .await?;
        sqlx::query(
            &self.q("INSERT INTO upstreams (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, subsets, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, backend_tls_sni, backend_tls_san_allow_list, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&upstream.id)
        .bind(&upstream.namespace)
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(&subsets_json)
        .bind(&upstream.backend_tls_client_cert_path)
        .bind(&upstream.backend_tls_client_key_path)
        .bind(upstream.backend_tls_verify_server_cert as i32)
        .bind(&upstream.backend_tls_server_ca_cert_path)
        .bind(&upstream.backend_tls_sni)
        .bind(&backend_tls_san_allow_list_json)
        .bind(upstream.created_at.to_rfc3339())
        .bind(upstream.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        self.record_config_change_tx(
            &mut tx,
            &upstream.namespace,
            "upstream",
            &upstream.id,
            "upsert",
        )
        .await?;
        self.compact_config_changes_tx(&mut tx, &upstream.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("create_upstream", start);
        Ok(())
    }

    pub async fn update_upstream(&self, upstream: &Upstream) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let service_discovery_json = upstream
            .service_discovery
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let subsets_json = upstream
            .subsets
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(upstream)?;

        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &upstream.namespace)
            .await?;
        // Existence read inside the transaction is the not-found authority —
        // not the UPDATE's rows_affected. MySQL without CLIENT_FOUND_ROWS
        // (sqlx's default) counts *changed* rows, so an update writing
        // identical values would falsely report 0 for an existing row.
        // FOR UPDATE locks the row against a concurrent delete until commit.
        let exists_sql = if self.db_type == "sqlite" {
            self.q("SELECT id FROM upstreams WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT id FROM upstreams WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        let existing: Option<AnyRow> = sqlx::query(&exists_sql)
            .bind(&upstream.id)
            .bind(&upstream.namespace)
            .fetch_optional(&mut *tx)
            .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("update_upstream", start);
            return Ok(false);
        }
        sqlx::query(
            &self.q("UPDATE upstreams SET name=?, targets=?, algorithm=?, hash_on=?, hash_on_cookie_config=?, health_checks=?, service_discovery=?, subsets=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, backend_tls_sni=?, backend_tls_san_allow_list=?, updated_at=? WHERE id=? AND namespace=?")
        )
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(&subsets_json)
        .bind(&upstream.backend_tls_client_cert_path)
        .bind(&upstream.backend_tls_client_key_path)
        .bind(upstream.backend_tls_verify_server_cert as i32)
        .bind(&upstream.backend_tls_server_ca_cert_path)
        .bind(&upstream.backend_tls_sni)
        .bind(&backend_tls_san_allow_list_json)
        .bind(upstream.updated_at.to_rfc3339())
        .bind(&upstream.id)
        .bind(&upstream.namespace)
        .execute(&mut *tx)
        .await?;
        self.record_config_change_tx(
            &mut tx,
            &upstream.namespace,
            "upstream",
            &upstream.id,
            "upsert",
        )
        .await?;
        self.compact_config_changes_tx(&mut tx, &upstream.namespace)
            .await?;
        tx.commit().await?;

        self.check_slow_query("update_upstream", start);
        Ok(true)
    }

    async fn mesh_route_dispatch_plugin_configs_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM plugin_configs WHERE plugin_name = ? AND enabled = 1"),
        )
        .bind("mesh_route_dispatch")
        .fetch_all(&mut **tx)
        .await?;

        let mut plugins = Vec::with_capacity(rows.len());
        for row in &rows {
            plugins.push(row_to_plugin_config(row)?);
        }
        Ok(plugins)
    }

    async fn find_mesh_route_dispatch_upstream_ref_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error> {
        let plugins = self.mesh_route_dispatch_plugin_configs_tx(tx).await?;
        Ok(plugins.into_iter().find(|plugin| {
            plugin.namespace == namespace
                && mesh_route_dispatch_references_upstream_id(plugin, upstream_id)
        }))
    }

    /// Delete an upstream only if it is not referenced by any proxy.
    /// Returns `Err` if the upstream is still in use.
    /// Uses a transaction to prevent race conditions between the reference
    /// check and the delete.
    pub async fn delete_upstream(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        // Scope the existence check to the caller's namespace (issue #2122) so
        // a tenant cannot delete a same-id upstream in another namespace.
        let existing: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&mut *tx)
                .await?;
        if existing.is_none() {
            tx.rollback().await?;
            self.check_slow_query("delete_upstream", start);
            return Ok(false);
        }

        // Check reference within the transaction to prevent races
        let ref_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT id FROM proxies WHERE upstream_id = ? AND namespace = ? LIMIT 1"),
        )
        .bind(id)
        .bind(namespace)
        .fetch_all(&mut *tx)
        .await?;
        if !ref_rows.is_empty() {
            tx.rollback().await?;
            anyhow::bail!(
                "Upstream {} is referenced by one or more proxies and cannot be deleted",
                id
            );
        }
        if let Some(plugin) = self
            .find_mesh_route_dispatch_upstream_ref_tx(&mut tx, id, namespace)
            .await?
        {
            tx.rollback().await?;
            anyhow::bail!(
                "Upstream {} is referenced by mesh_route_dispatch plugin_config '{}' and cannot be deleted",
                id,
                plugin.id
            );
        }

        let result = sqlx::query(&self.q("DELETE FROM upstreams WHERE id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        self.record_config_change_tx(&mut tx, namespace, "upstream", id, "delete")
            .await?;
        self.compact_config_changes_tx(&mut tx, namespace).await?;

        tx.commit().await?;

        self.check_slow_query("delete_upstream", start);
        Ok(result.rows_affected() > 0)
    }

    /// When a proxy changes its upstream_id, clean up the old upstream if it
    /// became orphaned (no other proxies reference it).
    /// Uses a transaction to prevent race conditions between check and delete.
    pub async fn cleanup_orphaned_upstream(
        &self,
        namespace: &str,
        old_upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;

        self.cleanup_orphaned_upstream_tx(&mut tx, namespace, old_upstream_id)
            .await?;

        tx.commit().await?;

        self.check_slow_query("cleanup_orphaned_upstream", start);
        Ok(())
    }

    pub async fn get_upstream(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams WHERE id = ? AND namespace = ?"))
                .bind(id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;

        let result = match row {
            Some(r) => Ok(Some(row_to_upstream(&r)?)),
            None => Ok(None),
        };
        self.check_slow_query("get_upstream", start);
        result
    }

    /// Check if a proxy's (hosts, listen_path) combination is unique.
    ///
    /// See `DatabaseBackend::check_listen_path_unique` for the full conflict
    /// semantics. In short: `Some(path)` candidates are uniqueness-keyed by
    /// `(namespace, listen_path)` + host overlap; `None` (host-only) candidates
    /// are uniqueness-keyed by `(namespace, listen_path IS NULL)` + host
    /// overlap. `None + empty hosts` is rejected by the caller — returned
    /// `Ok(false)` defensively here.
    pub async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        // Defensive: None + empty hosts has no meaningful uniqueness scope.
        // validate_fields_inner rejects this at admission time; we still guard
        // so the DB layer never accepts a "match everything" proxy if a caller
        // slips past validation.
        if listen_path.is_none() && hosts.is_empty() {
            return Ok(false);
        }

        let start = Instant::now();
        let sql = self.listen_path_candidate_sql(listen_path, exclude_id);
        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(path) = listen_path {
            query = query.bind(path);
        }
        if let Some(eid) = exclude_id {
            query = query.bind(eid);
        }
        let rows: Vec<AnyRow> = query.fetch_all(&self.pool()).await?;

        self.check_slow_query("check_listen_path_unique", start);
        Ok(Self::listen_path_rows_are_unique(listen_path, hosts, &rows))
    }

    /// Check if a proxy name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q("SELECT id FROM proxies WHERE namespace = ? AND name = ? AND id != ?"),
            )
            .bind(namespace)
            .bind(name)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE namespace = ? AND name = ?"))
                .bind(namespace)
                .bind(name)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_proxy_name_unique", start);
        Ok(rows.is_empty())
    }

    /// Check if an upstream name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q("SELECT id FROM upstreams WHERE namespace = ? AND name = ? AND id != ?"),
            )
            .bind(namespace)
            .bind(name)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE namespace = ? AND name = ?"))
                .bind(namespace)
                .bind(name)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_upstream_name_unique", start);
        Ok(rows.is_empty())
    }

    /// Check that a consumer id/username/custom_id combination does not collide
    /// with another consumer's shared identity namespace.
    pub async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        consumer_id: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        let start = Instant::now();
        let mut candidates = vec![("id", consumer_id), ("username", username)];
        if let Some(custom_id) = custom_id {
            candidates.push(("custom_id", custom_id));
        }

        let placeholders = std::iter::repeat_n("?", candidates.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT id, username, custom_id FROM consumers \
             WHERE namespace = ? AND (id IN ({}) OR username IN ({}) OR custom_id IN ({}))",
            placeholders, placeholders, placeholders
        );
        let sql = if exclude_id.is_some() {
            format!("{} AND id != ?", sql)
        } else {
            sql
        };

        let sql = self.q(&sql);
        let mut query = sqlx::query(&sql).bind(namespace);
        for _ in 0..3 {
            for (_, value) in &candidates {
                query = query.bind(*value);
            }
        }
        if let Some(exclude_id) = exclude_id {
            query = query.bind(exclude_id);
        }

        let rows = query.fetch_all(&self.pool()).await?;
        for row in rows {
            let id: String = row.try_get("id")?;
            let existing_username: String = row.try_get("username")?;
            let existing_custom_id: Option<String> = row.try_get("custom_id").ok();

            let existing_fields = [
                ("id", Some(id.as_str())),
                ("username", Some(existing_username.as_str())),
                ("custom_id", existing_custom_id.as_deref()),
            ];
            for (candidate_field, candidate_value) in &candidates {
                for (existing_field, existing_value) in existing_fields {
                    if existing_value == Some(*candidate_value) {
                        return Ok(Some(format_consumer_identity_conflict(
                            candidate_field,
                            candidate_value,
                            existing_field,
                            &id,
                        )));
                    }
                }
            }
        }

        self.check_slow_query("check_consumer_identity_unique", start);
        Ok(None)
    }

    /// Check if a keyauth API key is unique across all consumers.
    /// Returns `true` if the key is unique (no conflicts found).
    ///
    pub async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        api_key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let credential_hash = credential_value_hash(api_key);
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT consumer_id FROM consumer_credential_index \
                 WHERE namespace = ? AND credential_type = ? AND credential_hash = ?"))
            .bind(namespace)
            .bind("keyauth")
            .bind(credential_hash)
            .fetch_optional(&self.pool())
            .await?;
        let is_unique = match row {
            Some(row) => {
                let consumer_id: String = row.try_get("consumer_id")?;
                exclude_consumer_id == Some(consumer_id.as_str())
            }
            None => true,
        };
        self.check_slow_query("check_keyauth_key_unique", start);
        Ok(is_unique)
    }

    /// Check that an mTLS identity is not already used by another consumer.
    pub async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        mtls_identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let canonical_identity = canonical_mtls_identity(mtls_identity);
        let credential_hash = credential_value_hash(canonical_identity);
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT consumer_id FROM consumer_credential_index \
                 WHERE namespace = ? AND credential_type = ? AND credential_hash = ?"))
            .bind(namespace)
            .bind("mtls_auth")
            .bind(credential_hash)
            .fetch_optional(&self.pool())
            .await?;
        if let Some(row) = row {
            let consumer_id: String = row.try_get("consumer_id")?;
            if exclude_consumer_id != Some(consumer_id.as_str()) {
                self.check_slow_query("check_mtls_identity_unique", start);
                return Ok(false);
            }
        }

        // Rows written before surrounding whitespace was normalized have a hash
        // that a trimmed probe cannot find. Fall back to the authoritative
        // Consumer rows before admitting a write. Matching remains exact here:
        // only san_dns plugin candidates apply ASCII case-folded uniqueness.
        // The path is admin-only and paginated; malformed stored credentials
        // fail closed as a database error.
        let is_unique = self
            .stored_mtls_identity_is_unique(namespace, canonical_identity, exclude_consumer_id)
            .await?;
        self.check_slow_query("check_mtls_identity_unique", start);
        Ok(is_unique)
    }

    async fn stored_mtls_identity_is_unique(
        &self,
        namespace: &str,
        canonical_identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let mut last_id: Option<String> = None;
        loop {
            let sql = if last_id.is_some() {
                "SELECT id, credentials FROM consumers WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?"
            } else {
                "SELECT id, credentials FROM consumers WHERE namespace = ? ORDER BY id LIMIT ?"
            };
            let query_sql = self.q(sql);
            let mut query = sqlx::query(&query_sql).bind(namespace);
            if let Some(last_id) = last_id.as_deref() {
                query = query.bind(last_id);
            }
            let rows: Vec<AnyRow> = query
                .bind(self.full_load_page_size)
                .fetch_all(&self.pool())
                .await?;
            let fetched = rows.len();
            for row in rows {
                let consumer_id: String = row.try_get("id")?;
                let credentials_json: String = row.try_get("credentials")?;
                let credentials: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&credentials_json).map_err(|error| {
                        anyhow::anyhow!(
                            "Consumer {}: failed to parse credentials JSON while checking mTLS uniqueness: {}",
                            consumer_id,
                            error
                        )
                    })?;
                let excluded = exclude_consumer_id == Some(consumer_id.as_str());
                if !excluded
                    && credentials.get("mtls_auth").is_some_and(|credential| {
                        Consumer::credential_entries_from_value(credential)
                            .iter()
                            .any(|entry| {
                                entry
                                    .get("identity")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some_and(|identity| identity.trim() == canonical_identity)
                            })
                    })
                {
                    return Ok(false);
                }
                last_id = Some(consumer_id);
            }
            if (fetched as i64) < self.full_load_page_size {
                return Ok(true);
            }
        }
    }

    /// Check if a listen_port is unique across all stream proxies.
    /// Returns `true` if the port is unique (no conflicts found).
    pub async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q(
                    "SELECT id FROM proxies WHERE namespace = ? AND listen_port = ? AND id != ?",
                ),
            )
            .bind(namespace)
            .bind(port as i32)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE namespace = ? AND listen_port = ?"))
                .bind(namespace)
                .bind(port as i32)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_listen_port_unique", start);
        Ok(rows.is_empty())
    }

    /// Check if an upstream with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace.
    ///
    /// The `namespace` filter is mandatory: cross-namespace references would
    /// pass admin validation but silently 502 at runtime because the proxy
    /// load path filters upstreams by namespace.
    pub async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE id = ? AND namespace = ?"))
                .bind(upstream_id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;
        self.check_slow_query("check_upstream_exists", start);
        Ok(row.is_some())
    }

    /// Validate that a proxy's plugin associations reference existing
    /// proxy-scoped plugin configs targeted at the same proxy, and that the
    /// resolved plugin names remain unique for that proxy.
    ///
    /// Plugin configs are resolved only within `namespace`. References to
    /// plugin_configs in a different namespace surface as
    /// `non-existent plugin_config '<id>'` errors so admin validation
    /// cannot admit cross-namespace pollution.
    pub async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
        associations: &[PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> {
        if associations.is_empty() {
            return Ok(Vec::new());
        }

        let mut requested_ids = Vec::with_capacity(associations.len());
        let mut seen_assoc_ids: HashSet<&str> = HashSet::new();
        let mut errors = Vec::new();

        for assoc in associations {
            if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                errors.push(format!(
                    "Proxy '{}' references plugin_config '{}' more than once",
                    proxy_id, assoc.plugin_config_id
                ));
            } else {
                requested_ids.push(assoc.plugin_config_id.clone());
            }
        }

        let plugin_refs = self
            .load_plugin_config_refs(
                &requested_ids,
                namespace,
                "validate_proxy_plugin_associations",
            )
            .await?;

        for assoc in associations {
            match plugin_refs.get(assoc.plugin_config_id.as_str()) {
                Some(plugin) => match plugin.scope {
                    PluginScope::Global => {
                        errors.push(format!(
                            "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped or proxy_group-scoped plugin configs",
                            proxy_id, plugin.id
                        ));
                        continue;
                    }
                    PluginScope::Proxy => {
                        if plugin.proxy_id.as_deref() != Some(proxy_id) {
                            errors.push(format!(
                                "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                proxy_id,
                                plugin.id,
                                plugin.proxy_id.as_deref().unwrap_or("<none>")
                            ));
                        }
                    }
                    PluginScope::ProxyGroup => {
                        if plugin.proxy_id.is_some() {
                            errors.push(format!(
                                "Proxy '{}' references proxy_group plugin_config '{}' with proxy_id '{}'",
                                proxy_id,
                                plugin.id,
                                plugin.proxy_id.as_deref().unwrap_or("<none>")
                            ));
                        }
                    }
                },
                None => errors.push(format!(
                    "Proxy '{}' references non-existent plugin_config '{}'",
                    proxy_id, assoc.plugin_config_id
                )),
            }
        }

        Ok(errors)
    }

    // ---- Incremental Polling ----

    pub async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        let row = sqlx::query(
            &self.q("SELECT COALESCE(MAX(sequence), 0) AS max_sequence FROM config_changes WHERE namespace = ?"),
        )
        .bind(namespace)
        .fetch_one(&self.pool())
        .await?;
        let max_sequence: i64 = row.try_get("max_sequence")?;
        Ok(max_sequence.max(0) as u64)
    }

    /// Load only resources referenced by durable change records after `after_sequence`.
    pub async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error> {
        let start = Instant::now();
        let poll_timestamp = Utc::now();
        self.ensure_change_cursor_available(namespace, after_sequence)
            .await?;
        let changes = self
            .load_config_changes_after(namespace, after_sequence)
            .await?;
        self.ensure_change_cursor_available(namespace, after_sequence)
            .await?;

        if changes.is_empty() {
            self.check_slow_query("load_incremental_config", start);
            return Ok(IncrementalResult {
                added_or_modified_proxies: Vec::new(),
                removed_proxy_ids: Vec::new(),
                added_or_modified_consumers: Vec::new(),
                removed_consumer_ids: Vec::new(),
                added_or_modified_plugin_configs: Vec::new(),
                removed_plugin_config_ids: Vec::new(),
                added_or_modified_upstreams: Vec::new(),
                removed_upstream_ids: Vec::new(),
                sequence_cursor: after_sequence,
                poll_timestamp,
            });
        }

        let sequence_cursor = changes
            .iter()
            .map(|change| change.sequence)
            .max()
            .unwrap_or(after_sequence);
        let mut proxy_ops = HashMap::new();
        let mut consumer_ops = HashMap::new();
        let mut plugin_config_ops = HashMap::new();
        let mut upstream_ops = HashMap::new();

        for change in changes {
            if change.operation != "upsert" && change.operation != "delete" {
                warn!(
                    "Ignoring config_changes row with unknown operation '{}' for {} {}",
                    change.operation, change.resource_type, change.resource_id
                );
                continue;
            }
            match change.resource_type.as_str() {
                "proxy" => {
                    proxy_ops.insert(change.resource_id, change.operation);
                }
                "consumer" => {
                    consumer_ops.insert(change.resource_id, change.operation);
                }
                "plugin_config" => {
                    plugin_config_ops.insert(change.resource_id, change.operation);
                }
                "upstream" => {
                    upstream_ops.insert(change.resource_id, change.operation);
                }
                other => {
                    warn!(
                        "Ignoring config_changes row with unknown resource_type '{}' for id {}",
                        other, change.resource_id
                    );
                }
            }
        }

        if !consumer_ops.is_empty() {
            return Err(anyhow::Error::new(
                crate::config::db_backend::IncrementalFullReloadRequired::for_consumer_changes(
                    namespace,
                ),
            ));
        }

        let (proxy_upserts, mut removed_proxy_ids) = Self::split_change_ops(proxy_ops);
        let (consumer_upserts, mut removed_consumer_ids) = Self::split_change_ops(consumer_ops);
        let (plugin_config_upserts, mut removed_plugin_config_ids) =
            Self::split_change_ops(plugin_config_ops);
        let (upstream_upserts, mut removed_upstream_ids) = Self::split_change_ops(upstream_ops);

        let mut added_or_modified_proxies =
            self.load_proxies_by_ids(namespace, &proxy_upserts).await?;
        let loaded_proxy_ids: HashSet<String> = added_or_modified_proxies
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect();
        removed_proxy_ids.extend(
            proxy_upserts
                .iter()
                .filter(|id| !loaded_proxy_ids.contains(*id))
                .cloned(),
        );

        let added_or_modified_consumers = self
            .load_consumers_by_ids(namespace, &consumer_upserts)
            .await?;
        let loaded_consumer_ids: HashSet<String> = added_or_modified_consumers
            .iter()
            .map(|consumer| consumer.id.clone())
            .collect();
        removed_consumer_ids.extend(
            consumer_upserts
                .iter()
                .filter(|id| !loaded_consumer_ids.contains(*id))
                .cloned(),
        );
        let removed_consumer_ids = removed_consumer_ids
            .into_iter()
            .map(|id| NamespacedResourceId::new(namespace, id))
            .collect();

        let mut added_or_modified_plugin_configs = self
            .load_plugin_configs_by_ids(namespace, &plugin_config_upserts)
            .await?;
        let loaded_plugin_config_ids: HashSet<String> = added_or_modified_plugin_configs
            .iter()
            .map(|config| config.id.clone())
            .collect();
        removed_plugin_config_ids.extend(
            plugin_config_upserts
                .iter()
                .filter(|id| !loaded_plugin_config_ids.contains(*id))
                .cloned(),
        );

        let mut added_or_modified_upstreams = self
            .load_upstreams_by_ids(namespace, &upstream_upserts)
            .await?;
        let loaded_upstream_ids: HashSet<String> = added_or_modified_upstreams
            .iter()
            .map(|upstream| upstream.id.clone())
            .collect();
        removed_upstream_ids.extend(
            upstream_upserts
                .iter()
                .filter(|id| !loaded_upstream_ids.contains(*id))
                .cloned(),
        );

        for p in &mut added_or_modified_proxies {
            p.api_spec_id = None;
        }
        for u in &mut added_or_modified_upstreams {
            u.api_spec_id = None;
        }
        for pc in &mut added_or_modified_plugin_configs {
            pc.api_spec_id = None;
        }

        let result = IncrementalResult {
            added_or_modified_proxies,
            removed_proxy_ids,
            added_or_modified_consumers,
            removed_consumer_ids,
            added_or_modified_plugin_configs,
            removed_plugin_config_ids,
            added_or_modified_upstreams,
            removed_upstream_ids,
            sequence_cursor,
            poll_timestamp,
        };

        if result.is_empty() {
            debug!(
                "Incremental poll: no resource changes after sequence {}",
                after_sequence
            );
        } else {
            info!(
                "Incremental poll through sequence {}: {} proxies, {} consumers, {} plugins, {} upstreams changed; {} proxies, {} consumers, {} plugins, {} upstreams removed",
                result.sequence_cursor,
                result.added_or_modified_proxies.len(),
                result.added_or_modified_consumers.len(),
                result.added_or_modified_plugin_configs.len(),
                result.added_or_modified_upstreams.len(),
                result.removed_proxy_ids.len(),
                result.removed_consumer_ids.len(),
                result.removed_plugin_config_ids.len(),
                result.removed_upstream_ids.len(),
            );
        }

        self.check_slow_query("load_incremental_config", start);
        Ok(result)
    }

    async fn ensure_change_cursor_available(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<(), anyhow::Error> {
        let row = sqlx::query(
            &self.q("SELECT retained_sequence FROM config_change_retention WHERE namespace = ?"),
        )
        .bind(namespace)
        .fetch_optional(&self.pool())
        .await?;
        if let Some(row) = row {
            let retained_sequence: i64 = row.try_get("retained_sequence")?;
            let retained_sequence = retained_sequence.max(0) as u64;
            if after_sequence < retained_sequence {
                anyhow::bail!(
                    "config change cursor {} for namespace '{}' is behind retained sequence {}",
                    after_sequence,
                    namespace,
                    retained_sequence
                );
            }
        }
        Ok(())
    }

    async fn load_config_changes_after(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<Vec<ConfigChangeRecord>, anyhow::Error> {
        if after_sequence > i64::MAX as u64 {
            anyhow::bail!("config change cursor exceeds SQL BIGINT range");
        }
        let rows = sqlx::query(
            &self.q("SELECT sequence, resource_type, resource_id, operation \
             FROM config_changes \
             WHERE namespace = ? AND sequence > ? \
             ORDER BY sequence ASC \
             LIMIT ?"),
        )
        .bind(namespace)
        .bind(after_sequence as i64)
        .bind(Self::CHANGE_LOG_BATCH_LIMIT)
        .fetch_all(&self.pool())
        .await?;

        if rows.len() >= Self::CHANGE_LOG_BATCH_LIMIT as usize {
            anyhow::bail!(
                "config change batch for namespace '{}' reached limit {}; forcing full reload",
                namespace,
                Self::CHANGE_LOG_BATCH_LIMIT
            );
        }

        let mut changes = Vec::with_capacity(rows.len());
        for row in rows {
            let sequence: i64 = row.try_get("sequence")?;
            changes.push(ConfigChangeRecord {
                sequence: sequence.max(0) as u64,
                resource_type: row.try_get("resource_type")?,
                resource_id: row.try_get("resource_id")?,
                operation: row.try_get("operation")?,
            });
        }
        Ok(changes)
    }

    fn split_change_ops(ops: HashMap<String, String>) -> (Vec<String>, Vec<String>) {
        let mut upserts = Vec::new();
        let mut deletes = Vec::new();
        for (id, op) in ops {
            if op == "delete" {
                deletes.push(id);
            } else {
                upserts.push(id);
            }
        }
        upserts.sort();
        deletes.sort();
        (upserts, deletes)
    }

    async fn load_proxies_by_ids(
        &self,
        namespace: &str,
        ids: &[String],
    ) -> Result<Vec<Proxy>, anyhow::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut rows = Vec::new();
        for chunk in ids.chunks(Self::ASSOCIATION_LOOKUP_CHUNK_SIZE) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = self.q(&format!(
                "SELECT * FROM proxies WHERE namespace = ? AND id IN ({})",
                placeholders
            ));
            let mut query = sqlx::query(&sql).bind(namespace);
            for id in chunk {
                query = query.bind(id);
            }
            rows.extend(query.fetch_all(&self.pool()).await?);
        }

        let changed_ids: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect();
        let mut plugins_by_proxy = self
            .load_proxy_plugin_associations_for_proxy_ids(
                &changed_ids,
                "load_incremental_config",
                true,
            )
            .await?;

        let mut proxies = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            proxies.push(row_to_proxy(row, id, plugins)?);
        }
        Self::ensure_no_unmatched_proxy_plugin_associations(
            "load_incremental_config",
            &plugins_by_proxy,
        )?;
        Ok(proxies)
    }

    async fn load_consumers_by_ids(
        &self,
        namespace: &str,
        ids: &[String],
    ) -> Result<Vec<Consumer>, anyhow::Error> {
        let rows = self
            .load_rows_by_ids("consumers", namespace, ids, "load_consumers_by_ids")
            .await?;
        rows.iter().map(row_to_consumer).collect()
    }

    async fn load_plugin_configs_by_ids(
        &self,
        namespace: &str,
        ids: &[String],
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows = self
            .load_rows_by_ids(
                "plugin_configs",
                namespace,
                ids,
                "load_plugin_configs_by_ids",
            )
            .await?;
        rows.iter().map(row_to_plugin_config).collect()
    }

    async fn load_upstreams_by_ids(
        &self,
        namespace: &str,
        ids: &[String],
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        let rows = self
            .load_rows_by_ids("upstreams", namespace, ids, "load_upstreams_by_ids")
            .await?;
        rows.iter().map(row_to_upstream).collect()
    }

    async fn load_rows_by_ids(
        &self,
        table: &'static str,
        namespace: &str,
        ids: &[String],
        operation: &'static str,
    ) -> Result<Vec<AnyRow>, anyhow::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let start = Instant::now();
        let mut rows = Vec::new();
        for chunk in ids.chunks(Self::ASSOCIATION_LOOKUP_CHUNK_SIZE) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = self.q(&format!(
                "SELECT * FROM {} WHERE namespace = ? AND id IN ({})",
                table, placeholders
            ));
            let mut query = sqlx::query(&sql).bind(namespace);
            for id in chunk {
                query = query.bind(id);
            }
            rows.extend(query.fetch_all(&self.pool()).await?);
        }
        self.check_slow_query(operation, start);
        Ok(rows)
    }

    async fn select_resource_ids_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        table: &'static str,
        namespace: &str,
        extra_predicate: Option<(&'static str, &str)>,
        lock_rows: bool,
    ) -> Result<Vec<String>, anyhow::Error> {
        let lock_clause = if lock_rows && self.db_type != "sqlite" {
            " FOR UPDATE"
        } else {
            ""
        };
        let sql = if let Some((column, _)) = extra_predicate {
            self.q(&format!(
                "SELECT id FROM {} WHERE namespace = ? AND {} = ?{}",
                table, column, lock_clause
            ))
        } else {
            self.q(&format!(
                "SELECT id FROM {} WHERE namespace = ?{}",
                table, lock_clause
            ))
        };
        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some((_, value)) = extra_predicate {
            query = query.bind(value);
        }
        let rows = query.fetch_all(&mut **tx).await?;
        rows.iter()
            .map(|row| row.try_get("id").map_err(anyhow::Error::from))
            .collect()
    }

    async fn use_delete_capture_snapshot_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<(), anyhow::Error> {
        // PostgreSQL defaults to READ COMMITTED, where a namespace-wide DELETE
        // can see rows committed after the pre-scan used for change logging.
        if self.db_type == "postgres" {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    async fn record_config_change_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        resource_type: &str,
        resource_id: &str,
        operation: &str,
    ) -> Result<(), anyhow::Error> {
        self.lock_config_change_sequence_tx(tx).await?;
        sqlx::query(&self.q("INSERT INTO config_changes \
             (namespace, resource_type, resource_id, operation, created_at) \
             VALUES (?, ?, ?, ?, ?)"))
        .bind(namespace)
        .bind(resource_type)
        .bind(resource_id)
        .bind(operation)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn compact_config_changes_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
    ) -> Result<(), anyhow::Error> {
        let row = sqlx::query(&self.q("SELECT COALESCE(MAX(sequence), 0) AS max_sequence \
             FROM config_changes WHERE namespace = ?"))
        .bind(namespace)
        .fetch_one(&mut **tx)
        .await?;
        let max_sequence: i64 = row.try_get("max_sequence")?;
        let max_sequence = max_sequence.max(0) as u64;
        if max_sequence <= Self::CHANGE_LOG_RETAIN_PER_NAMESPACE {
            return Ok(());
        }
        let cutoff = max_sequence - Self::CHANGE_LOG_RETAIN_PER_NAMESPACE;
        let retained_row = sqlx::query(
            &self.q("SELECT COALESCE(MAX(sequence), 0) AS retained_sequence \
                 FROM config_changes WHERE namespace = ? AND sequence <= ?"),
        )
        .bind(namespace)
        .bind(cutoff as i64)
        .fetch_one(&mut **tx)
        .await?;
        let retained_sequence: i64 = retained_row.try_get("retained_sequence")?;
        sqlx::query(&self.q("DELETE FROM config_changes WHERE namespace = ? AND sequence <= ?"))
            .bind(namespace)
            .bind(cutoff as i64)
            .execute(&mut **tx)
            .await?;
        if retained_sequence > 0 {
            let upsert_sql = self.config_change_retention_upsert_sql();
            sqlx::query(&upsert_sql)
                .bind(namespace)
                .bind(retained_sequence)
                .bind(Utc::now().to_rfc3339())
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    /// Load `(id, scope, proxy_id)` for each plugin_config ID **within
    /// `namespace`**. Rows whose namespace does not match are filtered out
    /// at the SQL layer, so callers using the result map to validate
    /// references will report rows in other namespaces as missing.
    async fn load_plugin_config_refs(
        &self,
        ids: &[String],
        namespace: &str,
        operation: &str,
    ) -> Result<PluginConfigRefs, anyhow::Error> {
        let pool = self.pool();
        self.load_plugin_config_refs_from_pool(ids, namespace, operation, &pool)
            .await
    }

    async fn load_plugin_config_refs_from_pool(
        &self,
        ids: &[String],
        namespace: &str,
        operation: &str,
        pool: &AnyPool,
    ) -> Result<PluginConfigRefs, anyhow::Error> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let mut plugin_refs = std::collections::HashMap::new();
        for chunk in ids.chunks(Self::ASSOCIATION_LOOKUP_CHUNK_SIZE) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = self.q(&format!(
                "SELECT id, scope, proxy_id FROM plugin_configs WHERE namespace = ? AND id IN ({})",
                placeholders
            ));

            let mut query = sqlx::query(&sql);
            query = query.bind(namespace);
            for id in chunk {
                query = query.bind(id);
            }

            let rows = query.fetch_all(pool).await.map_err(|e| {
                Self::proxy_plugin_reference_lookup_error(operation, namespace, None, e)
            })?;
            for row in rows {
                let id: String = row.try_get("id").map_err(|e| {
                    Self::proxy_plugin_reference_lookup_error(operation, namespace, Some("id"), e)
                })?;
                let scope_raw: String = row.try_get("scope").map_err(|e| {
                    Self::proxy_plugin_reference_lookup_error(
                        operation,
                        namespace,
                        Some("scope"),
                        e,
                    )
                })?;
                let scope = match scope_raw.as_str() {
                    "proxy" => PluginScope::Proxy,
                    "proxy_group" => PluginScope::ProxyGroup,
                    _ => PluginScope::Global,
                };
                let proxy_id = row
                    .try_get::<Option<String>, _>("proxy_id")
                    .map_err(|e| {
                        Self::proxy_plugin_reference_lookup_error(
                            operation,
                            namespace,
                            Some("proxy_id"),
                            e,
                        )
                    })?
                    .filter(|id| !id.trim().is_empty());
                plugin_refs.insert(
                    id.clone(),
                    PluginConfigRef {
                        id,
                        scope,
                        proxy_id,
                    },
                );
            }
        }

        Ok(plugin_refs)
    }

    /// Maximum records per database transaction for batch operations.
    /// Keeps transaction WAL/redo log size manageable and reduces lock hold time.
    const BATCH_CHUNK_SIZE: usize = 1000;
    const ASSOCIATION_LOOKUP_CHUNK_SIZE: usize = 500;
    const CONFIG_CHANGE_LOCK_NAME: &str = "global";
    const CHANGE_LOG_BATCH_LIMIT: i64 = 10_000;
    const CHANGE_LOG_RETAIN_PER_NAMESPACE: u64 = 100_000;

    /// Fallback page size used only when no runtime override has been set
    /// via `set_full_load_page_size()`. Matches the default for
    /// `FERRUM_DB_FULL_LOAD_PAGE_SIZE`.
    const DEFAULT_FULL_LOAD_PAGE_SIZE: i64 = 10_000;

    /// Batch-create multiple proxies, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    #[allow(dead_code)]
    pub async fn batch_create_proxies(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        self.batch_create_proxies_internal(proxies, true, mode)
            .await
    }

    pub async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        self.batch_create_proxies_internal(proxies, false, mode)
            .await
    }

    async fn batch_create_proxies_internal(
        &self,
        proxies: &[Proxy],
        attach_plugins: bool,
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if proxies.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in proxies.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self
                .batch_create_proxies_chunk(chunk, attach_plugins, mode)
                .await?;
        }
        self.check_slow_query("batch_create_proxies", start);
        Ok(total)
    }

    /// Insert a single chunk of proxies in one transaction.
    async fn batch_create_proxies_chunk(
        &self,
        proxies: &[Proxy],
        attach_plugins: bool,
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let mut admission_namespaces: Vec<&str> = proxies
            .iter()
            .map(|proxy| proxy.namespace.as_str())
            .collect();
        admission_namespaces.sort_unstable();
        admission_namespaces.dedup();
        for namespace in &admission_namespaces {
            self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
                .await?;
        }
        let mut touched_namespaces = HashSet::new();
        let insert_sql = self.q(Self::PROXY_INSERT_SQL);
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");

        for proxy in proxies {
            self.ensure_proxy_route_unique_tx(&mut tx, proxy, None)
                .await?;

            let circuit_breaker_json = proxy
                .circuit_breaker
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let retry_json = proxy
                .retry
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let response_body_mode_str = match proxy.response_body_mode {
                ResponseBodyMode::Buffer => "buffer",
                ResponseBodyMode::Stream => "stream",
            };
            let hosts_json = serde_json::to_string(&proxy.hosts)?;

            sqlx::query(&insert_sql)
                .bind(&proxy.id)
                .bind(&proxy.namespace)
                .bind(&proxy.name)
                .bind(&hosts_json)
                .bind(&proxy.listen_path)
                .bind(proxy.effective_scheme().to_scheme_str())
                .bind(&proxy.backend_host)
                .bind(proxy.backend_port as i32)
                .bind(&proxy.backend_path)
                .bind(if proxy.strip_listen_path { 1i32 } else { 0 })
                .bind(if proxy.preserve_host_header { 1i32 } else { 0 })
                .bind(proxy.backend_connect_timeout_ms as i64)
                .bind(proxy.backend_read_timeout_ms as i64)
                .bind(proxy.backend_write_timeout_ms as i64)
                .bind(&proxy.backend_tls_client_cert_path)
                .bind(&proxy.backend_tls_client_key_path)
                .bind(if proxy.backend_tls_verify_server_cert {
                    1i32
                } else {
                    0
                })
                .bind(&proxy.backend_tls_server_ca_cert_path)
                .bind(&proxy.dns_override)
                .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
                .bind(match proxy.auth_mode {
                    AuthMode::Multi => "multi",
                    _ => "single",
                })
                .bind(&proxy.upstream_id)
                .bind(&circuit_breaker_json)
                .bind(&retry_json)
                .bind(response_body_mode_str)
                .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .pool_enable_http_keep_alive
                        .map(|v| if v { 1i32 } else { 0 }),
                )
                .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
                .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .pool_http2_keep_alive_interval_seconds
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_keep_alive_timeout_seconds
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_initial_stream_window_size
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_initial_connection_window_size
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_adaptive_window
                        .map(|v| if v { 1i32 } else { 0 }),
                )
                .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
                .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
                .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
                .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
                .bind(proxy.listen_port.map(|v| v as i32))
                .bind(if proxy.frontend_tls { 1i32 } else { 0 })
                .bind(if proxy.passthrough { 1i32 } else { 0 })
                .bind(proxy.udp_idle_timeout_seconds as i64)
                .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
                .bind(proxy.websocket_idle_timeout_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .allowed_methods
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                )
                .bind(if proxy.allowed_ws_origins.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&proxy.allowed_ws_origins)?)
                })
                .bind(
                    proxy
                        .udp_max_response_amplification_factor
                        .map(|v| v as f64),
                )
                .bind(
                    proxy
                        .stream_proxy_protocol
                        .map(|v| if v { 1i32 } else { 0 }),
                )
                .bind(&proxy.upstream_subset)
                .bind(proxy.created_at.to_rfc3339())
                .bind(proxy.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;

            if attach_plugins {
                for assoc in &proxy.plugins {
                    sqlx::query(&assoc_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            self.record_config_change_tx(&mut tx, &proxy.namespace, "proxy", &proxy.id, "upsert")
                .await?;
            touched_namespaces.insert(proxy.namespace.clone());
        }

        if mode.validates_mtls_dns() {
            for namespace in &admission_namespaces {
                self.validate_namespace_admission_tx(&mut tx, namespace)
                    .await?;
            }
        }
        for namespace in &touched_namespaces {
            self.compact_config_changes_tx(&mut tx, namespace).await?;
        }
        let count = proxies.len();
        tx.commit().await?;
        Ok(count)
    }

    pub async fn batch_attach_proxy_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        if proxies.is_empty() {
            return Ok(());
        }

        let assoc_exists_sql = self
            .q("SELECT 1 FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ? LIMIT 1");
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");
        let touch_proxy_sql =
            self.q("UPDATE proxies SET updated_at = ? WHERE id = ? AND namespace = ?");
        for chunk in proxies.chunks(Self::BATCH_CHUNK_SIZE) {
            let mut tx = self.pool().begin().await?;
            let mut admission_namespaces: Vec<&str> =
                chunk.iter().map(|proxy| proxy.namespace.as_str()).collect();
            admission_namespaces.sort_unstable();
            admission_namespaces.dedup();
            for namespace in &admission_namespaces {
                self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
                    .await?;
            }
            let mut seen = HashSet::new();
            let mut touched_proxies: HashSet<(&str, &str)> = HashSet::new();
            let mut touched_namespaces = HashSet::new();
            for proxy in chunk {
                for assoc in &proxy.plugins {
                    if !seen.insert((proxy.id.as_str(), assoc.plugin_config_id.as_str())) {
                        continue;
                    }
                    let already_attached = sqlx::query(&assoc_exists_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .fetch_optional(&mut *tx)
                        .await?
                        .is_some();
                    if already_attached {
                        continue;
                    }
                    sqlx::query(&assoc_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .execute(&mut *tx)
                        .await?;
                    touched_proxies.insert((proxy.id.as_str(), proxy.namespace.as_str()));
                    touched_namespaces.insert(proxy.namespace.clone());
                }
            }
            if !touched_proxies.is_empty() {
                let touch_ts = Utc::now().to_rfc3339();
                for (proxy_id, namespace) in touched_proxies {
                    sqlx::query(&touch_proxy_sql)
                        .bind(&touch_ts)
                        .bind(proxy_id)
                        .bind(namespace)
                        .execute(&mut *tx)
                        .await?;
                    self.record_config_change_tx(&mut tx, namespace, "proxy", proxy_id, "upsert")
                        .await?;
                }
            }
            if mode.validates_mtls_dns() {
                for namespace in &admission_namespaces {
                    self.validate_namespace_admission_tx(&mut tx, namespace)
                        .await?;
                }
            }
            for namespace in &touched_namespaces {
                self.compact_config_changes_tx(&mut tx, namespace).await?;
            }
            tx.commit().await?;
        }

        self.check_slow_query("batch_attach_proxy_plugins", start);
        Ok(())
    }

    /// Batch-create multiple consumers, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    pub async fn batch_create_consumers(
        &self,
        consumers: &[Consumer],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if consumers.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in consumers.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_consumers_chunk(chunk, mode).await?;
        }
        self.check_slow_query("batch_create_consumers", start);
        Ok(total)
    }

    /// Insert a single chunk of consumers in one transaction.
    async fn batch_create_consumers_chunk(
        &self,
        consumers: &[Consumer],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let mut admission_namespaces: Vec<&str> = consumers
            .iter()
            .map(|consumer| consumer.namespace.as_str())
            .collect();
        admission_namespaces.sort_unstable();
        admission_namespaces.dedup();
        for namespace in &admission_namespaces {
            self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
                .await?;
        }
        let mut touched_namespaces = HashSet::new();
        let sql = self.q("INSERT INTO consumers (id, namespace, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

        for consumer in consumers {
            let creds_json = serde_json::to_string(&consumer.credentials)?;
            let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
            sqlx::query(&sql)
                .bind(&consumer.id)
                .bind(&consumer.namespace)
                .bind(&consumer.username)
                .bind(&consumer.custom_id)
                .bind(&creds_json)
                .bind(&acl_groups_json)
                .bind(consumer.created_at.to_rfc3339())
                .bind(consumer.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;
            self.insert_consumer_credential_index_tx(&mut tx, consumer)
                .await?;
            self.insert_consumer_identity_index_tx(&mut tx, consumer)
                .await?;
            self.record_config_change_tx(
                &mut tx,
                &consumer.namespace,
                "consumer",
                &consumer.id,
                "upsert",
            )
            .await?;
            touched_namespaces.insert(consumer.namespace.clone());
        }

        if mode.validates_mtls_dns() {
            for namespace in &admission_namespaces {
                self.validate_mtls_dns_admission_tx(&mut tx, namespace)
                    .await?;
            }
        }
        for namespace in &touched_namespaces {
            self.compact_config_changes_tx(&mut tx, namespace).await?;
        }
        let count = consumers.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Batch-create multiple plugin configs. Graph-aware batches stay in one
    /// transaction so a later insert failure cannot strand a referrer or its
    /// schema definition; unrelated large imports retain bounded chunks.
    pub async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if configs.is_empty() {
            return Ok(0);
        }
        let (graph_configs, unrelated_configs): (Vec<_>, Vec<_>) = configs
            .iter()
            .cloned()
            .partition(crate::plugins::transaction_log_schema::is_enabled_config_graph_participant);
        let mut total = 0usize;
        if !graph_configs.is_empty() {
            total += self
                .batch_create_plugin_configs_chunk(&graph_configs, mode)
                .await?;
        }
        for chunk in unrelated_configs.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_plugin_configs_chunk(chunk, mode).await?;
        }
        self.check_slow_query("batch_create_plugin_configs", start);
        Ok(total)
    }

    /// Insert a single chunk of plugin configs in one transaction.
    async fn batch_create_plugin_configs_chunk(
        &self,
        configs: &[PluginConfig],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let mut admission_namespaces: Vec<&str> = configs
            .iter()
            .map(|config| config.namespace.as_str())
            .collect();
        admission_namespaces.sort_unstable();
        admission_namespaces.dedup();
        for namespace in &admission_namespaces {
            self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
                .await?;
        }
        let mut touched_namespaces = HashSet::new();
        let sql = self.q("INSERT INTO plugin_configs (id, namespace, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");

        for pc in configs {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                PluginScope::Proxy => "proxy",
                PluginScope::ProxyGroup => "proxy_group",
                PluginScope::Global => "global",
            };
            sqlx::query(&sql)
                .bind(&pc.id)
                .bind(&pc.namespace)
                .bind(&pc.plugin_name)
                .bind(&config_json)
                .bind(scope_str)
                .bind(&pc.proxy_id)
                .bind(if pc.enabled { 1i32 } else { 0 })
                .bind(pc.priority_override.map(|v| v as i32))
                .bind(pc.created_at.to_rfc3339())
                .bind(pc.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;

            if pc.scope == PluginScope::Proxy
                && let Some(proxy_id) = pc.proxy_id.as_deref()
            {
                sqlx::query(&assoc_sql)
                    .bind(proxy_id)
                    .bind(&pc.id)
                    .execute(&mut *tx)
                    .await?;
                self.record_config_change_tx(&mut tx, &pc.namespace, "proxy", proxy_id, "upsert")
                    .await?;
            }
            self.record_config_change_tx(&mut tx, &pc.namespace, "plugin_config", &pc.id, "upsert")
                .await?;
            touched_namespaces.insert(pc.namespace.clone());
        }

        if mode.validates_mtls_dns() {
            for namespace in &admission_namespaces {
                self.validate_namespace_admission_tx(&mut tx, namespace)
                    .await?;
            }
        }
        for namespace in &touched_namespaces {
            self.compact_config_changes_tx(&mut tx, namespace).await?;
        }
        let count = configs.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Batch-create multiple upstreams, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    pub async fn batch_create_upstreams(
        &self,
        upstreams: &[Upstream],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if upstreams.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in upstreams.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_upstreams_chunk(chunk, mode).await?;
        }
        self.check_slow_query("batch_create_upstreams", start);
        Ok(total)
    }

    /// Insert a single chunk of upstreams in one transaction.
    async fn batch_create_upstreams_chunk(
        &self,
        upstreams: &[Upstream],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let mut admission_namespaces: Vec<&str> = upstreams
            .iter()
            .map(|upstream| upstream.namespace.as_str())
            .collect();
        admission_namespaces.sort_unstable();
        admission_namespaces.dedup();
        for namespace in &admission_namespaces {
            self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
                .await?;
        }
        let mut touched_namespaces = HashSet::new();
        let sql = self.q("INSERT INTO upstreams (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, subsets, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, backend_tls_sni, backend_tls_san_allow_list, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        for upstream in upstreams {
            let targets_json = serde_json::to_string(&upstream.targets)?;
            let algo_json = serde_json::to_string(&upstream.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let hash_on_cookie_config_json = upstream
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let health_checks_json = upstream
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = upstream
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let subsets_json = upstream
                .subsets
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json =
                upstream_backend_tls_san_allow_list_json(upstream)?;
            sqlx::query(&sql)
                .bind(&upstream.id)
                .bind(&upstream.namespace)
                .bind(&upstream.name)
                .bind(&targets_json)
                .bind(algo_str)
                .bind(&upstream.hash_on)
                .bind(&hash_on_cookie_config_json)
                .bind(&health_checks_json)
                .bind(&service_discovery_json)
                .bind(&subsets_json)
                .bind(&upstream.backend_tls_client_cert_path)
                .bind(&upstream.backend_tls_client_key_path)
                .bind(upstream.backend_tls_verify_server_cert as i32)
                .bind(&upstream.backend_tls_server_ca_cert_path)
                .bind(&upstream.backend_tls_sni)
                .bind(&backend_tls_san_allow_list_json)
                .bind(upstream.created_at.to_rfc3339())
                .bind(upstream.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;
            self.record_config_change_tx(
                &mut tx,
                &upstream.namespace,
                "upstream",
                &upstream.id,
                "upsert",
            )
            .await?;
            touched_namespaces.insert(upstream.namespace.clone());
        }

        for namespace in &touched_namespaces {
            self.compact_config_changes_tx(&mut tx, namespace).await?;
        }
        let count = upstreams.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Delete all resources from all tables in a single transaction.
    ///
    /// Deletion order respects foreign key constraints:
    /// 1. proxy_plugins (junction table)
    /// 2. plugin_configs (may reference proxies)
    /// 3. proxies (may reference upstreams)
    /// 4. consumer_credential_index
    /// 5. consumer_identity_index
    /// 6. consumers
    /// 7. upstreams
    pub async fn delete_all_resources(
        &self,
        namespace: &str,
        mode: &BatchConfigWriteMode,
    ) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_for_owner_tx(&mut tx, namespace, mode.guard_owner())
            .await?;
        self.use_delete_capture_snapshot_tx(&mut tx).await?;
        let proxy_ids = self
            .select_resource_ids_tx(&mut tx, "proxies", namespace, None, true)
            .await?;
        let plugin_config_ids = self
            .select_resource_ids_tx(&mut tx, "plugin_configs", namespace, None, true)
            .await?;
        let consumer_ids = self
            .select_resource_ids_tx(&mut tx, "consumers", namespace, None, true)
            .await?;
        let upstream_ids = self
            .select_resource_ids_tx(&mut tx, "upstreams", namespace, None, true)
            .await?;

        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id IN (SELECT id FROM proxies WHERE namespace = ?)"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        // Delete api_specs BEFORE proxies: the FK cascade (proxy_id → proxies ON
        // DELETE CASCADE) would handle it, but explicit deletion is clearer and
        // matches the Mongo path.  Also ensures cleanup even if FK enforcement is
        // disabled (e.g. SQLite PRAGMA foreign_keys=OFF in recovery scenarios).
        sqlx::query(&self.q("DELETE FROM api_specs WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM proxies WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM consumer_credential_index WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM consumer_identity_index WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM consumers WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM upstreams WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        if mode.validates_mtls_dns() {
            self.validate_mtls_dns_admission_tx(&mut tx, namespace)
                .await?;
        }
        for id in proxy_ids {
            self.record_config_change_tx(&mut tx, namespace, "proxy", &id, "delete")
                .await?;
        }
        for id in plugin_config_ids {
            self.record_config_change_tx(&mut tx, namespace, "plugin_config", &id, "delete")
                .await?;
        }
        for id in consumer_ids {
            self.record_config_change_tx(&mut tx, namespace, "consumer", &id, "delete")
                .await?;
        }
        for id in upstream_ids {
            self.record_config_change_tx(&mut tx, namespace, "upstream", &id, "delete")
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, namespace).await?;

        tx.commit().await?;
        self.check_slow_query("delete_all_resources", start);
        Ok(())
    }

    /// Get a snapshot of the current connection pool.
    ///
    /// Returns an owned clone (cheap — `AnyPool` is `Arc`-based internally).
    /// The returned handle remains valid even if `reconnect()` swaps the pool.
    pub fn pool(&self) -> AnyPool {
        (**self.pool.load()).clone()
    }

    #[allow(dead_code)]
    pub fn db_type_str(&self) -> &str {
        &self.db_type
    }

    /// Atomically replace the connection pool with a freshly connected one.
    ///
    /// Called by the DB polling loop when DnsCache detects that the database
    /// FQDN now resolves to a different set of IPs. The old pool is closed
    /// gracefully in the background — in-flight queries complete normally.
    pub async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
        self.reconnect_for_topology(db_url, DatabaseTopology::Primary)
            .await
    }

    async fn reconnect_for_topology(
        &self,
        db_url: &str,
        topology: DatabaseTopology,
    ) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        let new_pool = connect_any_pool_with_timeout(
            self.build_pool_options(),
            db_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        )
        .await?;

        // Disable and close the configured primary-topology replica before
        // exposing a failover pool. Keeping the dormant pool would make it
        // look immediately available on failback and skip the one reconnect
        // that refreshes its connections after the topology transition.
        if topology == DatabaseTopology::Failover {
            self.primary_topology_active.store(false, Ordering::Release);
            self.suppress_read_replica_pool();
        }

        // Atomic swap — readers that already loaded the old pool keep using it.
        let old_pool = self.pool.swap(Arc::new(new_pool));
        info!(
            "Database pool reconnected (db_type={}). Old pool closing in background.",
            self.db_type
        );

        // Close old pool gracefully in the background so in-flight queries
        // finish without blocking the polling loop.
        tokio::spawn(async move {
            old_pool.close().await;
        });

        // If this store was bootstrapped via `connect_offline_with_pool_config`
        // (backup-file startup with an unreachable DB), migrations never ran.
        // Now that the pool is reconnected to a live DB, run them before
        // returning so the polling loop finds tables at the expected schema.
        // The helper uses a CAS so concurrent callers don't run migrations
        // twice, and restores the flag on failure so a transient error
        // doesn't silently skip migrations forever.
        self.maybe_apply_deferred_migrations().await?;

        if topology == DatabaseTopology::Primary {
            self.primary_topology_active.store(true, Ordering::Release);
        }

        Ok(())
    }

    /// Extract the hostname from a database URL, if it contains one.
    ///
    /// Delegates to [`crate::config::db_backend::extract_db_hostname`].
    #[allow(dead_code)]
    pub fn extract_db_hostname(db_url: &str) -> Option<String> {
        crate::config::db_backend::extract_db_hostname(db_url)
    }

    /// Connect to the primary database, trying failover URLs if the primary fails.
    ///
    /// Tries the primary URL first. If it fails and failover URLs are provided,
    /// tries each in order. The first successful connection is used. Migrations
    /// are run on the connected database.
    pub async fn connect_with_failover(
        db_type: &str,
        primary_url: &str,
        failover_urls: &[String],
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        match Self::connect_with_pool_config(db_type, primary_url, pool_config.clone()).await {
            Ok(mut store) => {
                store.failover_urls = failover_urls.to_vec();
                Ok(store)
            }
            Err(primary_err) => {
                if !is_transient_failover_error(&primary_err) {
                    return Err(mark_non_transient(
                        primary_err,
                        "Primary database initialization failed with a non-transient query, schema, data, constraint, authentication, or configuration error; failover was not attempted",
                        &[primary_url],
                    ));
                }
                if failover_urls.is_empty() {
                    return Err(primary_err);
                }
                let safe_primary_error =
                    crate::config::db_backend::redact_error_text(&primary_err, &[primary_url]);
                warn!(
                    "Primary database connection failed: {}. Trying {} failover URL(s)...",
                    safe_primary_error,
                    failover_urls.len()
                );
                for (i, url) in failover_urls.iter().enumerate() {
                    match Self::connect_with_pool_config(db_type, url, pool_config.clone()).await {
                        Ok(mut store) => {
                            info!(
                                "Connected to failover database #{} ({})",
                                i + 1,
                                Self::redact_url(url)
                            );
                            store.failover_urls = failover_urls.to_vec();
                            store
                                .primary_topology_active
                                .store(false, Ordering::Release);
                            return Ok(store);
                        }
                        Err(e) => {
                            if !is_transient_failover_error(&e) {
                                return Err(mark_non_transient(
                                    e,
                                    format!(
                                        "Failover database #{} initialization returned a non-transient query, schema, data, constraint, authentication, or configuration error; no further failover URLs were attempted",
                                        i + 1
                                    ),
                                    &[url.as_str()],
                                ));
                            }
                            let safe_error =
                                crate::config::db_backend::redact_error_text(&e, &[url]);
                            warn!(
                                "Failover database #{} ({}) failed: {}",
                                i + 1,
                                Self::redact_url(url),
                                safe_error
                            );
                        }
                    }
                }
                Err(anyhow::anyhow!(
                    "All database URLs failed. Primary: {}. Tried {} failover URL(s).",
                    safe_primary_error,
                    failover_urls.len()
                ))
            }
        }
    }

    /// Connect a read replica pool for admin read offload.
    ///
    /// The read replica pool uses the same connection settings (max_connections,
    /// max_lifetime) as the primary. Migrations are NOT run on the replica.
    pub async fn connect_read_replica(&mut self, replica_url: &str) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();
        self.read_replica_url = Some(replica_url.to_string());

        if !self.primary_topology_active.load(Ordering::Acquire) {
            info!(
                "Read replica configured but connection deferred while the database is failed over"
            );
            return Ok(());
        }

        let pool = connect_any_pool_with_timeout(
            self.build_pool_options(),
            replica_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        )
        .await?;
        sqlx::query("SELECT 1").fetch_one(&pool).await?;

        self.read_replica_pool.store(Some(Arc::new(pool)));
        info!(
            "Read replica connected for admin reads (db_type={}, url={})",
            self.db_type,
            Self::redact_url(replica_url)
        );
        Ok(())
    }

    /// Get a snapshot of the read pool for admin-only list/read APIs.
    ///
    /// Runtime configuration polling is intentionally excluded from this path:
    /// authoritative startup loads, incremental changed-row queries, deletion
    /// scans, and association validation must read from the primary pool so
    /// replica lag cannot hide changes or advance cursors incorrectly.
    fn admin_read_pool(&self) -> AdminReadPool {
        if self.primary_topology_active.load(Ordering::Acquire)
            && self.read_replica_url.is_some()
            && let Some(replica) = self.read_replica_pool.load_full()
        {
            let pool = replica.as_ref().clone();
            if !pool.is_closed() {
                return AdminReadPool {
                    pool,
                    source: AdminReadSource::ReadReplica,
                };
            }
            self.mark_read_replica_unavailable("admin_read_pool", "replica pool is closed");
        }

        AdminReadPool {
            pool: self.pool(),
            source: AdminReadSource::Primary,
        }
    }

    /// Snapshot the admin read pool. This is intentionally admin-only; runtime
    /// polling must call [`Self::pool`] directly.
    fn rpool(&self) -> AnyPool {
        self.admin_read_pool().pool
    }

    fn mark_read_replica_unavailable(
        &self,
        operation: &'static str,
        error: impl std::fmt::Display,
    ) {
        let old_pool = self.read_replica_pool.swap(None);
        if old_pool.is_some() {
            warn!(
                operation,
                error = %error,
                "Read replica marked unavailable; admin reads will use primary until reconnect succeeds"
            );
        } else {
            warn!(
                operation,
                error = %error,
                "Read replica unavailable; admin reads are using primary"
            );
        }
        if let Some(pool) = old_pool {
            tokio::spawn(async move {
                pool.close().await;
            });
        }
    }

    /// Remove the primary-topology replica pool while failover is active.
    /// The configured URL remains recorded so the scheduler reconnects it
    /// once after primary failback makes the replica eligible again.
    fn suppress_read_replica_pool(&self) {
        let old_pool = self.read_replica_pool.swap(None);
        if let Some(pool) = old_pool {
            info!(
                "Read replica pool suppressed while the database is failed over; it will reconnect after primary failback"
            );
            tokio::spawn(async move {
                pool.close().await;
            });
        }
    }

    /// Atomically replace the read replica pool with a freshly connected one.
    ///
    /// Called by the DB polling loop when DnsCache detects that the read
    /// replica FQDN now resolves to a different set of IPs, by the TLS reload
    /// watcher, and after startup if the initial replica connection failed.
    pub async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        if !self.primary_topology_active.load(Ordering::Acquire) {
            debug!("Read replica reconnect deferred while the database is failed over");
            return Ok(());
        }

        info!(
            "Attempting read replica reconnect for admin reads (db_type={}, url={})",
            self.db_type,
            Self::redact_url(replica_url)
        );
        let new_pool = connect_any_pool_with_timeout(
            self.build_pool_options(),
            replica_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        )
        .await?;
        sqlx::query("SELECT 1").fetch_one(&new_pool).await?;

        // Failover may have started while the connection was opening. Do not
        // publish a replica pool that admin reads must suppress; closing it
        // leaves the post-failback scheduler responsible for one fresh retry.
        if !self.primary_topology_active.load(Ordering::Acquire) {
            new_pool.close().await;
            debug!(
                "Discarded read replica reconnect because the database failed over while it was opening"
            );
            return Ok(());
        }

        let old_pool = self.read_replica_pool.swap(Some(Arc::new(new_pool)));

        // Close the remaining race between the check above and publication:
        // if failover flipped the topology and ran its first suppression just
        // before this swap, remove the newly-published pool ourselves.
        if !self.primary_topology_active.load(Ordering::Acquire) {
            let raced_pool = self.read_replica_pool.swap(None);
            if let Some(pool) = raced_pool {
                tokio::spawn(async move {
                    pool.close().await;
                });
            }
            if let Some(pool) = old_pool {
                tokio::spawn(async move {
                    pool.close().await;
                });
            }
            debug!(
                "Discarded read replica reconnect because the database failed over while it was being published"
            );
            return Ok(());
        }

        info!(
            "Read replica restored for admin reads (db_type={}). Old pool closing in background.",
            self.db_type,
        );

        if let Some(old_pool) = old_pool {
            tokio::spawn(async move {
                old_pool.close().await;
            });
        }

        Ok(())
    }

    /// Try to reconnect to any available database URL (primary first, then failover).
    ///
    /// Called by the polling loop when the current connection is failing.
    /// Returns the URL that succeeded, or an error if all failed.
    pub async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> {
        // Try primary first
        match self
            .reconnect_for_topology(primary_url, DatabaseTopology::Primary)
            .await
        {
            Ok(()) => {
                info!("Reconnected to primary database");
                return Ok(primary_url.to_string());
            }
            Err(error) if !is_transient_failover_error(&error) => {
                return Err(mark_non_transient(
                    error,
                    "Primary database reconnect returned a non-transient query, schema, data, constraint, authentication, or configuration error; failover was not attempted",
                    &[primary_url],
                ));
            }
            Err(error) => {
                let safe_error =
                    crate::config::db_backend::redact_error_text(&error, &[primary_url]);
                warn!("Primary database reconnect failed transiently: {safe_error}");
            }
        }

        // Try failover URLs in order
        for (i, url) in self.failover_urls.iter().enumerate() {
            match self
                .reconnect_for_topology(url, DatabaseTopology::Failover)
                .await
            {
                Ok(()) => {
                    info!(
                        "Reconnected to failover database #{} ({})",
                        i + 1,
                        Self::redact_url(url)
                    );
                    return Ok(url.clone());
                }
                Err(error) if !is_transient_failover_error(&error) => {
                    return Err(mark_non_transient(
                        error,
                        format!(
                            "Failover database #{} reconnect returned a non-transient query, schema, data, constraint, authentication, or configuration error; no further failover URLs were attempted",
                            i + 1
                        ),
                        &[url.as_str()],
                    ));
                }
                Err(error) => {
                    let safe_error = crate::config::db_backend::redact_error_text(&error, &[url]);
                    warn!(
                        "Failover database #{} ({}) reconnect failed transiently: {}",
                        i + 1,
                        Self::redact_url(url),
                        safe_error
                    );
                }
            }
        }

        Err(anyhow::anyhow!(
            "All database URLs failed during reconnect ({} failover URL(s) tried)",
            self.failover_urls.len()
        ))
    }

    /// Redact credentials from a database URL for safe logging.
    ///
    /// Delegates to [`crate::config::db_backend::redact_url`].
    pub fn redact_url(url: &str) -> String {
        crate::config::db_backend::redact_url(url)
    }

    /// Classify a [`connect_with_failover`](Self::connect_with_failover) (or
    /// reconnect) error as permanent/non-transient.
    ///
    /// `database::run` uses this to decide backup eligibility: only transient
    /// connectivity/resource/connect-timeout failures may bootstrap from
    /// `FERRUM_DB_CONFIG_BACKUP_PATH`. A non-transient schema/auth/config/query
    /// error must fail startup instead of silently serving a stale on-disk
    /// backup.
    pub fn is_non_transient_init_error(error: &anyhow::Error) -> bool {
        error.downcast_ref::<NonTransientDbInitError>().is_some()
    }

    /// Classify an initial full-config load failure for backup eligibility.
    ///
    /// `database::run` applies the same [`is_non_transient_init_error`] gate to
    /// the initial load that it uses for connect failures: only transient
    /// connectivity/resource failures may bootstrap from
    /// `FERRUM_DB_CONFIG_BACKUP_PATH`. Schema drift, bad rows, decode, query,
    /// authentication, and validation errors are marked non-transient here so
    /// startup fails loudly instead of masking a broken database with stale
    /// on-disk config. Works for both SQL and MongoDB backends.
    ///
    /// [`is_non_transient_init_error`]: Self::is_non_transient_init_error
    pub fn classify_initial_config_load_error(error: anyhow::Error) -> anyhow::Error {
        if is_transient_config_load_error(&error) {
            error
        } else {
            mark_non_transient(
                error,
                "Initial database config load failed with a non-transient schema, data, query, decode, or validation error; refusing to bootstrap from FERRUM_DB_CONFIG_BACKUP_PATH",
                &[],
            )
        }
    }

    /// Returns true if a read replica URL is configured.
    #[allow(dead_code)] // Public API for tests and future consumers
    pub fn has_read_replica_pool(&self) -> bool {
        self.read_replica_url.is_some()
    }

    /// Return all distinct namespaces across all resource tables for admin reads.
    pub async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self.list_namespaces_from_admin_read(&admin_read.pool).await {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_namespaces", &error);
                warn!("Read replica admin query failed; retrying list_namespaces against primary");
                let primary_pool = self.pool();
                let retry = self.list_namespaces_from_admin_read(&primary_pool).await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_namespaces");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    /// Return all distinct namespaces from the authoritative primary pool.
    pub async fn list_namespaces_authoritative(&self) -> Result<Vec<String>, anyhow::Error> {
        let pool = self.pool();
        self.list_namespaces_from_pool(&pool).await
    }

    async fn list_namespaces_from_admin_read(
        &self,
        pool: &AnyPool,
    ) -> Result<Vec<String>, anyhow::Error> {
        self.list_namespaces_from_pool(pool).await
    }

    async fn list_namespaces_from_pool(
        &self,
        pool: &AnyPool,
    ) -> Result<Vec<String>, anyhow::Error> {
        let start = Instant::now();
        let sql = "SELECT DISTINCT namespace FROM proxies \
                   UNION SELECT DISTINCT namespace FROM consumers \
                   UNION SELECT DISTINCT namespace FROM plugin_configs \
                   UNION SELECT DISTINCT namespace FROM upstreams \
                   ORDER BY 1";
        let rows: Vec<AnyRow> = sqlx::query(sql).fetch_all(pool).await?;
        let mut namespaces = Vec::with_capacity(rows.len());
        for row in rows {
            if let Ok(ns) = row.try_get::<String, _>("namespace") {
                namespaces.push(ns);
            }
        }
        self.check_slow_query("list_namespaces", start);
        Ok(namespaces)
    }

    /// List distinct namespaces with database-level LIMIT/OFFSET pagination.
    pub async fn list_namespaces_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<String>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_namespaces_paginated_from_pool(limit, offset, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_namespaces_paginated", &error);
                warn!(
                    "Read replica admin query failed; retrying list_namespaces_paginated against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_namespaces_paginated_from_pool(limit, offset, &primary_pool)
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_namespaces_paginated");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_namespaces_paginated_from_pool(
        &self,
        limit: i64,
        offset: i64,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<String>, anyhow::Error> {
        let start = Instant::now();
        // The union subquery keeps one deterministic ordering for both the
        // count and the page so `total` and the returned slice cannot drift
        // apart across the four resource tables.
        let count_sql = "SELECT COUNT(*) AS cnt FROM (\
                         SELECT DISTINCT namespace FROM proxies \
                         UNION SELECT DISTINCT namespace FROM consumers \
                         UNION SELECT DISTINCT namespace FROM plugin_configs \
                         UNION SELECT DISTINCT namespace FROM upstreams\
                         ) AS ferrum_namespaces";
        let count_row = sqlx::query(count_sql).fetch_one(pool).await?;
        let total: i64 = count_row.try_get("cnt")?;

        let page_sql = "SELECT DISTINCT namespace FROM proxies \
                        UNION SELECT DISTINCT namespace FROM consumers \
                        UNION SELECT DISTINCT namespace FROM plugin_configs \
                        UNION SELECT DISTINCT namespace FROM upstreams \
                        ORDER BY 1 LIMIT ? OFFSET ?";
        let rows: Vec<AnyRow> = sqlx::query(&self.q(page_sql))
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        let mut namespaces = Vec::with_capacity(rows.len());
        for row in rows {
            if let Ok(ns) = row.try_get::<String, _>("namespace") {
                namespaces.push(ns);
            }
        }
        self.check_slow_query("list_namespaces_paginated", start);
        Ok(PaginatedResult {
            items: namespaces,
            total,
        })
    }

    // -----------------------------------------------------------------------
    // ApiSpec operations — admin-only, never called from the hot proxy path.
    //
    // IMPORTANT: Do NOT call these from db_loader polling loops, GatewayConfig
    // loading, or gRPC distribution paths. The api_specs table is pure admin
    // metadata; the gateway runtime never reads it.
    // -----------------------------------------------------------------------

    /// Atomically insert all bundle resources + the api_spec row.
    ///
    /// Insertion order (respects FK dependencies):
    ///   1. upstream (optional) — no FK on proxies
    ///   2. proxy — depends on upstream FK
    ///   3. plugin_configs — depend on proxy FK
    ///   4. api_specs — depends on proxy FK (ON DELETE CASCADE)
    ///
    /// Each resource is tagged with `api_spec_id = spec.id` so that a later
    /// `replace_api_spec_bundle` / `delete_api_spec` can identify spec-owned
    /// rows via `WHERE api_spec_id = ?`.
    pub async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        self.restore_api_spec_bundle_inner(bundle, spec, &[], &[], None, false)
            .await
    }

    pub async fn restore_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
        additional_upstreams: &[crate::config::types::Upstream],
        additional_plugins: &[crate::config::types::PluginConfig],
        validation_http_client: &crate::plugins::PluginHttpClient,
    ) -> Result<(), anyhow::Error> {
        self.restore_api_spec_bundle_inner(
            bundle,
            spec,
            additional_upstreams,
            additional_plugins,
            Some(validation_http_client),
            true,
        )
        .await
    }

    async fn restore_api_spec_bundle_inner(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
        additional_upstreams: &[crate::config::types::Upstream],
        additional_plugins: &[crate::config::types::PluginConfig],
        validation_http_client: Option<&crate::plugins::PluginHttpClient>,
        compensation_restore: bool,
    ) -> Result<(), anyhow::Error> {
        use crate::config::types::{AuthMode, ResponseBodyMode};

        crate::config::db_backend::validate_api_spec_restore_inputs(
            bundle,
            spec,
            additional_upstreams,
            additional_plugins,
            compensation_restore,
        )?;

        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &spec.namespace)
            .await?;

        // 1. INSERT upstream (if present), tagged with api_spec_id. Additional
        // hand-owned upstreams may still exist when another proxy or mesh
        // dispatch kept them live through the delete. Preserve those current
        // rows instead of turning compensation into a duplicate-key failure.
        let mut inserted_additional_upstream_ids = HashSet::new();
        for (u, api_spec_id, allow_existing) in bundle
            .upstream
            .iter()
            .map(|upstream| (upstream, Some(spec.id.as_str()), false))
            .chain(
                additional_upstreams
                    .iter()
                    .map(|upstream| (upstream, upstream.api_spec_id.as_deref(), true)),
            )
        {
            if allow_existing {
                let existing_sql = if self.db_type == "sqlite" {
                    self.q("SELECT * FROM upstreams WHERE id = ? AND namespace = ?")
                } else {
                    self.q("SELECT * FROM upstreams WHERE id = ? AND namespace = ? FOR UPDATE")
                };
                let existing: Option<AnyRow> = sqlx::query(&existing_sql)
                    .bind(&u.id)
                    .bind(&u.namespace)
                    .fetch_optional(&mut *tx)
                    .await?;
                if let Some(existing) = existing {
                    let existing = row_to_upstream(&existing)?;
                    crate::config::db_backend::validate_api_spec_retained_upstream_identity(
                        u, &existing,
                    )?;
                    continue;
                }
                inserted_additional_upstream_ids.insert(u.id.clone());
            }
            let targets_json = serde_json::to_string(&u.targets)?;
            let algo_json = serde_json::to_string(&u.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let health_checks_json = u
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = u
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let subsets_json = u.subsets.as_ref().map(serde_json::to_string).transpose()?;
            let hash_on_cookie_config_json = u
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(u)?;

            sqlx::query(&self.q("INSERT INTO upstreams \
                 (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, \
                  health_checks, service_discovery, subsets, backend_tls_client_cert_path, \
                  backend_tls_client_key_path, backend_tls_verify_server_cert, \
                  backend_tls_server_ca_cert_path, backend_tls_sni, \
                  backend_tls_san_allow_list, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&u.id)
            .bind(&u.namespace)
            .bind(&u.name)
            .bind(&targets_json)
            .bind(algo_str)
            .bind(&u.hash_on)
            .bind(&hash_on_cookie_config_json)
            .bind(&health_checks_json)
            .bind(&service_discovery_json)
            .bind(&subsets_json)
            .bind(&u.backend_tls_client_cert_path)
            .bind(&u.backend_tls_client_key_path)
            .bind(u.backend_tls_verify_server_cert as i32)
            .bind(&u.backend_tls_server_ca_cert_path)
            .bind(&u.backend_tls_sni)
            .bind(&backend_tls_san_allow_list_json)
            .bind(api_spec_id)
            .bind(u.created_at.to_rfc3339())
            .bind(u.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // 2. INSERT proxy, tagged with api_spec_id.
        //
        // This SQL differs from `Self::PROXY_INSERT_SQL` only by the addition of
        // the `api_spec_id` column before `created_at`.  When adding a new column
        // to `proxies`, update BOTH this query AND `Self::PROXY_INSERT_SQL` (and
        // the corresponding `.bind()` chains in `create_proxy`, `batch_create_proxies_chunk`,
        // and the `replace_api_spec_bundle` UPDATE path).
        {
            let p = &bundle.proxy;
            self.ensure_proxy_route_unique_tx(&mut tx, p, None).await?;
            let hosts_json = serde_json::to_string(&p.hosts)?;
            let circuit_breaker_json = p
                .circuit_breaker
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let retry_json = p.retry.as_ref().map(serde_json::to_string).transpose()?;
            let response_body_mode_str = match p.response_body_mode {
                ResponseBodyMode::Buffer => "buffer",
                ResponseBodyMode::Stream => "stream",
            };

            sqlx::query(&self.q("INSERT INTO proxies \
                 (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, \
                  backend_port, backend_path, strip_listen_path, preserve_host_header, \
                  backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, \
                  backend_tls_client_cert_path, backend_tls_client_key_path, \
                  backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, \
                  dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, upstream_subset, \
                  circuit_breaker, retry, response_body_mode, \
                  pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, \
                  pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, \
                  pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, \
                  pool_http2_initial_connection_window_size, pool_http2_adaptive_window, \
                  pool_http2_max_frame_size, pool_http2_max_concurrent_streams, \
                  pool_http3_connections_per_backend, pool_max_requests_per_connection, \
                  listen_port, frontend_tls, passthrough, \
                  udp_idle_timeout_seconds, tcp_idle_timeout_seconds, websocket_idle_timeout_seconds, \
                  allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, \
                  stream_proxy_protocol, \
                  api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                         ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&p.id)
            .bind(&p.namespace)
            .bind(&p.name)
            .bind(&hosts_json)
            .bind(&p.listen_path)
            .bind(p.effective_scheme().to_scheme_str())
            .bind(&p.backend_host)
            .bind(p.backend_port as i32)
            .bind(&p.backend_path)
            .bind(if p.strip_listen_path { 1i32 } else { 0 })
            .bind(if p.preserve_host_header { 1i32 } else { 0 })
            .bind(p.backend_connect_timeout_ms as i64)
            .bind(p.backend_read_timeout_ms as i64)
            .bind(p.backend_write_timeout_ms as i64)
            .bind(&p.backend_tls_client_cert_path)
            .bind(&p.backend_tls_client_key_path)
            .bind(if p.backend_tls_verify_server_cert {
                1i32
            } else {
                0
            })
            .bind(&p.backend_tls_server_ca_cert_path)
            .bind(&p.dns_override)
            .bind(p.dns_cache_ttl_seconds.map(|v| v as i64))
            .bind(match p.auth_mode {
                AuthMode::Multi => "multi",
                _ => "single",
            })
            .bind(&p.upstream_id)
            .bind(&p.upstream_subset)
            .bind(&circuit_breaker_json)
            .bind(&retry_json)
            .bind(response_body_mode_str)
            .bind(p.pool_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.pool_enable_http_keep_alive
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
            .bind(p.pool_tcp_keepalive_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
            .bind(p.pool_http2_initial_stream_window_size.map(|v| v as i64))
            .bind(
                p.pool_http2_initial_connection_window_size
                    .map(|v| v as i64),
            )
            .bind(
                p.pool_http2_adaptive_window
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_http2_max_frame_size.map(|v| v as i64))
            .bind(p.pool_http2_max_concurrent_streams.map(|v| v as i64))
            .bind(p.pool_http3_connections_per_backend.map(|v| v as i64))
            .bind(p.pool_max_requests_per_connection.map(|v| v as i64))
            .bind(p.listen_port.map(|v| v as i32))
            .bind(if p.frontend_tls { 1i32 } else { 0 })
            .bind(if p.passthrough { 1i32 } else { 0 })
            .bind(p.udp_idle_timeout_seconds as i64)
            .bind(p.tcp_idle_timeout_seconds.map(|v| v as i64))
            .bind(p.websocket_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.allowed_methods
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(if p.allowed_ws_origins.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&p.allowed_ws_origins)?)
            })
            .bind(p.udp_max_response_amplification_factor.map(|v| v as f64))
            .bind(p.stream_proxy_protocol.map(|v| if v { 1i32 } else { 0 }))
            .bind(&spec.id)
            .bind(p.created_at.to_rfc3339())
            .bind(p.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;

            // NOTE: proxy_plugins junction rows are inserted AFTER plugin_configs
            // below (step 3) to satisfy the FK: plugin_config_id REFERENCES
            // plugin_configs(id). Inserting them here would violate that FK because
            // the plugin_configs rows don't exist yet.
        }

        // 3. INSERT plugin_configs, tagged with api_spec_id.
        for (pc, api_spec_id) in bundle
            .plugins
            .iter()
            .map(|plugin| (plugin, Some(spec.id.as_str())))
            .chain(additional_plugins.iter().map(|plugin| (plugin, None)))
        {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                crate::config::types::PluginScope::Proxy => "proxy",
                crate::config::types::PluginScope::ProxyGroup => "proxy_group",
                crate::config::types::PluginScope::Global => "global",
            };
            sqlx::query(&self.q("INSERT INTO plugin_configs \
                 (id, namespace, plugin_name, config, scope, proxy_id, enabled, \
                  priority_override, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&pc.id)
            .bind(&pc.namespace)
            .bind(&pc.plugin_name)
            .bind(&config_json)
            .bind(scope_str)
            .bind(&pc.proxy_id)
            .bind(if pc.enabled { 1i32 } else { 0 })
            .bind(pc.priority_override.map(|v| v as i32))
            .bind(api_spec_id)
            .bind(pc.created_at.to_rfc3339())
            .bind(pc.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // 3b. INSERT proxy_plugins junction rows — AFTER plugin_configs so the
        //     plugin_config_id FK is satisfied.
        {
            let p = &bundle.proxy;
            for assoc in &p.plugins {
                sqlx::query(
                    &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
                )
                .bind(&p.id)
                .bind(&assoc.plugin_config_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // 4. INSERT api_specs row.
        self.insert_api_spec_tx(&mut tx, spec).await?;
        if compensation_restore {
            let validation_http_client = validation_http_client.ok_or_else(|| {
                anyhow::anyhow!(
                    "restore_api_spec_bundle requires the configured plugin validation client"
                )
            })?;
            self.validate_api_spec_restore_candidate_tx(
                &mut tx,
                &spec.namespace,
                &bundle.proxy.id,
                validation_http_client,
            )
            .await?;
        } else {
            // Preserve the normal submission contract: ordinary API-spec
            // writes run the same guarded admission checks as the other
            // resource writers, but must remain available to repair an
            // unrelated invalid-but-present plugin graph. Compensation is
            // stricter because it must prove that the graph being restored
            // cannot publish the recovered proxy with the wrong plugin
            // instance or association.
            self.validate_namespace_admission_tx(&mut tx, &spec.namespace)
                .await?;
        }
        for u in bundle.upstream.iter().chain(
            additional_upstreams
                .iter()
                .filter(|upstream| inserted_additional_upstream_ids.contains(&upstream.id)),
        ) {
            self.record_config_change_tx(&mut tx, &u.namespace, "upstream", &u.id, "upsert")
                .await?;
        }
        self.record_config_change_tx(
            &mut tx,
            &bundle.proxy.namespace,
            "proxy",
            &bundle.proxy.id,
            "upsert",
        )
        .await?;
        for pc in bundle.plugins.iter().chain(additional_plugins) {
            self.record_config_change_tx(&mut tx, &pc.namespace, "plugin_config", &pc.id, "upsert")
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, &spec.namespace)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Atomically replace a spec: delete spec-owned resources, re-insert from
    /// the new bundle, then update the api_specs row in place.
    pub async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        use crate::config::types::{AuthMode, ResponseBodyMode};

        // --- Resource no-op shortcut (Wave 5 Feature A) -----------------------
        // Compare the current spec-owned resource graph to the incoming bundle
        // inside the SAME transaction as any subsequent write. If they already
        // match, only the api_specs metadata row is updated; proxy/upstream/plugin
        // tables are left untouched. Because this reads the live resources, direct
        // admin CRUD drift forces the full replace path even when the submitted
        // spec's resource_hash matches the stored metadata.
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, &spec.namespace)
            .await?;

        let existing_spec: Option<crate::config::types::ApiSpec> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(&spec.namespace)
                .bind(&spec.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(|row| row_to_api_spec(&row))
                .transpose()?;
        let previous_declared_assoc_ids = existing_spec
            .as_ref()
            .map(crate::admin::api_specs::declared_proxy_plugin_association_ids_from_stored_spec)
            .unwrap_or_default();
        let desired_resource_hash = store_canonical_resource_hash(bundle)?;

        let current_resource_hash = if !spec.resource_hash.is_empty() {
            self.current_api_spec_resource_hash_tx(
                &mut tx,
                bundle,
                spec,
                &previous_declared_assoc_ids,
            )
            .await?
        } else {
            None
        };
        if !spec.resource_hash.is_empty()
            && current_resource_hash.as_deref() == Some(desired_resource_hash.as_str())
        {
            // Bundle is unchanged — only update the api_specs metadata row.
            let tags_json = serialize_api_spec_string_list(&spec.id, "tags", &spec.tags)?;
            let server_urls_json =
                serialize_api_spec_string_list(&spec.id, "server_urls", &spec.server_urls)?;
            let spec_format_str = match spec.spec_format {
                crate::config::types::SpecFormat::Json => "json",
                crate::config::types::SpecFormat::Yaml => "yaml",
            };
            sqlx::query(&self.q("UPDATE api_specs SET \
                 spec_content = ?, content_encoding = ?, content_hash = ?, \
                 uncompressed_size = ?, resource_hash = ?, \
                 spec_format = ?, spec_version = ?, title = ?, info_version = ?, \
                 description = ?, contact_name = ?, contact_email = ?, \
                 license_name = ?, license_identifier = ?, \
                 tags = ?, server_urls = ?, operation_count = ?, \
                 updated_at = ? \
                 WHERE namespace = ? AND id = ?"))
            .bind(&spec.spec_content)
            .bind(&spec.content_encoding)
            .bind(&spec.content_hash)
            .bind(spec.uncompressed_size as i64)
            .bind(&spec.resource_hash)
            .bind(spec_format_str)
            .bind(&spec.spec_version)
            .bind(&spec.title)
            .bind(&spec.info_version)
            .bind(&spec.description)
            .bind(&spec.contact_name)
            .bind(&spec.contact_email)
            .bind(&spec.license_name)
            .bind(&spec.license_identifier)
            .bind(&tags_json)
            .bind(&server_urls_json)
            .bind(spec.operation_count as i64)
            .bind(spec.updated_at.to_rfc3339())
            .bind(&spec.namespace)
            .bind(&spec.id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(());
        }
        // Resource graph mismatch — fall through to the full replace path. The
        // same `tx` wraps the rest of the operation; opening another `begin()`
        // would double-nest and is redundant.

        self.ensure_no_external_spec_upstream_refs_tx(
            &mut tx,
            &spec.namespace,
            &spec.id,
            &spec.proxy_id,
        )
        .await?;
        let deleted_plugin_config_ids = self
            .select_resource_ids_tx(
                &mut tx,
                "plugin_configs",
                &spec.namespace,
                Some(("api_spec_id", &spec.id)),
                false,
            )
            .await?;
        let deleted_upstream_ids = self
            .select_resource_ids_tx(
                &mut tx,
                "upstreams",
                &spec.namespace,
                Some(("api_spec_id", &spec.id)),
                false,
            )
            .await?;

        // Delete only spec-owned plugin_configs. Hand-added plugins (api_spec_id IS NULL)
        // are intentionally preserved. The proxy itself is updated in place (not deleted)
        // so FK cascades do not wipe hand-added plugins.
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE api_spec_id = ? AND namespace = ?"))
            .bind(&spec.id)
            .bind(&spec.namespace)
            .execute(&mut *tx)
            .await?;

        // Fix 3: proxies.upstream_id FK is ON DELETE RESTRICT (not SET NULL).
        // We must clear proxy.upstream_id BEFORE deleting the old upstream row,
        // otherwise the DELETE violates the FK and rolls back the transaction.
        sqlx::query(&self.q("UPDATE proxies SET upstream_id = NULL \
                 WHERE id = ? AND api_spec_id = ? AND namespace = ?"))
        .bind(&spec.proxy_id)
        .bind(&spec.id)
        .bind(&spec.namespace)
        .execute(&mut *tx)
        .await?;

        // Now safe to delete spec-owned upstreams — no proxy references them.
        sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
            .bind(&spec.id)
            .bind(&spec.namespace)
            .execute(&mut *tx)
            .await?;
        for id in &deleted_plugin_config_ids {
            self.record_config_change_tx(&mut tx, &spec.namespace, "plugin_config", id, "delete")
                .await?;
        }
        for id in &deleted_upstream_ids {
            self.record_config_change_tx(&mut tx, &spec.namespace, "upstream", id, "delete")
                .await?;
        }

        // Insert the new upstream (if present).
        if let Some(u) = &bundle.upstream {
            let targets_json = serde_json::to_string(&u.targets)?;
            let algo_json = serde_json::to_string(&u.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let health_checks_json = u
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = u
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let subsets_json = u.subsets.as_ref().map(serde_json::to_string).transpose()?;
            let hash_on_cookie_config_json = u
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(u)?;

            sqlx::query(&self.q("INSERT INTO upstreams \
                 (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, \
                  health_checks, service_discovery, subsets, backend_tls_client_cert_path, \
                  backend_tls_client_key_path, backend_tls_verify_server_cert, \
                  backend_tls_server_ca_cert_path, backend_tls_sni, \
                  backend_tls_san_allow_list, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&u.id)
            .bind(&u.namespace)
            .bind(&u.name)
            .bind(&targets_json)
            .bind(algo_str)
            .bind(&u.hash_on)
            .bind(&hash_on_cookie_config_json)
            .bind(&health_checks_json)
            .bind(&service_discovery_json)
            .bind(&subsets_json)
            .bind(&u.backend_tls_client_cert_path)
            .bind(&u.backend_tls_client_key_path)
            .bind(u.backend_tls_verify_server_cert as i32)
            .bind(&u.backend_tls_server_ca_cert_path)
            .bind(&u.backend_tls_sni)
            .bind(&backend_tls_san_allow_list_json)
            .bind(&spec.id)
            .bind(u.created_at.to_rfc3339())
            .bind(u.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // UPDATE proxy in place (preserves the primary key and created_at, so
        // hand-added plugins whose proxy_id FK points at this row are unaffected).
        {
            let p = &bundle.proxy;
            self.ensure_proxy_route_unique_tx(&mut tx, p, Some(&p.id))
                .await?;
            let hosts_json = serde_json::to_string(&p.hosts)?;
            let circuit_breaker_json = p
                .circuit_breaker
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let retry_json = p.retry.as_ref().map(serde_json::to_string).transpose()?;
            let response_body_mode_str = match p.response_body_mode {
                ResponseBodyMode::Buffer => "buffer",
                ResponseBodyMode::Stream => "stream",
            };

            sqlx::query(&self.q("UPDATE proxies SET \
                 namespace = ?, name = ?, hosts = ?, listen_path = ?, backend_scheme = ?, \
                 backend_host = ?, backend_port = ?, backend_path = ?, \
                 strip_listen_path = ?, preserve_host_header = ?, \
                 backend_connect_timeout_ms = ?, backend_read_timeout_ms = ?, \
                 backend_write_timeout_ms = ?, \
                 backend_tls_client_cert_path = ?, backend_tls_client_key_path = ?, \
                 backend_tls_verify_server_cert = ?, backend_tls_server_ca_cert_path = ?, \
                 dns_override = ?, dns_cache_ttl_seconds = ?, auth_mode = ?, upstream_id = ?, \
                 upstream_subset = ?, \
                 circuit_breaker = ?, retry = ?, response_body_mode = ?, \
                 pool_idle_timeout_seconds = ?, pool_enable_http_keep_alive = ?, \
                 pool_enable_http2 = ?, pool_tcp_keepalive_seconds = ?, \
                 pool_http2_keep_alive_interval_seconds = ?, \
                 pool_http2_keep_alive_timeout_seconds = ?, \
                 pool_http2_initial_stream_window_size = ?, \
                 pool_http2_initial_connection_window_size = ?, \
                 pool_http2_adaptive_window = ?, pool_http2_max_frame_size = ?, \
                 pool_http2_max_concurrent_streams = ?, \
                 pool_http3_connections_per_backend = ?, \
                 pool_max_requests_per_connection = ?, \
                 listen_port = ?, frontend_tls = ?, passthrough = ?, \
                 udp_idle_timeout_seconds = ?, tcp_idle_timeout_seconds = ?, \
                 websocket_idle_timeout_seconds = ?, \
                 allowed_methods = ?, allowed_ws_origins = ?, \
                 udp_max_response_amplification_factor = ?, \
                 stream_proxy_protocol = ?, \
                 api_spec_id = ?, updated_at = ? \
                 WHERE id = ? AND namespace = ?"))
            .bind(&p.namespace)
            .bind(&p.name)
            .bind(&hosts_json)
            .bind(&p.listen_path)
            .bind(p.effective_scheme().to_scheme_str())
            .bind(&p.backend_host)
            .bind(p.backend_port as i32)
            .bind(&p.backend_path)
            .bind(if p.strip_listen_path { 1i32 } else { 0 })
            .bind(if p.preserve_host_header { 1i32 } else { 0 })
            .bind(p.backend_connect_timeout_ms as i64)
            .bind(p.backend_read_timeout_ms as i64)
            .bind(p.backend_write_timeout_ms as i64)
            .bind(&p.backend_tls_client_cert_path)
            .bind(&p.backend_tls_client_key_path)
            .bind(if p.backend_tls_verify_server_cert {
                1i32
            } else {
                0
            })
            .bind(&p.backend_tls_server_ca_cert_path)
            .bind(&p.dns_override)
            .bind(p.dns_cache_ttl_seconds.map(|v| v as i64))
            .bind(match p.auth_mode {
                AuthMode::Multi => "multi",
                _ => "single",
            })
            .bind(&p.upstream_id)
            .bind(&p.upstream_subset)
            .bind(&circuit_breaker_json)
            .bind(&retry_json)
            .bind(response_body_mode_str)
            .bind(p.pool_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.pool_enable_http_keep_alive
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
            .bind(p.pool_tcp_keepalive_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
            .bind(p.pool_http2_initial_stream_window_size.map(|v| v as i64))
            .bind(
                p.pool_http2_initial_connection_window_size
                    .map(|v| v as i64),
            )
            .bind(
                p.pool_http2_adaptive_window
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_http2_max_frame_size.map(|v| v as i64))
            .bind(p.pool_http2_max_concurrent_streams.map(|v| v as i64))
            .bind(p.pool_http3_connections_per_backend.map(|v| v as i64))
            .bind(p.pool_max_requests_per_connection.map(|v| v as i64))
            .bind(p.listen_port.map(|v| v as i32))
            .bind(if p.frontend_tls { 1i32 } else { 0 })
            .bind(if p.passthrough { 1i32 } else { 0 })
            .bind(p.udp_idle_timeout_seconds as i64)
            .bind(p.tcp_idle_timeout_seconds.map(|v| v as i64))
            .bind(p.websocket_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.allowed_methods
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(if p.allowed_ws_origins.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&p.allowed_ws_origins)?)
            })
            .bind(p.udp_max_response_amplification_factor.map(|v| v as f64))
            .bind(p.stream_proxy_protocol.map(|v| if v { 1i32 } else { 0 }))
            .bind(&spec.id)
            .bind(p.updated_at.to_rfc3339())
            // WHERE clause — match by primary key
            .bind(&p.id)
            .bind(&p.namespace)
            .execute(&mut *tx)
            .await?;
        }

        // Insert new spec-owned plugin_configs.
        for pc in &bundle.plugins {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                crate::config::types::PluginScope::Proxy => "proxy",
                crate::config::types::PluginScope::ProxyGroup => "proxy_group",
                crate::config::types::PluginScope::Global => "global",
            };
            sqlx::query(&self.q("INSERT INTO plugin_configs \
                 (id, namespace, plugin_name, config, scope, proxy_id, enabled, \
                  priority_override, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&pc.id)
            .bind(&pc.namespace)
            .bind(&pc.plugin_name)
            .bind(&config_json)
            .bind(scope_str)
            .bind(&pc.proxy_id)
            .bind(if pc.enabled { 1i32 } else { 0 })
            .bind(pc.priority_override.map(|v| v as i32))
            .bind(&spec.id)
            .bind(pc.created_at.to_rfc3339())
            .bind(pc.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // Rebuild the proxy_plugins junction table for this proxy. Associations
        // declared in the previous spec are removed when absent from the new
        // document; truly hand-added associations remain untouched.
        let desired_assoc_ids: HashSet<String> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.clone())
            .collect();
        for previous_id in &previous_declared_assoc_ids {
            if !desired_assoc_ids.contains(previous_id) {
                sqlx::query(
                    &self
                        .q("DELETE FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?"),
                )
                .bind(&bundle.proxy.id)
                .bind(previous_id)
                .execute(&mut *tx)
                .await?;
            }
        }
        for assoc in &bundle.proxy.plugins {
            sqlx::query(
                &self.q("DELETE FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?"),
            )
            .bind(&bundle.proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }
        // Re-insert — plugin_configs rows now exist (inserted above), so FK is satisfied.
        for assoc in &bundle.proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&bundle.proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }
        self.cleanup_orphaned_proxy_group_plugins(&mut tx, &spec.namespace)
            .await?;

        // Update the api_specs row (no CASCADE delete needed since proxy survives).
        let tags_json = serialize_api_spec_string_list(&spec.id, "tags", &spec.tags)?;
        let server_urls_json =
            serialize_api_spec_string_list(&spec.id, "server_urls", &spec.server_urls)?;
        let spec_format_str = match spec.spec_format {
            crate::config::types::SpecFormat::Json => "json",
            crate::config::types::SpecFormat::Yaml => "yaml",
        };
        sqlx::query(&self.q("UPDATE api_specs SET \
             proxy_id = ?, spec_content = ?, content_encoding = ?, content_hash = ?, \
             uncompressed_size = ?, \
             spec_format = ?, spec_version = ?, title = ?, info_version = ?, \
             description = ?, contact_name = ?, contact_email = ?, \
             license_name = ?, license_identifier = ?, \
             tags = ?, server_urls = ?, operation_count = ?, resource_hash = ?, \
             updated_at = ? \
             WHERE namespace = ? AND id = ?"))
        .bind(&spec.proxy_id)
        .bind(&spec.spec_content)
        .bind(&spec.content_encoding)
        .bind(&spec.content_hash)
        .bind(spec.uncompressed_size as i64)
        .bind(spec_format_str)
        .bind(&spec.spec_version)
        .bind(&spec.title)
        .bind(&spec.info_version)
        .bind(&spec.description)
        .bind(&spec.contact_name)
        .bind(&spec.contact_email)
        .bind(&spec.license_name)
        .bind(&spec.license_identifier)
        .bind(&tags_json)
        .bind(&server_urls_json)
        .bind(spec.operation_count as i64)
        .bind(&spec.resource_hash)
        .bind(spec.updated_at.to_rfc3339())
        .bind(&spec.namespace)
        .bind(&spec.id)
        .execute(&mut *tx)
        .await?;
        self.validate_namespace_admission_tx(&mut tx, &spec.namespace)
            .await?;
        self.record_config_change_tx(
            &mut tx,
            &bundle.proxy.namespace,
            "proxy",
            &bundle.proxy.id,
            "upsert",
        )
        .await?;
        if let Some(u) = &bundle.upstream {
            self.record_config_change_tx(&mut tx, &u.namespace, "upstream", &u.id, "upsert")
                .await?;
        }
        for pc in &bundle.plugins {
            self.record_config_change_tx(&mut tx, &pc.namespace, "plugin_config", &pc.id, "upsert")
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, &spec.namespace)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn current_api_spec_resource_hash_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
        previous_declared_assoc_ids: &HashSet<String>,
    ) -> Result<Option<String>, anyhow::Error> {
        let plugin_rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM plugin_configs ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(&spec.namespace)
        .bind(&spec.id)
        .fetch_all(&mut **tx)
        .await?;
        let mut plugins = Vec::with_capacity(plugin_rows.len());
        for row in &plugin_rows {
            let mut plugin = row_to_plugin_config(row)?;
            plugin.normalize_fields();
            plugins.push(plugin);
        }

        let spec_owned_plugin_ids: HashSet<String> =
            plugins.iter().map(|pc| pc.id.clone()).collect();
        let desired_assoc_ids: HashSet<String> = bundle
            .proxy
            .plugins
            .iter()
            .map(|assoc| assoc.plugin_config_id.clone())
            .collect();
        let mut relevant_assoc_ids = spec_owned_plugin_ids.clone();
        relevant_assoc_ids.extend(previous_declared_assoc_ids.iter().cloned());
        relevant_assoc_ids.extend(desired_assoc_ids.iter().cloned());

        let assoc_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT plugin_config_id FROM proxy_plugins WHERE proxy_id = ?"))
                .bind(&spec.proxy_id)
                .fetch_all(&mut **tx)
                .await?;
        let mut current_relevant_assoc_ids = HashSet::new();
        for row in &assoc_rows {
            if let Ok(id) = row.try_get::<String, _>("plugin_config_id")
                && relevant_assoc_ids.contains(&id)
            {
                current_relevant_assoc_ids.insert(id);
            }
        }
        if current_relevant_assoc_ids != desired_assoc_ids {
            return Ok(None);
        }

        let proxy_row: Option<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM proxies WHERE id = ? AND namespace = ? AND api_spec_id = ?"),
        )
        .bind(&spec.proxy_id)
        .bind(&spec.namespace)
        .bind(&spec.id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(proxy_row) = proxy_row else {
            return Ok(None);
        };
        let desired_assocs: Vec<PluginAssociation> = bundle
            .proxy
            .plugins
            .iter()
            .filter(|assoc| current_relevant_assoc_ids.contains(&assoc.plugin_config_id))
            .cloned()
            .collect();
        let mut proxy = row_to_proxy(&proxy_row, spec.proxy_id.clone(), desired_assocs)?;
        proxy.normalize_fields();

        let upstream_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams WHERE namespace = ? AND api_spec_id = ?"))
                .bind(&spec.namespace)
                .bind(&spec.id)
                .fetch_all(&mut **tx)
                .await?;
        if upstream_rows.len() > 1 {
            return Ok(None);
        }
        let upstream =
            upstream_rows
                .first()
                .map(row_to_upstream)
                .transpose()?
                .map(|mut upstream| {
                    upstream.normalize_fields();
                    upstream
                });

        let current = crate::admin::api_specs::ExtractedBundle {
            proxy,
            upstream,
            plugins,
        };
        crate::admin::api_specs::hash_resource_bundle(&current).map(Some)
    }

    async fn ensure_no_external_spec_upstream_refs_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        spec_id: &str,
        spec_proxy_id: &str,
    ) -> Result<(), anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT p.id AS proxy_id, p.upstream_id AS upstream_id ",
            "FROM proxies p ",
            "INNER JOIN upstreams u ON p.upstream_id = u.id ",
            "WHERE u.namespace = ? AND u.api_spec_id = ? AND p.id <> ? ",
            "LIMIT 1"
        )))
        .bind(namespace)
        .bind(spec_id)
        .bind(spec_proxy_id)
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = row {
            let proxy_id = row
                .try_get::<String, _>("proxy_id")
                .unwrap_or_else(|_| "<unknown>".to_string());
            let upstream_id = row
                .try_get::<String, _>("upstream_id")
                .unwrap_or_else(|_| "<unknown>".to_string());
            anyhow::bail!(
                "proxy '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                 detach it before replacing or deleting the API spec",
                proxy_id,
                upstream_id,
                spec_id
            );
        }

        let upstream_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT id FROM upstreams WHERE namespace = ? AND api_spec_id = ?"),
        )
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&mut **tx)
        .await?;
        let spec_upstream_ids: HashSet<String> = upstream_rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect();
        if spec_upstream_ids.is_empty() {
            return Ok(());
        }

        let plugin_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM plugin_configs WHERE plugin_name = ? AND enabled = 1"),
        )
        .bind("mesh_route_dispatch")
        .fetch_all(&mut **tx)
        .await?;
        for row in &plugin_rows {
            let plugin = row_to_plugin_config(row)?;
            if plugin.api_spec_id.as_deref() == Some(spec_id) {
                continue;
            }
            if let Some(upstream_id) =
                mesh_route_dispatch_referenced_upstream(&plugin, &spec_upstream_ids)
            {
                anyhow::bail!(
                    "mesh_route_dispatch plugin_config '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                     detach it before replacing or deleting the API spec",
                    plugin.id,
                    upstream_id,
                    spec_id
                );
            }
        }

        Ok(())
    }

    /// Insert the api_specs row inside an existing transaction.
    async fn insert_api_spec_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        let spec_format_str = match spec.spec_format {
            crate::config::types::SpecFormat::Json => "json",
            crate::config::types::SpecFormat::Yaml => "yaml",
        };
        let tags_json = serialize_api_spec_string_list(&spec.id, "tags", &spec.tags)?;
        let server_urls_json =
            serialize_api_spec_string_list(&spec.id, "server_urls", &spec.server_urls)?;
        sqlx::query(&self.q("INSERT INTO api_specs \
             (id, namespace, proxy_id, spec_version, spec_format, spec_content, \
              content_encoding, uncompressed_size, content_hash, title, info_version, \
              description, contact_name, contact_email, license_name, license_identifier, \
              tags, server_urls, operation_count, resource_hash, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
        .bind(&spec.id)
        .bind(&spec.namespace)
        .bind(&spec.proxy_id)
        .bind(&spec.spec_version)
        .bind(spec_format_str)
        .bind(&spec.spec_content)
        .bind(&spec.content_encoding)
        .bind(spec.uncompressed_size as i64)
        .bind(&spec.content_hash)
        .bind(&spec.title)
        .bind(&spec.info_version)
        .bind(&spec.description)
        .bind(&spec.contact_name)
        .bind(&spec.contact_email)
        .bind(&spec.license_name)
        .bind(&spec.license_identifier)
        .bind(&tags_json)
        .bind(&server_urls_json)
        .bind(spec.operation_count as i64)
        .bind(&spec.resource_hash)
        .bind(spec.created_at.to_rfc3339())
        .bind(spec.updated_at.to_rfc3339())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Fetch a single ApiSpec by namespace + id.
    pub async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(namespace)
                .bind(id)
                .fetch_optional(&self.pool())
                .await?;
        match row {
            Some(r) => Ok(Some(row_to_api_spec(&r)?)),
            None => Ok(None),
        }
    }

    /// Fetch the ApiSpec that owns a given proxy_id.
    pub async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND proxy_id = ?"))
                .bind(namespace)
                .bind(proxy_id)
                .fetch_optional(&self.pool())
                .await?;
        match row {
            Some(r) => Ok(Some(row_to_api_spec(&r)?)),
            None => Ok(None),
        }
    }

    /// List ApiSpecs in a namespace with optional filtering, sorting, and pagination.
    ///
    /// Returns a [`PaginatedResult`] that includes the filtered `total` row count
    /// (ignoring limit/offset) so callers can build "showing X of Y" UI.
    /// The count query uses the same WHERE conditions as the data query; both
    /// are issued against the read pool and run sequentially on a single
    /// connection from that pool.
    pub async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &crate::config::db_backend::ApiSpecListFilter,
    ) -> Result<
        crate::config::db_backend::PaginatedResult<crate::config::types::ApiSpec>,
        anyhow::Error,
    > {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_api_specs_from_admin_read(namespace, filter, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_api_specs", &error);
                warn!("Read replica admin query failed; retrying list_api_specs against primary");
                let primary_pool = self.pool();
                let retry = self
                    .list_api_specs_from_admin_read(namespace, filter, &primary_pool)
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_api_specs");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_api_specs_from_admin_read(
        &self,
        namespace: &str,
        filter: &crate::config::db_backend::ApiSpecListFilter,
        pool: &AnyPool,
    ) -> Result<
        crate::config::db_backend::PaginatedResult<crate::config::types::ApiSpec>,
        anyhow::Error,
    > {
        use crate::config::db_backend::{ApiSpecSortBy, PaginatedResult, SortOrder};

        // Build WHERE clause dynamically.
        // We collect bind values as strings/i64 in order to use sqlx's typed bind API.
        // All column references are whitelisted — no user input goes into the SQL template.
        //
        // Note: the COUNT and data queries run sequentially without a shared
        // transaction, so `total` can be stale relative to `items` if a
        // concurrent write lands between them.  Standard pagination trade-off;
        // wrapping both in a transaction would serialize all list calls.
        let mut conditions: Vec<&'static str> = vec!["namespace = ?"];
        let mut proxy_id_val: Option<String> = None;
        let mut spec_version_val: Option<String> = None;
        let mut title_contains_val: Option<String> = None;
        let mut updated_since_val: Option<String> = None;
        let mut has_tag_val: Option<String> = None;

        if filter.proxy_id.is_some() {
            conditions.push("proxy_id = ?");
            proxy_id_val = filter.proxy_id.clone();
        }
        if let Some(ref prefix) = filter.spec_version_prefix {
            conditions.push("spec_version LIKE ?");
            spec_version_val = Some(format!("{prefix}%"));
        }
        if let Some(ref substr) = filter.title_contains {
            // LOWER() + LIKE for case-insensitive substring.
            conditions.push("LOWER(title) LIKE ?");
            title_contains_val = Some(format!("%{}%", substr.to_lowercase()));
        }
        if let Some(ref since) = filter.updated_since {
            conditions.push("updated_at >= ?");
            updated_since_val = Some(since.to_rfc3339());
        }
        if let Some(ref tag) = filter.has_tag {
            // Tags are stored as a JSON text array e.g. `["foo","bar"]`.
            // We match with LIKE `%"tag_name"%` — this correctly handles the JSON
            // quote-wrapping without requiring JSON functions (cross-dialect).
            //
            // SAFETY-CRITICAL CROSS-FILE INVARIANT:
            // The bare LIKE pattern here has NO ESCAPE clause.  It is safe ONLY
            // because tag names containing `"`, `%`, `_`, or `\` are rejected
            // at extract time via `ExtractError::InvalidTagName` in
            // src/admin/api_specs/extractor.rs (tag validation section).
            // Note: `_` is the SQL LIKE single-character wildcard — without
            // rejecting it, `?has_tag=api_v1` would falsely match `apixv1`.
            // If you ever relax that extractor whitelist, you MUST switch this
            // query to use `LIKE ... ESCAPE '\\'` and pre-escape the tag value
            // before binding it — otherwise `%`, `_`, or `\` in a tag name
            // would turn into a wildcard or escape token, producing false
            // positives.
            //
            // MongoDB uses native array membership (`filter_doc.insert("tags", tag)`)
            // with a multikey index and is unaffected by this pattern.
            conditions.push(r#"tags LIKE ?"#);
            has_tag_val = Some(format!("%\"{}\"", tag) + "%");
        }

        let where_clause = conditions.join(" AND ");

        // --- COUNT query (same WHERE, no ORDER BY / LIMIT / OFFSET) ----------
        let count_sql = self.q(&format!(
            "SELECT COUNT(*) AS cnt FROM api_specs WHERE {where_clause}"
        ));
        let mut count_query = sqlx::query(&count_sql).bind(namespace);
        if let Some(ref v) = proxy_id_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = spec_version_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = title_contains_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = updated_since_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = has_tag_val {
            count_query = count_query.bind(v);
        }
        let count_row = count_query.fetch_one(pool).await?;
        let total: i64 = count_row.try_get("cnt")?;

        // --- Data query (ORDER BY + LIMIT + OFFSET) --------------------------
        // Whitelist the ORDER BY column to prevent injection.
        let order_col = match filter.sort_by {
            ApiSpecSortBy::UpdatedAt => "updated_at",
            ApiSpecSortBy::Title => "title",
            ApiSpecSortBy::OperationCount => "operation_count",
            ApiSpecSortBy::CreatedAt => "created_at",
        };
        let order_dir = match filter.order {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        };

        let sql = self.q(&format!(
            "SELECT id, namespace, proxy_id, spec_version, spec_format, \
             content_encoding, uncompressed_size, content_hash, title, \
             info_version, description, contact_name, contact_email, \
             license_name, license_identifier, tags, server_urls, \
             operation_count, created_at, updated_at \
             FROM api_specs WHERE {where_clause} \
             ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?"
        ));

        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(ref v) = proxy_id_val {
            query = query.bind(v);
        }
        if let Some(ref v) = spec_version_val {
            query = query.bind(v);
        }
        if let Some(ref v) = title_contains_val {
            query = query.bind(v);
        }
        if let Some(ref v) = updated_since_val {
            query = query.bind(v);
        }
        if let Some(ref v) = has_tag_val {
            query = query.bind(v);
        }
        let rows: Vec<AnyRow> = query
            .bind(filter.limit as i64)
            .bind(filter.offset as i64)
            .fetch_all(pool)
            .await?;
        let mut specs = Vec::with_capacity(rows.len());
        for row in &rows {
            specs.push(row_to_api_spec_summary(row)?);
        }
        Ok(PaginatedResult {
            items: specs,
            total,
        })
    }

    /// Delete an ApiSpec and all resources it owns.
    ///
    /// The api_spec row has FK `proxy_id REFERENCES proxies(id) ON DELETE CASCADE`,
    /// so deleting the proxy cascades to remove the api_specs row and the
    /// proxy-scoped plugin_configs (via plugin_configs.proxy_id FK). Upstreams
    /// have no FK to proxies, so they are cleaned up manually by api_spec_id.
    pub async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        self.lock_mtls_dns_admission_tx(&mut tx, namespace).await?;
        let prior_mtls_dns_conflicts = self
            .mtls_dns_identity_conflicts_tx(&mut tx, namespace)
            .await?;
        self.use_delete_capture_snapshot_tx(&mut tx).await?;

        // Find the proxy_id for this spec.
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT proxy_id FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(namespace)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(false);
        };

        let proxy_id: String = row.try_get("proxy_id")?;

        let proxy_lock_sql = if self.db_type == "sqlite" {
            self.q("SELECT id FROM proxies WHERE id = ? AND namespace = ?")
        } else {
            self.q("SELECT id FROM proxies WHERE id = ? AND namespace = ? FOR UPDATE")
        };
        sqlx::query(&proxy_lock_sql)
            .bind(&proxy_id)
            .bind(namespace)
            .fetch_optional(&mut *tx)
            .await?;

        self.ensure_no_external_spec_upstream_refs_tx(&mut tx, namespace, id, &proxy_id)
            .await?;
        let mut deleted_plugin_config_ids = self
            .select_resource_ids_tx(
                &mut tx,
                "plugin_configs",
                namespace,
                Some(("api_spec_id", id)),
                true,
            )
            .await?;
        let proxy_plugin_sql = if self.db_type == "sqlite" {
            self.q("SELECT id FROM plugin_configs WHERE proxy_id = ? AND namespace = ?")
        } else {
            self.q("SELECT id FROM plugin_configs WHERE proxy_id = ? AND namespace = ? FOR UPDATE")
        };
        let proxy_plugin_rows: Vec<AnyRow> = sqlx::query(&proxy_plugin_sql)
            .bind(&proxy_id)
            .bind(namespace)
            .fetch_all(&mut *tx)
            .await?;
        for row in proxy_plugin_rows {
            let plugin_id: String = row.try_get("id")?;
            if !deleted_plugin_config_ids.contains(&plugin_id) {
                deleted_plugin_config_ids.push(plugin_id);
            }
        }
        let deleted_upstream_ids = self
            .select_resource_ids_tx(
                &mut tx,
                "upstreams",
                namespace,
                Some(("api_spec_id", id)),
                true,
            )
            .await?;

        // Delete spec-owned plugin_configs by api_spec_id (belt-and-suspenders;
        // the proxy FK cascade below would handle proxy-scoped ones, but
        // being explicit ensures correctness even if FK enforcement is disabled).
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE api_spec_id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Delete the proxy. FK ON DELETE CASCADE on api_specs.proxy_id removes
        // the api_specs row. FK ON DELETE CASCADE on plugin_configs.proxy_id
        // removes any remaining proxy-scoped plugins.
        sqlx::query(&self.q("DELETE FROM proxies WHERE id = ? AND namespace = ?"))
            .bind(&proxy_id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Deleting the proxy removes proxy_plugins junction rows via FK
        // cascade. If a spec-associated proxy was the last proxy referencing a
        // proxy_group plugin, mirror delete_proxy() and remove that now-orphaned
        // shared plugin config inside the same transaction.
        self.cleanup_orphaned_proxy_group_plugins(&mut tx, namespace)
            .await?;

        // Delete spec-owned upstream (no FK cascade on this path).
        sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Defensive explicit delete of the api_specs row in case the FK
        // cascade did not fire (e.g. SQLite with foreign_keys OFF).
        sqlx::query(&self.q("DELETE FROM api_specs WHERE id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        self.validate_namespace_repair_delete_admission_tx(
            &mut tx,
            namespace,
            &prior_mtls_dns_conflicts,
        )
        .await?;
        self.record_config_change_tx(&mut tx, namespace, "proxy", &proxy_id, "delete")
            .await?;
        for plugin_id in deleted_plugin_config_ids {
            self.record_config_change_tx(&mut tx, namespace, "plugin_config", &plugin_id, "delete")
                .await?;
        }
        for upstream_id in deleted_upstream_ids {
            self.record_config_change_tx(&mut tx, namespace, "upstream", &upstream_id, "delete")
                .await?;
        }
        self.compact_config_changes_tx(&mut tx, namespace).await?;

        tx.commit().await?;
        Ok(true)
    }

    /// List plugin configs owned by `spec_id` (i.e., tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to reuse existing plugin IDs rather than
    /// minting fresh UUIDs on every re-submit of a spec with empty plugin IDs.
    /// Admin-only — NEVER call from polling loops or GatewayConfig loading.
    pub async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = std::time::Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM plugin_configs ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&self.pool())
        .await?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }
        self.check_slow_query("list_spec_owned_plugin_configs", start);
        Ok(configs)
    }

    /// List upstreams owned by `spec_id` (i.e., tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to reuse the previous spec-owned upstream ID
    /// even when direct admin CRUD drifted the proxy's upstream pointer.
    /// Admin-only — NEVER call from polling loops or GatewayConfig loading.
    pub async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = std::time::Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM upstreams ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&self.pool())
        .await?;

        let mut upstreams = Vec::with_capacity(rows.len());
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }
        self.check_slow_query("list_spec_owned_upstreams", start);
        Ok(upstreams)
    }

    pub async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error> {
        let start = std::time::Instant::now();
        let diff = serde_json::to_string(&event.diff)?;
        sqlx::query(&self.q("INSERT INTO audit_events \
             (id, ts, actor, action, resource_type, resource_id, namespace, diff) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"))
        .bind(&event.id)
        .bind(audit_ts_string(&event.ts))
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&event.namespace)
        .bind(diff)
        .execute(&self.pool())
        .await?;
        self.check_slow_query("insert_audit_event", start);
        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
        let admin_read = self.admin_read_pool();
        let source = admin_read.source;
        match self
            .list_audit_events_from_admin_read(namespace, filter, &admin_read.pool)
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if source == AdminReadSource::ReadReplica => {
                self.mark_read_replica_unavailable("list_audit_events", &error);
                warn!(
                    "Read replica admin query failed; retrying list_audit_events against primary"
                );
                let primary_pool = self.pool();
                let retry = self
                    .list_audit_events_from_admin_read(namespace, filter, &primary_pool)
                    .await;
                if retry.is_ok() {
                    info!("Admin read fallback to primary succeeded for list_audit_events");
                }
                retry
            }
            Err(error) => Err(error),
        }
    }

    async fn list_audit_events_from_admin_read(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
        pool: &AnyPool,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
        let start = std::time::Instant::now();
        let mut conditions: Vec<&'static str> = vec!["namespace = ?"];

        if filter.actor.is_some() {
            conditions.push("actor = ?");
        }
        if filter.action.is_some() {
            conditions.push("action = ?");
        }
        if filter.resource_type.is_some() {
            conditions.push("resource_type = ?");
        }
        if filter.resource_id.is_some() {
            conditions.push("resource_id = ?");
        }
        if filter.start.is_some() {
            conditions.push("ts >= ?");
        }
        if filter.end.is_some() {
            conditions.push("ts <= ?");
        }

        let where_clause = conditions.join(" AND ");
        let count_sql = self.q(&format!(
            "SELECT COUNT(*) AS cnt FROM audit_events WHERE {where_clause}"
        ));
        let mut count_query = sqlx::query(&count_sql).bind(namespace);
        if let Some(ref value) = filter.actor {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.action {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.resource_type {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.resource_id {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.start {
            count_query = count_query.bind(audit_ts_string(value));
        }
        if let Some(ref value) = filter.end {
            count_query = count_query.bind(audit_ts_string(value));
        }
        let total: i64 = count_query.fetch_one(pool).await?.try_get("cnt")?;

        let sql = self.q(&format!(
            "SELECT id, ts, actor, action, resource_type, resource_id, namespace, diff \
             FROM audit_events WHERE {where_clause} \
             ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        ));
        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(ref value) = filter.actor {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.action {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.resource_type {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.resource_id {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.start {
            query = query.bind(audit_ts_string(value));
        }
        if let Some(ref value) = filter.end {
            query = query.bind(audit_ts_string(value));
        }
        let rows = query
            .bind(filter.limit as i64)
            .bind(filter.offset as i64)
            .fetch_all(pool)
            .await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(row_to_audit_event(row)?);
        }
        self.check_slow_query("list_audit_events", start);
        Ok(PaginatedResult { items, total })
    }
}

// ---------------------------------------------------------------------------
// DatabaseBackend trait implementation for sqlx-backed DatabaseStore
// ---------------------------------------------------------------------------

#[async_trait]
impl NamespaceConfigAdmissionLeaseBackend for DatabaseStore {
    async fn try_acquire_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<Option<u64>, anyhow::Error> {
        let sql = self.config_admission_lease_acquire_sql();
        sqlx::query(&sql)
            .bind(namespace)
            .bind(owner)
            .bind(CONFIG_ADMISSION_LEASE_DURATION_MILLIS)
            .execute(&self.pool())
            .await?;
        let now = self.config_admission_lease_now_sql();
        let generation_sql = self.q(&format!(
            "SELECT generation FROM config_admission_locks \
             WHERE namespace = ? AND owner = ? AND expires_at > {now}"
        ));
        let generation_result = sqlx::query_scalar::<_, i64>(&generation_sql)
            .bind(namespace)
            .bind(owner)
            .fetch_optional(&self.pool())
            .await;
        let generation_result = match generation_result {
            Ok(generation) => generation
                .map(u64::try_from)
                .transpose()
                .map_err(|_| anyhow::anyhow!("namespace config admission generation is negative")),
            Err(error) => Err(error.into()),
        };
        match generation_result {
            Ok(generation) => Ok(generation),
            Err(error) => {
                if let Err(release_error) = self
                    .release_namespace_config_admission_lease(namespace, owner)
                    .await
                {
                    return Err(anyhow::anyhow!(
                        "namespace config admission generation lookup failed: {error}; \
                         additionally failed to release the claimed lease: {release_error}"
                    ));
                }
                Err(error)
            }
        }
    }

    async fn renew_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        let sql = self.config_admission_lease_renew_sql();
        let result = sqlx::query(&sql)
            .bind(CONFIG_ADMISSION_LEASE_DURATION_MILLIS)
            .bind(namespace)
            .bind(owner)
            .execute(&self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn release_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        let sql = self.q("UPDATE config_admission_locks SET expires_at = 0 \
             WHERE namespace = ? AND owner = ?");
        let result = sqlx::query(&sql)
            .bind(namespace)
            .bind(owner)
            .execute(&self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl DatabaseBackend for DatabaseStore {
    async fn health_check(&self) -> Result<(), anyhow::Error> {
        sqlx::query("SELECT 1").fetch_one(&self.pool()).await?;
        Ok(())
    }

    fn db_type(&self) -> &str {
        &self.db_type
    }

    fn has_read_replica(&self) -> bool {
        self.has_read_replica_pool()
    }

    fn read_replica_available(&self) -> bool {
        self.primary_topology_active.load(Ordering::Acquire)
            && self
                .read_replica_pool
                .load_full()
                .is_some_and(|pool| !pool.is_closed())
    }

    fn read_replica_suppressed(&self) -> bool {
        // A configured replica is suppressed (not broken) precisely while the
        // active write/runtime pool points at a failover URL. The scheduler
        // skips reconnects in this state; failback re-enables eligibility.
        self.read_replica_url.is_some() && !self.primary_topology_active.load(Ordering::Acquire)
    }

    fn pool_stats(&self) -> Option<crate::config::db_backend::DbPoolStats> {
        let primary = self.pool.load();
        let size = primary.size();
        let idle = primary.num_idle() as u32;

        let replica = self
            .primary_topology_active
            .load(Ordering::Acquire)
            .then(|| self.read_replica_pool.load_full())
            .flatten()
            .map(|rp| {
                Box::new(crate::config::db_backend::DbPoolStatsInner {
                    size: rp.size(),
                    idle: rp.num_idle() as u32,
                    active: rp.size().saturating_sub(rp.num_idle() as u32),
                })
            });

        Some(crate::config::db_backend::DbPoolStats {
            size,
            idle,
            active: size.saturating_sub(idle),
            max_connections: self.pool_config.max_connections,
            min_connections: self.pool_config.min_connections,
            read_replica: replica,
        })
    }

    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>) {
        self.slow_query_threshold_ms = threshold_ms;
    }

    fn set_full_load_page_size(&mut self, page_size: u64) {
        self.full_load_page_size = page_size as i64;
    }

    fn set_cert_expiry_warning_days(&mut self, days: u64) {
        self.cert_expiry_warning_days = days;
    }

    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendEgressPolicy) {
        self.backend_allow_ips = policy;
    }

    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        match purpose {
            FullConfigLoadPurpose::Runtime => {
                DatabaseStore::load_full_config(self, namespace).await
            }
            FullConfigLoadPurpose::ControlPlane | FullConfigLoadPurpose::BackupExport => {
                DatabaseStore::load_full_config_for_purpose(self, namespace, purpose).await
            }
        }
    }

    async fn load_namespace_snapshot(
        &self,
        namespace: &str,
    ) -> Result<GatewayConfig, anyhow::Error> {
        DatabaseStore::load_namespace_snapshot(self, namespace).await
    }

    async fn count_namespace_resources(
        &self,
        namespace: &str,
    ) -> Result<NamespaceResourceCounts, anyhow::Error> {
        DatabaseStore::count_namespace_resources(self, namespace).await
    }

    async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        DatabaseStore::latest_change_sequence(self, namespace).await
    }

    async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error> {
        DatabaseStore::load_incremental_config(self, namespace, after_sequence).await
    }

    async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        DatabaseStore::create_proxy(self, proxy).await
    }

    async fn update_proxy(&self, proxy: &Proxy) -> Result<bool, anyhow::Error> {
        DatabaseStore::update_proxy(self, proxy).await
    }

    async fn delete_proxy(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_proxy(self, namespace, id).await
    }

    async fn get_proxy(&self, namespace: &str, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        DatabaseStore::get_proxy(self, namespace, id).await
    }

    async fn get_proxy_for_write(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Proxy>, anyhow::Error> {
        DatabaseStore::get_proxy_for_write(self, namespace, id).await
    }

    async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_exists(self, proxy_id, namespace).await
    }

    async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        DatabaseStore::list_proxies_paginated(self, namespace, limit, offset).await
    }

    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        DatabaseStore::create_consumer(self, consumer).await
    }

    async fn update_consumer(
        &self,
        consumer: &Consumer,
        mode: &BatchConfigWriteMode,
    ) -> Result<bool, anyhow::Error> {
        self.update_consumer_for_guard(consumer, mode.guard_owner())
            .await
    }

    async fn delete_consumer(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_consumer(self, namespace, id).await
    }

    async fn get_consumer(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Consumer>, anyhow::Error> {
        DatabaseStore::get_consumer(self, namespace, id).await
    }

    async fn list_consumers_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        DatabaseStore::list_consumers_paginated(self, namespace, limit, offset).await
    }

    async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        DatabaseStore::create_plugin_config(self, pc).await
    }

    async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<bool, anyhow::Error> {
        DatabaseStore::update_plugin_config(self, pc).await
    }

    async fn delete_plugin_config(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_plugin_config(self, namespace, id).await
    }

    async fn get_plugin_config(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error> {
        DatabaseStore::get_plugin_config(self, namespace, id).await
    }

    async fn list_plugin_configs_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        DatabaseStore::list_plugin_configs_paginated(self, namespace, limit, offset).await
    }

    async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        DatabaseStore::create_upstream(self, upstream).await
    }

    async fn update_upstream(&self, upstream: &Upstream) -> Result<bool, anyhow::Error> {
        DatabaseStore::update_upstream(self, upstream).await
    }

    async fn delete_upstream(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_upstream(self, namespace, id).await
    }

    async fn get_upstream(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Upstream>, anyhow::Error> {
        DatabaseStore::get_upstream(self, namespace, id).await
    }

    async fn cleanup_orphaned_upstream(
        &self,
        namespace: &str,
        upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::cleanup_orphaned_upstream(self, namespace, upstream_id).await
    }

    async fn list_upstreams_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        DatabaseStore::list_upstreams_paginated(self, namespace, limit, offset).await
    }

    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_path_unique(
            self,
            namespace,
            listen_path,
            hosts,
            exclude_proxy_id,
        )
        .await
    }

    async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_name_unique(self, namespace, name, exclude_proxy_id).await
    }

    async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_name_unique(self, namespace, name, exclude_upstream_id).await
    }

    async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        consumer_id: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        DatabaseStore::check_consumer_identity_unique(
            self,
            namespace,
            consumer_id,
            username,
            custom_id,
            exclude_consumer_id,
        )
        .await
    }

    async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_keyauth_key_unique(self, namespace, key, exclude_consumer_id).await
    }

    async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_mtls_identity_unique(self, namespace, identity, exclude_consumer_id)
            .await
    }

    async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_port_unique(self, namespace, port, exclude_proxy_id).await
    }

    async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_exists(self, upstream_id, namespace).await
    }

    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::validate_proxy_plugin_associations(self, proxy_id, namespace, plugins).await
    }

    async fn batch_create_proxies(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_proxies(self, proxies, mode).await
    }

    async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_proxies_without_plugins(self, proxies, mode).await
    }

    async fn batch_attach_proxy_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::batch_attach_proxy_plugins(self, proxies, mode).await
    }

    async fn batch_create_consumers(
        &self,
        consumers: &[Consumer],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_consumers(self, consumers, mode).await
    }

    async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_plugin_configs(self, configs, mode).await
    }

    async fn batch_create_upstreams(
        &self,
        upstreams: &[Upstream],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_upstreams(self, upstreams, mode).await
    }

    async fn delete_all_resources(
        &self,
        namespace: &str,
        write_mode: &BatchConfigWriteMode,
    ) -> Result<
        crate::config::db_backend::DeleteMode,
        crate::config::db_backend::DeleteAllResourcesError,
    > {
        let mode = crate::config::db_backend::DeleteMode::Atomic;
        DatabaseStore::delete_all_resources(self, namespace, write_mode)
            .await
            .map(|()| mode)
            .map_err(|error| crate::config::db_backend::DeleteAllResourcesError::new(mode, error))
    }

    async fn acquire_mtls_dns_admission_guard(
        &self,
        namespace: &str,
    ) -> Result<String, anyhow::Error> {
        self.acquire_mtls_dns_admission_guard_inner(namespace).await
    }

    async fn release_mtls_dns_admission_guard(
        &self,
        namespace: &str,
        guard_owner: &str,
    ) -> Result<(), anyhow::Error> {
        self.release_mtls_dns_admission_guard_inner(namespace, guard_owner)
            .await
    }

    async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect(self, db_url).await
    }

    async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect_read_replica(self, replica_url).await
    }

    async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> {
        DatabaseStore::try_failover_reconnect(self, primary_url).await
    }

    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        DatabaseStore::run_migrations(self).await
    }

    async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        DatabaseStore::maybe_apply_deferred_migrations(self).await
    }

    async fn pending_plugin_migrations(
        &self,
        plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PendingPluginMigration>, anyhow::Error> {
        if plugin_migrations.is_empty() {
            return Ok(Vec::new());
        }
        let runner =
            crate::config::migrations::MigrationRunner::new(self.pool(), self.db_type.clone());
        let status = runner.plugin_status(plugin_migrations).await?;
        Ok(status.pending)
    }

    async fn apply_plugin_migrations(
        &self,
        plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PluginMigrationRecord>, anyhow::Error> {
        if plugin_migrations.is_empty() {
            return Ok(Vec::new());
        }
        let runner =
            crate::config::migrations::MigrationRunner::new(self.pool(), self.db_type.clone());
        runner.run_plugin_pending(plugin_migrations).await
    }

    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::list_namespaces(self).await
    }

    async fn list_namespaces_authoritative(&self) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::list_namespaces_authoritative(self).await
    }

    async fn list_namespaces_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<String>, anyhow::Error> {
        DatabaseStore::list_namespaces_paginated(self, limit, offset).await
    }

    async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::submit_api_spec_bundle(self, bundle, spec).await
    }

    async fn restore_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
        additional_upstreams: &[crate::config::types::Upstream],
        additional_plugins: &[crate::config::types::PluginConfig],
        validation_http_client: &crate::plugins::PluginHttpClient,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::restore_api_spec_bundle(
            self,
            bundle,
            spec,
            additional_upstreams,
            additional_plugins,
            validation_http_client,
        )
        .await
    }

    async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::replace_api_spec_bundle(self, bundle, spec).await
    }

    async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        DatabaseStore::get_api_spec(self, namespace, id).await
    }

    async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        DatabaseStore::get_api_spec_by_proxy(self, namespace, proxy_id).await
    }

    async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &crate::config::db_backend::ApiSpecListFilter,
    ) -> Result<
        crate::config::db_backend::PaginatedResult<crate::config::types::ApiSpec>,
        anyhow::Error,
    > {
        DatabaseStore::list_api_specs(self, namespace, filter).await
    }

    async fn count_api_specs(&self, namespace: &str) -> Result<u64, anyhow::Error> {
        DatabaseStore::count_api_specs(self, namespace).await
    }

    async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_api_spec(self, namespace, id).await
    }

    async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        DatabaseStore::list_spec_owned_plugin_configs(self, namespace, spec_id).await
    }

    async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        DatabaseStore::list_spec_owned_upstreams(self, namespace, spec_id).await
    }

    async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::insert_audit_event(self, event).await
    }

    async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
        DatabaseStore::list_audit_events(self, namespace, filter).await
    }
}

/// Parse a stored backend scheme string into the canonical 6-variant
/// `BackendScheme`.
pub(crate) fn parse_scheme(s: &str) -> Result<BackendScheme, String> {
    match s.to_lowercase().as_str() {
        "http" => Ok(BackendScheme::Http),
        "https" => Ok(BackendScheme::Https),
        "tcp" => Ok(BackendScheme::Tcp),
        "tcps" => Ok(BackendScheme::Tcps),
        "udp" => Ok(BackendScheme::Udp),
        "dtls" => Ok(BackendScheme::Dtls),
        _ => Err(format!(
            "unsupported backend_scheme '{s}' (expected one of: http, https, tcp, tcps, udp, dtls)"
        )),
    }
}

pub(crate) fn parse_auth_mode(s: &str) -> AuthMode {
    match s.to_lowercase().as_str() {
        "multi" => AuthMode::Multi,
        _ => AuthMode::Single,
    }
}

/// Parse a proxy row into a Proxy struct (shared by load_proxies and get_proxy).
fn row_to_proxy(
    row: &AnyRow,
    id: String,
    plugins: Vec<PluginAssociation>,
) -> Result<Proxy, anyhow::Error> {
    // Clone id for use in error messages (the original is moved into the Proxy struct).
    let pid = id.clone();
    let scheme_str: String = row
        .try_get::<String, _>("backend_scheme")
        .map_err(|e| anyhow::anyhow!("Proxy {}: failed to read backend_scheme: {}", pid, e))?;
    let backend_scheme =
        parse_scheme(&scheme_str).map_err(|e| anyhow::anyhow!("Proxy {}: {}", pid, e))?;
    let auth_mode_str: String = row
        .try_get("auth_mode")
        .map_err(|e| anyhow::anyhow!("Proxy {}: failed to read auth_mode: {}", pid, e))?;

    let hosts_str: String = row
        .try_get::<String, _>("hosts")
        .unwrap_or_else(|_| "[]".into());
    let hosts: Vec<String> = serde_json::from_str(&hosts_str).map_err(|e| {
        anyhow::anyhow!(
            "Proxy {}: failed to parse hosts JSON '{}': {}",
            pid,
            hosts_str,
            e
        )
    })?;

    Ok(Proxy {
        id,
        namespace: row_namespace_or_default(row),
        name: row.try_get("name").ok(),
        hosts,
        // Propagate decode errors — silently defaulting to None would turn a
        // malformed listen_path into a host-only proxy and change routing
        // behavior. `Option<String>` already represents SQL NULL, so `?` is
        // safe for the expected nullable case and fails fast on real errors.
        listen_path: row.try_get::<Option<String>, _>("listen_path")?,
        backend_scheme: Some(backend_scheme),
        // `dispatch_kind` is populated by `GatewayConfig::normalize_fields()`
        // once the full config is loaded. Seed it here from the row values so
        // single-row reads (e.g., `get_proxy`) still return a usable Proxy
        // even when no normalization pass runs.
        dispatch_kind: DispatchKind::from(backend_scheme),
        backend_host: row.try_get("backend_host")?,
        backend_port: row
            .try_get::<i32, _>("backend_port")
            .map(|v| v.clamp(0, 65535) as u16)
            .unwrap_or(80),
        backend_path: row.try_get("backend_path").ok(),
        strip_listen_path: row.try_get::<i32, _>("strip_listen_path").unwrap_or(1) != 0,
        preserve_host_header: row.try_get::<i32, _>("preserve_host_header").unwrap_or(0) != 0,
        backend_connect_timeout_ms: row
            .try_get::<i64, _>("backend_connect_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(5000),
        backend_read_timeout_ms: row
            .try_get::<i64, _>("backend_read_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(30000),
        backend_write_timeout_ms: row
            .try_get::<i64, _>("backend_write_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(30000),
        // Propagate decode errors — silently defaulting to None would disable
        // backend mTLS (client cert/key) or swap the trust anchor from a custom
        // CA to the global bundle/webpki. `Option<String>` already represents
        // SQL NULL, so `?` is safe for the expected nullable case.
        backend_tls_client_cert_path: row
            .try_get::<Option<String>, _>("backend_tls_client_cert_path")?,
        backend_tls_client_key_path: row
            .try_get::<Option<String>, _>("backend_tls_client_key_path")?,
        backend_tls_verify_server_cert: row
            .try_get::<i32, _>("backend_tls_verify_server_cert")
            .unwrap_or(1)
            != 0,
        backend_tls_server_ca_cert_path: row
            .try_get::<Option<String>, _>("backend_tls_server_ca_cert_path")?,
        // DNS override redirects egress; silently dropping it can send traffic
        // to an unintended resolved address.
        dns_override: row.try_get::<Option<String>, _>("dns_override")?,
        dns_cache_ttl_seconds: row
            .try_get::<i64, _>("dns_cache_ttl_seconds")
            .ok()
            .map(|v| v as u64),
        auth_mode: parse_auth_mode(&auth_mode_str),
        plugins,
        // Propagate decode errors — silently defaulting to None would detach
        // the proxy from its load-balanced upstream and fall back to
        // `backend_host`, changing routing behavior.
        upstream_id: row.try_get::<Option<String>, _>("upstream_id")?,
        circuit_breaker: match row.try_get::<String, _>("circuit_breaker") {
            Ok(s) => Some(
                serde_json::from_str::<CircuitBreakerConfig>(&s).map_err(|e| {
                    anyhow::anyhow!("Proxy {}: failed to parse circuit_breaker JSON: {}", pid, e)
                })?,
            ),
            Err(_) => None,
        },
        retry: match row.try_get::<String, _>("retry") {
            Ok(s) => Some(serde_json::from_str::<RetryConfig>(&s).map_err(|e| {
                anyhow::anyhow!("Proxy {}: failed to parse retry JSON: {}", pid, e)
            })?),
            Err(_) => None,
        },
        response_body_mode: row
            .try_get::<String, _>("response_body_mode")
            .ok()
            .map(|s| match s.as_str() {
                "buffer" => ResponseBodyMode::Buffer,
                _ => ResponseBodyMode::Stream,
            })
            .unwrap_or_default(),
        pool_idle_timeout_seconds: row
            .try_get::<i64, _>("pool_idle_timeout_seconds")
            .ok()
            .map(|v| v as u64),
        pool_enable_http_keep_alive: row
            .try_get::<i32, _>("pool_enable_http_keep_alive")
            .ok()
            .map(|v| v != 0),
        pool_enable_http2: row
            .try_get::<i32, _>("pool_enable_http2")
            .ok()
            .map(|v| v != 0),
        pool_tcp_keepalive_seconds: row
            .try_get::<i64, _>("pool_tcp_keepalive_seconds")
            .ok()
            .map(|v| v as u64),
        pool_http2_keep_alive_interval_seconds: row
            .try_get::<i64, _>("pool_http2_keep_alive_interval_seconds")
            .ok()
            .map(|v| v as u64),
        pool_http2_keep_alive_timeout_seconds: row
            .try_get::<i64, _>("pool_http2_keep_alive_timeout_seconds")
            .ok()
            .map(|v| v as u64),
        pool_http2_initial_stream_window_size: row
            .try_get::<i64, _>("pool_http2_initial_stream_window_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_initial_connection_window_size: row
            .try_get::<i64, _>("pool_http2_initial_connection_window_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_adaptive_window: row
            .try_get::<i32, _>("pool_http2_adaptive_window")
            .ok()
            .map(|v| v != 0),
        pool_http2_max_frame_size: row
            .try_get::<i64, _>("pool_http2_max_frame_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_max_concurrent_streams: row
            .try_get::<i64, _>("pool_http2_max_concurrent_streams")
            .ok()
            .map(|v| v as u32),
        pool_http3_connections_per_backend: row
            .try_get::<i64, _>("pool_http3_connections_per_backend")
            .ok()
            .map(|v| v.max(1) as usize),
        // Derived-only: `h2_upgrade_policy` is projected from the mesh
        // DestinationRule port overrides at dispatch time, never persisted as a
        // proxy column, so a DB-loaded proxy always starts at `None`.
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: row
            .try_get::<i64, _>("pool_max_requests_per_connection")
            .ok()
            .map(|v| v.max(0) as u64),
        // Derived-only: `pool_http1_max_pending_requests` is projected from the
        // mesh DestinationRule port overrides at dispatch time, never persisted
        // as a proxy column, so a DB-loaded proxy always starts at `None`.
        pool_http1_max_pending_requests: None,
        // Subset selection is routing-sensitive; silently mapping a decode
        // failure to None would broaden traffic across all upstream targets.
        upstream_subset: row.try_get::<Option<String>, _>("upstream_subset")?,
        listen_port: row
            .try_get::<i32, _>("listen_port")
            .ok()
            .map(|v| v.clamp(0, 65535) as u16),
        frontend_tls: row.try_get::<i32, _>("frontend_tls").unwrap_or(0) != 0,
        passthrough: row.try_get::<i32, _>("passthrough").unwrap_or(0) != 0,
        udp_idle_timeout_seconds: row
            .try_get::<i64, _>("udp_idle_timeout_seconds")
            .map(|v| v.max(0) as u64)
            .unwrap_or(60),
        tcp_idle_timeout_seconds: row
            .try_get::<i64, _>("tcp_idle_timeout_seconds")
            .ok()
            .map(|v| v.max(0) as u64),
        websocket_idle_timeout_seconds: row
            .try_get::<i64, _>("websocket_idle_timeout_seconds")
            .ok()
            .map(|v| v.max(0) as u64),
        allowed_methods: match row.try_get::<String, _>("allowed_methods") {
            Ok(s) => Some(serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!("Proxy {}: failed to parse allowed_methods JSON: {}", pid, e)
            })?),
            Err(_) => None,
        },
        allowed_ws_origins: match row.try_get::<String, _>("allowed_ws_origins") {
            Ok(s) => serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Proxy {}: failed to parse allowed_ws_origins JSON: {}",
                    pid,
                    e
                )
            })?,
            Err(_) => Vec::new(),
        },
        udp_max_response_amplification_factor: row
            .try_get::<f64, _>("udp_max_response_amplification_factor")
            .ok()
            .map(|v| v as f32),
        // Written as an i32 0/1 (like the other proxy booleans); decode with
        // the same width. `Option<i32>` represents SQL NULL, so `?` fails only
        // on real decode errors — silently mapping those to `None` would
        // disable PROXY-header consumption on an enabled listener and corrupt
        // the first bytes of the application/TLS stream.
        stream_proxy_protocol: row
            .try_get::<Option<i32>, _>("stream_proxy_protocol")?
            .map(|v| v != 0),
        // api_spec_id: PRESERVE here. This row mapper is shared between
        // admin GET/list paths (which need the real owning spec id to
        // serialise per the OpenAPI schema) and the runtime config loader
        // (which must NOT see it). The runtime callers
        // `load_full_config` / `load_incremental_config` strip it
        // explicitly via `strip_api_spec_id_from_runtime_config(&mut cfg)`
        // before returning — see Wave 1A's hot-path isolation invariant.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        resolved_tls: Default::default(),
        // Populated by `GatewayConfig::resolve_dispatch_port_overrides()` after
        // upstreams are loaded and any mesh DR overrides applied.
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a consumer row into a Consumer struct.
fn required_utf8_text_column(row: &AnyRow, column: &str) -> Result<String, anyhow::Error> {
    match row.try_get::<String, _>(column) {
        Ok(value) => Ok(value),
        Err(text_error) => {
            // sqlx Any maps MySQL TEXT-family wire types (including
            // MEDIUMTEXT) to its generic BLOB type. Decode those bytes
            // explicitly, but still reject invalid UTF-8 rather than hiding a
            // corrupt JSON/config value behind a default.
            let bytes: Vec<u8> = row.try_get(column).map_err(|blob_error| {
                anyhow::anyhow!(
                    "column '{column}' could not be decoded as SQL text ({text_error}) \
                     or bytes ({blob_error})"
                )
            })?;
            String::from_utf8(bytes)
                .map_err(|error| anyhow::anyhow!("column '{column}' is not valid UTF-8: {error}"))
        }
    }
}

fn row_to_consumer(row: &AnyRow) -> Result<Consumer, anyhow::Error> {
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let creds_str = required_utf8_text_column(row, "credentials").map_err(|e| {
        anyhow::anyhow!(
            "Consumer {}: failed to read credentials column: {}",
            id_preview,
            e
        )
    })?;
    let credentials = serde_json::from_str(&creds_str).map_err(|e| {
        anyhow::anyhow!(
            "Consumer {}: failed to parse credentials JSON: {}",
            id_preview,
            e
        )
    })?;

    let acl_groups_str = required_utf8_text_column(row, "acl_groups").map_err(|e| {
        anyhow::anyhow!(
            "Consumer {}: failed to read acl_groups column: {}",
            id_preview,
            e
        )
    })?;
    let acl_groups: Vec<String> = serde_json::from_str(&acl_groups_str).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse acl_groups JSON for consumer: {} (raw: {})",
            e,
            acl_groups_str
        )
    })?;

    Ok(Consumer {
        id: row.try_get("id")?,
        namespace: row_namespace_or_default(row),
        username: row.try_get("username")?,
        custom_id: row.try_get("custom_id").ok(),
        credentials,
        acl_groups,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a plugin_config row into a PluginConfig struct.
fn row_to_plugin_config(row: &AnyRow) -> Result<PluginConfig, anyhow::Error> {
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let config_str: String = row.try_get("config").map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to read config column: {}",
            id_preview,
            e
        )
    })?;
    let config_val = serde_json::from_str(&config_str).map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to parse config JSON: {}",
            id_preview,
            e
        )
    })?;
    let scope_str: String = row.try_get("scope").map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to read scope column: {}",
            id_preview,
            e
        )
    })?;

    Ok(PluginConfig {
        id: row.try_get("id")?,
        namespace: row_namespace_or_default(row),
        plugin_name: row.try_get("plugin_name")?,
        config: config_val,
        scope: match scope_str.as_str() {
            "proxy" => PluginScope::Proxy,
            "proxy_group" => PluginScope::ProxyGroup,
            _ => PluginScope::Global,
        },
        proxy_id: row.try_get("proxy_id").ok(),
        enabled: row.try_get::<i32, _>("enabled").unwrap_or(1) != 0,
        priority_override: row
            .try_get::<Option<i32>, _>("priority_override")
            .ok()
            .flatten()
            .map(|v| v.clamp(0, 10_000) as u16),
        // See row_to_proxy for the rationale: preserve here so admin reads
        // get the real owning spec id; runtime callers strip via
        // strip_api_spec_id_from_runtime_config.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse an upstream row into an Upstream struct.
fn row_to_upstream(row: &AnyRow) -> Result<Upstream, anyhow::Error> {
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let targets_str: String = row.try_get("targets").map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to read targets column: {}",
            id_preview,
            e
        )
    })?;
    let targets: Vec<UpstreamTarget> = serde_json::from_str(&targets_str).map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to parse targets JSON: {}",
            id_preview,
            e
        )
    })?;

    let algo_str: String = row.try_get("algorithm").map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to read algorithm column: {}",
            id_preview,
            e
        )
    })?;
    let algorithm: LoadBalancerAlgorithm =
        serde_json::from_value(serde_json::Value::String(algo_str.clone())).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse algorithm '{}': {}",
                id_preview,
                algo_str,
                e
            )
        })?;

    let health_checks: Option<HealthCheckConfig> = match row.try_get::<String, _>("health_checks") {
        Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse health_checks JSON: {}",
                id_preview,
                e
            )
        })?),
        Err(_) => None,
    };

    let service_discovery: Option<ServiceDiscoveryConfig> =
        match row.try_get::<String, _>("service_discovery") {
            Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Upstream {}: failed to parse service_discovery JSON: {}",
                    id_preview,
                    e
                )
            })?),
            Err(_) => None,
        };

    let hash_on_cookie_config: Option<crate::config::types::HashOnCookieConfig> =
        match row.try_get::<Option<String>, _>("hash_on_cookie_config") {
            Ok(Some(s)) => Some(serde_json::from_str(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Upstream {}: failed to parse hash_on_cookie_config JSON: {}",
                    id_preview,
                    e
                )
            })?),
            Ok(None) | Err(_) => None,
        };

    // Parse backend TLS fields
    let backend_tls_verify_server_cert: bool = row
        .try_get::<i32, _>("backend_tls_verify_server_cert")
        .map(|v| v != 0)
        .unwrap_or(true);

    let subsets = match row.try_get::<String, _>("subsets") {
        Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse subsets JSON: {}",
                id_preview,
                e
            )
        })?),
        Err(_) => None,
    };

    let backend_tls_san_allow_list =
        match row.try_get::<Option<String>, _>("backend_tls_san_allow_list") {
            Ok(Some(s)) => serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Upstream {}: failed to parse backend_tls_san_allow_list JSON: {}",
                    id_preview,
                    e
                )
            })?,
            Ok(None) => Vec::new(),
            Err(e) => return Err(e.into()),
        };
    let backend_tls_sni: Option<String> = row.try_get("backend_tls_sni")?;

    Ok(Upstream {
        id: row.try_get("id")?,
        namespace: row_namespace_or_default(row),
        name: row.try_get("name").ok(),
        targets,
        algorithm,
        hash_on: row.try_get("hash_on").ok(),
        hash_on_cookie_config,
        health_checks,
        service_discovery,
        subsets,
        // Per-port overrides are populated in-memory by the mesh apply
        // pipeline (`apply_destination_rules`); they are not persisted to SQL
        // backends today, so SQL rows always start with an empty map.
        port_overrides: std::collections::HashMap::new(),
        // `source_locality` is projected at mesh slice apply by
        // `project_mesh_source_locality` from the workload's locality; SQL
        // backends do not persist it (no column), and `Upstream::validate_fields`
        // rejects operator writes via the admin API. SQL rows always start `None`.
        source_locality: None,
        // Mesh-only projection (`FERRUM_MESH_LOCALITY_LB_STRICT`): SQL backends
        // do not persist it and `Upstream::validate_fields` rejects operator
        // writes, so SQL rows always start `false`.
        locality_lb_strict: false,
        locality_lb_setting: None,
        // Same trust/mTLS contract as `row_to_proxy`: reject non-NULL decode
        // failures instead of silently disabling custom CA / client identity.
        backend_tls_client_cert_path: row
            .try_get::<Option<String>, _>("backend_tls_client_cert_path")?,
        backend_tls_client_key_path: row
            .try_get::<Option<String>, _>("backend_tls_client_key_path")?,
        backend_tls_verify_server_cert,
        backend_tls_server_ca_cert_path: row
            .try_get::<Option<String>, _>("backend_tls_server_ca_cert_path")?,
        backend_tls_sni,
        backend_tls_san_allow_list,
        // Per-subset TLS overlays are derived state populated by mesh
        // `apply_destination_rules`; SQL backends do not persist them, so SQL
        // rows always start with an empty map.
        resolved_subset_tls: std::collections::HashMap::new(),
        dispatch_port_override_fallback: None,
        // See row_to_proxy for the rationale: preserve here so admin reads
        // get the real owning spec id; runtime callers strip via
        // strip_api_spec_id_from_runtime_config.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Strip `api_spec_id` from every resource in a `GatewayConfig` so the
/// gateway runtime never observes the ownership tag.
///
/// The row mappers (`row_to_proxy`, `row_to_upstream`, `row_to_plugin_config`)
/// PRESERVE `api_spec_id` so admin GET/list paths can serialise it per the
/// OpenAPI schema. The runtime callers (`load_full_config`,
/// `load_incremental_config`) call this helper before returning to enforce
/// the hot-path isolation invariant: api_specs is admin-only metadata,
/// CP gRPC broadcasts must not leak ownership tags to DPs, and the
/// polling delta path keys off resource fields that should not include
/// admin metadata.
///
/// Mirror of the Mongo path's strip in `MongoStore::load_full_config` /
/// `MongoStore::load_incremental_config`.
pub(crate) fn strip_api_spec_id_from_runtime_config(config: &mut GatewayConfig) {
    for p in &mut config.proxies {
        p.api_spec_id = None;
    }
    for u in &mut config.upstreams {
        u.api_spec_id = None;
    }
    for pc in &mut config.plugin_configs {
        pc.api_spec_id = None;
    }
}

/// Parse an api_specs row into an [`ApiSpec`] struct.
///
/// This function is used exclusively by the admin-layer api_spec methods.
/// It must NEVER be called from runtime polling paths.
fn row_to_api_spec(row: &AnyRow) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    // spec_content is stored as BLOB/BYTEA — sqlx returns Vec<u8>.
    let spec_content: Vec<u8> = row.try_get("spec_content")?;
    row_to_api_spec_with_content(row, spec_content)
}

/// Parse an api_specs list row into an [`ApiSpec`] summary.
///
/// The list endpoint must not pull the compressed `spec_content` blob for
/// every row. Keep `spec_content` empty here; full document retrieval goes
/// through [`row_to_api_spec`].
fn row_to_api_spec_summary(row: &AnyRow) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    row_to_api_spec_with_content(row, Vec::new())
}

fn row_to_api_spec_with_content(
    row: &AnyRow,
    spec_content: Vec<u8>,
) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    use crate::config::types::{ApiSpec, SpecFormat};

    let spec_format_str: String = row.try_get("spec_format")?;
    let spec_format = match spec_format_str.as_str() {
        "json" => SpecFormat::Json,
        _ => SpecFormat::Yaml,
    };
    let uncompressed_size: i64 = row.try_get("uncompressed_size")?;

    // Wave 5: parse JSON-text arrays for tags / server_urls.
    let tags: Vec<String> = row
        .try_get::<String, _>("tags")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let server_urls: Vec<String> = row
        .try_get::<String, _>("server_urls")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let operation_count: u32 = row
        .try_get::<i64, _>("operation_count")
        .map(|v| v.clamp(0, u32::MAX as i64) as u32)
        .unwrap_or(0);
    let resource_hash: String = row
        .try_get::<String, _>("resource_hash")
        .unwrap_or_default();

    Ok(ApiSpec {
        id: row.try_get("id")?,
        namespace: row_namespace_or_default(row),
        proxy_id: row.try_get("proxy_id")?,
        spec_version: row.try_get("spec_version")?,
        spec_format,
        spec_content,
        content_encoding: row
            .try_get::<String, _>("content_encoding")
            .unwrap_or_else(|_| "gzip".to_string()),
        uncompressed_size: uncompressed_size.max(0) as u64,
        content_hash: row.try_get("content_hash")?,
        title: row.try_get("title").ok().flatten(),
        info_version: row.try_get("info_version").ok().flatten(),
        description: row.try_get("description").ok().flatten(),
        contact_name: row.try_get("contact_name").ok().flatten(),
        contact_email: row.try_get("contact_email").ok().flatten(),
        license_name: row.try_get("license_name").ok().flatten(),
        license_identifier: row.try_get("license_identifier").ok().flatten(),
        tags,
        server_urls,
        operation_count,
        resource_hash,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

fn row_to_audit_event(row: &AnyRow) -> Result<crate::admin::audit::AuditEvent, anyhow::Error> {
    let id: String = row.try_get("id")?;
    let diff_raw: String = row.try_get("diff")?;
    let diff = serde_json::from_str(&diff_raw).unwrap_or_else(|e| {
        warn!(
            audit_event_id = %id,
            error = %e,
            "Audit event diff column is not valid JSON; returning empty diff"
        );
        serde_json::json!({})
    });
    Ok(crate::admin::audit::AuditEvent {
        id,
        ts: parse_datetime_column(row, "ts"),
        actor: row.try_get("actor")?,
        action: row.try_get("action")?,
        resource_type: row.try_get("resource_type")?,
        resource_id: row.try_get("resource_id")?,
        namespace: row.try_get("namespace")?,
        diff,
    })
}

fn audit_ts_string(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn serialize_api_spec_string_list(
    spec_id: &str,
    field: &str,
    values: &[String],
) -> Result<String, anyhow::Error> {
    serde_json::to_string(values).map_err(|e| {
        anyhow::anyhow!(
            "ApiSpec {}: failed to serialize {} JSON: {}",
            spec_id,
            field,
            e
        )
    })
}

fn row_namespace_or_default(row: &AnyRow) -> String {
    row.try_get::<String, _>("namespace")
        .unwrap_or_else(|_| crate::config::types::default_namespace())
}

/// Parse a datetime column from a database row. Database stores timestamps as
/// RFC 3339 strings or SQLite `CURRENT_TIMESTAMP` format.
fn parse_datetime_column(row: &AnyRow, column: &str) -> chrono::DateTime<Utc> {
    match row.try_get::<String, _>(column) {
        Ok(raw) => chrono::DateTime::parse_from_rfc3339(&raw)
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|_| {
                // SQLite CURRENT_TIMESTAMP format: "YYYY-MM-DD HH:MM:SS"
                chrono::NaiveDateTime::parse_from_str(&raw, "%Y-%m-%d %H:%M:%S")
                    .map(|ndt| ndt.and_utc())
            })
            .unwrap_or_else(|_| {
                warn!(
                    column,
                    value = %raw,
                    "Could not parse datetime column, falling back to Utc::now()"
                );
                Utc::now()
            }),
        Err(error) => {
            warn!(
                column,
                error = %error,
                "Could not read datetime column, falling back to Utc::now()"
            );
            Utc::now()
        }
    }
}

#[cfg(test)]
mod proxy_insert_sql_drift_tests {
    //! Drift-catcher tests for the proxy INSERT call sites.
    //!
    //! See the "Drift-prevention contract for proxy INSERT call sites"
    //! comment block in [`DatabaseStore::PROXY_INSERT_PLACEHOLDER_COUNT`]
    //! for the contract these tests enforce.
    //!
    //! When you add a column to `proxies`:
    //!   1. Bump `PROXY_INSERT_PLACEHOLDER_COUNT` by 1.
    //!   2. Bump `PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT` by 1.
    //!   3. Add the column + `?` placeholder + `.bind()` to all four sites
    //!      listed in the contract block.
    //!   4. Re-run these tests; they verify the SQL placeholder counts match
    //!      the constants. If the bind chain is missing a column, sqlx will
    //!      surface "wrong number of parameters" at execute time (caught by
    //!      the existing integration tests).
    use super::{DatabaseStore, audit_ts_string};

    #[test]
    fn audit_ts_string_is_fixed_width_and_lexically_ordered() {
        let base = chrono::DateTime::parse_from_rfc3339("2026-05-18T03:00:00Z")
            .expect("base timestamp")
            .with_timezone(&chrono::Utc);
        let later = base + chrono::Duration::milliseconds(100);

        assert_eq!(audit_ts_string(&base), "2026-05-18T03:00:00.000000000Z");
        assert_eq!(audit_ts_string(&later), "2026-05-18T03:00:00.100000000Z");
        assert!(audit_ts_string(&base) < audit_ts_string(&later));
    }

    #[test]
    fn proxy_insert_sql_placeholder_count_matches_const() {
        let placeholders = DatabaseStore::PROXY_INSERT_SQL.matches('?').count();
        assert_eq!(
            placeholders,
            DatabaseStore::PROXY_INSERT_PLACEHOLDER_COUNT,
            "PROXY_INSERT_SQL `?` placeholder count drifted from \
             PROXY_INSERT_PLACEHOLDER_COUNT — see the drift-prevention \
             contract comment block in db_loader.rs",
        );
    }

    /// The `submit_api_spec_bundle` INSERT is built inline (it carries an
    /// extra `api_spec_id` column), so we mirror its SQL skeleton here and
    /// assert the same `?` count contract. If the inline SQL in
    /// `submit_api_spec_bundle` drifts, edit BOTH this fixture and the
    /// `PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT` constant.
    #[test]
    fn submit_api_spec_bundle_proxy_insert_placeholder_count_matches_const() {
        // VALUES list has one `?` per column; we lifted this row count from
        // the actual INSERT in submit_api_spec_bundle. Update if columns
        // change there.
        let values_clause = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                                     ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                                     ?, ?, ?, ?, ?, ?, ?)";
        let placeholders = values_clause.matches('?').count();
        assert_eq!(
            placeholders,
            DatabaseStore::PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT,
            "submit_api_spec_bundle proxy INSERT placeholder count must match \
             PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT — see drift-prevention contract",
        );
    }
}

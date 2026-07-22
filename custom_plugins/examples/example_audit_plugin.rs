//! Example Audit Plugin — Custom Plugin with Database Migrations
//!
//! Opt-in pedagogical plugin (see `custom_plugins/examples/README.md`). When
//! compiled in via `FERRUM_CUSTOM_PLUGINS=example_audit_plugin`, it records a
//! bounded audit row for every gateway transaction it is selected for —
//! HTTP-family `log()` hooks and stream `on_stream_disconnect()` hooks —
//! into a plugin-prefixed table created by its bundled migrations.
//!
//! ## Storage target
//!
//! Migrations and runtime writes both use the **gateway configuration
//! database**. Runtime pool construction resolves `FERRUM_DB_TYPE` /
//! `FERRUM_DB_URL` / `FERRUM_DB_TLS_*` through
//! [`EnvConfig::resolve_effective_sql_backend`](crate::config::EnvConfig::resolve_effective_sql_backend)
//! — the same environment-over-`ferrum.conf` path and canonical TLS query
//! parameters as the gateway primary pool. There is no separate plugin
//! database URL: a second URL would silently diverge from the schema that
//! migrate mode / auto-apply maintain. MongoDB is rejected because this
//! example is SQL-only (`sqlite` / `postgres` / `mysql`).
//!
//! The runtime worker opens a **lazy** SQL pool during
//! `start_background_tasks` (construction itself does not connect). The first
//! flush surfaces connectivity errors through the batching retry/warn path.
//! Supported modes for the storage path: `database`, `cp`, and standalone
//! `migrate` (for schema). File / DP / mesh / injector / node-agent modes do
//! not run SQL custom-plugin migrations; constructing the plugin there will
//! still attempt writes against the effective gateway SQL URL when those
//! settings are present.
//!
//! ## Failure contract
//!
//! This is a best-effort audit example (`OptionalFailOpen` at construction).
//! Queue-full and flush failures are logged and dropped — not a compliance
//! or durable-audit guarantee. When the gateway SQL backend cannot be resolved
//! at `start_background_tasks` (MongoDB, missing `FERRUM_DB_TYPE` /
//! `FERRUM_DB_URL`, unsupported dialect), the plugin logs a loud warning,
//! leaves the logger un-started, and returns `Ok(())` so admission cannot
//! wedge config reload — records then drop on the hot path. Do not treat an
//! empty table as proof that no traffic occurred when the sink was
//! unavailable. Batch writes are transactional so a retry never encounters
//! rows partially committed by its own previous attempt. The hourly retention
//! task is aborted with the plugin generation, so repeated configuration
//! reloads do not accumulate workers.
//! Native and translated gRPC transactions retain their terminal gRPC status
//! separately from the HTTP transport status. WebSocket uses its HTTP upgrade
//! transaction; this example deliberately does not capture frame payloads.
//! Request methods are capped at 256 Unicode characters; client/proxy
//! identities at 255; and connection diagnostics at 4,096. These bounds are
//! applied before persistence so hostile extension methods, external identity
//! claims, or error text cannot overrun the portable MySQL column contract or
//! inflate queued records without limit.
//!
//! ## MySQL custom-migration contract
//!
//! The gateway runner executes every MySQL custom-plugin migration statement
//! outside an enclosing transaction (MySQL implicitly commits around DDL, and
//! the runner uses the same non-transactional path for all MySQL custom
//! migrations — including DML-only bodies — so statement/tracking boundaries
//! never become ambiguously half-transactional). **All MySQL custom
//! migrations for this plugin, including DML-only migrations, are therefore
//! non-atomic with the tracking insert and must be idempotent / re-runnable.**
//!
//! ## Features Demonstrated
//!
//! - Database migrations via `plugin_migrations()` with multi-DB support
//! - Bounded queue + lifecycle-owned worker (`start_background_tasks`)
//! - `ALL_PROTOCOLS` coverage with HTTP `log` and stream disconnect hooks
//! - PostgreSQL-specific and MySQL-specific SQL overrides
//! - Multi-statement migrations with exact MySQL index reconciliation
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "plugin_name": "example_audit_plugin",
//!   "config": {
//!     "log_request_headers": false,
//!     "retention_days": 90,
//!     "queue_capacity": 10000
//!   }
//! }
//! ```
//!
//! `log_request_headers` includes a redacted metadata / user-agent snapshot
//! when true. Full request headers are not available on the terminal log
//! hook; this field does not capture `Authorization` / cookie values.
//! `retention_days` accepts 1 through 36,500. Configure only one of
//! `queue_capacity` or its shared batching alias `buffer_capacity`.
//!
//! ## Running Migrations
//!
//! ```bash
//! FERRUM_CUSTOM_PLUGINS=example_audit_plugin \
//!   FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up cargo run
//! ```

use async_trait::async_trait;
use serde_json::Value;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

use crate::config::migrations::CustomPluginMigration;
use crate::plugins::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLogger, build_batch_config, validate_batch_config,
    wait_until_committed,
};
use crate::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient, ProxyProtocol, StreamTransactionSummary,
    TransactionSummary,
};

const TABLE_NAME: &str = "example_audit_log";
const PLUGIN_NAME: &str = "example_audit_plugin";
const MAX_RETENTION_DAYS: u64 = 36_500;
const MAX_HTTP_METHOD_CHARS: usize = 256;
const MAX_CONSUMER_USERNAME_CHARS: usize = 255;
const MAX_CLIENT_IP_CHARS: usize = 255;
const MAX_PROXY_ID_CHARS: usize = 255;
const MAX_CONNECTION_ERROR_CHARS: usize = 4096;
const MAX_METADATA_ENTRIES: usize = 64;
const MAX_METADATA_KEY_CHARS: usize = 128;
const MAX_METADATA_VALUE_CHARS: usize = 512;
const MAX_CONTEXT_BYTES: usize = 4096;
const INSERT_COLUMN_COUNT: usize = 13;
/// Cap multi-row INSERT binds under SQLite's 999-variable floor (13 × 76 = 988).
const INSERT_MAX_ROWS_PER_STATEMENT: usize = 50;
/// Chunk size for retention DELETE so a multi-million-row backlog cannot hold
/// the shared configuration-database write lock for one unbounded statement.
const RETENTION_DELETE_CHUNK_SIZE: u64 = 1_000;
const RETENTION_DELETE_CHUNK_PAUSE: Duration = Duration::from_millis(50);
const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);

/// Per-connection SQLite setup for the audit pool. Must stay aligned with the
/// primary gateway SQLite pool (`DatabaseStore` `after_connect`).
pub const SQLITE_AUDIT_CONNECT_PRAGMAS: &[&str] = &[
    "PRAGMA foreign_keys = ON",
    "PRAGMA journal_mode = WAL",
    "PRAGMA busy_timeout = 5000",
];

/// Gateway SQL dialect resolved from `FERRUM_DB_TYPE` (never from the raw URL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditSqlDialect {
    Sqlite,
    Postgres,
    Mysql,
}

impl AuditSqlDialect {
    pub fn from_db_type(db_type: &str) -> Result<Self, String> {
        match db_type {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            "mysql" => Ok(Self::Mysql),
            other => Err(format!(
                "example_audit_plugin: unsupported FERRUM_DB_TYPE '{other}' \
                 (expected sqlite, postgres, or mysql)"
            )),
        }
    }

    fn row_placeholders(self, row_index: usize) -> String {
        match self {
            Self::Postgres => {
                let base = row_index * INSERT_COLUMN_COUNT;
                let mut parts = Vec::with_capacity(INSERT_COLUMN_COUNT);
                for offset in 1..=INSERT_COLUMN_COUNT {
                    parts.push(format!("${}", base + offset));
                }
                format!("({})", parts.join(", "))
            }
            Self::Sqlite | Self::Mysql => {
                let parts = vec!["?"; INSERT_COLUMN_COUNT];
                format!("({})", parts.join(", "))
            }
        }
    }

    /// Multi-row INSERT for this dialect. PostgreSQL uses `$1..$N` because
    /// `sqlx::Any` does not rewrite `?` placeholders; SQLite/MySQL keep `?`.
    pub fn insert_sql(self, row_count: usize) -> String {
        let row_count = row_count.max(1);
        let mut value_rows = Vec::with_capacity(row_count);
        for row_index in 0..row_count {
            value_rows.push(self.row_placeholders(row_index));
        }
        format!(
            "INSERT INTO {TABLE_NAME} (\n\
                id, timestamp, client_ip, protocol, http_method, request_path,\n\
                response_status, grpc_status, latency_ms, consumer_username, proxy_id,\n\
                request_context, connection_error\n\
            ) VALUES {}",
            value_rows.join(", ")
        )
    }

    /// Chunked retention DELETE. Postgres deletes by `ctid` subquery; SQLite
    /// uses `rowid` (plain `DELETE ... LIMIT` needs SQLITE_ENABLE_UPDATE_DELETE_LIMIT);
    /// MySQL supports `DELETE ... LIMIT` natively.
    pub fn retention_delete_sql(self) -> String {
        match self {
            Self::Postgres => format!(
                "DELETE FROM {TABLE_NAME} WHERE ctid IN (\
                     SELECT ctid FROM {TABLE_NAME} WHERE timestamp < $1 \
                     LIMIT {RETENTION_DELETE_CHUNK_SIZE}\
                 )"
            ),
            Self::Sqlite => format!(
                "DELETE FROM {TABLE_NAME} WHERE rowid IN (\
                     SELECT rowid FROM {TABLE_NAME} WHERE timestamp < ? \
                     LIMIT {RETENTION_DELETE_CHUNK_SIZE}\
                 )"
            ),
            Self::Mysql => {
                format!(
                    "DELETE FROM {TABLE_NAME} WHERE timestamp < ? \
                     LIMIT {RETENTION_DELETE_CHUNK_SIZE}"
                )
            }
        }
    }
}

struct GatewayAuditStore {
    pool: AnyPool,
    dialect: AuditSqlDialect,
}

#[derive(Clone)]
struct AuditRecord {
    id: String,
    timestamp: String,
    client_ip: String,
    protocol: String,
    http_method: Option<String>,
    request_path: Option<String>,
    response_status: Option<i32>,
    grpc_status: Option<i64>,
    latency_ms: f64,
    consumer_username: Option<String>,
    proxy_id: Option<String>,
    request_context: Option<String>,
    connection_error: Option<String>,
}

pub struct ExampleAuditPlugin {
    log_request_headers: bool,
    retention_days: u64,
    batch_config: BatchConfig,
    /// Set once during `start_background_tasks`; hot-path enqueue is lock-free.
    logger: OnceLock<BatchingLogger<AuditRecord>>,
    retention_task: OnceLock<tokio::task::AbortHandle>,
    /// Serializes idempotent startup only; never acquired on steady-state hooks.
    start_lock: Mutex<()>,
}

impl ExampleAuditPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or_else(|| "example_audit_plugin config must be a JSON object".to_string())?;

        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "log_request_headers"
                    | "retention_days"
                    | "queue_capacity"
                    | "batch_size"
                    | "flush_interval_ms"
                    | "max_retries"
                    | "retry_delay_ms"
                    | "buffer_capacity"
            ) {
                return Err(format!(
                    "example_audit_plugin config contains unknown key '{key}'; \
                     expected only log_request_headers, retention_days, and optional batch keys \
                     (queue_capacity/buffer_capacity, batch_size, flush_interval_ms, max_retries, retry_delay_ms). \
                     Storage uses the gateway SQL database via EnvConfig::resolve_effective_sql_backend \
                     (FERRUM_DB_URL / FERRUM_DB_TYPE / FERRUM_DB_TLS_*); \
                     per-plugin db_url/db_type are not supported."
                ));
            }
        }

        let log_request_headers = match config.get("log_request_headers") {
            None | Some(Value::Null) => false,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "log_request_headers must be a boolean".to_string())?,
        };

        let retention_days = match config.get("retention_days") {
            None | Some(Value::Null) => 90,
            Some(value) => {
                let days = value
                    .as_u64()
                    .ok_or_else(|| "retention_days must be a positive integer".to_string())?;
                if days == 0 {
                    return Err("retention_days must be greater than zero".to_string());
                }
                if days > MAX_RETENTION_DAYS {
                    return Err(format!(
                        "retention_days must not exceed {MAX_RETENTION_DAYS}"
                    ));
                }
                days
            }
        };

        let queue_capacity_configured = config
            .get("queue_capacity")
            .is_some_and(|value| !value.is_null());
        let buffer_capacity_configured = config
            .get("buffer_capacity")
            .is_some_and(|value| !value.is_null());
        if queue_capacity_configured && buffer_capacity_configured {
            return Err(
                "example_audit_plugin: configure only one of queue_capacity or buffer_capacity"
                    .to_string(),
            );
        }

        let queue_capacity = match config
            .get("queue_capacity")
            .filter(|value| !value.is_null())
            .or_else(|| {
                config
                    .get("buffer_capacity")
                    .filter(|value| !value.is_null())
            }) {
            None | Some(Value::Null) => 10_000u64,
            Some(value) => {
                let capacity = value
                    .as_u64()
                    .ok_or_else(|| "queue_capacity must be a positive integer".to_string())?;
                if capacity == 0 {
                    return Err("queue_capacity must be greater than zero".to_string());
                }
                capacity
            }
        };

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: queue_capacity,
            max_retries: 3,
            retry_delay_ms: 1000,
        };
        // validate_batch_config expects buffer_capacity on the config object;
        // synthesize a view that includes the resolved queue capacity.
        let mut batch_cfg_value = config.clone();
        if let Some(obj) = batch_cfg_value.as_object_mut() {
            obj.insert("buffer_capacity".to_string(), Value::from(queue_capacity));
        }
        validate_batch_config(&batch_cfg_value, PLUGIN_NAME, batch_defaults)?;
        let batch_config = build_batch_config(&batch_cfg_value, PLUGIN_NAME, batch_defaults);

        Ok(Self {
            log_request_headers,
            retention_days,
            batch_config,
            logger: OnceLock::new(),
            retention_task: OnceLock::new(),
            start_lock: Mutex::new(()),
        })
    }

    fn enqueue_with(&self, build_record: impl FnOnce() -> AuditRecord) {
        match self.logger.get() {
            Some(logger) => {
                // Reserve the bounded-channel slot before cloning summary
                // strings, sorting metadata, or generating a UUID. During a
                // database outage a full queue must remain a cheap drop path.
                if let Some(permit) = logger.try_reserve() {
                    permit.send(build_record());
                }
            }
            None => {
                warn!(
                    plugin = PLUGIN_NAME,
                    "example_audit_plugin: dropping audit record because the \
                     background worker has not started (start_background_tasks)"
                );
            }
        }
    }

    fn record_from_http(&self, summary: &TransactionSummary) -> AuditRecord {
        let request_context = if self.log_request_headers {
            Some(bounded_http_context(summary))
        } else {
            None
        };
        let grpc_status = summary.grpc_status().map(i64::from);
        AuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: canonical_timestamp(&summary.timestamp_received),
            client_ip: truncate_chars(&summary.client_ip, MAX_CLIENT_IP_CHARS),
            protocol: classify_http_audit_protocol(summary),
            http_method: Some(truncate_chars(
                &summary.http_method,
                MAX_HTTP_METHOD_CHARS,
            )),
            request_path: Some(truncate_chars(&summary.request_path, 2048)),
            response_status: Some(i32::from(summary.response_status_code)),
            grpc_status,
            latency_ms: summary.latency_total_ms,
            consumer_username: summary
                .consumer_username
                .as_deref()
                .map(|username| truncate_chars(username, MAX_CONSUMER_USERNAME_CHARS)),
            proxy_id: summary
                .proxy_id
                .as_deref()
                .map(|proxy_id| truncate_chars(proxy_id, MAX_PROXY_ID_CHARS)),
            request_context,
            connection_error: summary
                .error_class
                .as_ref()
                .map(|c| format!("{c:?}"))
                .or_else(|| {
                    summary
                        .body_error_class
                        .as_ref()
                        .map(|c| format!("{c:?}"))
                })
                .map(|error| truncate_chars(&error, MAX_CONNECTION_ERROR_CHARS)),
        }
    }

    fn record_from_stream(&self, summary: &StreamTransactionSummary) -> AuditRecord {
        let request_context = if self.log_request_headers {
            Some(bounded_stream_context(summary))
        } else {
            None
        };
        AuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: canonical_timestamp(&summary.timestamp_disconnected),
            client_ip: truncate_chars(&summary.client_ip, MAX_CLIENT_IP_CHARS),
            protocol: classify_stream_audit_protocol(summary),
            http_method: None,
            request_path: None,
            response_status: None,
            grpc_status: None,
            latency_ms: summary.duration_ms,
            consumer_username: summary
                .consumer_username
                .as_deref()
                .map(|username| truncate_chars(username, MAX_CONSUMER_USERNAME_CHARS)),
            proxy_id: Some(truncate_chars(&summary.proxy_id, MAX_PROXY_ID_CHARS)),
            request_context,
            connection_error: summary
                .connection_error
                .as_deref()
                .map(|error| truncate_chars(error, MAX_CONNECTION_ERROR_CHARS)),
        }
    }
}

/// Classify the persisted protocol label for an HTTP-family `log()` summary.
///
/// Precise mapping supported by summary fields / metadata (not invented
/// transport versions):
/// - `mesh.request_protocol=grpc-web` → `grpc-web`
/// - `request_protocol=grpc` or terminal `grpc_status` → `grpc`
/// - H1 WebSocket upgrade (`101`) or H2 Extended CONNECT (`CONNECT` + `200`,
///   excluding HBONE) → `websocket`
/// - otherwise → `http` (H1/H2/H3 and SSE share `ProxyProtocol::Http`)
pub fn classify_http_audit_protocol(summary: &TransactionSummary) -> String {
    if summary
        .metadata
        .get("mesh.request_protocol")
        .is_some_and(|protocol| protocol == "grpc-web")
    {
        return "grpc-web".to_string();
    }
    if let Some(protocol) = summary.metadata.get("request_protocol") {
        match protocol.as_str() {
            "grpc" => return "grpc".to_string(),
            "grpc-web" => return "grpc-web".to_string(),
            "websocket" => return "websocket".to_string(),
            "hbone" => return "hbone".to_string(),
            "http" | "http1" | "http2" | "http3" | "https" => return "http".to_string(),
            // Metadata is a shared plugin surface. Never copy an unknown value
            // into MySQL's VARCHAR(32) protocol column: an oversized value from
            // another plugin would roll back the entire audit batch. Fall
            // through to the typed/status-derived classification below.
            _ => {}
        }
    }
    if summary.grpc_status().is_some() {
        return "grpc".to_string();
    }
    if summary.response_status_code == 101 {
        return "websocket".to_string();
    }
    // H2 Extended CONNECT WebSocket handshake returns 200 with method CONNECT.
    // HBONE also uses CONNECT-shaped traffic but stamps `request_protocol=hbone`
    // (handled above), so an unstamped CONNECT+200 is the H2 WS upgrade path.
    if summary.http_method.eq_ignore_ascii_case("CONNECT") && summary.response_status_code == 200 {
        return "websocket".to_string();
    }
    "http".to_string()
}

/// Stream disconnect labels are the backend scheme strings already present on
/// `StreamTransactionSummary.protocol` (`tcp` / `tcps` / `udp` / `dtls`).
pub fn classify_stream_audit_protocol(summary: &StreamTransactionSummary) -> String {
    summary.protocol.clone()
}

/// Deterministic, redacted, bounded metadata snapshot for tests and context
/// encoding. Sensitive values are redacted before persistence; entry/value
/// bounds are hard caps; truncation collisions and omitted entries are marked.
pub fn bounded_redacted_metadata(metadata: &std::collections::HashMap<String, String>) -> Value {
    use crate::plugins::utils::metadata_redaction::{
        REDACTED_PLACEHOLDER, is_sensitive_metadata_key,
    };

    let mut keys: Vec<&str> = metadata.keys().map(String::as_str).collect();
    keys.sort_unstable();

    let selected: Vec<&str> = keys.into_iter().take(MAX_METADATA_ENTRIES).collect();
    let omitted = metadata.len().saturating_sub(selected.len());

    let mut bounded = serde_json::Map::new();
    let mut collision_count = 0u64;
    for key in selected {
        let value = if is_sensitive_metadata_key(key) {
            REDACTED_PLACEHOLDER.to_string()
        } else {
            truncate_chars(
                metadata.get(key).map(String::as_str).unwrap_or(""),
                MAX_METADATA_VALUE_CHARS,
            )
        };
        let stored_key = truncate_chars(key, MAX_METADATA_KEY_CHARS);
        if bounded.contains_key(&stored_key) {
            // Lexicographically earlier original key already claimed this
            // truncated prefix; keep the first value and surface the collision.
            collision_count += 1;
            continue;
        }
        bounded.insert(stored_key, Value::String(value));
    }
    if omitted > 0 {
        bounded.insert(
            "__ferrum_omitted_metadata_entries".to_string(),
            Value::from(omitted as u64),
        );
    }
    if collision_count > 0 {
        bounded.insert(
            "__ferrum_metadata_key_collisions".to_string(),
            Value::from(collision_count),
        );
    }
    Value::Object(bounded)
}

fn bounded_http_context(summary: &TransactionSummary) -> String {
    let mut map = serde_json::Map::new();
    if let Some(ua) = &summary.request_user_agent {
        map.insert(
            "user_agent".to_string(),
            Value::String(truncate_chars(ua, 512)),
        );
    }
    if let Some(auth) = summary.auth_method {
        map.insert("auth_method".to_string(), Value::String(auth.to_string()));
    }
    map.insert(
        "metadata".to_string(),
        bounded_redacted_metadata(&summary.metadata),
    );
    encode_bounded_context(map)
}

fn bounded_stream_context(summary: &StreamTransactionSummary) -> String {
    let mut map = serde_json::Map::new();
    if let Some(auth) = summary.auth_method {
        map.insert("auth_method".to_string(), Value::String(auth.to_string()));
    }
    if let Some(sni) = &summary.sni_hostname {
        map.insert(
            "sni_hostname".to_string(),
            Value::String(truncate_chars(sni, 256)),
        );
    }
    map.insert(
        "metadata".to_string(),
        bounded_redacted_metadata(&summary.metadata),
    );
    encode_bounded_context(map)
}

fn encode_bounded_context(map: serde_json::Map<String, Value>) -> String {
    let encoded = Value::Object(map).to_string();
    if encoded.len() <= MAX_CONTEXT_BYTES {
        encoded
    } else {
        // Never byte/character-slice serialized JSON: doing so can leave an
        // invalid document or split an escape sequence. Oversized context is
        // represented by a small valid marker instead.
        serde_json::json!({
            "metadata": {
                "__ferrum_context_truncated": true
            }
        })
        .to_string()
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn canonical_timestamp(input: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(input) {
        Ok(timestamp) => timestamp
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        Err(error) => {
            warn!(
                plugin = PLUGIN_NAME,
                error = %error,
                "example_audit_plugin: transaction summary carried an invalid timestamp; using current time"
            );
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    }
}

fn connect_gateway_pool_lazy() -> Result<GatewayAuditStore, String> {
    // Use the gateway's effective SQL backend (conf-aware URL + canonical
    // FERRUM_DB_TLS_* parameters). Never infer dialect from the raw URL, and
    // never log the effective URL (it may embed credentials).
    let backend = crate::config::EnvConfig::resolve_effective_sql_backend()
        .map_err(|error| format!("example_audit_plugin: {error}"))?;
    let dialect = AuditSqlDialect::from_db_type(&backend.db_type)?;
    // Use a lazy pool so `start_background_tasks` stays sync-safe on the Tokio
    // runtime; the first flush surfaces connectivity errors through the
    // batching retry/warn path.
    sqlx::any::install_default_drivers();
    let is_sqlite = matches!(dialect, AuditSqlDialect::Sqlite);
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                if is_sqlite {
                    use sqlx::Executor;
                    for pragma in SQLITE_AUDIT_CONNECT_PRAGMAS {
                        conn.execute(*pragma).await?;
                    }
                }
                Ok(())
            })
        })
        .connect_lazy(&backend.effective_url)
        .map_err(|_| {
            "example_audit_plugin: failed to create gateway database pool from effective configuration"
                .to_string()
        })?;
    Ok(GatewayAuditStore { pool, dialect })
}

async fn insert_batch(
    pool: &AnyPool,
    dialect: AuditSqlDialect,
    batch: Vec<AuditRecord>,
) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("example_audit_plugin batch transaction failed: {e}"))?;
    for chunk in batch.chunks(INSERT_MAX_ROWS_PER_STATEMENT) {
        let insert_sql = dialect.insert_sql(chunk.len());
        let mut query = sqlx::query(&insert_sql);
        for record in chunk {
            query = query
                .bind(&record.id)
                .bind(&record.timestamp)
                .bind(&record.client_ip)
                .bind(&record.protocol)
                .bind(&record.http_method)
                .bind(&record.request_path)
                .bind(record.response_status)
                .bind(record.grpc_status)
                .bind(record.latency_ms)
                .bind(&record.consumer_username)
                .bind(&record.proxy_id)
                .bind(&record.request_context)
                .bind(&record.connection_error);
        }
        query
            .execute(&mut *transaction)
            .await
            .map_err(|e| format!("example_audit_plugin insert failed: {e}"))?;
    }
    transaction
        .commit()
        .await
        .map_err(|e| format!("example_audit_plugin batch commit failed: {e}"))
}

async fn run_retention(pool: AnyPool, dialect: AuditSqlDialect, retention_days: u64) {
    let delete_sql = dialect.retention_delete_sql();
    // Skip the immediate first tick: plugin-cache rebuilds reconstruct this
    // worker on global-plugin changes, and an immediate full-range DELETE on
    // every rebuild would thrash the shared configuration database.
    let start = tokio::time::Instant::now() + RETENTION_INTERVAL;
    let mut interval = tokio::time::interval_at(start, RETENTION_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut total_deleted: u64 = 0;
        loop {
            match sqlx::query(&delete_sql).bind(&cutoff).execute(&pool).await {
                Ok(result) => {
                    let deleted = result.rows_affected();
                    total_deleted = total_deleted.saturating_add(deleted);
                    if deleted < RETENTION_DELETE_CHUNK_SIZE {
                        break;
                    }
                    tokio::time::sleep(RETENTION_DELETE_CHUNK_PAUSE).await;
                }
                Err(e) => {
                    warn!(
                        plugin = PLUGIN_NAME,
                        error = %e,
                        "example_audit_plugin: retention delete failed"
                    );
                    break;
                }
            }
        }
        if total_deleted > 0 {
            tracing::info!(
                plugin = PLUGIN_NAME,
                deleted = total_deleted,
                retention_days,
                "example_audit_plugin: purged expired audit rows"
            );
        }
    }
}

impl Drop for ExampleAuditPlugin {
    fn drop(&mut self) {
        if let Some(task) = self.retention_task.get() {
            task.abort();
        }
    }
}

#[async_trait]
impl Plugin for ExampleAuditPlugin {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        // Run in the logging band, after all other processing
        9150
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        if self.logger.get().is_some() {
            return Ok(());
        }
        let _start_guard = self.start_lock.lock().map_err(|_| {
            "example_audit_plugin: start lock poisoned; refusing to start background tasks"
                .to_string()
        })?;
        if self.logger.get().is_some() {
            return Ok(());
        }

        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            "example_audit_plugin: start_background_tasks requires a Tokio runtime".to_string()
        })?;

        // Backend-resolution failure must not abort gateway startup / config
        // reload (OptionalFailOpen). Degrade to an un-started logger so the
        // hot path drops records with the documented best-effort contract.
        let GatewayAuditStore { pool, dialect } = match connect_gateway_pool_lazy() {
            Ok(store) => store,
            Err(error) => {
                warn!(
                    plugin = PLUGIN_NAME,
                    error = %error,
                    "example_audit_plugin: SQL backend unavailable; audit logger \
                     left un-started and records will be dropped until the next \
                     successful plugin rebuild with a resolvable gateway SQL backend"
                );
                return Ok(());
            }
        };
        let flush_pool = pool.clone();
        let flush_dialect = dialect;
        let logger = BatchingLogger::spawn(self.batch_config, move |batch| {
            let pool = flush_pool.clone();
            async move { insert_batch(&pool, flush_dialect, batch).await }
        });

        let retention_pool = pool.clone();
        let retention_days = self.retention_days;
        let retention_commit = logger.commit_sender().subscribe();
        let retention_task = runtime
            .spawn(async move {
                if !wait_until_committed(retention_commit).await {
                    return;
                }
                run_retention(retention_pool, dialect, retention_days).await;
            })
            .abort_handle();

        // OnceLock::set is idempotent under the start_lock double-check above.
        let _ = self.logger.set(logger);
        let _ = self.retention_task.set(retention_task);

        Ok(())
    }

    fn commit_background_tasks(&self) {
        if let Some(logger) = self.logger.get() {
            logger.commit();
        }
    }

    /// Record each HTTP-family transaction. Buffered handlers await this hook;
    /// hyper-owned streaming bodies invoke it from a spawned terminal task;
    /// native H3 awaits it after body completion. The hot path only enqueues.
    async fn log(&self, summary: &TransactionSummary) {
        self.enqueue_with(|| self.record_from_http(summary));
    }

    /// Record TCP/TLS, UDP/DTLS, and other stream sessions at disconnect.
    /// WebSocket upgraded sessions are covered by the HTTP `log()` hook for
    /// the handshake transaction; this hook covers native stream proxies.
    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.enqueue_with(|| self.record_from_stream(summary));
    }
}

/// Factory function — called automatically by the build-script-generated registry.
/// Must return `Result` so invalid configs are rejected at admission time.
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(ExampleAuditPlugin::new(config)?)))
}

pub fn failure_policy() -> crate::plugins::PluginFailurePolicy {
    // Best-effort telemetry: a bad new config can fall back to the previous
    // generation rather than taking down the proxy. Storage failures at flush
    // time are still only warnings — see the module failure contract.
    crate::plugins::PluginFailurePolicy::OptionalFailOpen
}

/// Database migrations for this plugin.
///
/// Discovered by the build script when this example is opted in via
/// `FERRUM_CUSTOM_PLUGINS`. Applied against the gateway configuration
/// database by migrate mode / `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS`.
///
/// ## Versioning note
///
/// Versions **1** and **2** are retired. An earlier default-compiled revision
/// of this example used the same tracking name (`example_audit_plugin`) with
/// versions 1/2 against a different table (`audit_log`). Reusing those
/// version numbers would leave upgraded deployments with tracking rows but
/// without `example_audit_log`. New installs and upgrades apply **3** / **4**
/// (idempotent `CREATE TABLE IF NOT EXISTS`). Operators may still see a
/// leftover `audit_log` table from the old revision; drop it deliberately if
/// unused.
///
/// ## Guidelines
///
/// - Version numbers are scoped to this plugin (monotonic; 1/2 retired)
/// - Table names are plugin-prefixed (`example_audit_log`) to avoid collisions
/// - The `sql` field is the default SQL used for all databases
/// - Use `sql_postgres` / `sql_mysql` for database-specific overrides
/// - Multi-statement SQL is supported (separate statements with `;`)
/// - MySQL index reconciliation is retry-safe: pair `DROP INDEX` with
///   `CREATE INDEX`; the runner tolerates only a structured missing-key (1091)
///   error on the drop so every retry reconstructs the intended definition
/// - **MySQL contract:** every MySQL custom migration for this plugin,
///   including DML-only migrations, is non-atomic with the tracking insert
///   and must be idempotent / re-runnable (see module docs)
pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
    vec![
        CustomPluginMigration {
            version: 3,
            name: "create_example_audit_log",
            checksum: "v3_create_example_audit_log_7c2b31",
            sql: r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    http_method TEXT,
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status INTEGER,
                    latency_ms REAL NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_context TEXT,
                    connection_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            sql_postgres: Some(
                r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    http_method TEXT,
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status BIGINT,
                    latency_ms DOUBLE PRECISION NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_context TEXT,
                    connection_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            ),
            // MySQL index DDL implicitly commits. Rebuild these plugin-owned
            // indexes from their intended definitions on every retry; the
            // runner tolerates only missing-key 1091 on each DROP INDEX.
            sql_mysql: Some(
                r#"
                CREATE TABLE IF NOT EXISTS example_audit_log (
                    id VARCHAR(255) PRIMARY KEY,
                    timestamp VARCHAR(32) NOT NULL,
                    client_ip VARCHAR(255) NOT NULL,
                    protocol VARCHAR(32) NOT NULL,
                    http_method VARCHAR(256),
                    request_path TEXT,
                    response_status INTEGER,
                    grpc_status BIGINT,
                    latency_ms DOUBLE NOT NULL,
                    consumer_username VARCHAR(255),
                    proxy_id VARCHAR(255),
                    request_context TEXT,
                    connection_error TEXT
                );
                DROP INDEX idx_example_audit_log_timestamp ON example_audit_log;
                CREATE INDEX idx_example_audit_log_timestamp ON example_audit_log (timestamp);
                DROP INDEX idx_example_audit_log_client_ip ON example_audit_log;
                CREATE INDEX idx_example_audit_log_client_ip ON example_audit_log (client_ip)
            "#,
            ),
        },
        CustomPluginMigration {
            version: 4,
            name: "add_status_timestamp_index",
            checksum: "v4_example_audit_status_ts_91e4c6",
            sql: "CREATE INDEX IF NOT EXISTS idx_example_audit_log_status_ts ON example_audit_log (response_status, timestamp)",
            sql_postgres: None,
            sql_mysql: Some(
                "DROP INDEX idx_example_audit_log_status_ts ON example_audit_log; \
                 CREATE INDEX idx_example_audit_log_status_ts ON example_audit_log (response_status, timestamp)",
            ),
        },
    ]
}

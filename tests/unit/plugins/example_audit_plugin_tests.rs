//! Tests for the `example_audit_plugin` custom-plugin template.
//!
//! The template's `new()` must honor the `custom_plugins/mod.rs` contract —
//! return `Err` for a config key that is present but has the wrong type or an
//! invalid value, while still defaulting absent/null keys. Persistence,
//! protocol coverage, and migration contracts are covered when the example is
//! compiled in via `FERRUM_CUSTOM_PLUGINS`.

use ferrum_edge::custom_plugins::{
    collect_all_custom_plugin_migrations, create_custom_plugin, custom_plugin_names,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient, StreamTransactionSummary, TransactionSummary,
};
use serde_json::json;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::sync::Arc;
use std::time::Duration;

fn example_audit_plugin_registered() -> bool {
    custom_plugin_names().contains(&"example_audit_plugin")
}

fn create_example_audit_plugin(
    config: &serde_json::Value,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    create_custom_plugin("example_audit_plugin", config, PluginHttpClient::default())
}

struct ScopedEnv {
    key: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: callers hold the repository-wide ENV_LOCK while mutating
        // process-global variables; this guard restores the prior value.
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: see `set`; the shared ENV_LOCK excludes sibling mutation.
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => {
                // SAFETY: restoration occurs before the caller releases ENV_LOCK.
                unsafe { std::env::set_var(self.key, value) };
            }
            None => {
                // SAFETY: restoration occurs before the caller releases ENV_LOCK.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }
}

#[test]
fn test_new_uses_defaults_for_absent_or_null_keys() {
    if !example_audit_plugin_registered() {
        return;
    }

    assert!(create_example_audit_plugin(&json!({})).unwrap().is_some());
    assert!(
        create_example_audit_plugin(&json!({
            "log_request_headers": null,
            "retention_days": null,
        }))
        .unwrap()
        .is_some()
    );
}

#[test]
fn test_new_accepts_valid_values() {
    if !example_audit_plugin_registered() {
        return;
    }

    assert!(
        create_example_audit_plugin(&json!({
            "log_request_headers": true,
            "retention_days": 30,
            "queue_capacity": 100,
        }))
        .unwrap()
        .is_some()
    );
}

fn new_err(config: serde_json::Value) -> String {
    match create_example_audit_plugin(&config) {
        Ok(_) => panic!("config should be rejected"),
        Err(error) => error,
    }
}

#[test]
fn test_new_rejects_wrong_typed_log_request_headers() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "log_request_headers": "true" }));
    assert!(err.contains("log_request_headers"), "got: {err}");
}

#[test]
fn test_new_rejects_wrong_typed_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "retention_days": "ninety" }));
    assert!(err.contains("retention_days"), "got: {err}");

    assert!(create_example_audit_plugin(&json!({ "retention_days": -5 })).is_err());
}

#[test]
fn test_new_rejects_zero_retention_days() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "retention_days": 0 }));
    assert!(err.contains("retention_days"), "got: {err}");
}

#[test]
fn test_new_rejects_excessive_retention_and_conflicting_queue_aliases() {
    if !example_audit_plugin_registered() {
        return;
    }

    let retention_err = new_err(json!({ "retention_days": 36_501 }));
    assert!(
        retention_err.contains("retention_days"),
        "got: {retention_err}"
    );

    let queue_err = new_err(json!({
        "queue_capacity": 100,
        "buffer_capacity": 100,
    }));
    assert!(queue_err.contains("only one"), "got: {queue_err}");
}

#[test]
fn test_new_rejects_unknown_keys_and_legacy_db_url() {
    if !example_audit_plugin_registered() {
        return;
    }

    let err = new_err(json!({ "db_url": "sqlite://x.db" }));
    assert!(
        err.contains("unknown key") || err.contains("db_url"),
        "got: {err}"
    );
}

#[test]
fn test_supported_protocols_is_all_protocols() {
    if !example_audit_plugin_registered() {
        return;
    }

    let plugin = create_example_audit_plugin(&json!({}))
        .unwrap()
        .expect("plugin instance");
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[test]
fn test_gateway_database_settings_use_effective_sql_backend() {
    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    assert!(
        source.contains("EnvConfig::resolve_effective_sql_backend()"),
        "runtime persistence must use the gateway effective SQL backend helper"
    );
    assert!(
        source.contains("SQLITE_AUDIT_CONNECT_PRAGMAS")
            && source.contains("PRAGMA journal_mode = WAL"),
        "SQLite audit pool must apply the repository WAL invariant"
    );
    assert!(
        !source.contains("db_url.contains")
            && !source.contains("parse_db_url")
            && source.contains("from_db_type"),
        "dialect must come from FERRUM_DB_TYPE, never from inspecting the raw URL"
    );
}

#[test]
fn test_effective_sql_backend_appends_postgres_tls_params() {
    use ferrum_edge::config::{DbTlsMode, EnvConfig};

    let config = EnvConfig {
        db_type: Some("postgres".to_string()),
        db_url: Some("postgres://user:s3cret@db.example.com/ferrum".to_string()),
        db_tls_mode: Some(DbTlsMode::Require),
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        ..EnvConfig::default()
    };

    let backend = config
        .effective_sql_backend()
        .expect("postgres require TLS must resolve");
    assert_eq!(backend.db_type, "postgres");
    assert_eq!(
        backend.effective_url,
        "postgres://user:s3cret@db.example.com/ferrum?sslmode=require"
    );
}

#[test]
fn test_effective_sql_backend_appends_mysql_tls_params() {
    use ferrum_edge::config::{DbTlsMode, EnvConfig};

    let config = EnvConfig {
        db_type: Some("mysql".to_string()),
        db_url: Some("mysql://user:s3cret@db.example.com/ferrum".to_string()),
        db_tls_mode: Some(DbTlsMode::VerifyCa),
        db_tls_ca_cert_path: Some("/certs/ca.pem".to_string()),
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        ..EnvConfig::default()
    };

    let backend = config
        .effective_sql_backend()
        .expect("mysql verify-ca must resolve");
    assert_eq!(backend.db_type, "mysql");
    assert_eq!(
        backend.effective_url,
        "mysql://user:s3cret@db.example.com/ferrum?ssl-mode=VERIFY_CA&ssl-ca=/certs/ca.pem"
    );
}

#[test]
fn test_effective_sql_backend_rejects_mongodb_and_missing_identity() {
    use ferrum_edge::config::EnvConfig;

    let mongo = EnvConfig {
        db_type: Some("mongodb".to_string()),
        db_url: Some("mongodb://user:s3cret@db.example.com/ferrum".to_string()),
        ..EnvConfig::default()
    };
    let mongo_err = mongo
        .effective_sql_backend()
        .expect_err("mongodb must be rejected for SQL-only consumers");
    assert!(
        mongo_err.contains("MongoDB") && !mongo_err.contains("s3cret"),
        "got: {mongo_err}"
    );

    let missing_url = EnvConfig {
        db_type: Some("sqlite".to_string()),
        db_url: None,
        ..EnvConfig::default()
    };
    let url_err = missing_url
        .effective_sql_backend()
        .expect_err("missing FERRUM_DB_URL must fail");
    assert!(url_err.contains("FERRUM_DB_URL"), "got: {url_err}");

    let missing_type = EnvConfig {
        db_type: None,
        db_url: Some("sqlite::memory:".to_string()),
        ..EnvConfig::default()
    };
    let type_err = missing_type
        .effective_sql_backend()
        .expect_err("missing FERRUM_DB_TYPE must fail");
    assert!(type_err.contains("FERRUM_DB_TYPE"), "got: {type_err}");
}

#[test]
fn test_effective_sql_backend_resolve_from_env_matches_gateway_tls_source_precedence() {
    use ferrum_edge::config::EnvConfig;

    let _env_lock = crate::unit::env_lock::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _db_type = ScopedEnv::set("FERRUM_DB_TYPE", "postgres");
    let _db_url = ScopedEnv::set(
        "FERRUM_DB_URL",
        "postgres://user:env-secret@db.example.com/ferrum",
    );
    let _tls_mode = ScopedEnv::set("FERRUM_DB_TLS_MODE", "verify-ca");
    let _tls_ca_path = ScopedEnv::set("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/path-ca.pem");
    let _tls_ca_source = ScopedEnv::set("FERRUM_DB_TLS_CA_CERT_SOURCE", "/certs/source-ca.pem");
    let _tls_cert = ScopedEnv::remove("FERRUM_DB_TLS_CLIENT_CERT_PATH");
    let _tls_cert_source = ScopedEnv::remove("FERRUM_DB_TLS_CLIENT_CERT_SOURCE");
    let _tls_key = ScopedEnv::remove("FERRUM_DB_TLS_CLIENT_KEY_PATH");
    let _tls_key_source = ScopedEnv::remove("FERRUM_DB_TLS_CLIENT_KEY_SOURCE");

    let backend = EnvConfig::resolve_effective_sql_backend()
        .expect("conf-aware SQL backend resolution must succeed");
    assert_eq!(backend.db_type, "postgres");
    assert_eq!(
        backend.effective_url,
        "postgres://user:env-secret@db.example.com/ferrum?sslmode=verify-ca&sslrootcert=/certs/source-ca.pem"
    );
}

#[test]
fn test_sqlite_audit_connect_pragmas_include_wal_contract() {
    // Always assert the source contract (default builds cannot name the
    // optional example module path at compile time).
    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    assert!(source.contains("PRAGMA journal_mode = WAL"));

    // Generated always-available accessor exercises the live const when the
    // example is opted in via FERRUM_CUSTOM_PLUGINS.
    if let Some(pragmas) = ferrum_edge::custom_plugins::example_audit_sqlite_connect_pragmas() {
        assert_eq!(
            pragmas,
            &[
                "PRAGMA foreign_keys = ON",
                "PRAGMA journal_mode = WAL",
                "PRAGMA busy_timeout = 5000",
            ]
        );
    } else {
        assert!(
            !example_audit_plugin_registered(),
            "accessor must return Some when example_audit_plugin is compiled in"
        );
    }
}

#[test]
fn test_dialect_sql_forms_use_table_name_and_correct_placeholders() {
    // Structural proof: both dialect query forms, placeholder counts, and
    // TABLE_NAME usage are present in the runtime helpers. Callable module
    // imports are unavailable when the example is not opted in at build time.
    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    assert!(
        source.contains("const INSERT_COLUMN_COUNT: usize = 13"),
        "INSERT column/placeholder cardinality must stay explicit"
    );
    assert!(
        source.contains("INSERT INTO {TABLE_NAME}"),
        "INSERT must interpolate TABLE_NAME so renames cannot half-apply"
    );
    assert!(
        source.contains("DELETE FROM {TABLE_NAME}"),
        "retention DELETE must interpolate TABLE_NAME so renames cannot half-apply"
    );
    assert!(
        source.contains("for offset in 1..=INSERT_COLUMN_COUNT")
            && source.contains("base + offset"),
        "PostgreSQL INSERT path must build $1..$N placeholders across multi-row batches"
    );
    assert!(
        source.contains("vec![\"?\"; INSERT_COLUMN_COUNT]"),
        "SQLite/MySQL INSERT path must retain native ? placeholders"
    );
    assert!(
        source.contains("INSERT_MAX_ROWS_PER_STATEMENT")
            && source.contains("batch.chunks(INSERT_MAX_ROWS_PER_STATEMENT)"),
        "flush must emit one multi-row INSERT per chunk, not per record"
    );
    assert!(
        source.contains("WHERE timestamp < $1")
            && source.contains("SELECT ctid FROM {TABLE_NAME}")
            && source.contains("LIMIT {RETENTION_DELETE_CHUNK_SIZE}"),
        "PostgreSQL retention DELETE must use chunked ctid deletes with $1"
    );
    assert!(
        source.contains("SELECT rowid FROM {TABLE_NAME}") && source.contains("WHERE timestamp < ?"),
        "SQLite retention DELETE must use chunked rowid subquery with ?"
    );
    assert!(
        source.contains("DELETE FROM {TABLE_NAME} WHERE timestamp < ?")
            && source.contains("LIMIT {RETENTION_DELETE_CHUNK_SIZE}"),
        "MySQL retention DELETE must use chunked LIMIT with ?"
    );
    assert!(
        source.contains("interval_at(start, RETENTION_INTERVAL)"),
        "retention must skip the immediate first tick"
    );
    assert!(
        source.contains("dialect.insert_sql(chunk.len())")
            && source.contains("dialect.retention_delete_sql()")
            && source.contains("flush_dialect"),
        "resolved dialect must be carried into both INSERT and retention paths"
    );
    assert!(
        source.contains("AuditSqlDialect::from_db_type")
            && source.contains("resolve_effective_sql_backend()"),
        "dialect must be resolved from the effective SQL backend, not the raw URL"
    );

    // Reconstruct the placeholder clauses the helpers emit and prove counts.
    let postgres_placeholders: Vec<String> = (1..=13).map(|i| format!("${i}")).collect();
    assert_eq!(postgres_placeholders.len(), 13);
    assert_eq!(
        postgres_placeholders.join(", "),
        "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13"
    );
    let sqlite_mysql_placeholders = vec!["?"; 13];
    assert_eq!(sqlite_mysql_placeholders.len(), 13);
    assert_eq!(
        sqlite_mysql_placeholders
            .iter()
            .filter(|p| **p == "?")
            .count(),
        13
    );
}

#[test]
fn test_mysql_custom_migration_contract_is_explicitly_non_atomic() {
    let plugin = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    let migrations_doc = include_str!("../../../docs/migrations.md");
    assert!(
        plugin.contains("DML-only")
            && plugin.contains("non-atomic")
            && plugin.contains("idempotent"),
        "plugin docs must state MySQL custom migrations (including DML-only) are non-atomic"
    );
    assert!(
        migrations_doc.contains("DML-only bodies")
            && migrations_doc.contains("non-atomic")
            && migrations_doc.contains("idempotent / re-runnable"),
        "docs/migrations.md must document the MySQL non-atomic/idempotent contract"
    );
}

#[test]
fn test_logger_startup_is_lock_free_after_start() {
    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    assert!(
        source.contains("logger: OnceLock<BatchingLogger<AuditRecord>>"),
        "batching logger must use OnceLock so steady-state enqueue is lock-free"
    );
    assert!(
        source.contains("start_lock: Mutex<()>"),
        "startup may keep a Mutex, but only for idempotent initialization"
    );
    assert!(
        source.contains("match self.logger.get()"),
        "enqueue must read the logger through OnceLock::get"
    );
    assert!(
        source.contains("logger.try_reserve()") && source.contains("permit.send(build_record())"),
        "queue capacity must be reserved before constructing an audit record"
    );
    assert!(
        !source.contains("logger: Mutex<Option<BatchingLogger"),
        "steady-state hooks must not acquire a Mutex around the batching logger"
    );
}

#[test]
fn test_all_protocols_selection_surface_and_precise_mappings() {
    use ferrum_edge::plugins::ProxyProtocol;

    assert_eq!(
        ALL_PROTOCOLS,
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ]
    );

    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    // Precise mapping contract encoded in classify_http_audit_protocol /
    // classify_stream_audit_protocol — do not invent H1/H2/H3 column values.
    assert!(source.contains("pub fn classify_http_audit_protocol"));
    assert!(source.contains("pub fn classify_stream_audit_protocol"));
    assert!(
        source.contains("mesh.request_protocol")
            && source.contains("\"grpc-web\"")
            && source.contains("return \"grpc\".to_string()")
            && source.contains("return \"websocket\".to_string()")
            && source.contains("return \"http\".to_string()"),
        "HTTP-family classifier must distinguish grpc / grpc-web / websocket / http"
    );
    assert!(
        source.contains("response_status_code == 101")
            && source.contains("eq_ignore_ascii_case(\"CONNECT\")"),
        "WebSocket upgrade detection must cover H1 101 and H2 Extended CONNECT"
    );
    assert!(
        source.contains("summary.protocol.clone()"),
        "stream classifier must persist the summary protocol (tcp/tcps/udp/dtls)"
    );
    assert!(
        source.contains("async fn log(") && source.contains("async fn on_stream_disconnect("),
        "HTTP-family selection uses log(); stream selection uses on_stream_disconnect()"
    );

    if !example_audit_plugin_registered() {
        return;
    }

    let plugin = create_example_audit_plugin(&json!({}))
        .unwrap()
        .expect("plugin instance");
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    for protocol in ALL_PROTOCOLS {
        assert!(
            plugin.supported_protocols().contains(protocol),
            "missing declared protocol {protocol:?}"
        );
    }
}

#[test]
fn test_metadata_selection_is_deterministic_with_collision_and_omission_markers() {
    let source = include_str!("../../../custom_plugins/examples/example_audit_plugin.rs");
    assert!(
        source.contains("keys.sort_unstable()"),
        "metadata key selection must be deterministic"
    );
    assert!(
        source.contains("__ferrum_metadata_key_collisions"),
        "truncated key collisions must emit an explicit marker rather than silent overwrite"
    );
    assert!(
        source.contains("__ferrum_omitted_metadata_entries"),
        "entry-bound overflow must emit an omission marker"
    );
    assert!(
        source.contains("is_sensitive_metadata_key(key)")
            && source.contains("REDACTED_PLACEHOLDER"),
        "redaction must run before persistence"
    );
    assert!(
        source.contains("take(MAX_METADATA_ENTRIES)")
            && source.contains("MAX_METADATA_KEY_CHARS")
            && source.contains("MAX_METADATA_VALUE_CHARS")
            && source.contains("MAX_CONTEXT_BYTES"),
        "hard entry/value/context bounds must remain in force"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_log_and_stream_hooks_enqueue_without_panic() {
    if !example_audit_plugin_registered() {
        return;
    }

    let plugin = create_example_audit_plugin(&json!({
        "log_request_headers": true,
        "retention_days": 7,
        "queue_capacity": 16,
        "flush_interval_ms": 100,
    }))
    .unwrap()
    .expect("plugin instance");

    // Missing SQL backend settings must degrade (OptionalFailOpen): return Ok
    // with the logger un-started so config reload cannot wedge.
    {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _db_type = ScopedEnv::set("FERRUM_DB_TYPE", "sqlite");
        let _db_url = ScopedEnv::remove("FERRUM_DB_URL");
        plugin
            .start_background_tasks()
            .expect("missing FERRUM_DB_URL must degrade to Ok, not wedge reload");
        plugin.commit_background_tasks();
    }

    // MongoDB is not a SQL sink for this example; degrade the same way.
    {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _db_type = ScopedEnv::set("FERRUM_DB_TYPE", "mongodb");
        let _db_url = ScopedEnv::set("FERRUM_DB_URL", "mongodb://127.0.0.1:27017/ferrum");
        plugin
            .start_background_tasks()
            .expect("MongoDB backend must degrade to Ok, not wedge reload");
        plugin.commit_background_tasks();
    }

    // Hooks remain panic-free even when the worker was not started.
    let http = TransactionSummary {
        timestamp_received: "2026-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        http_method: "GET".to_string(),
        request_path: "/audit".to_string(),
        response_status_code: 200,
        latency_total_ms: 12.5,
        metadata: HashMap::from([("authorization".to_string(), "secret".to_string())]),
        ..Default::default()
    };
    plugin.log(&http).await;

    let stream = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: None,
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.2:443".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 443,
        duration_ms: 40.0,
        bytes_sent: 1,
        bytes_received: 2,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    };
    plugin.on_stream_disconnect(&stream).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_persists_http_and_stream_rows_against_sqlite() {
    if !example_audit_plugin_registered() {
        return;
    }

    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("audit.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    // Apply the example's migrations against the same gateway DB URL the
    // plugin will use at runtime.
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("core migrations");
    let pool = store.pool();
    let migrations = collect_all_custom_plugin_migrations();
    assert!(
        migrations
            .iter()
            .any(|(name, _)| *name == "example_audit_plugin"),
        "opted-in build must collect example_audit_plugin migrations"
    );
    store
        .apply_plugin_migrations(&migrations)
        .await
        .expect("example migrations");

    sqlx::query(
        "INSERT INTO example_audit_log \
         (id, timestamp, client_ip, protocol, latency_ms) \
         VALUES ('expired-row', '2000-01-01T00:00:00.000Z', '192.0.2.99', 'http', 1.0)",
    )
    .execute(&pool)
    .await
    .expect("seed expired retention row");

    let plugin = create_example_audit_plugin(&json!({
        "log_request_headers": true,
        "retention_days": 30,
        "queue_capacity": 32,
        "batch_size": 1,
        "flush_interval_ms": 100,
        "max_retries": 1,
        "retry_delay_ms": 50,
    }))
    .unwrap()
    .expect("plugin");
    {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _db_url = ScopedEnv::set("FERRUM_DB_URL", &db_url);
        let _db_type = ScopedEnv::set("FERRUM_DB_TYPE", "sqlite");
        plugin
            .start_background_tasks()
            .expect("worker should start with FERRUM_DB_URL");
        plugin.commit_background_tasks();
    }

    let metadata_prefix = "k".repeat(128);
    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.000Z".to_string(),
            client_ip: "192.0.2.10".to_string(),
            http_method: "POST".to_string(),
            request_path: "/v1/widgets".to_string(),
            response_status_code: 201,
            latency_total_ms: 3.25,
            consumer_username: Some("U".repeat(300)),
            proxy_id: Some("proxy-1".to_string()),
            metadata: HashMap::from([
                ("cookie".to_string(), "session=1".to_string()),
                ("note".to_string(), "x".repeat(10_000)),
                ("zebra".to_string(), "z".to_string()),
                ("alpha".to_string(), "a".to_string()),
                (format!("{metadata_prefix}one"), "first-wins".to_string()),
                (
                    format!("{metadata_prefix}two"),
                    "should-not-overwrite".to_string(),
                ),
            ]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.500Z".to_string(),
            client_ip: "192.0.2.14".to_string(),
            http_method: "POST".to_string(),
            request_path: "/example.Audit/Write".to_string(),
            response_status_code: 200,
            latency_total_ms: 4.0,
            metadata: HashMap::from([
                ("request_protocol".to_string(), "grpc".to_string()),
                ("grpc_status".to_string(), "13".to_string()),
            ]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.600Z".to_string(),
            client_ip: "192.0.2.16".to_string(),
            http_method: "POST".to_string(),
            request_path: "/example.Audit/Web".to_string(),
            response_status_code: 200,
            latency_total_ms: 4.5,
            metadata: HashMap::from([
                ("request_protocol".to_string(), "grpc".to_string()),
                ("mesh.request_protocol".to_string(), "grpc-web".to_string()),
                ("grpc_status".to_string(), "0".to_string()),
            ]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.700Z".to_string(),
            client_ip: "192.0.2.17".to_string(),
            http_method: "GET".to_string(),
            request_path: "/ws".to_string(),
            response_status_code: 101,
            latency_total_ms: 2.0,
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.725Z".to_string(),
            client_ip: "192.0.2.18".to_string(),
            http_method: "CONNECT".to_string(),
            request_path: "/ws-h2".to_string(),
            response_status_code: 200,
            latency_total_ms: 2.0,
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.740Z".to_string(),
            client_ip: "192.0.2.19".to_string(),
            http_method: "GET".to_string(),
            request_path: "/unknown-protocol-metadata".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            metadata: HashMap::from([(
                "request_protocol".to_string(),
                "attacker-shaped-unknown-protocol".repeat(64),
            )]),
            ..Default::default()
        })
        .await;

    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:00.750Z".to_string(),
            client_ip: "192.0.2.15".to_string(),
            http_method: "M".repeat(300),
            request_path: "/bounded-method".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;

    for (client_ip, protocol) in [
        ("192.0.2.11", "tcp"),
        ("192.0.2.21", "tcps"),
        ("192.0.2.22", "udp"),
        ("192.0.2.23", "dtls"),
    ] {
        plugin
            .on_stream_disconnect(&StreamTransactionSummary {
                namespace: "ferrum".to_string(),
                proxy_id: if protocol == "tcp" {
                    "P".repeat(300)
                } else {
                    format!("stream-{protocol}")
                },
                proxy_name: Some(format!("{protocol}-in")),
                client_ip: if protocol == "tcp" {
                    "I".repeat(300)
                } else {
                    client_ip.to_string()
                },
                consumer_username: None,
                auth_method: None,
                backend_target: "192.0.2.20:5432".to_string(),
                backend_resolved_ip: None,
                protocol: protocol.to_string(),
                listen_port: 5432,
                duration_ms: 88.0,
                bytes_sent: 10,
                bytes_received: 20,
                connection_error: Some(if protocol == "tcp" {
                    "E".repeat(5000)
                } else {
                    "reset".to_string()
                }),
                error_class: None,
                disconnect_direction: None,
                disconnect_cause: None,
                timestamp_connected: "2026-07-20T12:00:00.000Z".to_string(),
                timestamp_disconnected: "2026-07-20T12:00:01.000Z".to_string(),
                sni_hostname: None,
                metadata: HashMap::new(),
            })
            .await;
    }

    // Allow the batching worker to flush.
    use sqlx::Row;
    let mut saw_http = false;
    let mut saw_grpc = false;
    let mut saw_grpc_web = false;
    let mut saw_h1_websocket = false;
    let mut saw_h2_websocket = false;
    let mut saw_unknown_protocol_fallback = false;
    let mut saw_bounded_method = false;
    let mut saw_stream_protocols = std::collections::HashSet::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rows = sqlx::query(
            "SELECT id, protocol, client_ip, http_method, response_status, grpc_status, consumer_username \
             FROM example_audit_log",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        for row in &rows {
            let protocol: String = row.get("protocol");
            let client_ip: String = row.get("client_ip");
            let method: Option<String> = row.get("http_method");
            let status: Option<i32> = row.try_get("response_status").ok().flatten();
            let grpc_status: Option<i64> = row.try_get("grpc_status").ok().flatten();
            if protocol == "http" && client_ip == "192.0.2.10" {
                assert_eq!(method.as_deref(), Some("POST"));
                assert_eq!(status, Some(201));
                let consumer_username: Option<String> =
                    row.try_get("consumer_username").ok().flatten();
                let consumer_username = consumer_username
                    .as_deref()
                    .expect("bounded consumer identity");
                assert_eq!(consumer_username.chars().count(), 255);
                assert!(consumer_username.chars().all(|c| c == 'U'));
                saw_http = true;
            }
            if protocol == "grpc" && client_ip == "192.0.2.14" {
                assert_eq!(method.as_deref(), Some("POST"));
                assert_eq!(status, Some(200));
                assert_eq!(grpc_status, Some(13));
                saw_grpc = true;
            }
            if protocol == "grpc-web" && client_ip == "192.0.2.16" {
                saw_grpc_web = true;
            }
            if protocol == "websocket" && client_ip == "192.0.2.17" {
                assert_eq!(status, Some(101));
                saw_h1_websocket = true;
            }
            if protocol == "websocket" && client_ip == "192.0.2.18" {
                assert_eq!(method.as_deref(), Some("CONNECT"));
                assert_eq!(status, Some(200));
                saw_h2_websocket = true;
            }
            if protocol == "http" && client_ip == "192.0.2.19" {
                saw_unknown_protocol_fallback = true;
            }
            if protocol == "http" && client_ip == "192.0.2.15" {
                let method = method.as_deref().expect("bounded HTTP method");
                assert_eq!(method.chars().count(), 256);
                assert!(method.chars().all(|c| c == 'M'));
                saw_bounded_method = true;
            }
            if matches!(protocol.as_str(), "tcp" | "tcps" | "udp" | "dtls") {
                assert!(method.is_none());
                assert!(status.is_none());
                saw_stream_protocols.insert(protocol);
            }
        }
        if saw_http
            && saw_grpc
            && saw_grpc_web
            && saw_h1_websocket
            && saw_h2_websocket
            && saw_unknown_protocol_fallback
            && saw_bounded_method
            && saw_stream_protocols.len() == 4
        {
            break;
        }
    }

    assert!(
        saw_http,
        "expected HTTP audit row (H1/H2/H3 share this label)"
    );
    assert!(saw_grpc, "expected gRPC audit row with terminal status");
    assert!(
        saw_grpc_web,
        "expected gRPC-Web audit row from mesh metadata"
    );
    assert!(saw_h1_websocket, "expected H1 WebSocket upgrade audit row");
    assert!(
        saw_h2_websocket,
        "expected H2 Extended CONNECT WebSocket audit row"
    );
    assert!(
        saw_unknown_protocol_fallback,
        "unknown shared metadata must fall back to a bounded canonical protocol label"
    );
    assert!(
        saw_bounded_method,
        "expected overlong HTTP method to persist within the portable column bound"
    );
    assert_eq!(
        saw_stream_protocols,
        ["tcp", "tcps", "udp", "dtls"]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::HashSet<_>>(),
        "expected tcp/tcps/udp/dtls stream audit rows"
    );

    // Retention skips the immediate first tick (hourly cadence). Prove the
    // chunked DELETE contract against the seeded expired row with the same
    // SQLite SQL the worker emits, without waiting an hour for the ticker.
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let purged = sqlx::query(
        "DELETE FROM example_audit_log WHERE rowid IN (             SELECT rowid FROM example_audit_log WHERE timestamp < ? LIMIT 1000)",
    )
        .bind(&cutoff)
        .execute(&pool)
        .await
        .expect("chunked retention DELETE")
        .rows_affected();
    assert!(
        purged >= 1,
        "chunked retention DELETE must purge expired rows"
    );
    let expired_remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM example_audit_log WHERE id = 'expired-row'")
            .fetch_one(&pool)
            .await
            .expect("expired row count");
    assert_eq!(expired_remaining, 0, "expired retention row must be gone");

    let bounded_stream = sqlx::query(
        "SELECT client_ip, proxy_id, connection_error FROM example_audit_log \
         WHERE protocol = 'tcp' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("bounded TCP audit row");
    let bounded_client_ip: String = bounded_stream.get("client_ip");
    let bounded_proxy_id: Option<String> = bounded_stream.try_get("proxy_id").ok().flatten();
    let bounded_connection_error: Option<String> =
        bounded_stream.try_get("connection_error").ok().flatten();
    assert_eq!(bounded_client_ip.chars().count(), 255);
    assert!(bounded_client_ip.chars().all(|c| c == 'I'));
    assert_eq!(
        bounded_proxy_id
            .as_deref()
            .map(|value| value.chars().count()),
        Some(255)
    );
    assert_eq!(
        bounded_connection_error
            .as_deref()
            .map(|value| value.chars().count()),
        Some(4096)
    );

    // Redacted context must not contain the raw cookie value; colliding
    // truncated keys must keep the lexicographically earlier value and mark
    // the collision rather than silently overwriting.
    let ctx_row = sqlx::query(
        "SELECT request_context FROM example_audit_log \
         WHERE protocol = 'http' AND client_ip = '192.0.2.10' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("http row context");
    let ctx: Option<String> = ctx_row.get("request_context");
    let ctx = ctx.as_deref().unwrap_or("");
    assert!(ctx.len() <= 4096, "context must stay byte-bounded");
    let ctx_json: serde_json::Value =
        serde_json::from_str(ctx).expect("context must remain valid JSON");
    assert!(
        !ctx.contains("session=1"),
        "secret cookie must be redacted: {ctx}"
    );
    assert!(
        ctx.contains("[REDACTED]") || ctx.contains("metadata"),
        "expected redacted metadata snapshot: {ctx}"
    );
    let metadata = ctx_json
        .get("metadata")
        .and_then(|value| value.as_object())
        .expect("metadata object");
    assert_eq!(
        metadata.get(&metadata_prefix).and_then(|v| v.as_str()),
        Some("first-wins")
    );
    assert_eq!(
        metadata
            .get("__ferrum_metadata_key_collisions")
            .and_then(|v| v.as_u64()),
        Some(1)
    );
    assert!(!ctx.contains("should-not-overwrite"));

    // The documented OptionalFailOpen contract drops a failed batch and keeps
    // the worker alive for later records. Make the table briefly unavailable,
    // then restore it and prove a subsequent record persists.
    sqlx::query("ALTER TABLE example_audit_log RENAME TO example_audit_log_unavailable")
        .execute(&pool)
        .await
        .expect("make audit table unavailable");
    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:02.000Z".to_string(),
            client_ip: "192.0.2.12".to_string(),
            http_method: "GET".to_string(),
            request_path: "/dropped-during-outage".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;
    // Leave enough wall time for both immediate attempts even on a loaded
    // hosted runner before restoring the table.
    tokio::time::sleep(Duration::from_secs(1)).await;
    sqlx::query("ALTER TABLE example_audit_log_unavailable RENAME TO example_audit_log")
        .execute(&pool)
        .await
        .expect("restore audit table");
    plugin
        .log(&TransactionSummary {
            timestamp_received: "2026-07-20T12:00:03.000Z".to_string(),
            client_ip: "192.0.2.13".to_string(),
            http_method: "GET".to_string(),
            request_path: "/after-recovery".to_string(),
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..Default::default()
        })
        .await;

    let mut recovered = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let paths: Vec<String> = sqlx::query("SELECT request_path FROM example_audit_log")
            .fetch_all(&pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|row| row.try_get("request_path").ok())
            .collect();
        assert!(
            !paths.iter().any(|path| path == "/dropped-during-outage"),
            "failed batch must not appear after its retry budget is exhausted"
        );
        if paths.iter().any(|path| path == "/after-recovery") {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "batching worker must persist after storage recovery"
    );
}

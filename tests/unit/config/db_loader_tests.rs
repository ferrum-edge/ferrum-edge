use ferrum_edge::_test_support::{
    DbPoolConfig, SqlReconnectTopology, SqlReconnectTransitionTestHooks,
    await_pool_connect_with_timeout, database_store_reconnect_as_failover_for_test,
    database_store_set_reconnect_transition_hooks_for_test, db_code_is_transient, db_diff_removed,
    db_mongo_error_is_transient, db_mysql_error_number_is_transient,
    db_wrap_mysql_isolation_read_error, effective_pool_connect_timeout_seconds,
    is_config_validation_rejection, lock_wait_timeout_sql, mysql_config_change_lock_insert_sql,
    mysql_mtls_dns_admission_lock_insert_sql, mysql_proxy_route_lock_insert_sql, parse_auth_mode,
    parse_scheme, statement_timeout_sql, validate_tcp_connection_throttle_attachments,
};
use ferrum_edge::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, checked_next_config_topology_epoch,
    is_incremental_full_reload_required, is_mtls_dns_admission_unavailable,
    is_mtls_dns_identity_conflict, tcp_connection_throttle_attachment_conflict,
};
use ferrum_edge::config::db_loader::{
    DatabaseStore, is_retryable_sql_transaction_conflict, sqlite_code_is_retryable_write_conflict,
    sqlstate_is_retryable_transaction_conflict,
};
use ferrum_edge::config::namespace_registry::{
    NAMESPACE_RENAME_COPY_TABLES, NAMESPACE_RENAME_SIMPLE_TABLES, NamespaceRegistryCorrupt,
};
use ferrum_edge::config::plugin_trigger::PluginTrigger;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, LoadBalancerAlgorithm, PluginAssociation, PluginConfig,
    PluginScope, Proxy, Upstream, UpstreamTarget,
};
use serde_json::json;
use sqlx::error::{DatabaseError, ErrorKind};
use std::borrow::Cow;
use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Debug)]
struct TestDatabaseError {
    code: &'static str,
}

impl fmt::Display for TestDatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "test database error {}", self.code)
    }
}

impl StdError for TestDatabaseError {}

impl DatabaseError for TestDatabaseError {
    fn message(&self) -> &str {
        "test database error"
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.code))
    }

    fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

#[test]
fn mysql_mtls_dns_lock_insert_takes_an_exclusive_duplicate_key_lock() {
    let sql = mysql_mtls_dns_admission_lock_insert_sql();
    assert!(sql.contains("ON DUPLICATE KEY UPDATE"), "{sql}");
    assert!(
        sql.contains("updated_at = mtls_dns_admission_locks.updated_at"),
        "{sql}"
    );
    assert!(!sql.contains("INSERT IGNORE"), "{sql}");
}

#[test]
fn mysql_config_change_lock_insert_takes_an_exclusive_duplicate_key_lock() {
    let sql = mysql_config_change_lock_insert_sql();
    assert!(sql.contains("ON DUPLICATE KEY UPDATE"), "{sql}");
    assert!(
        sql.contains("updated_at = config_change_locks.updated_at"),
        "{sql}"
    );
    assert!(!sql.contains("INSERT IGNORE"), "{sql}");
}

#[test]
fn mysql_proxy_route_lock_insert_takes_an_exclusive_duplicate_key_lock() {
    let sql = mysql_proxy_route_lock_insert_sql();
    assert!(sql.contains("ON DUPLICATE KEY UPDATE"), "{sql}");
    assert!(
        sql.contains("created_at = proxy_route_locks.created_at"),
        "{sql}"
    );
    assert!(!sql.contains("INSERT IGNORE"), "{sql}");
}

#[test]
fn mysql_sequence_and_route_lock_helpers_skip_redundant_for_update() {
    // The MySQL upsert already holds X. A follow-up SELECT ... FOR UPDATE on
    // those paths is both redundant and the historical S->X deadlock shape.
    let source = include_str!("../../../src/config/db_loader.rs");
    let config_change = source
        .split("async fn lock_config_change_sequence_tx(")
        .nth(1)
        .and_then(|rest| {
            rest.split("async fn lock_config_change_sequences_tx(")
                .next()
        })
        .expect("lock_config_change_sequence_tx body");
    assert!(
        config_change.contains("db_type != \"mysql\""),
        "MySQL must be excluded from the config_change FOR UPDATE path:\n{config_change}"
    );
    assert!(
        config_change.contains("FOR UPDATE"),
        "PostgreSQL config_change lock path must retain SELECT ... FOR UPDATE:\n{config_change}"
    );
    assert!(
        config_change.contains(".bind(namespace)"),
        "config-change sequence lock must key the row by namespace:\n{config_change}"
    );
    assert!(
        !config_change.contains("CONFIG_CHANGE_LOCK_NAME"),
        "the global lock-name constant must not remain on the sequence lock path:\n{config_change}"
    );

    let proxy_route = source
        .split("async fn lock_proxy_route_bucket_tx(")
        .nth(1)
        .and_then(|rest| {
            rest.split("async fn lock_config_change_sequence_tx(")
                .next()
        })
        .expect("lock_proxy_route_bucket_tx body");
    assert!(
        proxy_route.contains("db_type != \"mysql\""),
        "MySQL must be excluded from the proxy_route FOR UPDATE path:\n{proxy_route}"
    );
    // PostgreSQL still needs FOR UPDATE after INSERT ... DO NOTHING.
    assert!(
        proxy_route.contains("FOR UPDATE"),
        "PostgreSQL proxy_route lock path must retain SELECT ... FOR UPDATE:\n{proxy_route}"
    );
}

fn make_upstream(id: &str) -> Upstream {
    Upstream {
        labels: Default::default(),
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("tls-upstream".to_string()),
        targets: vec![UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: Default::default(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: Default::default(),
        source_locality: None,
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: Default::default(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        labels: Default::default(),
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_http_proxy(id: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "hosts": [format!("{id}.test")],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .unwrap()
}

fn make_tcp_proxy(id: &str, listen_port: u16) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "backend_scheme": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": 9000,
        "listen_port": listen_port
    }))
    .unwrap()
}

fn make_global_tcp_throttle(id: &str) -> PluginConfig {
    let now = chrono::Utc::now();
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        plugin_name: "tcp_connection_throttle".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({"max_connections_per_key": 10}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

// ── await_pool_connect_with_timeout ──────────────────────────────────────────
//
// Deterministic coverage for FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS: drive the
// shared helper with gated / never-ready futures under tokio's paused clock
// instead of blackhole networking.

struct DropTrack(Arc<AtomicBool>);

impl Drop for DropTrack {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn pool_connect_timeout_fires_on_never_ready_future_without_wall_clock() {
    let task = tokio::spawn(async {
        await_pool_connect_with_timeout(2, std::future::pending::<Result<(), sqlx::Error>>()).await
    });
    // Arm the timeout waiter before advancing paused time.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    let err = task
        .await
        .expect("join")
        .expect_err("never-ready connect must time out");
    match err {
        sqlx::Error::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::TimedOut);
            let message = io_err.to_string();
            assert!(
                message.contains("database pool connect timed out after 2s"),
                "timeout message must be non-secret and stable: {message}"
            );
            assert!(
                !message.contains("postgres://")
                    && !message.contains("mysql://")
                    && !message.contains("password"),
                "timeout must not embed DSN/credentials: {message}"
            );
        }
        other => panic!("expected Io(TimedOut), got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn pool_connect_timeout_drops_hung_connect_future() {
    let dropped = Arc::new(AtomicBool::new(false));
    let track = DropTrack(Arc::clone(&dropped));
    let task = tokio::spawn(async move {
        await_pool_connect_with_timeout(1, async move {
            let _track = track;
            std::future::pending::<Result<(), sqlx::Error>>().await
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    let _ = task.await.expect("join");
    assert!(
        dropped.load(Ordering::SeqCst),
        "timeout must drop the connect future (no detached attempt)"
    );
}

#[tokio::test(start_paused = true)]
async fn pool_connect_completes_when_gated_future_ready_before_timeout() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        await_pool_connect_with_timeout(5, async move {
            rx.await.map_err(|_| sqlx::Error::WorkerCrashed)?;
            Ok(())
        })
        .await
    });
    tokio::task::yield_now().await;
    tx.send(()).expect("gate open");
    tokio::task::yield_now().await;

    assert!(
        task.await.expect("join").is_ok(),
        "gated success before the bound must not time out"
    );
}

#[tokio::test]
async fn pool_connect_timeout_zero_waits_for_gated_success() {
    // `0` disables the Ferrum bound; the future must still be awaitable.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        await_pool_connect_with_timeout(0, async move {
            rx.await.map_err(|_| sqlx::Error::WorkerCrashed)?;
            Ok::<(), sqlx::Error>(())
        })
        .await
    });
    tx.send(()).expect("gate open");
    assert!(
        task.await.expect("join").is_ok(),
        "timeout_seconds=0 must await the connect future without a Ferrum bound"
    );
}

#[tokio::test(start_paused = true)]
async fn pool_connect_timeout_error_stays_transient_for_failover() {
    let task = tokio::spawn(async {
        await_pool_connect_with_timeout(1, std::future::pending::<Result<(), sqlx::Error>>()).await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    let err = anyhow::Error::new(task.await.expect("join").expect_err("timed out"));
    assert!(
        !DatabaseStore::is_non_transient_init_error(
            &DatabaseStore::classify_initial_config_load_error(err)
        ),
        "Io(TimedOut) connect bound must remain backup/failover eligible"
    );
}

#[test]
fn pool_connect_timeout_only_applies_to_network_sql_backends() {
    assert_eq!(effective_pool_connect_timeout_seconds("postgres", 10), 10);
    assert_eq!(effective_pool_connect_timeout_seconds("mysql", 10), 10);
    assert_eq!(effective_pool_connect_timeout_seconds("sqlite", 10), 0);
    assert_eq!(effective_pool_connect_timeout_seconds("postgres", 0), 0);
}

// ── DbPoolConfig defaults ────────────────────────────────────────────────────

#[test]
fn test_db_pool_config_default() {
    let config = DbPoolConfig::default();
    assert_eq!(config.max_connections, 32);
    assert_eq!(config.min_connections, 1);
    assert_eq!(config.acquire_timeout_seconds, 30);
    assert_eq!(config.idle_timeout_seconds, 600);
    assert_eq!(config.max_lifetime_seconds, 300);
    assert_eq!(config.connect_timeout_seconds, 10);
    assert_eq!(config.statement_timeout_seconds, 30);
}

// ── diff_removed ─────────────────────────────────────────────────────────────

#[test]
fn test_diff_removed_empty_sets() {
    let known = HashSet::new();
    let current = HashSet::new();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_no_deletions() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current = known.clone();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_all_deleted() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current = HashSet::new();
    let mut removed = db_diff_removed(&known, &current);
    removed.sort();
    assert_eq!(removed, vec!["a", "b", "c"]);
}

#[test]
fn test_diff_removed_partial_deletion() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
    let removed = db_diff_removed(&known, &current);
    assert_eq!(removed, vec!["b"]);
}

#[test]
fn test_diff_removed_current_has_new_ids() {
    let known: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["a", "b", "d", "e"].iter().map(|s| s.to_string()).collect();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_known_empty_current_has_items() {
    let known = HashSet::new();
    let current: HashSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
    assert!(db_diff_removed(&known, &current).is_empty());
}

#[test]
fn test_diff_removed_mixed_additions_and_deletions() {
    let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let current: HashSet<String> = ["b", "d", "e"].iter().map(|s| s.to_string()).collect();
    let mut removed = db_diff_removed(&known, &current);
    removed.sort();
    assert_eq!(removed, vec!["a", "c"]);
}

// ── parse_scheme ─────────────────────────────────────────────────────────────

#[test]
fn test_parse_scheme_known_values() {
    assert!(matches!(parse_scheme("http").unwrap(), BackendScheme::Http));
    assert!(matches!(
        parse_scheme("https").unwrap(),
        BackendScheme::Https
    ));
    assert!(matches!(parse_scheme("tcp").unwrap(), BackendScheme::Tcp));
    assert!(matches!(parse_scheme("tcps").unwrap(), BackendScheme::Tcps));
    assert!(matches!(parse_scheme("udp").unwrap(), BackendScheme::Udp));
    assert!(matches!(parse_scheme("dtls").unwrap(), BackendScheme::Dtls));
}

#[test]
fn test_parse_scheme_case_insensitive() {
    assert!(matches!(
        parse_scheme("HTTPS").unwrap(),
        BackendScheme::Https
    ));
    assert!(matches!(parse_scheme("TCPS").unwrap(), BackendScheme::Tcps));
}

#[test]
fn test_parse_scheme_rejects_unknown_or_removed_aliases() {
    for value in [
        "ftp", "", "nonsense", "ws", "wss", "grpc", "grpcs", "h3", "tcp_tls",
    ] {
        let err = parse_scheme(value).expect_err(&format!(
            "{value:?} should not be accepted as backend_scheme"
        ));
        assert!(
            !err.contains(value) || value.is_empty(),
            "scheme rejection must not embed the raw column body: {err}"
        );
        assert!(
            err.contains("unsupported backend_scheme"),
            "scheme rejection must stay actionable: {err}"
        );
    }
}

// ── parse_auth_mode ──────────────────────────────────────────────────────────

#[test]
fn test_parse_auth_mode_known_values() {
    assert!(matches!(parse_auth_mode("single"), AuthMode::Single));
    assert!(matches!(parse_auth_mode("multi"), AuthMode::Multi));
}

#[test]
fn test_parse_auth_mode_case_insensitive() {
    assert!(matches!(parse_auth_mode("MULTI"), AuthMode::Multi));
    assert!(matches!(parse_auth_mode("Single"), AuthMode::Single));
}

#[test]
fn test_parse_auth_mode_unknown_defaults_to_single() {
    assert!(matches!(parse_auth_mode("unknown"), AuthMode::Single));
    assert!(matches!(parse_auth_mode(""), AuthMode::Single));
}

// ── statement_timeout_sql ───────────────────────────────────────────────────

#[test]
fn test_statement_timeout_sql_zero_disables() {
    // 0 = disabled — no SET emitted for any database type.
    assert_eq!(statement_timeout_sql(0, true, false), None);
    assert_eq!(statement_timeout_sql(0, false, true), None);
    assert_eq!(statement_timeout_sql(0, false, false), None);
}

#[test]
fn test_statement_timeout_sql_postgres_unquoted_numeric() {
    // PostgreSQL: unquoted numeric milliseconds.
    let sql = statement_timeout_sql(30, true, false).unwrap();
    assert_eq!(sql, "SET statement_timeout = 30000");
}

#[test]
fn test_statement_timeout_sql_postgres_at_max() {
    // 3600 s = 3_600_000 ms — the maximum allowed value.
    let sql = statement_timeout_sql(3600, true, false).unwrap();
    assert_eq!(sql, "SET statement_timeout = 3600000");
}

#[test]
fn test_statement_timeout_sql_mysql() {
    let sql = statement_timeout_sql(30, false, true).unwrap();
    assert_eq!(sql, "SET SESSION max_execution_time = 30000");
}

#[test]
fn test_statement_timeout_sql_sqlite_returns_none() {
    // SQLite does not support statement timeouts.
    assert_eq!(statement_timeout_sql(30, false, false), None);
}

#[test]
fn test_lock_wait_timeout_sql_is_mysql_only_and_in_seconds() {
    // MySQL's max_execution_time bounds read-only SELECTs, so a write queued
    // behind an abandoned transaction's row lock is otherwise unbounded — the
    // zombie-lock pileup in issue #4146. innodb_lock_wait_timeout is expressed
    // in seconds, not milliseconds.
    assert_eq!(
        lock_wait_timeout_sql(30, true),
        Some("SET SESSION innodb_lock_wait_timeout = 30".to_string())
    );
    // PostgreSQL's statement_timeout already bounds blocked statements, and
    // SQLite uses PRAGMA busy_timeout.
    assert_eq!(lock_wait_timeout_sql(30, false), None);
    // 0 = disabled, same as the statement timeout.
    assert_eq!(lock_wait_timeout_sql(0, true), None);
}

#[tokio::test]
async fn upstream_backend_tls_identity_fields_round_trip_sql_store() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("upstream_tls_identity.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut upstream = make_upstream("tls-u1");
    upstream.backend_tls_sni = Some("reviews.mesh.internal".to_string());
    upstream.backend_tls_san_allow_list = vec![
        "reviews.mesh.internal".to_string(),
        "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
    ];

    store.create_upstream(&upstream).await.unwrap();
    let loaded = store
        .get_upstream("ferrum", "tls-u1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        loaded.backend_tls_san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
        ]
    );

    upstream.backend_tls_sni = Some("ratings.mesh.internal".to_string());
    upstream.backend_tls_san_allow_list = vec!["10.0.0.8".to_string()];
    store.update_upstream(&upstream).await.unwrap();

    let loaded = store
        .get_upstream("ferrum", "tls-u1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.backend_tls_sni.as_deref(),
        Some("ratings.mesh.internal")
    );
    assert_eq!(loaded.backend_tls_san_allow_list, vec!["10.0.0.8"]);
}

/// SQL writers bind the payload they receive directly. Mixed-case hosts /
/// SNI / SAN values and blank consumer `custom_id` therefore survive in the
/// durable rows unless restore/CRUD admission normalizes before persistence
/// (issue #2402). Assert against raw columns because `get_*` re-normalizes on
/// read and would hide a write-path miss.
///
/// Blank plugin `proxy_id` is deliberately not part of the wire-form proof:
/// `plugin_configs.proxy_id` has `REFERENCES proxies(id)`, so `Some("")` is a
/// non-NULL FK value that cannot match any proxy row (SQLite 787). That is
/// exactly why restore/CRUD must clear blank `proxy_id` → None before SQL
/// insert — not evidence that SQL itself domain-normalizes identifiers.
#[tokio::test]
async fn sql_create_persists_wire_form_without_domain_normalization() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("restore_normalization_sql.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut proxy = make_http_proxy("mixed-proxy");
    proxy.hosts = vec!["API.Example.COM".to_string()];
    proxy.backend_host = "Backend.Example.COM".to_string();
    proxy.listen_path = Some("/mixed".to_string());

    let mut consumer = make_consumer("mixed-consumer", "mixed_user");
    consumer.custom_id = Some("   ".to_string());

    let mut upstream = make_upstream("mixed-upstream");
    upstream.targets[0].host = "Reviews.Mesh.Internal".to_string();
    upstream.backend_tls_sni = Some("Reviews.Mesh.Internal".to_string());
    upstream.backend_tls_san_allow_list = vec![
        "Reviews.Mesh.Internal".to_string(),
        "spiffe://Cluster.Local/ns/Default/sa/Reviews".to_string(),
    ];

    // Global plugin with proxy_id omitted (None). Handing SQL Some("") would
    // fail the proxies(id) FK before any domain-normalization question arises.
    //
    // `tcp_connection_throttle` admission requires at least one TCP/TCP+TLS
    // proxy for a global instance to protect, so the fixture carries one
    // alongside the HTTP proxy under test. Without it, admission rejects the
    // plugin before SQL is reached and this test never exercises persistence.
    // The TCP proxy is fixture scaffolding only — every assertion below targets
    // `mixed-proxy`, `mixed-consumer`, `mixed-upstream`, and `mixed-plugin`.
    let throttle_target = make_tcp_proxy("mixed-tcp-proxy", 19_432);
    let plugin = make_global_tcp_throttle("mixed-plugin");

    store.create_proxy(&proxy).await.expect("proxy create");
    store
        .create_proxy(&throttle_target)
        .await
        .expect("tcp proxy create");
    store
        .create_consumer(&consumer)
        .await
        .expect("consumer create");
    store
        .create_upstream(&upstream)
        .await
        .expect("upstream create");
    store
        .create_plugin_config(&plugin)
        .await
        .expect("plugin create");

    let mut blank_proxy_id = make_global_tcp_throttle("blank-proxy-id-plugin");
    blank_proxy_id.proxy_id = Some(String::new());
    let blank_err = store
        .create_plugin_config(&blank_proxy_id)
        .await
        .expect_err("blank proxy_id string must fail proxies(id) FK");
    let blank_msg = blank_err.to_string();
    assert!(
        blank_msg.contains("FOREIGN KEY") || blank_msg.contains("787"),
        "empty-string proxy_id must be an FK failure, not silent persist: {blank_msg}"
    );

    let hosts: String = sqlx::query_scalar("SELECT hosts FROM proxies WHERE id = 'mixed-proxy'")
        .fetch_one(&store.pool())
        .await
        .unwrap();
    let backend_host: String =
        sqlx::query_scalar("SELECT backend_host FROM proxies WHERE id = 'mixed-proxy'")
            .fetch_one(&store.pool())
            .await
            .unwrap();
    assert!(
        hosts.contains("API.Example.COM"),
        "SQL proxy insert must not lowercase hosts: {hosts}"
    );
    assert_eq!(backend_host, "Backend.Example.COM");

    let custom_id: Option<String> =
        sqlx::query_scalar("SELECT custom_id FROM consumers WHERE id = 'mixed-consumer'")
            .fetch_one(&store.pool())
            .await
            .unwrap();
    assert_eq!(custom_id.as_deref(), Some("   "));

    let targets: String =
        sqlx::query_scalar("SELECT targets FROM upstreams WHERE id = 'mixed-upstream'")
            .fetch_one(&store.pool())
            .await
            .unwrap();
    let sni: Option<String> =
        sqlx::query_scalar("SELECT backend_tls_sni FROM upstreams WHERE id = 'mixed-upstream'")
            .fetch_one(&store.pool())
            .await
            .unwrap();
    let sans: Option<String> = sqlx::query_scalar(
        "SELECT backend_tls_san_allow_list FROM upstreams WHERE id = 'mixed-upstream'",
    )
    .fetch_one(&store.pool())
    .await
    .unwrap();
    assert!(
        targets.contains("Reviews.Mesh.Internal"),
        "SQL upstream insert must not lowercase target hosts: {targets}"
    );
    assert_eq!(sni.as_deref(), Some("Reviews.Mesh.Internal"));
    assert!(
        sans.as_deref()
            .is_some_and(|value| value.contains("Reviews.Mesh.Internal")),
        "SQL upstream insert must not lowercase DNS SANs: {sans:?}"
    );

    let proxy_id: Option<String> =
        sqlx::query_scalar("SELECT proxy_id FROM plugin_configs WHERE id = 'mixed-plugin'")
            .fetch_one(&store.pool())
            .await
            .unwrap();
    assert!(
        proxy_id.is_none(),
        "global plugin without proxy_id must persist NULL, not empty string: {proxy_id:?}"
    );
}

#[tokio::test]
async fn consumer_credential_index_enforces_keyauth_uniqueness() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_credential_index.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("keyauth".to_string(), json!([{ "key": "shared-key" }]));
    store.create_consumer(&c1).await.unwrap();

    assert!(
        !store
            .check_keyauth_key_unique("ferrum", "shared-key", None)
            .await
            .unwrap()
    );
    assert!(
        store
            .check_keyauth_key_unique("ferrum", "shared-key", Some("c1"))
            .await
            .unwrap()
    );

    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".to_string(), json!([{ "key": "shared-key" }]));
    let err = store
        .create_consumer(&c2)
        .await
        .expect_err("duplicate keyauth key must violate credential index");
    let msg = err.to_string();
    assert!(
        msg.contains("consumer_credential_index")
            || msg.contains("UNIQUE")
            || msg.contains("constraint"),
        "unexpected duplicate-key error: {msg}"
    );
}

#[tokio::test]
async fn consumer_credential_index_enforces_namespace_scoped_hmac_uniqueness() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_hmac_credential_index.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();
    let secret = "datastore-unique-hmac-secret-at-least-32-characters";

    let mut tenant_a_owner = make_consumer("c1", "alice");
    tenant_a_owner.namespace = "tenant-a".to_string();
    tenant_a_owner.credentials.insert(
        "hmac_auth".to_string(),
        json!([{ "secret": secret }, { "secret": secret }]),
    );
    store.create_consumer(&tenant_a_owner).await.unwrap();

    let mut tenant_a_conflict = make_consumer("c2", "bob");
    tenant_a_conflict.namespace = "tenant-a".to_string();
    tenant_a_conflict
        .credentials
        .insert("hmac_auth".to_string(), json!([{ "secret": secret }]));
    let error = store
        .create_consumer(&tenant_a_conflict)
        .await
        .expect_err("a second consumer in one namespace must not claim the HMAC secret");
    let message = error.to_string();
    assert!(
        message.contains("consumer_credential_index")
            || message.contains("UNIQUE")
            || message.contains("constraint"),
        "unexpected duplicate-HMAC error: {message}"
    );

    let mut tenant_b_owner = make_consumer("c1", "carol");
    tenant_b_owner.namespace = "tenant-b".to_string();
    tenant_b_owner
        .credentials
        .insert("hmac_auth".to_string(), json!([{ "secret": secret }]));
    store
        .create_consumer(&tenant_b_owner)
        .await
        .expect("the HMAC index must preserve namespace isolation");

    let original_secret = "transaction-preserved-hmac-secret-at-least-32-characters";
    let mut rotating = make_consumer("c3", "dave");
    rotating.namespace = "tenant-a".to_string();
    rotating.credentials.insert(
        "hmac_auth".to_string(),
        json!([{ "secret": original_secret }]),
    );
    store.create_consumer(&rotating).await.unwrap();
    rotating
        .credentials
        .insert("hmac_auth".to_string(), json!([{ "secret": secret }]));
    store
        .update_consumer(&rotating, &BatchConfigWriteMode::Admission)
        .await
        .expect_err("a conflicting HMAC update must roll back atomically");
    let stored = store.get_consumer("tenant-a", "c3").await.unwrap().unwrap();
    assert_eq!(
        stored.credentials["hmac_auth"],
        json!([{ "secret": original_secret }])
    );
}

#[tokio::test]
async fn incremental_consumer_change_requires_full_reload_for_hmac_rehydration() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_incremental_full_reload.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "hmac_auth".to_string(),
        json!([{ "secret": "first-hmac-secret-at-least-32-characters" }]),
    );
    store.create_consumer(&consumer).await.unwrap();
    let accepted_sequence = store.latest_change_sequence("ferrum").await.unwrap();

    consumer.credentials.insert(
        "hmac_auth".to_string(),
        json!([{ "secret": "repaired-hmac-secret-at-least-32-characters" }]),
    );
    assert!(
        store
            .update_consumer(&consumer, &BatchConfigWriteMode::Admission)
            .await
            .unwrap()
    );

    let error = match store
        .load_incremental_config("ferrum", accepted_sequence)
        .await
    {
        Ok(_) => panic!("consumer deltas must escalate to an authoritative full reload"),
        Err(error) => error,
    };
    assert!(is_incremental_full_reload_required(&error));

    let reloaded = store.load_full_config("ferrum").await.unwrap();
    assert_eq!(reloaded.consumers.len(), 1);
    assert_eq!(
        reloaded.consumers[0].credentials["hmac_auth"],
        json!([{ "secret": "repaired-hmac-secret-at-least-32-characters" }])
    );
}

#[tokio::test]
async fn consumer_credential_index_preserves_exact_mtls_identity_semantics() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_mtls_identity_index.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "API.Example.COM" }]),
    );
    store.create_consumer(&c1).await.unwrap();

    assert!(
        store
            .check_mtls_identity_unique("ferrum", "api.example.com", None)
            .await
            .unwrap()
    );

    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "api.example.com" }]),
    );
    store
        .create_consumer(&c2)
        .await
        .expect("case-variant exact identities must coexist in the credential index");
    let loaded = store.load_full_config("ferrum").await.unwrap();
    assert_eq!(loaded.consumers.len(), 2);
    assert_eq!(loaded.consumers[0].username, "alice");

    let now = chrono::Utc::now();
    let error = store
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect_err("activating san_dns must atomically reject the ambiguous snapshot");
    assert!(is_mtls_dns_identity_conflict(&error));

    let loaded = store
        .load_full_config("ferrum")
        .await
        .expect("the rejected policy must not leave an invalid runtime snapshot");
    assert_eq!(loaded.consumers.len(), 2);
    assert!(loaded.plugin_configs.is_empty());

    let mut c3 = make_consumer("c3", "carol");
    c3.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "API.Example.COM" }]),
    );
    let error = store
        .create_consumer(&c3)
        .await
        .expect_err("an exact duplicate mTLS identity must violate the credential index");
    let message = error.to_string();
    assert!(
        message.contains("consumer_credential_index")
            || message.contains("UNIQUE")
            || message.contains("constraint"),
        "unexpected exact duplicate-identity error: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_sqlite_stores_serialize_mtls_dns_consumer_admission() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mtls_dns_cross_process_consumers.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store_a =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();
    let store_b =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();

    let now = chrono::Utc::now();
    store_a
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mut upper = make_consumer("upper", "alice");
    upper.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "API.Example.COM"}]),
    );
    let mut lower = make_consumer("lower", "bob");
    lower.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "api.example.com"}]),
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let (upper_result, lower_result) = tokio::join!(
        async {
            barrier_a.wait().await;
            store_a.create_consumer(&upper).await
        },
        async {
            barrier_b.wait().await;
            store_b.create_consumer(&lower).await
        }
    );

    assert_ne!(upper_result.is_ok(), lower_result.is_ok());
    let conflict = upper_result.err().or_else(|| lower_result.err()).unwrap();
    assert!(is_mtls_dns_identity_conflict(&conflict), "{conflict:#}");

    let loaded = store_a.load_full_config("ferrum").await.unwrap();
    assert_eq!(loaded.consumers.len(), 1);
    loaded
        .validate_unique_mtls_dns_identities()
        .expect("the persisted winner must remain unambiguous");
}

#[tokio::test]
async fn deleting_last_tcp_proxy_rolls_back_authoritative_plugin_graph_candidate() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("tcp_throttle_delete_candidate.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    store
        .create_proxy(&make_tcp_proxy("tcp", 19001))
        .await
        .unwrap();
    store.create_proxy(&make_http_proxy("http")).await.unwrap();
    store
        .create_plugin_config(&make_global_tcp_throttle("global-throttle"))
        .await
        .expect("a mixed global graph with a supported TCP target is valid");

    let update_error = store
        .update_proxy(&make_http_proxy("tcp"))
        .await
        .expect_err("changing the final TCP target to HTTP must be rejected");
    assert!(
        tcp_connection_throttle_attachment_conflict(&update_error).is_some(),
        "unexpected proxy update rejection: {update_error:#}"
    );
    assert!(
        store
            .get_proxy("ferrum", "tcp")
            .await
            .unwrap()
            .is_some_and(|proxy| matches!(proxy.effective_scheme(), BackendScheme::Tcp)),
        "the rejected update must retain the TCP proxy shape"
    );

    let error = store
        .delete_proxy("ferrum", "tcp")
        .await
        .expect_err("deleting the final supported target must be rejected before commit");
    assert!(
        tcp_connection_throttle_attachment_conflict(&error).is_some(),
        "unexpected delete rejection: {error:#}"
    );
    assert!(
        store.get_proxy("ferrum", "tcp").await.unwrap().is_some(),
        "the rejected transaction must retain the TCP proxy"
    );
    let candidate = store.load_namespace_snapshot("ferrum").await.unwrap();
    validate_tcp_connection_throttle_attachments(&candidate)
        .expect("the committed graph must remain runtime-valid");
}

#[tokio::test]
async fn enabling_global_tcp_throttle_rolls_back_for_unsupported_only_graph() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir
        .path()
        .join("tcp_throttle_plugin_update_candidate.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();
    store.create_proxy(&make_http_proxy("http")).await.unwrap();
    let mut throttle = make_global_tcp_throttle("global-throttle");
    throttle.enabled = false;
    store.create_plugin_config(&throttle).await.unwrap();

    throttle.enabled = true;
    let error = store
        .update_plugin_config(&throttle)
        .await
        .expect_err("enabling a global throttle with only HTTP targets must be rejected");
    assert!(
        tcp_connection_throttle_attachment_conflict(&error).is_some(),
        "unexpected plugin update rejection: {error:#}"
    );
    assert!(
        !store
            .get_plugin_config("ferrum", "global-throttle")
            .await
            .unwrap()
            .unwrap()
            .enabled,
        "the rejected plugin update must roll back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_sqlite_stores_serialize_tcp_throttle_and_proxy_graph_admission() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("tcp_throttle_cross_process_graph.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store_a =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();
    let store_b =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();
    let http_proxy = make_http_proxy("http");
    let throttle = make_global_tcp_throttle("global-throttle");

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let (proxy_result, plugin_result) = tokio::join!(
        async {
            barrier_a.wait().await;
            store_a.create_proxy(&http_proxy).await
        },
        async {
            barrier_b.wait().await;
            store_b.create_plugin_config(&throttle).await
        }
    );

    assert_ne!(
        proxy_result.is_ok(),
        plugin_result.is_ok(),
        "the namespace lock must permit only the first individually-valid mutation"
    );
    let conflict = proxy_result.err().or_else(|| plugin_result.err()).unwrap();
    assert!(
        tcp_connection_throttle_attachment_conflict(&conflict).is_some(),
        "unexpected losing mutation: {conflict:#}"
    );
    let candidate = store_a.load_namespace_snapshot("ferrum").await.unwrap();
    validate_tcp_connection_throttle_attachments(&candidate)
        .expect("cross-store admission must never commit the invalid aggregate graph");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_sqlite_stores_atomically_serialize_policy_association_and_identity_update() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir
        .path()
        .join("mtls_dns_cross_process_association.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store_a =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();
    let store_b =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();

    let mut owner = make_consumer("owner", "alice");
    owner.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "API.Example.COM"}]),
    );
    store_a.create_consumer(&owner).await.unwrap();
    let rotating = make_consumer("rotating", "bob");
    store_a.create_consumer(&rotating).await.unwrap();

    let proxy: Proxy = serde_json::from_value(json!({
        "id": "api",
        "namespace": "ferrum",
        "hosts": ["api.test"],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .unwrap();
    store_a.create_proxy(&proxy).await.unwrap();
    let now = chrono::Utc::now();
    store_a
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Proxy,
            proxy_id: Some(proxy.id.clone()),
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mut associated_proxy = proxy.clone();
    associated_proxy.plugins.push(PluginAssociation {
        plugin_config_id: "dns-mtls".to_string(),
    });
    let mut rotated_consumer = rotating.clone();
    rotated_consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "api.example.com"}]),
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let (association_result, rotation_result) = tokio::join!(
        async {
            barrier_a.wait().await;
            store_a.update_proxy(&associated_proxy).await
        },
        async {
            barrier_b.wait().await;
            store_b
                .update_consumer(&rotated_consumer, &BatchConfigWriteMode::Admission)
                .await
        }
    );

    let association_succeeded = matches!(&association_result, Ok(true));
    let rotation_succeeded = matches!(&rotation_result, Ok(true));
    assert_ne!(association_succeeded, rotation_succeeded);
    let conflict = association_result
        .err()
        .or_else(|| rotation_result.err())
        .unwrap();
    assert!(is_mtls_dns_identity_conflict(&conflict), "{conflict:#}");

    let loaded = store_a.load_full_config("ferrum").await.unwrap();
    loaded
        .validate_unique_mtls_dns_identities()
        .expect("association and credential admission must commit as one valid order");
    let stored_proxy = store_a.get_proxy("ferrum", "api").await.unwrap().unwrap();
    let stored_consumer = store_a
        .get_consumer("ferrum", "rotating")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        !stored_proxy.plugins.is_empty(),
        !stored_consumer.credentials.contains_key("mtls_auth")
    );
}

#[tokio::test]
async fn persistent_admission_guard_blocks_other_sqlite_admin_writers_across_batches() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mtls_dns_restore_guard.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store_a =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();
    let store_b =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .unwrap();

    let guard_owner = store_a
        .acquire_mtls_dns_admission_guard("ferrum")
        .await
        .unwrap();
    let replay_mode = BatchConfigWriteMode::RestoreRollbackReplay {
        guard_owner: guard_owner.clone(),
    };
    store_a
        .delete_all_resources("ferrum", &replay_mode)
        .await
        .expect("the guard owner must be able to clear the partial restore state");
    let replayed = make_consumer("replayed", "alice");
    store_a
        .batch_create_consumers(&[replayed], &replay_mode)
        .await
        .expect("the guard owner must be able to replay a batch");

    // Credential handlers acquire this same owner before reading the
    // Consumer, then borrow it for the full update. Pin that reentrant path so
    // a future refactor cannot move the cross-process lock back after the read.
    let guarded_mode = BatchConfigWriteMode::GuardedAdmission {
        guard_owner: guard_owner.clone(),
    };
    let mut guarded_consumer = store_a
        .get_consumer("ferrum", "replayed")
        .await
        .unwrap()
        .unwrap();
    guarded_consumer
        .credentials
        .insert("keyauth".to_string(), json!([{ "key": "guarded-key" }]));
    DatabaseBackend::update_consumer(&store_a, &guarded_consumer, &guarded_mode)
        .await
        .expect("the pre-read guard owner must be able to persist the credential update");
    store_a
        .batch_create_upstreams(&[make_upstream("guarded-upstream")], &guarded_mode)
        .await
        .expect("the restore owner must be able to persist its upstream batch");

    let wrong_owner_mode = BatchConfigWriteMode::RestoreRollbackReplay {
        guard_owner: "not-the-owner".to_string(),
    };
    let wrong_owner = store_b
        .batch_create_consumers(
            &[make_consumer("wrong-owner", "mallory")],
            &wrong_owner_mode,
        )
        .await
        .expect_err("a replay must not borrow another rollback's guard");
    assert!(is_mtls_dns_admission_unavailable(&wrong_owner));
    assert!(
        wrong_owner.to_string().contains("guarded operation owns"),
        "unexpected wrong-owner rejection: {wrong_owner:#}"
    );

    let blocked = store_b
        .create_consumer(&make_consumer("concurrent", "bob"))
        .await
        .expect_err("another admin process must remain blocked between replay batches");
    assert!(is_mtls_dns_admission_unavailable(&blocked));
    assert!(
        blocked.to_string().contains("guarded operation owns"),
        "unexpected rollback-guard rejection: {blocked:#}"
    );
    let blocked_upstream = store_b
        .create_upstream(&make_upstream("concurrent-upstream"))
        .await
        .expect_err("another admin process must not mutate upstreams during restore");
    assert!(is_mtls_dns_admission_unavailable(&blocked_upstream));
    assert!(
        blocked_upstream
            .to_string()
            .contains("guarded operation owns"),
        "unexpected upstream restore-guard rejection: {blocked_upstream:#}"
    );

    store_a
        .release_mtls_dns_admission_guard("ferrum", &guard_owner)
        .await
        .unwrap();
    let lost_owner = store_a
        .batch_create_upstreams(&[make_upstream("lost-owner")], &guarded_mode)
        .await
        .expect_err("a released guard owner must not authorize another mutation");
    assert!(is_mtls_dns_admission_unavailable(&lost_owner));
    store_b
        .create_consumer(&make_consumer("after-release", "carol"))
        .await
        .expect("normal admission must resume after persistent guard release");
}

#[tokio::test]
async fn mtls_uniqueness_falls_back_to_consumers_for_legacy_whitespace_index_rows() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir
        .path()
        .join("consumer_legacy_mtls_identity_index.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut consumer = make_consumer("legacy", "alice");
    consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": " API.Example.COM " }]),
    );
    store.create_consumer(&consumer).await.unwrap();

    // Simulate an index row written before surrounding whitespace was
    // canonicalized. A trimmed exact lookup misses this row, so admission must
    // inspect the authoritative Consumer record instead of treating it as unique.
    sqlx::query(
        "UPDATE consumer_credential_index SET credential_hash = ? \
         WHERE namespace = ? AND consumer_id = ? AND credential_type = ?",
    )
    .bind("legacy-case-sensitive-hash")
    .bind("ferrum")
    .bind("legacy")
    .bind("mtls_auth")
    .execute(&store.pool())
    .await
    .unwrap();

    assert!(
        !store
            .check_mtls_identity_unique("ferrum", "API.Example.COM", None)
            .await
            .unwrap()
    );
    assert!(
        store
            .check_mtls_identity_unique("ferrum", "api.example.com", None)
            .await
            .unwrap()
    );
    assert!(
        store
            .check_mtls_identity_unique("ferrum", "API.Example.COM", Some("legacy"))
            .await
            .unwrap()
    );

    sqlx::query("UPDATE consumers SET credentials = ? WHERE namespace = ? AND id = ?")
        .bind("not-json")
        .bind("ferrum")
        .bind("legacy")
        .execute(&store.pool())
        .await
        .unwrap();
    let error = store
        .check_mtls_identity_unique("ferrum", "other.example.com", None)
        .await
        .expect_err("malformed stored credentials must fail uniqueness closed");
    assert!(
        error
            .to_string()
            .contains("failed to parse credentials JSON")
    );
    // Excluding the undecodable row itself must not fail — PUT overwrite
    // repair with mTLS credentials needs to skip its own corrupt body
    // (issue #2997).
    assert!(
        store
            .check_mtls_identity_unique("ferrum", "other.example.com", Some("legacy"))
            .await
            .expect("excluded undecodable consumer must not block self uniqueness"),
        "excluded undecodable consumer is not a conflict"
    );
}

#[tokio::test]
async fn mtls_dns_admission_loads_consumers_only_for_effective_dns_policy() {
    use ferrum_edge::_test_support::is_row_decode_rejection;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mtls_dns_policy_fast_path.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    store
        .create_consumer(&make_consumer("malformed", "alice"))
        .await
        .unwrap();
    sqlx::query("UPDATE consumers SET credentials = ? WHERE namespace = ? AND id = ?")
        .bind("not-json")
        .bind("ferrum")
        .bind("malformed")
        .execute(&store.pool())
        .await
        .unwrap();

    store
        .create_consumer(&make_consumer("fast-path", "bob"))
        .await
        .expect("ordinary admission must not decode all Consumers without a DNS policy");

    let now = chrono::Utc::now();
    let error = store
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect_err("enabling san_dns must take the full Consumer validation path");
    let message = error.to_string();
    assert!(
        message.contains("failed to parse credentials JSON"),
        "full-path admission must surface the credentials parse failure: {error:#}"
    );
    assert!(
        message.contains("malformed"),
        "full-path admission must identify the undecodable consumer id: {error:#}"
    );
    assert!(
        !is_row_decode_rejection(&error),
        "admin-write admission must not retain the poll-loop RowDecodeRejection marker: {error:#}"
    );
}

#[tokio::test]
async fn mtls_dns_repair_deletes_may_only_reduce_existing_ambiguity() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mtls_dns_repair_delete.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut upper = make_consumer("upper", "alice");
    upper.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "API.Example.COM"}]),
    );
    let mut lower = make_consumer("lower", "bob");
    lower.credentials.insert(
        "mtls_auth".to_string(),
        json!([{"identity": "api.example.com"}]),
    );
    store.create_consumer(&upper).await.unwrap();
    store.create_consumer(&lower).await.unwrap();
    store
        .create_consumer(&make_consumer("unrelated", "carol"))
        .await
        .unwrap();

    let now = chrono::Utc::now();
    store
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: false,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    sqlx::query("UPDATE plugin_configs SET enabled = 1 WHERE namespace = ? AND id = ?")
        .bind("ferrum")
        .bind("dns-mtls")
        .execute(&store.pool())
        .await
        .unwrap();

    assert!(
        store
            .delete_consumer("ferrum", "unrelated")
            .await
            .expect("an unrelated delete must remain available as an operator repair action")
    );
    assert!(
        store
            .delete_consumer("ferrum", "upper")
            .await
            .expect("deleting one conflicting owner must repair the ambiguity")
    );

    let loaded = store.load_full_config("ferrum").await.unwrap();
    assert_eq!(loaded.consumers.len(), 1);
    loaded
        .validate_unique_mtls_dns_identities()
        .expect("repair delete must leave a valid DNS identity index");
}

#[tokio::test]
async fn load_full_config_rejects_hmac_request_body_transform_composition() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("cp_hmac_transform_validation.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();
    let now = chrono::Utc::now();
    for (id, plugin_name, config) in [
        (
            "cp-global-hmac",
            "hmac_auth",
            json!({"clock_skew_seconds": 300, "replay_scope": "process"}),
        ),
        (
            "cp-global-transformer",
            "request_transformer",
            json!({"rules": [{
                "operation": "add",
                "target": "body",
                "key": "gateway",
                "value": "ferrum"
            }]}),
        ),
    ] {
        store
            .create_plugin_config(&PluginConfig {
                labels: Default::default(),
                id: id.to_string(),
                plugin_name: plugin_name.to_string(),
                namespace: "ferrum".to_string(),
                config,
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                trigger: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
    }

    let error = store
        .load_full_config("ferrum")
        .await
        .expect_err("CP/database loaders must reject an unsafe HMAC plugin chain");
    assert!(
        is_config_validation_rejection(&error),
        "composition failure must use the shared semantic rejection marker: {error}"
    );
}

#[tokio::test]
async fn consumer_credential_index_updates_on_consumer_update() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("consumer_credential_index_update.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    let mut consumer = make_consumer("c1", "alice");
    consumer
        .credentials
        .insert("keyauth".to_string(), json!([{ "key": "old-key" }]));
    consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "spiffe://example.test/ns/default/sa/alice" }]),
    );
    store.create_consumer(&consumer).await.unwrap();

    consumer
        .credentials
        .insert("keyauth".to_string(), json!([{ "key": "new-key" }]));
    consumer.credentials.insert(
        "mtls_auth".to_string(),
        json!([{ "identity": "spiffe://example.test/ns/default/sa/alice-v2" }]),
    );
    store
        .update_consumer(&consumer, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();

    assert!(
        store
            .check_keyauth_key_unique("ferrum", "old-key", None)
            .await
            .unwrap()
    );
    assert!(
        !store
            .check_keyauth_key_unique("ferrum", "new-key", None)
            .await
            .unwrap()
    );
    assert!(
        store
            .check_mtls_identity_unique("ferrum", "spiffe://example.test/ns/default/sa/alice", None)
            .await
            .unwrap()
    );
    assert!(
        !store
            .check_mtls_identity_unique(
                "ferrum",
                "spiffe://example.test/ns/default/sa/alice-v2",
                None,
            )
            .await
            .unwrap()
    );
}

async fn seed_sqlite_namespace(db_url: &str, namespace: &str) {
    let store = DatabaseStore::connect_with_pool_config("sqlite", db_url, DbPoolConfig::default())
        .await
        .unwrap();
    sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
        .bind(format!("{namespace}-upstream"))
        .bind(namespace)
        .bind(format!("{namespace}-name"))
        .execute(&store.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn failover_does_not_mask_non_transient_schema_errors() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("broken-primary.db");
    let failover_path = temp_dir.path().join("healthy-failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let raw_pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&primary_url)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE proxies (id TEXT PRIMARY KEY)")
        .execute(&raw_pool)
        .await
        .unwrap();
    raw_pool.close().await;

    let result = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("schema/query errors must stop instead of selecting failover"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("non-transient"),
        "unexpected failover classification: {error}"
    );
    assert!(
        DatabaseStore::is_non_transient_init_error(&error),
        "a non-transient schema error must be classified so database::run refuses backup bootstrap: {error}"
    );
    assert!(
        !failover_path.exists(),
        "the failover database must not be opened for a permanent primary schema error"
    );
}

#[tokio::test]
async fn transient_connectivity_failure_stays_backup_eligible() {
    // database::run may only bootstrap from FERRUM_DB_CONFIG_BACKUP_PATH for
    // TRANSIENT failures; pin that a plain connectivity failure is classified
    // transient (not marked non-transient) so backup bootstrap stays eligible.
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let missing_path = temp_dir.path().join("missing-primary.db");
    // mode=rw refuses to create the file, so opening a missing database is a
    // transient connectivity failure (SQLITE_CANTOPEN).
    let primary_url = format!("sqlite:{}?mode=rw", missing_path.to_string_lossy());
    let no_failover: Vec<String> = Vec::new();

    let error = match DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_url,
        &no_failover,
        DbPoolConfig::default(),
    )
    .await
    {
        Ok(_) => panic!("opening a missing read-only sqlite database must fail"),
        Err(error) => error,
    };
    assert!(
        !DatabaseStore::is_non_transient_init_error(&error),
        "a transient connectivity failure must remain backup-eligible: {error}"
    );
    assert!(
        !missing_path.exists(),
        "mode=rw must not create the database file"
    );
}

#[test]
fn initial_config_load_validation_error_is_non_transient() {
    // A schema/data/validation load failure that carries no transient
    // sqlx/mongodb error must be marked non-transient so database::run refuses
    // to bootstrap from FERRUM_DB_CONFIG_BACKUP_PATH and fails startup instead
    // of masking a broken database with stale on-disk config.
    let raw = anyhow::anyhow!("proxy 'api' references unknown upstream 'missing'");
    let classified = DatabaseStore::classify_initial_config_load_error(raw);
    assert!(
        DatabaseStore::is_non_transient_init_error(&classified),
        "a non-transient config-load error must be marked so backup bootstrap is refused: {classified}"
    );
}

#[test]
fn initial_config_load_row_decode_rejection_is_non_transient() {
    // Issue #2997: poll loops treat RowDecodeRejection like a validation
    // rejection (keep admin writable), but startup must stay fail-loud — a
    // decode failure must still refuse FERRUM_DB_CONFIG_BACKUP_PATH bootstrap.
    use ferrum_edge::_test_support::{
        is_poll_validation_rejection, is_row_decode_rejection, row_decode_rejection_error,
    };

    let raw = row_decode_rejection_error(
        "consumer",
        Some("c-bad"),
        "Consumer c-bad: failed to parse credentials JSON: EOF",
    );
    assert!(is_row_decode_rejection(&raw));
    assert!(
        is_poll_validation_rejection(&raw),
        "row-decode must classify for the poll loop"
    );
    let classified = DatabaseStore::classify_initial_config_load_error(raw);
    assert!(
        DatabaseStore::is_non_transient_init_error(&classified),
        "startup must keep row-decode fail-loud / non-transient: {classified}"
    );
}

#[test]
fn initial_config_load_transient_sqlx_error_stays_backup_eligible() {
    // A connectivity failure during the initial full load (the DB became
    // unreachable between connect and load) must stay backup-eligible so the
    // gateway can still come up serving FERRUM_DB_CONFIG_BACKUP_PATH.
    let raw = anyhow::Error::new(sqlx::Error::PoolTimedOut)
        .context("load_full_config: initial database query failed");
    let classified = DatabaseStore::classify_initial_config_load_error(raw);
    assert!(
        !DatabaseStore::is_non_transient_init_error(&classified),
        "a transient connectivity load failure must remain backup-eligible: {classified}"
    );
}

#[test]
fn mysql_transaction_isolation_read_disconnect_stays_backup_eligible() {
    // A MySQL primary can drop mid-`configure_full_load_snapshot` while
    // `mysql_transaction_isolation()` reads @@transaction_isolation. That is a
    // transient post-connect load failure the backup path is meant to cover, so
    // the isolation-read wrapper must keep the fallback sqlx error typed in its
    // source chain instead of stringifying it. Reconstruct the EXACT production
    // wrapper (via the shared helper) and pin that classification leaves it
    // backup-eligible.
    let primary_error = sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset by peer while reading @@transaction_isolation",
    ));
    let fallback_error = sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset by peer while reading @@tx_isolation",
    ));
    let wrapped = db_wrap_mysql_isolation_read_error(&primary_error, fallback_error);

    assert!(
        wrapped
            .chain()
            .any(|source| source.downcast_ref::<sqlx::Error>().is_some()),
        "the isolation-read wrapper must retain a typed sqlx source: {wrapped:#}"
    );

    let classified = DatabaseStore::classify_initial_config_load_error(wrapped);
    assert!(
        !DatabaseStore::is_non_transient_init_error(&classified),
        "a transient MySQL disconnect during the isolation read must remain backup-eligible: {classified}"
    );
}

#[test]
fn sqlite_low_byte_codes_stay_transient_only_for_sqlite() {
    // SQLite reports base result codes in the low byte of extended codes.
    // BUSY/LOCKED/CANTOPEN and their extended forms are temporary resource or
    // connectivity failures, but only when emitted by the SQLite driver.
    for code in ["5", "6", "14", "517", "262", "1038"] {
        assert!(
            db_code_is_transient(code, true),
            "SQLite result code {code} must remain transient"
        );
        assert!(
            !db_code_is_transient(code, false),
            "non-SQLite result code {code} must not use SQLite low-byte classification"
        );
    }
}

fn mongo_command_error(code: i32, message: &str) -> mongodb::error::Error {
    let command_error: mongodb::error::CommandError = mongodb::bson::from_document(
        mongodb::bson::doc! { "code": code, "codeName": "TestCommandError", "errmsg": message },
    )
    .unwrap();
    mongodb::error::ErrorKind::Command(command_error).into()
}

#[test]
fn mongo_election_command_errors_stay_backup_eligible() {
    let stepped_down = mongo_command_error(189, "primary stepped down during config read");
    assert!(
        db_mongo_error_is_transient(&stepped_down),
        "PrimarySteppedDown must remain eligible for backup fallback"
    );

    for (code, name) in [(13, "Unauthorized"), (18, "AuthenticationFailed")] {
        let auth_error = mongo_command_error(code, name);
        assert!(
            !db_mongo_error_is_transient(&auth_error),
            "authentication-ish command code {code} must refuse backup fallback"
        );
    }
}

#[test]
fn mysql_per_user_connection_limits_stay_transient() {
    for code in [1203, 1226] {
        assert!(
            db_mysql_error_number_is_transient(code),
            "temporary MySQL per-user resource limit {code} must remain failover/backup-eligible"
        );
    }
    assert!(
        !db_mysql_error_number_is_transient(1045),
        "MySQL access denied must remain non-transient"
    );
}

#[test]
fn numeric_postgres_sqlstates_do_not_use_sqlite_low_byte_classification() {
    // PostgreSQL has all-numeric SQLSTATEs whose low bytes collide with
    // SQLITE_BUSY/CANTOPEN. They are data exceptions and must refuse failover
    // and backup bootstrap rather than being treated as transient.
    for code in ["22021", "22030"] {
        assert!(
            !db_code_is_transient(code, false),
            "non-SQLite SQLSTATE {code} must not use SQLite low-byte classification"
        );
        let raw = anyhow::Error::new(sqlx::Error::Database(Box::new(TestDatabaseError { code })))
            .context("load_full_config: PostgreSQL query failed");
        let classified = DatabaseStore::classify_initial_config_load_error(raw);
        assert!(
            DatabaseStore::is_non_transient_init_error(&classified),
            "PostgreSQL data-exception SQLSTATE {code} must refuse backup bootstrap: {classified}"
        );
    }
}

#[tokio::test]
async fn proxy_plugin_query_wrapper_preserves_typed_sqlx_source() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("proxy_plugin_source.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    sqlx::query("DROP TABLE proxy_plugins")
        .execute(&store.pool())
        .await
        .unwrap();
    let error = store.load_full_config("ferrum").await.unwrap_err();
    assert!(
        error
            .chain()
            .any(|source| source.downcast_ref::<sqlx::Error>().is_some()),
        "the association-load wrapper must retain the typed sqlx source: {error:#}"
    );

    let classified = DatabaseStore::classify_initial_config_load_error(error);
    assert!(
        DatabaseStore::is_non_transient_init_error(&classified),
        "a retained non-transient schema error must still refuse backup bootstrap: {classified}"
    );
}

#[tokio::test]
async fn plugin_trigger_round_trips_create_update_full_load_and_clear() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("plugin_trigger_round_trip.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    store
        .create_proxy(&make_http_proxy("trigger-proxy"))
        .await
        .expect("proxy create");

    let initial: PluginTrigger = serde_json::from_value(json!({
        "when": {"match": {"method": ["POST"]}}
    }))
    .unwrap();
    let updated: PluginTrigger = serde_json::from_value(json!({
        "when": {"all": [
            {"match": {"method": ["PUT"]}},
            {"match": {"path": {"prefix": ["/v2/"]}}}
        ]}
    }))
    .unwrap();
    let now = chrono::Utc::now();
    let mut plugin = PluginConfig {
        labels: Default::default(),
        id: "triggered-transformer".to_string(),
        plugin_name: "request_transformer".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "x-triggered",
                "value": "1"
            }]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("trigger-proxy".to_string()),
        enabled: true,
        priority_override: None,
        trigger: Some(initial.clone()),
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    store
        .create_plugin_config(&plugin)
        .await
        .expect("triggered plugin create");
    let created = store
        .get_plugin_config("ferrum", &plugin.id)
        .await
        .unwrap()
        .expect("created plugin");
    assert_eq!(created.trigger.as_ref(), Some(&initial));
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT trigger_json FROM plugin_configs WHERE id = ? AND namespace = ?",
    )
    .bind(&plugin.id)
    .bind("ferrum")
    .fetch_one(&store.pool())
    .await
    .unwrap();
    assert!(
        stored.is_some(),
        "a present trigger must not be stored as NULL"
    );

    plugin.trigger = Some(updated.clone());
    plugin.updated_at = chrono::Utc::now();
    assert!(store.update_plugin_config(&plugin).await.unwrap());
    let full = store.load_full_config("ferrum").await.unwrap();
    let reloaded = full
        .plugin_configs
        .iter()
        .find(|candidate| candidate.id == plugin.id)
        .expect("updated plugin in full load");
    assert_eq!(reloaded.trigger.as_ref(), Some(&updated));

    plugin.trigger = None;
    plugin.updated_at = chrono::Utc::now();
    assert!(store.update_plugin_config(&plugin).await.unwrap());
    let cleared = store
        .get_plugin_config("ferrum", &plugin.id)
        .await
        .unwrap()
        .expect("cleared plugin");
    assert!(cleared.trigger.is_none());
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT trigger_json FROM plugin_configs WHERE id = ? AND namespace = ?",
    )
    .bind(&plugin.id)
    .bind("ferrum")
    .fetch_one(&store.pool())
    .await
    .unwrap();
    assert!(stored.is_none(), "clearing a trigger must restore SQL NULL");
}

#[tokio::test]
async fn whitespace_trigger_json_is_rejected_instead_of_disabling_trigger() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("whitespace_trigger_json.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO plugin_configs (id, namespace, plugin_name, trigger_json) \
         VALUES (?, ?, ?, ?)",
    )
    .bind("whitespace-trigger")
    .bind("ferrum")
    .bind("rate_limiting")
    .bind("   \t")
    .execute(&store.pool())
    .await
    .unwrap();

    let error = store.load_full_config("ferrum").await.unwrap_err();
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("failed to parse trigger JSON"),
        "a non-NULL malformed trigger must reject the row, never broaden it into an untriggered instance: {rendered}"
    );
}

#[test]
fn non_transient_load_error_message_preserves_driver_cause() {
    // main logs fatal errors with `{}` (outermost anyhow context only), so the
    // surfaced startup message must fold in the underlying driver cause instead
    // of hiding it behind the generic non-transient explanation.
    let raw = anyhow::anyhow!("relation \"proxies\" does not exist");
    let classified = DatabaseStore::classify_initial_config_load_error(raw);
    let rendered = classified.to_string();
    assert!(
        rendered.contains("non-transient"),
        "expected the non-transient explanation in the surfaced message: {rendered}"
    );
    assert!(
        rendered.contains("relation \"proxies\" does not exist"),
        "the underlying driver cause must survive in the Display output: {rendered}"
    );
}

#[tokio::test]
async fn read_replica_scheduling_state_tracks_failover_and_failback() {
    // Pin the exact flags the poll scheduler branches on: while failed over the
    // replica is suppressed (not broken) so no reconnect is scheduled; after
    // failback it becomes unavailable-but-eligible, prompting exactly one
    // reconnect before subsequent cycles observe it as healthy.
    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let replica_path = temp_dir.path().join("replica.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());
    let replica_url = format!("sqlite:{}?mode=rwc", replica_path.to_string_lossy());

    // The primary (mode=rw) does not exist yet, so the store comes up on the
    // failover topology.
    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    store.connect_read_replica(&replica_url).await.unwrap();

    // Failed over: the replica belongs to the down primary topology. It must
    // report as suppressed, not available, so the scheduler skips reconnects.
    assert!(!store.read_replica_available());
    assert!(store.read_replica_suppressed());

    // Fail back to the now-reachable primary.
    seed_sqlite_namespace(&primary_create_url, "primary-ns").await;
    let active_url = store.try_failover_reconnect(&primary_rw_url).await.unwrap();
    assert_eq!(active_url, primary_rw_url);

    // Back on primary: the dormant failover-era pool was discarded. The
    // scheduler now sees one unavailable-but-eligible replica and reconnects
    // it; after that, later cycles see it as available and do not retry.
    assert!(!store.read_replica_available());
    assert!(!store.read_replica_suppressed());
    store.reconnect_read_replica(&replica_url).await.unwrap();
    assert!(store.read_replica_available());
    assert!(!store.read_replica_suppressed());
}

#[tokio::test]
async fn read_replica_tracks_primary_topology_across_failover_and_failback() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let replica_path = temp_dir.path().join("replica.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());
    let replica_url = format!("sqlite:{}?mode=rwc", replica_path.to_string_lossy());

    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets) VALUES ('failover-upstream', 'failover-ns', 'failover-name', '[]')",
    )
    .execute(&store.pool())
    .await
    .unwrap();

    seed_sqlite_namespace(&replica_url, "replica-ns").await;
    store.connect_read_replica(&replica_url).await.unwrap();
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()],
        "admin reads must stay on the active failover topology"
    );

    seed_sqlite_namespace(&primary_create_url, "primary-ns").await;
    let active_url = store.try_failover_reconnect(&primary_rw_url).await.unwrap();
    assert_eq!(active_url, primary_rw_url);
    assert!(
        !store.read_replica_available(),
        "failback should require one fresh replica reconnect"
    );
    store.reconnect_read_replica(&replica_url).await.unwrap();
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["ferrum".to_string(), "replica-ns".to_string()],
        "the configured read replica should become eligible again after primary failback"
    );
}

// ---- list_namespaces_paginated ----

async fn connect_namespaces_test_store(dir: &tempfile::TempDir, name: &str) -> DatabaseStore {
    let db_path = dir.path().join(format!("{name}.db"));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, DbPoolConfig::default())
        .await
        .expect("connect sqlite store")
}

async fn seed_namespace_upstream(store: &DatabaseStore, namespace: &str, id: &str) {
    sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
        .bind(id)
        .bind(namespace)
        .bind(format!("{id}-name"))
        .execute(&store.pool())
        .await
        .unwrap();
}

/// Seed a namespace that exists *only* as a gateway trust bundle row.
/// Listing must discover it even when proxies/consumers/plugins/upstreams are empty.
async fn seed_namespace_trust_bundle_only(store: &DatabaseStore, namespace: &str) {
    sqlx::query(
        "INSERT INTO gateway_trust_bundles \
         (namespace, id, trust_domain, bundle, revision, created_at, updated_at) \
         VALUES (?, ?, ?, '{}', 1, '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')",
    )
    .bind(namespace)
    .bind(namespace)
    .bind(format!("{namespace}.local"))
    .execute(&store.pool())
    .await
    .unwrap();
}

async fn registry_row_exists(store: &DatabaseStore, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM namespaces WHERE name = ?")
        .bind(name)
        .fetch_one(&store.pool())
        .await
        .unwrap()
        > 0
}

async fn namespace_registry_backfill_completed(store: &DatabaseStore) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _ferrum_schema_compat WHERE name = ?")
        .bind(ferrum_edge::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID)
        .fetch_one(&store.pool())
        .await
        .unwrap()
        > 0
}

#[tokio::test]
async fn list_namespaces_paginated_empty_store_returns_default_ferrum() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-empty").await;

    let page = store.list_namespaces_paginated(100, 0).await.unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.items, vec!["ferrum"]);
}

#[tokio::test]
async fn list_namespaces_paginated_dedupes_across_tables_and_orders() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-dedup").await;

    // The same namespace in two tables must be counted once; namespaces only
    // present in consumers or plugin_configs must still appear.
    seed_namespace_upstream(&store, "zeta", "up-1").await;
    seed_namespace_upstream(&store, "alpha", "up-2").await;
    sqlx::query("INSERT INTO consumers (id, namespace, username) VALUES (?, ?, ?)")
        .bind("consumer-1")
        .bind("alpha")
        .bind("user-1")
        .execute(&store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO plugin_configs (id, namespace, plugin_name) VALUES (?, ?, ?)")
        .bind("plugin-1")
        .bind("middle")
        .bind("rate_limiting")
        .execute(&store.pool())
        .await
        .unwrap();

    let page = store.list_namespaces_paginated(100, 0).await.unwrap();
    assert_eq!(page.total, 4);
    assert_eq!(page.items, vec!["alpha", "ferrum", "middle", "zeta"]);
}

#[tokio::test]
async fn list_namespaces_paginated_slices_pages_and_preserves_total() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-pages").await;
    for i in 0..5 {
        seed_namespace_upstream(&store, &format!("ns-{i:02}"), &format!("up-{i:02}")).await;
    }

    let page = store.list_namespaces_paginated(2, 0).await.unwrap();
    assert_eq!(page.items, vec!["ferrum", "ns-00"]);
    assert_eq!(page.total, 6);

    let page = store.list_namespaces_paginated(2, 2).await.unwrap();
    assert_eq!(page.items, vec!["ns-01", "ns-02"]);
    assert_eq!(page.total, 6);

    let page = store.list_namespaces_paginated(2, 4).await.unwrap();
    assert_eq!(page.items, vec!["ns-03", "ns-04"]);
    assert_eq!(page.total, 6);

    // An offset at or beyond the total is a valid empty page, not an error.
    let page = store.list_namespaces_paginated(2, 6).await.unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.total, 6);

    let page = store.list_namespaces_paginated(2, 100).await.unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.total, 6);
}

#[tokio::test]
async fn list_namespaces_paginated_large_collection_pages_stably() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-large").await;
    for i in 0..120 {
        seed_namespace_upstream(&store, &format!("ns-{i:03}"), &format!("up-{i:03}")).await;
    }

    let mut collected = Vec::new();
    let mut offset = 0i64;
    loop {
        let page = store.list_namespaces_paginated(50, offset).await.unwrap();
        assert_eq!(page.total, 121);
        if page.items.is_empty() {
            break;
        }
        offset += page.items.len() as i64;
        collected.extend(page.items);
    }
    assert_eq!(collected.len(), 121);
    let mut sorted = collected.clone();
    sorted.sort();
    assert_eq!(
        collected, sorted,
        "pages must concatenate in ascending order"
    );
    assert_eq!(collected.first().map(String::as_str), Some("ferrum"));
    assert_eq!(collected.last().map(String::as_str), Some("ns-119"));
}

#[tokio::test]
async fn list_namespaces_paginated_insert_after_cursor_keeps_pages_stable() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-insert").await;
    for i in 0..10 {
        seed_namespace_upstream(&store, &format!("ns-{i:02}"), &format!("up-{i:02}")).await;
    }

    let first = store.list_namespaces_paginated(4, 0).await.unwrap();
    assert_eq!(first.items, vec!["ferrum", "ns-00", "ns-01", "ns-02"]);
    assert_eq!(first.total, 11);

    // Inserts that sort after the fetched window must not shift already-
    // returned rows into a later page.
    for i in 0..5 {
        seed_namespace_upstream(&store, &format!("ns-a{i}"), &format!("up-a{i}")).await;
    }

    let second = store.list_namespaces_paginated(100, 4).await.unwrap();
    assert_eq!(second.total, 16);
    let remainder: Vec<&str> = second.items.iter().map(String::as_str).collect();
    assert_eq!(
        remainder[..7],
        [
            "ns-03", "ns-04", "ns-05", "ns-06", "ns-07", "ns-08", "ns-09"
        ],
        "rows after the cursor keep their relative order; new inserts append"
    );
    assert!(
        !first
            .items
            .iter()
            .any(|returned| second.items.contains(returned)),
        "no row from the first page may reappear after the cursor"
    );
}

#[tokio::test]
async fn list_namespaces_includes_trust_bundle_only_namespace() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-trust-list").await;

    seed_namespace_upstream(&store, "alpha", "up-alpha").await;
    seed_namespace_trust_bundle_only(&store, "trust-only").await;

    let namespaces = store.list_namespaces().await.unwrap();
    assert_eq!(
        namespaces,
        vec![
            "alpha".to_string(),
            "ferrum".to_string(),
            "trust-only".to_string()
        ],
        "a namespace that only owns a gateway trust bundle must still enumerate"
    );
}

#[tokio::test]
async fn list_namespaces_paginated_includes_trust_bundle_only_namespace() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-trust-page").await;

    seed_namespace_upstream(&store, "zeta", "up-zeta").await;
    seed_namespace_trust_bundle_only(&store, "middle-trust").await;
    seed_namespace_upstream(&store, "alpha", "up-alpha").await;

    let page = store.list_namespaces_paginated(100, 0).await.unwrap();
    assert_eq!(page.total, 4);
    assert_eq!(page.items, vec!["alpha", "ferrum", "middle-trust", "zeta"]);

    // Paginate so the trust-only name is not on the first page, proving the
    // count and ordered union both include gateway_trust_bundles.
    let first = store.list_namespaces_paginated(2, 0).await.unwrap();
    assert_eq!(first.items, vec!["alpha", "ferrum"]);
    assert_eq!(first.total, 4);

    let second = store.list_namespaces_paginated(2, 2).await.unwrap();
    assert_eq!(second.items, vec!["middle-trust", "zeta"]);
    assert_eq!(second.total, 4);
}

#[tokio::test]
async fn namespace_registry_backfill_is_one_time_and_does_not_reseed() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let name = "ns-backfill-once";
    let store = connect_namespaces_test_store(&temp_dir, name).await;
    assert!(
        registry_row_exists(&store, "ferrum").await,
        "first-run backfill must still seed canonical ferrum"
    );
    assert!(
        namespace_registry_backfill_completed(&store).await,
        "first-run backfill must durably mark completion"
    );
    let listed = store.list_namespaces().await.unwrap();
    assert!(listed.contains(&"ferrum".to_string()));
    assert!(
        !listed.iter().any(|item| item == "_ferrum_schema_compat"
            || item == ferrum_edge::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID),
        "compatibility state must never appear in GET /namespaces: {listed:?}"
    );

    seed_namespace_upstream(&store, "derived-only", "up-derived").await;
    assert!(
        !registry_row_exists(&store, "derived-only").await,
        "ordinary resource writes must not insert a registry row"
    );
    drop(store);

    let store = connect_namespaces_test_store(&temp_dir, name).await;
    assert!(registry_row_exists(&store, "ferrum").await);
    assert!(
        !registry_row_exists(&store, "derived-only").await,
        "a later compatibility pass must not materialize newer derived-only names"
    );
    let listed = store.list_namespaces().await.unwrap();
    assert!(
        listed.contains(&"derived-only".to_string()),
        "GET /namespaces remains the union of registry and derived names: {listed:?}"
    );

    sqlx::query("DELETE FROM namespaces WHERE name = 'ferrum'")
        .execute(&store.pool())
        .await
        .unwrap();
    assert!(!registry_row_exists(&store, "ferrum").await);
    drop(store);

    let store = connect_namespaces_test_store(&temp_dir, name).await;
    assert!(
        !registry_row_exists(&store, "ferrum").await,
        "a later compatibility pass must not resurrect a deleted ferrum row"
    );
    assert!(!registry_row_exists(&store, "derived-only").await);
    assert!(namespace_registry_backfill_completed(&store).await);
}

#[tokio::test]
async fn unmarked_namespace_registry_backfill_retries_idempotently() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let name = "ns-backfill-retry";
    let store = connect_namespaces_test_store(&temp_dir, name).await;
    sqlx::query("DELETE FROM _ferrum_schema_compat")
        .execute(&store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM namespaces WHERE name = 'ferrum'")
        .execute(&store.pool())
        .await
        .unwrap();
    seed_namespace_upstream(&store, "legacy", "up-legacy").await;
    assert!(
        !namespace_registry_backfill_completed(&store).await,
        "clearing the marker simulates an interrupted first-run attempt"
    );
    drop(store);

    let store = connect_namespaces_test_store(&temp_dir, name).await;
    assert!(
        namespace_registry_backfill_completed(&store).await,
        "an unmarked attempt must remain retryable"
    );
    assert!(
        registry_row_exists(&store, "ferrum").await,
        "retry must still seed canonical ferrum"
    );
    assert!(
        registry_row_exists(&store, "legacy").await,
        "retry must still insert pre-existing derived names"
    );
}

#[tokio::test]
async fn namespace_registry_backfill_rejects_invalid_derived_names_before_completion() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let name = "ns-backfill-invalid-derived";
    let db_path = temp_dir.path().join(format!("{name}.db"));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = connect_namespaces_test_store(&temp_dir, name).await;

    sqlx::query("DELETE FROM _ferrum_schema_compat")
        .execute(&store.pool())
        .await
        .unwrap();
    seed_namespace_upstream(&store, "invalid/namespace", "up-invalid").await;

    let error = match DatabaseStore::connect_with_pool_config(
        "sqlite",
        &url,
        DbPoolConfig::default(),
    )
    .await
    {
        Ok(_) => panic!("an invalid legacy namespace must fail the compatibility pass"),
        Err(error) => error,
    };
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains(NamespaceRegistryCorrupt::MESSAGE),
        "the failure must use the redacted registry-corruption diagnostic: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("invalid/namespace"),
        "the hostile stored value must not be echoed: {diagnostic}"
    );
    assert!(
        !namespace_registry_backfill_completed(&store).await,
        "a rejected pass must leave the marker absent for a later repair and retry"
    );
    assert!(
        !registry_row_exists(&store, "invalid/namespace").await,
        "the derived registry insert must roll back with the rejected pass"
    );
}

/// Source-level drift guard: issue #3727 trust bundles are a namespaced
/// resource and must participate in both list and paginated list unions.
#[test]
fn list_namespaces_sql_unions_gateway_trust_bundles() {
    let source = include_str!("../../../src/config/db_loader.rs");

    let list_body = source
        .split("async fn list_namespaces_from_pool(")
        .nth(1)
        .and_then(|rest| rest.split("pub async fn list_namespaces_paginated(").next())
        .expect("list_namespaces_from_pool body");
    assert!(
        list_body.contains("UNION SELECT DISTINCT namespace FROM gateway_trust_bundles"),
        "list_namespaces_from_pool must union gateway_trust_bundles"
    );
    assert!(
        list_body.contains("SELECT name FROM namespaces"),
        "list_namespaces_from_pool must union the namespaces registry"
    );
    assert!(
        !list_body.contains("_ferrum_schema_compat"),
        "compatibility-state rows must not appear in GET /namespaces"
    );

    let page_body = source
        .split("async fn list_namespaces_paginated_from_pool(")
        .nth(1)
        .and_then(|rest| rest.split("ApiSpec operations").next())
        .expect("list_namespaces_paginated_from_pool body");
    let trust_unions = page_body
        .matches("UNION SELECT DISTINCT namespace FROM gateway_trust_bundles")
        .count();
    assert!(
        trust_unions >= 2,
        "paginated count and page queries must both union gateway_trust_bundles (found {trust_unions})"
    );
}

/// Source-level drift guard for issue #3000: trust/routing nullable columns in
/// `row_to_proxy` / `row_to_upstream` must fail closed on non-NULL decode
/// failures (via `optional_utf8_text_column` / `try_get::<Option<_>>(...)?`)
/// so a corrupt value rejects the candidate load instead of silently becoming
/// `None` (trust downgrade, mTLS disable, or upstream detach).
#[test]
fn row_mappers_use_strict_nullable_decodes_for_tls_and_routing_columns() {
    let source = include_str!("../../../src/config/db_loader.rs");

    let row_to_proxy = source
        .split("fn row_to_proxy_inner(")
        .nth(1)
        // Bound at the UTF-8 helpers that sit between proxy_inner and consumer
        // so the drift assertions inspect only the mapper body.
        .and_then(|rest| rest.split("fn required_utf8_text_column(").next())
        .expect("row_to_proxy_inner body");
    let row_to_upstream = source
        .split("fn row_to_upstream_inner(")
        .nth(1)
        .and_then(|rest| {
            rest.split("fn strip_api_spec_id_from_runtime_config(")
                .next()
        })
        .expect("row_to_upstream_inner body");

    // Already-hardened contrast cases that established this contract.
    assert!(
        row_to_proxy.contains("optional_utf8_text_column(row, \"listen_path\")?")
            || row_to_proxy.contains("try_get::<Option<String>, _>(\"listen_path\")?"),
        "listen_path must keep a strict Option decode that motivated this fix"
    );
    assert!(
        row_to_proxy.contains("try_get::<Option<i32>, _>(\"stream_proxy_protocol\")?"),
        "stream_proxy_protocol must keep the strict Option decode"
    );
    assert!(
        row_to_proxy.contains("optional_utf8_text_column(row, \"stream_match\")?"),
        "stream_match must keep strict nullable UTF-8 and JSON decoding"
    );

    let proxy_columns = [
        "backend_tls_client_cert_path",
        "backend_tls_client_key_path",
        "backend_tls_server_ca_cert_path",
        "dns_override",
        "upstream_id",
        "upstream_subset",
    ];
    for column in proxy_columns {
        assert_strict_nullable_string_decode(row_to_proxy, "row_to_proxy", column);
    }

    let upstream_columns = [
        "backend_tls_client_cert_path",
        "backend_tls_client_key_path",
        "backend_tls_server_ca_cert_path",
    ];
    for column in upstream_columns {
        assert_strict_nullable_string_decode(row_to_upstream, "row_to_upstream", column);
    }

    assert!(
        row_to_upstream.contains("required_utf8_text_column(row, \"targets\")"),
        "row_to_upstream must decode MySQL MEDIUMTEXT targets via required_utf8_text_column"
    );
    assert!(
        row_to_upstream.contains("optional_utf8_text_column(row, \"backend_tls_san_allow_list\")"),
        "row_to_upstream must decode nullable MEDIUMTEXT san allow-list via optional_utf8_text_column"
    );

    // SNI was already fail-closed; keep that contract pinned.
    assert!(
        row_to_upstream.contains("backend_tls_sni")
            && !row_to_upstream.contains("\"backend_tls_sni\").ok()"),
        "row_to_upstream must not swallow backend_tls_sni decode errors with .ok()"
    );
}

#[test]
fn every_sql_proxy_write_path_persists_stream_match() {
    let source = include_str!("../../../src/config/db_loader.rs");
    assert_eq!(
        source
            .matches("let stream_match_json = serialize_stream_match(")
            .count(),
        5,
        "create, update, bulk insert, spec submit, and spec replace must serialize stream_match"
    );
    assert_eq!(
        source.matches(".bind(&stream_match_json)").count(),
        5,
        "every SQL proxy write path must bind serialized stream_match"
    );
    assert!(source.contains("stream_proxy_protocol, backend_proxy_protocol, stream_match, \\"));
    assert!(source.contains(
        "stream_proxy_protocol=?, backend_proxy_protocol=?, stream_match=?, updated_at=?"
    ));
    assert!(
        source.contains(
            "stream_proxy_protocol = ?, backend_proxy_protocol = ?, stream_match = ?, \\"
        )
    );
}

#[test]
fn delete_paths_set_postgres_snapshot_isolation_before_other_tx_statements() {
    let source = include_str!("../../../src/config/db_loader.rs");

    for (fn_name, marker) in [
        ("delete_all_resources", "pub async fn delete_all_resources("),
        ("delete_api_spec", "pub async fn delete_api_spec("),
    ] {
        let body = source
            .split(marker)
            .nth(1)
            .and_then(|rest| rest.split("pub async fn ").next())
            .unwrap_or_else(|| panic!("{fn_name} body"));
        let begin = body
            .find("self.begin_write_tx()")
            .unwrap_or_else(|| panic!("{fn_name} must begin a transaction"));
        let set_iso = body
            .find("use_delete_capture_snapshot_tx")
            .unwrap_or_else(|| panic!("{fn_name} must call use_delete_capture_snapshot_tx"));
        let lock = body
            .find("lock_mtls_dns_admission")
            .unwrap_or_else(|| panic!("{fn_name} must lock mTLS DNS admission"));
        assert!(
            begin < set_iso && set_iso < lock,
            "{fn_name} must SET TRANSACTION (via use_delete_capture_snapshot_tx) \
             immediately after begin and before lock_mtls_dns_admission*; \
             Postgres rejects SET TRANSACTION after other statements"
        );
    }
}

fn assert_strict_nullable_string_decode(body: &str, mapper: &str, column: &str) {
    // Long column names push the call past rustfmt's width, so it wraps the
    // arguments and appends a trailing comma:
    //   optional_utf8_text_column(\n row,\n "backend_tls_client_cert_path",\n )?
    // Collapse whitespace *and* that trailing comma so the guard matches the
    // wrapped and single-line forms identically.
    let collapsed: String = body.split_whitespace().collect();
    let compact_body = collapsed.replace(",)", ")");
    let via_helper = format!("optional_utf8_text_column(row,\"{column}\")?");
    let via_try_get = format!("try_get::<Option<String>,_>(\"{column}\")?");
    assert!(
        compact_body.contains(&via_helper) || compact_body.contains(&via_try_get),
        "{mapper} must decode `{column}` with `{via_helper}` or `{via_try_get}` so NULL stays None and \
         non-NULL decode failures reject the load"
    );
    // Reject the historical silent-downgrade shapes.
    assert!(
        !body.contains(&format!("try_get(\"{column}\").ok()")),
        "{mapper} must not use try_get(\"{column}\").ok()"
    );
    assert!(
        !body.contains(&format!("try_get::<String, _>(\"{column}\").ok()")),
        "{mapper} must not use try_get::<String, _>(\"{column}\").ok()"
    );
}

#[tokio::test]
async fn failover_write_gate_fences_primary_after_opt_in_admission() {
    // Issue #3001: default fail-closed Admin writes on failover; an admitted
    // opt-in mutation fences automatic primary failback.
    use ferrum_edge::config::db_backend::DatabaseBackend;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();

    let status = store.failover_topology_status();
    assert!(
        !status.primary_active,
        "startup must land on failover when primary is missing"
    );
    assert!(!status.allow_writes);
    assert!(!status.opt_in_writes_enabled_during_window);

    // Failback without opt-in remains available.
    seed_sqlite_namespace(&primary_create_url, "primary-ns").await;
    let active = store.try_failover_reconnect(&primary_rw_url).await.unwrap();
    assert_eq!(active, primary_rw_url);
    assert!(store.failover_topology_status().primary_active);

    // Return to failover topology with opt-in enabled.
    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &format!(
            "sqlite:{}?mode=rw",
            temp_dir.path().join("missing-primary.db").to_string_lossy()
        ),
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    store.set_failover_allow_writes(true);
    assert!(!store.failover_topology_status().primary_active);
    assert!(
        store
            .failover_topology_status()
            .opt_in_writes_enabled_during_window
    );

    sqlx::query(
        "INSERT INTO upstreams (id, namespace, name, targets) VALUES ('failover-write', 'failover-ns', 'failover-name', '[]')",
    )
    .execute(&store.pool())
    .await
    .unwrap();
    store.note_failover_admin_write();
    assert!(store.failover_topology_status().primary_failback_fenced);

    // Even though primary is reachable, the store must retain the failover
    // snapshot after a mutation admission there.
    let active = store
        .try_failover_reconnect(&primary_rw_url)
        .await
        .expect("the fenced primary must fall through to a healthy failover");
    assert_eq!(active, failover_url);
    assert!(
        !store.failover_topology_status().primary_active,
        "the stale primary must not replace the failover topology"
    );
    assert!(
        store
            .failover_topology_status()
            .opt_in_writes_enabled_during_window,
        "the failover window remains active"
    );
    assert!(
        store.failover_topology_status().primary_failback_fenced,
        "reconnecting the failover must preserve the local fence"
    );
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()],
        "the failover-side write must remain visible"
    );
}

/// Issue #3001: a primary reconnect that pauses after pool publication (the
/// deferred-migration window) must not let a concurrent failover publish and
/// then be overwritten by a delayed `mark_primary` — that left the active pool
/// on failover while `primary_active=true` and made `check_write_allowed` fail
/// open. Rendezvous via test seams; no sleeps.
#[tokio::test]
async fn delayed_primary_reconnect_cannot_overwrite_later_failover_topology() {
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::{Mutex as AsyncMutex, oneshot};

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    // Start on failover; seed both topologies so each reconnect can publish.
    let store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    assert!(!store.failover_topology_status().primary_active);
    seed_sqlite_namespace(&primary_create_url, "primary-ns").await;
    seed_sqlite_namespace(&failover_url, "failover-ns").await;

    let (primary_holding_tx, primary_holding_rx) = oneshot::channel::<()>();
    let (primary_resume_tx, primary_resume_rx) = oneshot::channel::<()>();
    let (failover_before_lock_tx, failover_before_lock_rx) = oneshot::channel::<()>();
    let failover_holding = Arc::new(AtomicBool::new(false));

    let primary_holding_tx = Arc::new(StdMutex::new(Some(primary_holding_tx)));
    let primary_resume_rx = Arc::new(AsyncMutex::new(Some(primary_resume_rx)));
    let failover_before_lock_tx = Arc::new(StdMutex::new(Some(failover_before_lock_tx)));

    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                move |topology| {
                    let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = failover_before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let primary_holding_tx = Arc::clone(&primary_holding_tx);
                let primary_resume_rx = Arc::clone(&primary_resume_rx);
                let failover_holding = Arc::clone(&failover_holding);
                move |topology| {
                    let primary_holding_tx = Arc::clone(&primary_holding_tx);
                    let primary_resume_rx = Arc::clone(&primary_resume_rx);
                    let failover_holding = Arc::clone(&failover_holding);
                    Box::pin(async move {
                        match topology {
                            SqlReconnectTopology::Primary => {
                                if let Some(tx) = primary_holding_tx.lock().unwrap().take() {
                                    let _ = tx.send(());
                                }
                                if let Some(rx) = primary_resume_rx.lock().await.take() {
                                    let _ = rx.await;
                                }
                            }
                            SqlReconnectTopology::Failover => {
                                failover_holding.store(true, Ordering::SeqCst);
                            }
                        }
                    })
                }
            })),
        }),
    );

    let primary_store = store.clone();
    let primary_url = primary_rw_url.clone();
    let primary_task = tokio::spawn(async move { primary_store.reconnect(&primary_url).await });

    primary_holding_rx
        .await
        .expect("primary reconnect must enter while_holding under the transition mutex");
    assert!(
        !store.failover_topology_status().primary_active,
        "primary must stay fail-closed until mark_primary after the deferred window"
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });

    failover_before_lock_rx
        .await
        .expect("failover reconnect must reach the transition mutex while primary holds it");
    assert!(
        !failover_holding.load(Ordering::SeqCst),
        "failover must not enter while_holding while primary still holds the transition"
    );

    primary_resume_tx.send(()).expect("resume primary");
    primary_task
        .await
        .expect("join primary")
        .expect("primary reconnect");
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect");
    assert!(
        failover_holding.load(Ordering::SeqCst),
        "failover must enter while_holding only after primary releases the transition"
    );

    database_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(
        !store.failover_topology_status().primary_active,
        "later failover must own topology after the serialized primary transition"
    );
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()],
        "active pool must match the later failover publication"
    );
}

/// Inverse of the delayed-primary race: a failover holding the transition
/// after gate-before-publish must not observe a concurrent primary finalizing
/// topology/pool out of order.
#[tokio::test]
async fn delayed_failover_reconnect_cannot_race_later_primary_topology() {
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::{Mutex as AsyncMutex, oneshot};

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &primary_url, DbPoolConfig::default())
            .await
            .unwrap();
    seed_sqlite_namespace(&primary_url, "primary-ns").await;
    seed_sqlite_namespace(&failover_url, "failover-ns").await;
    assert!(store.failover_topology_status().primary_active);

    let (failover_holding_tx, failover_holding_rx) = oneshot::channel::<()>();
    let (failover_resume_tx, failover_resume_rx) = oneshot::channel::<()>();
    let (primary_before_lock_tx, primary_before_lock_rx) = oneshot::channel::<()>();
    let primary_holding = Arc::new(AtomicBool::new(false));

    let failover_holding_tx = Arc::new(StdMutex::new(Some(failover_holding_tx)));
    let failover_resume_rx = Arc::new(AsyncMutex::new(Some(failover_resume_rx)));
    let primary_before_lock_tx = Arc::new(StdMutex::new(Some(primary_before_lock_tx)));

    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let primary_before_lock_tx = Arc::clone(&primary_before_lock_tx);
                move |topology| {
                    let primary_before_lock_tx = Arc::clone(&primary_before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Primary {
                            return;
                        }
                        if let Some(tx) = primary_before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let failover_holding_tx = Arc::clone(&failover_holding_tx);
                let failover_resume_rx = Arc::clone(&failover_resume_rx);
                let primary_holding = Arc::clone(&primary_holding);
                move |topology| {
                    let failover_holding_tx = Arc::clone(&failover_holding_tx);
                    let failover_resume_rx = Arc::clone(&failover_resume_rx);
                    let primary_holding = Arc::clone(&primary_holding);
                    Box::pin(async move {
                        match topology {
                            SqlReconnectTopology::Failover => {
                                if let Some(tx) = failover_holding_tx.lock().unwrap().take() {
                                    let _ = tx.send(());
                                }
                                if let Some(rx) = failover_resume_rx.lock().await.take() {
                                    let _ = rx.await;
                                }
                            }
                            SqlReconnectTopology::Primary => {
                                primary_holding.store(true, Ordering::SeqCst);
                            }
                        }
                    })
                }
            })),
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });

    failover_holding_rx
        .await
        .expect("failover reconnect must enter while_holding after gate-before-publish");
    assert!(
        !store.failover_topology_status().primary_active,
        "failover must flip the write gate before publication completes"
    );

    let primary_store = store.clone();
    let primary_url_task = primary_url.clone();
    let primary_task =
        tokio::spawn(async move { primary_store.reconnect(&primary_url_task).await });

    primary_before_lock_rx
        .await
        .expect("primary reconnect must reach the transition mutex while failover holds it");
    assert!(
        !primary_holding.load(Ordering::SeqCst),
        "primary must not enter while_holding while failover still holds the transition"
    );

    failover_resume_tx.send(()).expect("resume failover");
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect");
    primary_task
        .await
        .expect("join primary")
        .expect("primary reconnect");
    assert!(
        primary_holding.load(Ordering::SeqCst),
        "primary must enter while_holding only after failover releases the transition"
    );

    database_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(
        store.failover_topology_status().primary_active,
        "later primary must own topology after the serialized failover transition"
    );
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["ferrum".to_string(), "primary-ns".to_string()],
        "active pool must match the later primary publication"
    );
}

/// Issue #3001: a mutation admitted on primary must pin write topology so a
/// later failover reconnect cannot publish until the permit drops — closing the
/// check-to-use race where the sync gate alone admitted on primary_active=true
/// but persistence observed the newly published failover pool.
#[tokio::test]
async fn write_topology_permit_blocks_failover_until_dropped() {
    use std::sync::Mutex as StdMutex;
    use tokio::sync::oneshot;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &primary_url, DbPoolConfig::default())
            .await
            .unwrap();
    seed_sqlite_namespace(&primary_url, "primary-ns").await;
    seed_sqlite_namespace(&failover_url, "failover-ns").await;
    assert!(store.failover_topology_status().primary_active);

    let permit = store.acquire_write_topology_permit().await;
    let primary_epoch = permit.topology_epoch();
    assert!(
        permit.is_pinned(),
        "SQL write admit must retain a reconnect-transition read pin"
    );
    assert!(
        store.failover_topology_status().primary_active,
        "pin must observe primary topology"
    );
    assert_eq!(store.config_topology_epoch(), primary_epoch);
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["ferrum".to_string(), "primary-ns".to_string()],
        "pinned mutation must keep using the primary pool"
    );

    let (failover_before_lock_tx, failover_before_lock_rx) = oneshot::channel::<()>();
    let (failover_holding_tx, failover_holding_rx) = oneshot::channel::<()>();
    let failover_holding = Arc::new(AtomicBool::new(false));
    let failover_before_lock_tx = Arc::new(StdMutex::new(Some(failover_before_lock_tx)));
    let failover_holding_tx = Arc::new(StdMutex::new(Some(failover_holding_tx)));

    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                move |topology| {
                    let failover_before_lock_tx = Arc::clone(&failover_before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = failover_before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let failover_holding = Arc::clone(&failover_holding);
                let failover_holding_tx = Arc::clone(&failover_holding_tx);
                move |topology| {
                    let failover_holding = Arc::clone(&failover_holding);
                    let failover_holding_tx = Arc::clone(&failover_holding_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        failover_holding.store(true, Ordering::SeqCst);
                        if let Some(tx) = failover_holding_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });

    failover_before_lock_rx.await.expect(
        "failover reconnect must reach the transition write lock while the mutation pin is held",
    );
    // Deterministic: the writer cannot enter while_holding until readers drop.
    assert!(
        !failover_holding.load(Ordering::SeqCst),
        "failover must not publish while a write-topology permit pins primary"
    );
    assert!(
        store.failover_topology_status().primary_active,
        "topology must stay primary for the pinned mutation's full lifetime"
    );
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["ferrum".to_string(), "primary-ns".to_string()],
        "pinned mutation must not observe the failover pool mid-flight"
    );

    drop(permit);
    failover_holding_rx
        .await
        .expect("failover must enter while_holding only after the write permit drops");
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(!store.failover_topology_status().primary_active);
    let failover_epoch = store.config_topology_epoch();
    assert!(
        failover_epoch > primary_epoch,
        "a published SQL topology must advance its process-local epoch"
    );
    let failover_permit = store.acquire_write_topology_permit().await;
    assert_eq!(failover_permit.topology_epoch(), failover_epoch);
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()]
    );
}

#[test]
fn topology_epoch_refuses_wraparound() {
    assert_eq!(checked_next_config_topology_epoch(1).unwrap(), 2);
    assert!(
        checked_next_config_topology_epoch(u64::MAX).is_err(),
        "epoch exhaustion must refuse reconnect publication instead of allowing ABA"
    );
}

/// Inverse race: failover publication that wins the transition lock first must
/// cause a subsequent admit to observe failover and fail closed (default
/// allow_writes=false) — not persist on the newly published failover pool
/// under a stale primary admission.
#[tokio::test]
async fn failover_before_admit_rejects_without_opt_in() {
    use std::sync::Mutex as StdMutex;
    use tokio::sync::{Mutex as AsyncMutex, oneshot};

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &primary_url, DbPoolConfig::default())
            .await
            .unwrap();
    seed_sqlite_namespace(&primary_url, "primary-ns").await;
    seed_sqlite_namespace(&failover_url, "failover-ns").await;

    let (failover_holding_tx, failover_holding_rx) = oneshot::channel::<()>();
    let (failover_resume_tx, failover_resume_rx) = oneshot::channel::<()>();
    let failover_holding_tx = Arc::new(StdMutex::new(Some(failover_holding_tx)));
    let failover_resume_rx = Arc::new(AsyncMutex::new(Some(failover_resume_rx)));

    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: None,
            while_holding: Some(Arc::new({
                let failover_holding_tx = Arc::clone(&failover_holding_tx);
                let failover_resume_rx = Arc::clone(&failover_resume_rx);
                move |topology| {
                    let failover_holding_tx = Arc::clone(&failover_holding_tx);
                    let failover_resume_rx = Arc::clone(&failover_resume_rx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = failover_holding_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = failover_resume_rx.lock().await.take() {
                            let _ = rx.await;
                        }
                    })
                }
            })),
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });

    failover_holding_rx
        .await
        .expect("failover must hold the write lock after gate-before-publish");
    assert!(!store.failover_topology_status().primary_active);

    // Admit waits for the exclusive write lock, then evaluates policy under its
    // read pin — must reject rather than persist on failover without opt-in.
    let admit_store = store.clone();
    let admit_task = tokio::spawn(async move {
        let permit = admit_store.acquire_write_topology_permit().await;
        let status = admit_store.failover_topology_status();
        (
            permit.is_pinned(),
            status.primary_active,
            status.allow_writes,
        )
    });

    // Give the admit task a chance to block on the write lock (no sleeps: the
    // resume channel is the only progress edge).
    failover_resume_tx.send(()).expect("resume failover");
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect");
    let (pinned, primary_active, allow_writes) = admit_task.await.expect("join admit");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(
        pinned,
        "admit after failover must still take a topology pin"
    );
    assert!(!primary_active, "admit must observe published failover");
    assert!(
        !allow_writes,
        "default policy must leave allow_writes false so AdminState::admit_write returns 503"
    );
}

/// Opt-in failover mutations must pin the failover generation so failback
/// cannot split a multi-step mutation across topologies.
#[tokio::test]
async fn opt_in_write_permit_blocks_failback_until_dropped() {
    use std::sync::Mutex as StdMutex;
    use tokio::sync::oneshot;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let primary_create_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    store.set_failover_allow_writes(true);
    seed_sqlite_namespace(&primary_create_url, "primary-ns").await;
    seed_sqlite_namespace(&failover_url, "failover-ns").await;
    assert!(!store.failover_topology_status().primary_active);
    assert!(store.failover_topology_status().allow_writes);

    let permit = store.acquire_write_topology_permit().await;
    assert!(permit.is_pinned());
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()],
        "opt-in mutation must stay on the pinned failover pool"
    );

    let (primary_before_lock_tx, primary_before_lock_rx) = oneshot::channel::<()>();
    let (primary_holding_tx, primary_holding_rx) = oneshot::channel::<()>();
    let primary_holding = Arc::new(AtomicBool::new(false));
    let primary_before_lock_tx = Arc::new(StdMutex::new(Some(primary_before_lock_tx)));
    let primary_holding_tx = Arc::new(StdMutex::new(Some(primary_holding_tx)));

    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let primary_before_lock_tx = Arc::clone(&primary_before_lock_tx);
                move |topology| {
                    let primary_before_lock_tx = Arc::clone(&primary_before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Primary {
                            return;
                        }
                        if let Some(tx) = primary_before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let primary_holding = Arc::clone(&primary_holding);
                let primary_holding_tx = Arc::clone(&primary_holding_tx);
                move |topology| {
                    let primary_holding = Arc::clone(&primary_holding);
                    let primary_holding_tx = Arc::clone(&primary_holding_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Primary {
                            return;
                        }
                        primary_holding.store(true, Ordering::SeqCst);
                        if let Some(tx) = primary_holding_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
        }),
    );

    let primary_store = store.clone();
    let primary_url = primary_create_url.clone();
    let primary_task = tokio::spawn(async move { primary_store.reconnect(&primary_url).await });

    primary_before_lock_rx
        .await
        .expect("failback must reach the transition write lock while the opt-in pin is held");
    assert!(
        !primary_holding.load(Ordering::SeqCst),
        "failback must not publish while an opt-in failover write permit is held"
    );
    assert!(!store.failover_topology_status().primary_active);
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["failover-ns".to_string(), "ferrum".to_string()]
    );

    drop(permit);
    primary_holding_rx
        .await
        .expect("failback must enter while_holding only after the write permit drops");
    primary_task
        .await
        .expect("join primary")
        .expect("primary reconnect");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);

    assert!(store.failover_topology_status().primary_active);
    assert_eq!(
        store.list_namespaces().await.unwrap(),
        vec!["ferrum".to_string(), "primary-ns".to_string()]
    );
}

#[test]
fn last_remaining_sql_is_registry_row_authority_not_the_get_union() {
    let source = include_str!("../../../src/config/db_loader.rs");
    let start = source
        .find("const ANY_NAMESPACE_REMAINS_SQL")
        .expect("ANY_NAMESPACE_REMAINS_SQL");
    let sql = &source[start..start + 400];
    assert!(
        sql.contains("SELECT 1 AS present FROM namespaces LIMIT 1"),
        "last-remaining protection must count durable registry rows only:\n{sql}"
    );
    assert!(
        !sql.contains("UNION SELECT namespace FROM proxies"),
        "the GET union must not be the delete authority; resource writers do not take \
         the global registry lease:\n{sql}"
    );
}

#[test]
fn sql_namespace_rename_rewrites_historical_audit_events() {
    let source = include_str!("../../../src/config/db_loader.rs");
    let start = source
        .find("async fn rename_namespace_in_tx(")
        .expect("rename_namespace_in_tx");
    let body = source[start..]
        .split("async fn delete_namespace_guard_rows_tx(")
        .next()
        .expect("rename_namespace_in_tx body");
    assert!(
        body.contains("NAMESPACE_RENAME_SIMPLE_TABLES"),
        "the in-place rewrite plan must still be walked for audit_events:\n{body}"
    );
    assert_eq!(
        NAMESPACE_RENAME_SIMPLE_TABLES,
        &["audit_events"],
        "historical audit_events must follow the renamed tenant"
    );
    assert!(
        !body.contains("namespace_at_event"),
        "namespace_at_event is immutable evidence and must not be rewritten on rename:\n{body}"
    );
    // Issue #4627: the namespace-keyed resource tables are copied under the new
    // name and then deleted under the old one, parent-first, because `namespace`
    // is part of every one of their primary and foreign keys.
    assert!(
        body.contains("NAMESPACE_RENAME_COPY_TABLES"),
        "rename must walk the copy plan for the namespace-keyed resource tables:\n{body}"
    );
    assert!(
        body.contains("copy_namespace_pk_rows_tx"),
        "rename must copy rather than update the namespace-keyed resource tables:\n{body}"
    );
    for table in ["proxies", "plugin_configs", "upstreams", "api_specs"] {
        assert!(
            NAMESPACE_RENAME_COPY_TABLES
                .iter()
                .any(|(name, _)| *name == table),
            "rename must still cover live resource table {table}"
        );
        assert!(
            !body.contains(&format!("UPDATE {table} SET namespace")),
            "{table} must not be renamed with an in-place namespace UPDATE:\n{body}"
        );
    }
}

/// Issue #4627 drift catcher: the rename copy plan must project EVERY column
/// of each namespace-keyed resource table. A column added to the baseline
/// schema without being added here would be silently dropped by a rename.
#[test]
fn sql_namespace_rename_copy_plan_matches_baseline_schema() {
    let schema = include_str!("../../../src/config/migrations/sql_dialect.rs");
    for (table, columns) in NAMESPACE_RENAME_COPY_TABLES {
        let expected: Vec<&str> = columns.to_vec();
        let marker = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let mut rest = schema;
        let mut branches = 0usize;
        while let Some(idx) = rest.find(&marker) {
            let body_start = idx + marker.len();
            let body_end = body_start
                + rest[body_start..]
                    .find("\n            )")
                    .unwrap_or_else(|| panic!("{table} CREATE TABLE body must terminate"));
            let declared: Vec<&str> = rest[body_start..body_end]
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .filter_map(|line| line.split_whitespace().next())
                .filter(|first| {
                    !matches!(
                        first.to_ascii_uppercase().as_str(),
                        "PRIMARY" | "FOREIGN" | "CONSTRAINT" | "CHECK" | "UNIQUE"
                    )
                })
                .collect();
            assert_eq!(
                declared, expected,
                "{table} rename copy plan is out of sync with the baseline schema"
            );
            branches += 1;
            rest = &rest[body_end..];
        }
        assert!(
            branches >= 2,
            "{table} must declare at least a MySQL and a non-MySQL branch, found {branches}"
        );
    }
}

#[test]
fn sql_namespace_rename_locks_source_and_target_mtls_dns_fences_in_order() {
    let source = include_str!("../../../src/config/db_loader.rs");
    let start = source
        .find("pub async fn update_namespace(")
        .expect("update_namespace");
    let body = source[start..]
        .split("async fn upsert_namespace_registry_row_tx(")
        .next()
        .expect("update_namespace body");
    assert!(
        body.contains("mtls_dns_admission_namespaces(")
            && body.contains("lock_mtls_dns_admission_for_owner_tx"),
        "rename must lock both names in sorted order inside the same transaction:\n{body}"
    );
    assert!(
        !body.contains("lock_mtls_dns_admission_for_owner_tx(&mut tx, current_name, None)"),
        "locking only current_name would bypass a restore owner on the target:\n{body}"
    );
}

#[test]
fn sql_namespace_row_mapper_fails_closed_on_corrupt_timestamps() {
    let source = include_str!("../../../src/config/db_loader.rs");
    let start = source
        .find("fn row_to_namespace_record(")
        .expect("row_to_namespace_record");
    let body = source[start..]
        .split("const NAMESPACE_NAME_IN_USE_SQL")
        .next()
        .expect("row_to_namespace_record body");
    assert!(
        body.contains("parse_namespace_rfc3339")
            && body.contains("NamespaceRegistryCorrupt")
            && body.contains("require_namespace_identity")
            && body.contains("require_canonical_stored_description"),
        "corrupt registry rows must not be served as plausible API data:\n{body}"
    );
    assert!(
        !body.contains("unwrap_or_else(Utc::now)")
            && !body.contains("unwrap_or(created_at)")
            && !body.contains("normalize_description"),
        "missing timestamps must not be fabricated and stored descriptions must not be normalized:\n{body}"
    );
}

#[test]
fn sql_namespace_list_fails_closed_on_corrupt_registry_rows() {
    let source = include_str!("../../../src/config/db_loader.rs");
    for marker in [
        "async fn list_namespaces_from_pool(",
        "async fn list_namespaces_paginated_from_pool(",
    ] {
        let start = source.find(marker).unwrap_or_else(|| panic!("{marker}"));
        let body = &source[start..start + 600];
        assert!(
            body.contains("ensure_namespace_registry_rows_readable(pool)"),
            "{marker} must refuse to serve names from an unreadable registry:\n{body}"
        );
    }
}

#[test]
fn sql_namespace_registry_mutations_require_canonical_lease_set_before_begin() {
    let source = include_str!("../../../src/config/db_loader.rs");
    for (marker, names) in [
        (
            "pub async fn create_namespace(",
            "require_namespace_registry_admission_leases(&[&record.name], leases)",
        ),
        (
            "pub async fn update_namespace(",
            "require_namespace_registry_admission_leases(&[current_name, new_name], leases)",
        ),
        (
            "pub async fn delete_namespace(",
            "require_namespace_registry_admission_leases(&[name], leases)",
        ),
    ] {
        let start = source.find(marker).expect(marker);
        let body = source[start..]
            .split("\n    pub async fn ")
            .next()
            .unwrap_or(&source[start..]);
        let require_at = body
            .find("require_namespace_registry_admission_leases")
            .unwrap_or_else(|| panic!("{marker} must validate the canonical lease set:\n{body}"));
        let begin_at = body
            .find("begin_write_tx()")
            .unwrap_or_else(|| panic!("{marker} must open a transaction:\n{body}"));
        assert!(
            body.contains(names),
            "{marker} must require the canonical names {names}:\n{body}"
        );
        assert!(
            require_at < begin_at,
            "{marker} must reject a substituted lease set before opening a transaction:\n{body}"
        );
        assert!(
            body.contains("verify_namespace_registry_leases_tx"),
            "{marker} must still re-verify owner/generation inside the transaction:\n{body}"
        );
    }

    let verify = source[source
        .find("async fn verify_namespace_registry_leases_tx(")
        .expect("verify helper")..]
        .split("\n    pub async fn create_namespace(")
        .next()
        .expect("verify body");
    assert!(
        verify.contains("require_namespace_registry_admission_leases(names, leases)")
            && verify.contains("verify_namespace_config_admission_lease_tx"),
        "commit-boundary verification must re-check the canonical key set then owner/generation:\n{verify}"
    );
}

// ── Retryable serialization/deadlock classification (issue #3955 review) ─────

/// SQLite's writer lock must be taken by `BEGIN`, not by the first write.
///
/// A deferred `BEGIN` pins a WAL read snapshot on its first `SELECT`; the
/// upgrade to the writer lock then fails with `SQLITE_BUSY_SNAPSHOT` (extended
/// code 517) the moment another connection committed in between, and
/// `PRAGMA busy_timeout` deliberately does not wait that error out. Every
/// read-then-write store path is exposed to it, and a background admission
/// lease release on a second pooled connection is enough to trigger it.
#[tokio::test]
async fn sqlite_write_transactions_hold_the_writer_lock_from_begin() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("sqlite_write_tx.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();
    insert_namespace_row(&store, "writer-lock-seed").await;

    // A deferred `BEGIN` reproduces the failure exactly.
    let mut deferred = store.pool().begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM namespaces")
        .fetch_one(&mut *deferred)
        .await
        .unwrap();
    insert_namespace_row(&store, "interleaved-commit").await;
    let error = sqlx::query("UPDATE namespaces SET updated_at = ? WHERE name = ?")
        .bind("2026-01-01T00:00:00Z")
        .bind("writer-lock-seed")
        .execute(&mut *deferred)
        .await
        .expect_err("a stale deferred snapshot cannot upgrade to the writer lock");
    let wrapped = anyhow::Error::new(error).context("namespace registry transaction failed");
    assert!(
        is_retryable_sql_transaction_conflict(&wrapped),
        "a SQLite busy/locked write conflict aborts before commit and must classify as \
         retryable, not surface as a driver error: {wrapped:#}"
    );
    drop(deferred);

    // `begin_write_tx()` takes the writer lock up front, so the same
    // interleaving serializes instead of failing: the concurrent writer waits
    // for this transaction's commit.
    let mut immediate = store.begin_write_tx().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM namespaces")
        .fetch_one(&mut *immediate)
        .await
        .unwrap();
    let concurrent_store = store.pool();
    let concurrent = tokio::spawn(async move {
        sqlx::query(
            "INSERT INTO namespaces (name, description, created_at, updated_at) \
             VALUES (?, NULL, ?, ?)",
        )
        .bind("waits-for-the-writer")
        .bind("2026-01-01T00:00:00Z")
        .bind("2026-01-01T00:00:00Z")
        .execute(&concurrent_store)
        .await
    });
    sqlx::query("UPDATE namespaces SET updated_at = ? WHERE name = ?")
        .bind("2026-01-02T00:00:00Z")
        .bind("writer-lock-seed")
        .execute(&mut *immediate)
        .await
        .expect("an immediate transaction already owns the writer lock");
    immediate.commit().await.unwrap();
    concurrent
        .await
        .unwrap()
        .expect("the queued writer proceeds once the write transaction commits");
}

async fn insert_namespace_row(store: &DatabaseStore, name: &str) {
    sqlx::query(
        "INSERT INTO namespaces (name, description, created_at, updated_at) VALUES (?, NULL, ?, ?)",
    )
    .bind(name)
    .bind("2026-01-01T00:00:00Z")
    .bind("2026-01-01T00:00:00Z")
    .execute(&store.pool())
    .await
    .unwrap();
}

#[test]
fn sqlite_busy_and_locked_result_codes_are_the_retryable_write_conflicts() {
    for code in [
        "5",   // SQLITE_BUSY
        "6",   // SQLITE_LOCKED
        "517", // SQLITE_BUSY_SNAPSHOT — busy_timeout never waits this one out
        "261", // SQLITE_BUSY_RECOVERY
        "262", // SQLITE_LOCKED_SHAREDCACHE
    ] {
        assert!(
            sqlite_code_is_retryable_write_conflict(code),
            "SQLite {code} aborts the write before commit and is safe to retry"
        );
    }
    for code in [
        "1",    // SQLITE_ERROR
        "8",    // SQLITE_READONLY
        "19",   // SQLITE_CONSTRAINT — a real conflict a retry would only repeat
        "1555", // SQLITE_CONSTRAINT_PRIMARYKEY
        "787",  // SQLITE_CONSTRAINT_FOREIGNKEY
        "14",   // SQLITE_CANTOPEN — connectivity, not a write conflict
        "40001",
        "",
        "not-a-code",
    ] {
        assert!(
            !sqlite_code_is_retryable_write_conflict(code),
            "SQLite {code} must not be classified as a retryable write conflict"
        );
    }
}

#[test]
fn retryable_transaction_conflict_sqlstates_are_exactly_serialization_and_deadlock() {
    for code in ["40001", "40P01"] {
        assert!(
            sqlstate_is_retryable_transaction_conflict(code),
            "{code} is a database-aborted transaction and is safe to retry"
        );
    }
    for code in [
        // Uniqueness / name conflicts: a retry would only repeat them.
        "23505", "23000",
        "23503", // Connectivity, syntax, permissions, and MySQL's generic class.
        "08006", "08001", "42601", "42501", "HY000", "40002", "400011", "4000", "",
    ] {
        assert!(
            !sqlstate_is_retryable_transaction_conflict(code),
            "{code} must not be classified as a safe-retry transaction conflict"
        );
    }
}

#[test]
fn retryable_transaction_conflict_classification_is_chain_aware() {
    // Persistence layers wrap driver errors in their own context, so the
    // outermost message alone misses the abort.
    for code in ["40001", "40P01"] {
        let wrapped =
            anyhow::Error::new(sqlx::Error::Database(Box::new(TestDatabaseError { code })))
                .context("namespace registry transaction failed")
                .context("delete_namespace");
        assert!(
            is_retryable_sql_transaction_conflict(&wrapped),
            "a wrapped SQLSTATE {code} must still classify as retryable: {wrapped:#}"
        );
    }
}

#[test]
fn retryable_transaction_conflict_classification_does_not_misclassify() {
    // A unique-constraint violation is a real 409, not a retryable abort.
    let unique = anyhow::Error::new(sqlx::Error::Database(Box::new(TestDatabaseError {
        code: "23505",
    })))
    .context("namespace registry transaction failed");
    assert!(!is_retryable_sql_transaction_conflict(&unique));

    // Connectivity failures carry no SQLSTATE at all.
    let connectivity = anyhow::Error::new(sqlx::Error::PoolTimedOut).context("acquire failed");
    assert!(!is_retryable_sql_transaction_conflict(&connectivity));
    assert!(!is_retryable_sql_transaction_conflict(&anyhow::anyhow!(
        "connection refused"
    )));

    // A typed registry error must never be swallowed by the classifier.
    use ferrum_edge::config::namespace_registry::NamespaceRegistryError as RegistryError;
    let name_in_use = RegistryError::name_in_use("tenant-a");
    assert!(!is_retryable_sql_transaction_conflict(&name_in_use));
}

#[test]
fn sql_registry_mutations_map_database_aborts_to_the_typed_retryable_conflict() {
    // The three public entry points must funnel through the classifier so the
    // admin layer never has to inspect driver text, and the driver error is
    // dropped rather than chained (it is the last place a `{:#}` rendering
    // could leak the relation name and the conflicting statement).
    let source = include_str!("../../../src/config/db_loader.rs");
    for (public, inner) in [
        ("pub async fn create_namespace(", "create_namespace_inner("),
        ("pub async fn update_namespace(", "update_namespace_inner("),
        ("pub async fn delete_namespace(", "delete_namespace_inner("),
    ] {
        let start = source.find(public).expect(public);
        let body = source[start..]
            .split("\n    async fn ")
            .next()
            .unwrap_or(&source[start..]);
        assert!(
            body.contains("classify_namespace_registry_result") && body.contains(inner),
            "{public} must route its result through the retryable classifier:\n{body}"
        );
    }

    let classifier_start = source
        .find("fn classify_namespace_registry_result")
        .expect("classifier");
    let classifier_tail = &source[classifier_start..];
    let classifier_end = classifier_tail
        .find("\n}\n")
        .map(|offset| offset + 3)
        .unwrap_or(classifier_tail.len());
    let classifier = &classifier_tail[..classifier_end];
    assert!(
        classifier.contains("is_retryable_sql_transaction_conflict")
            && classifier.contains("NamespaceRegistryRetryableConflict"),
        "the classifier must map a database-aborted transaction onto the typed conflict:\n{classifier}"
    );
    assert!(
        !classifier.contains(".context(") && !classifier.contains("to_string()"),
        "the driver error must be dropped, never rendered or chained:\n{classifier}"
    );
}

// ── One-time backfill serialization (issue #3955 review) ────────────────────

#[test]
fn sql_namespace_registry_backfill_runs_under_the_global_registry_lease() {
    let source = include_str!("../../../src/config/migrations/sql_dialect.rs");
    let start = source
        .find("async fn run_serialized_namespaces_registry_backfill(")
        .expect("serialized backfill entry point");
    let serialized = source[start..]
        .split("\n    /// Conditionally take the global registry admission lease.")
        .next()
        .expect("serialized backfill body");

    let acquire_at = serialized
        .find("try_acquire_namespaces_registry_backfill_lease")
        .expect("the pass must take the global registry admission lease");
    let backfill_at = serialized
        .find(".backfill_namespaces_registry(")
        .expect("the pass must run the backfill under that lease");
    let release_at = serialized
        .find("release_namespaces_registry_backfill_lease")
        .expect("the pass must release the lease");
    assert!(
        acquire_at < backfill_at && backfill_at < release_at,
        "the lease must be held across the whole compatibility pass:\n{serialized}"
    );
    assert!(
        serialized.contains("(Err(backfill_error), _) => Err(backfill_error)"),
        "the lease must be released on the error path too, without masking the failure:\n{serialized}"
    );
    // The lock order stays total: the pass takes ONLY the global key, which is
    // always first, so it can never invert the order against a live mutation.
    let acquire = source[source
        .find("async fn try_acquire_namespaces_registry_backfill_lease(")
        .expect("acquire helper")..]
        .split("\n    async fn ")
        .next()
        .expect("acquire body");
    assert!(
        acquire.contains("NAMESPACE_REGISTRY_ADMISSION_KEY")
            && acquire.contains("config_admission_lease_acquire_sql"),
        "acquisition must reuse the runtime store's non-stealing lease SQL:\n{acquire}"
    );
}

#[test]
fn sql_namespace_registry_backfill_commits_once_and_verifies_its_lease() {
    let source = include_str!("../../../src/config/migrations/sql_dialect.rs");
    let dispatcher = source[source
        .find("async fn backfill_namespaces_registry(")
        .expect("backfill dispatcher")..]
        .split("\n    /// PostgreSQL / MySQL:")
        .next()
        .expect("dispatcher body");
    assert!(
        dispatcher.contains("is_sqlite()")
            && dispatcher.contains("backfill_namespaces_registry_under_sqlite_savepoint")
            && dispatcher.contains("backfill_namespaces_registry_in_explicit_transaction"),
        "SQLite must take the savepoint path; PostgreSQL/MySQL keep an explicit transaction:\n\
         {dispatcher}"
    );
    assert!(
        !dispatcher.contains("connection.begin()") && !dispatcher.contains("tx.commit()"),
        "the dispatcher must not itself begin or commit a nested transaction:\n{dispatcher}"
    );

    let explicit = source[source
        .find("async fn backfill_namespaces_registry_in_explicit_transaction(")
        .expect("explicit transaction helper")..]
        .split("\n    /// SQLite: run the backfill")
        .next()
        .expect("explicit transaction body");
    assert!(
        explicit.contains("connection.begin()")
            && explicit.contains("tx.commit()")
            && explicit.contains("tx.rollback()")
            && explicit.contains("backfill_namespaces_registry_body"),
        "PostgreSQL/MySQL must retain one explicit backfill transaction:\n{explicit}"
    );

    let body = source[source
        .find("async fn backfill_namespaces_registry_body(")
        .expect("shared backfill body")..]
        .split("\n    /// Authoritative namespace-keyed")
        .next()
        .expect("shared backfill body");
    let pin_at = body
        .find("pin_namespaces_registry_backfill_lease")
        .expect("start-of-transaction lease pin");
    let completed_at = body
        .find("namespaces_registry_backfill_completed")
        .expect("authoritative completion check");
    let insert_at = body.find("insert_derived").expect("derived-name insert");
    let mark_at = body
        .find("mark_namespaces_registry_backfill_complete")
        .expect("completion mark");
    let verify_at = body
        .find("namespaces_registry_backfill_lease_held")
        .expect("commit-boundary lease verification");
    let apply_at = body
        .find("NamespacesRegistryBackfillOutcome::Apply")
        .expect("apply outcome");
    assert!(
        pin_at < completed_at,
        "the lease row must be verified and locked as the FIRST statement of the atomic unit, \
         before anything is read or written:\n{body}"
    );
    assert!(
        completed_at < insert_at,
        "a completed backfill must skip the inserts:\n{body}"
    );
    assert!(
        insert_at < mark_at,
        "the marker must be written after the idempotent inserts so a crash retries:\n{body}"
    );
    assert!(
        mark_at < verify_at && verify_at < apply_at,
        "the lease must be re-verified immediately before the caller commits:\n{body}"
    );
    assert!(
        !body.contains("connection.begin()")
            && !body.contains("tx.commit()")
            && !body.contains("tx.rollback()"),
        "the shared body must not begin, commit, or roll back the caller's atomic unit:\n{body}"
    );

    let pin = source[source
        .find("async fn pin_namespaces_registry_backfill_lease(")
        .expect("lease pin helper")..]
        .split("\n    /// Commit-boundary proof")
        .next()
        .expect("lease pin body");
    assert!(
        pin.contains("FOR UPDATE") && pin.contains("is_sqlite()"),
        "the pin must take a real row lock on every dialect that has FOR UPDATE, with an \
         explicit SQLite branch:\n{pin}"
    );
    assert!(
        pin.contains("UPDATE config_admission_locks SET expires_at"),
        "the SQLite branch must promote the transaction to a WRITE transaction so the single \
         database writer lock excludes a competing acquisition:\n{pin}"
    );
    assert!(
        pin.contains("generation = ?") && pin.contains("expires_at > {now}"),
        "the pin must verify owner, generation, and database-clock expiry before locking:\n{pin}"
    );

    let verify = source[source
        .find("async fn namespaces_registry_backfill_lease_held(")
        .expect("lease verification helper")..]
        .split("\n    /// Rewrite `?` placeholders")
        .next()
        .expect("lease verification body");
    assert!(
        verify.contains("FOR UPDATE") && verify.contains("is_sqlite()"),
        "the lease row must stay pinned through the commit on every dialect that has \
         FOR UPDATE:\n{verify}"
    );
    assert!(
        verify.contains("owner = ?") && verify.contains("generation = ?"),
        "the commit-boundary proof must still be owner- and generation-qualified:\n{verify}"
    );
    // Regression: an otherwise uncontended backfill that outruns the 120s lease
    // TTL while the row is transactionally pinned must still commit. Re-testing
    // `expires_at` here would roll it back and starve it on every retry.
    assert!(
        !verify.contains("expires_at"),
        "elapsed wall time under the row pin is not lost ownership; the commit-boundary proof \
         must not re-check the lease TTL:\n{verify}"
    );
}

/// Hosted SQLite migrations already hold `BEGIN IMMEDIATE` on this connection
/// (`MigrationConnectionLock`). A nested `connection.begin()` is the
/// `(code: 1) cannot start a transaction within a transaction` failure.
#[test]
fn sql_namespace_registry_backfill_does_not_nest_a_sqlite_begin() {
    let migrations = include_str!("../../../src/config/migrations/mod.rs");
    assert!(
        migrations.contains("BEGIN IMMEDIATE")
            && migrations.contains("struct MigrationConnectionLock")
            && migrations.contains("ensure_compatibility_tables(connection)"),
        "SQLite migrations must take BEGIN IMMEDIATE before the compatibility pass, and that \
         outer transaction remains the durable commit boundary"
    );

    let source = include_str!("../../../src/config/migrations/sql_dialect.rs");
    let sqlite = source[source
        .find("async fn backfill_namespaces_registry_under_sqlite_savepoint(")
        .expect("sqlite savepoint helper")..]
        .split("\n    async fn rollback_sqlite_namespaces_registry_backfill_savepoint(")
        .next()
        .expect("sqlite savepoint body");
    assert!(
        sqlite.contains("SAVEPOINT namespaces_registry_backfill")
            && sqlite.contains("RELEASE SAVEPOINT namespaces_registry_backfill")
            && sqlite.contains("rollback_sqlite_namespaces_registry_backfill_savepoint"),
        "SQLite must isolate the backfill with a SAVEPOINT on the already-open migration \
         transaction:\n{sqlite}"
    );
    assert!(
        !sqlite.contains("connection.begin()")
            && !sqlite.contains("tx.commit()")
            && !sqlite.contains("tx.rollback()")
            && !sqlite.contains("sqlx::query(\"BEGIN")
            && !sqlite.contains("sqlx::query(\"COMMIT")
            && !sqlite.contains("sqlx::query(\"ROLLBACK"),
        "the SQLite savepoint path must never emit BEGIN/COMMIT/ROLLBACK that would close \
         or nest inside the outer BEGIN IMMEDIATE:\n{sqlite}"
    );

    let rollback = source[source
        .find("async fn rollback_sqlite_namespaces_registry_backfill_savepoint(")
        .expect("sqlite savepoint rollback")..]
        .split("\n    /// Shared pin / scan")
        .next()
        .expect("sqlite savepoint rollback body");
    assert!(
        rollback.contains("ROLLBACK TO SAVEPOINT namespaces_registry_backfill")
            && rollback.contains("RELEASE SAVEPOINT namespaces_registry_backfill"),
        "failure/defer must roll back only the savepoint, then release it:\n{rollback}"
    );
    assert!(
        !rollback.contains("sqlx::query(\"COMMIT")
            && !rollback.contains("sqlx::query(\"ROLLBACK\")")
            && !rollback.contains("connection.begin()"),
        "savepoint rollback must not COMMIT or ROLLBACK the outer migration transaction:\n\
         {rollback}"
    );
}

fn http_route_proxy(id: &str, namespace: &str, listen_path: Option<&str>, hosts: &[&str]) -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "hosts": hosts,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .unwrap();
    proxy.normalize_fields();
    proxy
}

async fn sqlite_uniqueness_store() -> (DatabaseStore, tempfile::TempDir) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("admission_point_lookups.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .unwrap();
    (store, temp_dir)
}

#[tokio::test]
async fn check_listen_path_unique_rejects_catch_all_and_isolates_namespaces() {
    let (store, _tmp) = sqlite_uniqueness_store().await;

    let catch_all = http_route_proxy("p-catch", "ferrum", Some("/svc/1"), &[]);
    store.create_proxy(&catch_all).await.unwrap();

    let same_path_other_hosts =
        http_route_proxy("p-overlap", "ferrum", Some("/svc/1"), &["api.example.com"]);
    assert!(
        !store
            .check_listen_path_unique(
                "ferrum",
                same_path_other_hosts.listen_path.as_deref(),
                &same_path_other_hosts.hosts,
                None,
            )
            .await
            .unwrap(),
        "empty hosts is a catch-all that overlaps every host on the same listen_path"
    );

    let other_namespace = http_route_proxy("p-other-ns", "tenant-b", Some("/svc/1"), &[]);
    assert!(
        store
            .check_listen_path_unique(
                "tenant-b",
                other_namespace.listen_path.as_deref(),
                &other_namespace.hosts,
                None,
            )
            .await
            .unwrap(),
        "the same listen_path in another namespace must not collide"
    );

    let host_only = http_route_proxy("p-host-only", "ferrum", None, &["api.example.com"]);
    store.create_proxy(&host_only).await.unwrap();
    let path_carrying =
        http_route_proxy("p-path", "ferrum", Some("/svc/path"), &["api.example.com"]);
    assert!(
        store
            .check_listen_path_unique(
                "ferrum",
                path_carrying.listen_path.as_deref(),
                &path_carrying.hosts,
                None,
            )
            .await
            .unwrap(),
        "host-only and path-carrying proxies on the same host occupy different match tiers"
    );
}

#[tokio::test]
async fn check_consumer_identity_unique_is_namespace_isolated() {
    let (store, _tmp) = sqlite_uniqueness_store().await;

    let mut alice = make_consumer("c-alice", "alice");
    alice.namespace = "ferrum".to_string();
    store.create_consumer(&alice).await.unwrap();

    let conflict = store
        .check_consumer_identity_unique("ferrum", "c-other", "alice", None, None)
        .await
        .unwrap();
    assert!(
        conflict.is_some(),
        "the same username in the same namespace must collide: {conflict:?}"
    );

    let isolated = store
        .check_consumer_identity_unique("tenant-b", "c-other", "alice", None, None)
        .await
        .unwrap();
    assert!(
        isolated.is_none(),
        "the same username in another namespace must be unique: {isolated:?}"
    );
}

#[test]
fn replace_api_spec_metadata_shortcut_uses_transactional_existence_not_rows_affected() {
    // Issue #4285: fail closed when the api_specs row is missing, but do not treat
    // MySQL changed-row count as existence. sqlx MySQL without CLIENT_FOUND_ROWS
    // reports 0 for an UPDATE that matches an existing row and writes identical
    // values. Existence is the same-transaction SELECT (FOR UPDATE on
    // PostgreSQL/MySQL; SQLite write-tx writer lock).
    let source = include_str!("../../../src/config/db_loader.rs");
    let replace = source
        .split("pub async fn replace_api_spec_bundle(")
        .nth(1)
        .and_then(|rest| {
            rest.split("\n    async fn current_api_spec_resource_hash_tx(")
                .next()
        })
        .expect("replace_api_spec_bundle body");

    let existing = replace
        .find("Existence read inside the transaction is the not-found authority")
        .expect("existence-authority comment");
    let existing_end = replace[existing..]
        .find("let previous_declared_assoc_ids")
        .expect("existence select ends before declared assoc ids")
        + existing;
    let existing_sql = &replace[existing..existing_end];
    assert!(
        existing_sql.contains("CLIENT_FOUND_ROWS")
            && existing_sql.contains("if self.db_type == \"sqlite\""),
        "existence must document CLIENT_FOUND_ROWS and sqlite branch:\n{existing_sql}"
    );
    assert!(
        existing_sql.contains("self.q(\"SELECT * FROM api_specs WHERE namespace = ? AND id = ?\")")
            && existing_sql.contains(
                "self.q(\"SELECT * FROM api_specs WHERE namespace = ? AND id = ? FOR UPDATE\")"
            ),
        "existence SELECT must lock api_specs with FOR UPDATE except on SQLite:\n{existing_sql}"
    );

    let shortcut = replace
        .find("Bundle is unchanged — only update the api_specs metadata row.")
        .expect("metadata-only shortcut marker");
    let commit = replace[shortcut..]
        .find("tx.commit().await?;")
        .expect("metadata shortcut commit");
    let shortcut_to_commit = &replace[shortcut..shortcut + commit];
    let missing = shortcut_to_commit
        .find("existing_spec.is_none()")
        .expect("shortcut must fail closed when the locked existence read found no row");
    assert!(
        !shortcut_to_commit.contains("rows_affected()")
            && !shortcut_to_commit.contains("update_result"),
        "shortcut must not use UPDATE rows_affected as existence:\n{shortcut_to_commit}"
    );
    let update = shortcut_to_commit
        .find("UPDATE api_specs SET")
        .expect("shortcut must still UPDATE metadata on an existing row");
    assert!(
        missing < update,
        "missing-row fail-closed must run before the metadata UPDATE:\n{shortcut_to_commit}"
    );
}

#[test]
fn consumer_identity_uniqueness_queries_the_identity_index() {
    let source = include_str!("../../../src/config/db_loader.rs");
    let start = source
        .find("    pub async fn check_consumer_identity_unique(")
        .expect("SQL identity uniqueness check");
    let end = source[start..]
        .find("\n    pub async fn check_keyauth_key_unique(")
        .expect("keyauth uniqueness follows identity uniqueness")
        + start;
    let body = &source[start..end];
    assert!(
        body.contains("FROM consumer_identity_index"),
        "identity uniqueness must probe the identity index, not scan consumers:\n{body}"
    );
    assert!(
        body.contains("WHERE namespace = ?"),
        "identity uniqueness must carry the namespace predicate in the query:\n{body}"
    );
    assert!(
        body.contains("LIMIT 1"),
        "identity uniqueness must stop at the first index hit:\n{body}"
    );
    assert!(
        !body.contains("id IN (")
            && !body.contains("username IN (")
            && !body.contains("custom_id IN ("),
        "identity uniqueness must not scan the consumers table:\n{body}"
    );
}

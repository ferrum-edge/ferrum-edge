use ferrum_edge::_test_support::{
    DbPoolConfig, db_append_connect_timeout, db_code_is_transient, db_diff_removed,
    db_mongo_error_is_transient, db_mysql_error_number_is_transient,
    db_wrap_mysql_isolation_read_error, is_config_validation_rejection,
    mysql_config_change_lock_insert_sql, mysql_mtls_dns_admission_lock_insert_sql,
    mysql_proxy_route_lock_insert_sql, parse_auth_mode, parse_scheme, statement_timeout_sql,
    validate_tcp_connection_throttle_attachments,
};
use ferrum_edge::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, is_incremental_full_reload_required,
    is_mtls_dns_admission_unavailable, is_mtls_dns_identity_conflict,
    tcp_connection_throttle_attachment_conflict,
};
use ferrum_edge::config::db_loader::DatabaseStore;
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
        .and_then(|rest| rest.split("async fn lock_mtls_dns_admission_tx(").next())
        .expect("lock_config_change_sequence_tx body");
    assert!(
        config_change.contains("db_type != \"mysql\""),
        "MySQL must be excluded from the config_change FOR UPDATE path:\n{config_change}"
    );
    assert!(
        config_change.contains("FOR UPDATE"),
        "PostgreSQL config_change lock path must retain SELECT ... FOR UPDATE:\n{config_change}"
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
    }
}

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
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
        id: id.to_string(),
        plugin_name: "tcp_connection_throttle".to_string(),
        namespace: "ferrum".to_string(),
        config: json!({"max_connections_per_key": 10}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

// ── append_connect_timeout ───────────────────────────────────────────────────

#[test]
fn test_append_connect_timeout_postgres_no_existing_params() {
    let result = db_append_connect_timeout("postgres://user:pass@localhost/mydb", "postgres", 10);
    assert_eq!(
        result,
        "postgres://user:pass@localhost/mydb?connect_timeout=10"
    );
}

#[test]
fn test_append_connect_timeout_postgres_with_existing_params() {
    let result = db_append_connect_timeout(
        "postgres://user:pass@localhost/mydb?sslmode=require",
        "postgres",
        15,
    );
    assert_eq!(
        result,
        "postgres://user:pass@localhost/mydb?sslmode=require&connect_timeout=15"
    );
}

#[test]
fn test_append_connect_timeout_mysql() {
    let result = db_append_connect_timeout("mysql://user:pass@localhost/mydb", "mysql", 5);
    assert_eq!(result, "mysql://user:pass@localhost/mydb?connect_timeout=5");
}

#[test]
fn test_append_connect_timeout_sqlite_skipped() {
    let result = db_append_connect_timeout("sqlite://mydb.sqlite", "sqlite", 10);
    assert_eq!(result, "sqlite://mydb.sqlite");
}

#[test]
fn test_append_connect_timeout_zero_disabled() {
    let result = db_append_connect_timeout("postgres://user:pass@localhost/mydb", "postgres", 0);
    assert_eq!(result, "postgres://user:pass@localhost/mydb");
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
        assert!(
            parse_scheme(value).is_err(),
            "{value:?} should not be accepted as backend_scheme"
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
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
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
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
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
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Proxy,
            proxy_id: Some(proxy.id.clone()),
            enabled: true,
            priority_override: None,
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
}

#[tokio::test]
async fn mtls_dns_admission_loads_consumers_only_for_effective_dns_policy() {
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
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect_err("enabling san_dns must take the full Consumer validation path");
    assert!(
        error
            .to_string()
            .contains("failed to parse credentials JSON"),
        "unexpected full-path error: {error:#}"
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
            id: "dns-mtls".to_string(),
            plugin_name: "mtls_auth".to_string(),
            namespace: "ferrum".to_string(),
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: false,
            priority_override: None,
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
            json!({"clock_skew_seconds": 300}),
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
                id: id.to_string(),
                plugin_name: plugin_name.to_string(),
                namespace: "ferrum".to_string(),
                config,
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
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
        vec!["failover-ns".to_string()],
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
        vec!["replica-ns".to_string()],
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

#[tokio::test]
async fn list_namespaces_paginated_empty_store_returns_zero_total() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-empty").await;

    let page = store.list_namespaces_paginated(100, 0).await.unwrap();
    assert_eq!(page.total, 0);
    assert!(page.items.is_empty());
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
    assert_eq!(page.total, 3);
    assert_eq!(page.items, vec!["alpha", "middle", "zeta"]);
}

#[tokio::test]
async fn list_namespaces_paginated_slices_pages_and_preserves_total() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let store = connect_namespaces_test_store(&temp_dir, "ns-pages").await;
    for i in 0..5 {
        seed_namespace_upstream(&store, &format!("ns-{i:02}"), &format!("up-{i:02}")).await;
    }

    let page = store.list_namespaces_paginated(2, 0).await.unwrap();
    assert_eq!(page.items, vec!["ns-00", "ns-01"]);
    assert_eq!(page.total, 5);

    let page = store.list_namespaces_paginated(2, 2).await.unwrap();
    assert_eq!(page.items, vec!["ns-02", "ns-03"]);
    assert_eq!(page.total, 5);

    let page = store.list_namespaces_paginated(2, 4).await.unwrap();
    assert_eq!(page.items, vec!["ns-04"]);
    assert_eq!(page.total, 5);

    // An offset at or beyond the total is a valid empty page, not an error.
    let page = store.list_namespaces_paginated(2, 5).await.unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.total, 5);

    let page = store.list_namespaces_paginated(2, 100).await.unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.total, 5);
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
        assert_eq!(page.total, 120);
        if page.items.is_empty() {
            break;
        }
        offset += page.items.len() as i64;
        collected.extend(page.items);
    }
    assert_eq!(collected.len(), 120);
    let mut sorted = collected.clone();
    sorted.sort();
    assert_eq!(
        collected, sorted,
        "pages must concatenate in ascending order"
    );
    assert_eq!(collected.first().map(String::as_str), Some("ns-000"));
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
    assert_eq!(first.items, vec!["ns-00", "ns-01", "ns-02", "ns-03"]);
    assert_eq!(first.total, 10);

    // Inserts that sort after the fetched window must not shift already-
    // returned rows into a later page.
    for i in 0..5 {
        seed_namespace_upstream(&store, &format!("ns-a{i}"), &format!("up-a{i}")).await;
    }

    let second = store.list_namespaces_paginated(100, 4).await.unwrap();
    assert_eq!(second.total, 15);
    let remainder: Vec<&str> = second.items.iter().map(String::as_str).collect();
    assert_eq!(
        remainder[..6],
        ["ns-04", "ns-05", "ns-06", "ns-07", "ns-08", "ns-09"],
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

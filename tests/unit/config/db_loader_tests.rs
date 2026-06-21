use ferrum_edge::_test_support::{
    DbPoolConfig, db_append_connect_timeout, db_diff_removed, parse_auth_mode, parse_scheme,
    statement_timeout_sql,
};
use ferrum_edge::config::db_loader::DatabaseStore;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, LoadBalancerAlgorithm, Upstream, UpstreamTarget,
};
use serde_json::json;
use std::collections::HashSet;

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
    let loaded = store.get_upstream("tls-u1").await.unwrap().unwrap();
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

    let loaded = store.get_upstream("tls-u1").await.unwrap().unwrap();
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
    store.update_consumer(&consumer).await.unwrap();

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

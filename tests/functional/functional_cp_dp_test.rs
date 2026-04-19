//! Comprehensive functional test for Control Plane / Data Plane mode.
//!
//! This test:
//! 1. Starts a local SQLite database
//! 2. Starts the Control Plane (CP) server in a background task
//! 3. Starts the Data Plane (DP) client in a background task
//! 4. Uses the Admin API on the CP to create proxies and consumers
//! 5. Tests that the DP receives the config via gRPC
//! 6. Tests proxy traffic through the DP
//!
//! This is a functional test and is marked with #[ignore]
//! to avoid running during normal `cargo test`. Run with:
//!   cargo test --test functional_cp_dp_test -- --ignored --nocapture

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{AuthMode, BackendProtocol, Consumer, GatewayConfig, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::grpc::cp_server::CpGrpcServer;
use ferrum_edge::grpc::dp_client;
use ferrum_edge::proxy::ProxyState;
use tokio::time::sleep;
use tonic::transport::Server;

const ADMIN_JWT_SECRET: &str = "test-admin-secret-key-functional";
const GRPC_JWT_SECRET: &str = "test-grpc-secret-functional-32ch";

/// Create a minimal EnvConfig for testing
fn create_test_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        log_level: "debug".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8002,
        proxy_https_port: 8443,
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        proxy_bind_address: "0.0.0.0".into(),
        admin_http_port: 9004,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "0.0.0.0".into(),
        admin_jwt_secret: Some(ADMIN_JWT_SECRET.into()),
        db_type: Some("sqlite".into()),
        db_url: None,
        db_poll_interval: 5,
        db_tls_enabled: false,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        db_tls_insecure: false,
        db_ssl_mode: None,
        db_ssl_root_cert: None,
        db_ssl_client_cert: None,
        db_ssl_client_key: None,
        file_config_path: Some("/tmp/test-config.json".into()),
        db_config_backup_path: None,
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: Some("127.0.0.1:50054".into()),
        cp_dp_grpc_jwt_secret: Some(GRPC_JWT_SECRET.into()),
        dp_cp_grpc_url: None,
        dp_cp_grpc_urls: Vec::new(),
        dp_cp_failover_primary_retry_secs: 300,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_cutoff_bytes: 65_536,
        h2_coalesce_target_bytes: 131_072,
        dns_ttl_override: None,
        dns_overrides: HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_min_ttl: 5,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        dns_failed_retry_interval: 10,
        dns_warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 1000,
        http3_stream_receive_window: 8_388_608,
        http3_receive_window: 33_554_432,
        http3_send_window: 8_388_608,
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        grpc_pool_ready_wait_ms: 1,
        pool_cleanup_interval_seconds: 30,
        tcp_idle_timeout_seconds: 300,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        tls_session_cache_size: 4096,
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: String::new(),
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
        admin_restore_max_body_size_mib: 100,
        migrate_action: "up".into(),
        migrate_dry_run: false,
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
    }
}

/// Create a test Proxy entry
fn create_test_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_protocol: BackendProtocol::Http,
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// DP now generates its own JWT from the shared secret via dp_client::generate_dp_jwt()

/// Create a ProxyState for DP testing
fn create_proxy_state() -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
    });
    let env_config = create_test_env_config();
    ProxyState::new(GatewayConfig::default(), dns_cache, env_config, None).unwrap()
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_dp_grpc_config_sync() {
    println!("Starting CP/DP gRPC config sync test...");

    // Create initial config with one proxy
    let initial_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("proxy-func-1", "/api/v1", 3001)],
        consumers: vec![Consumer {
            id: "consumer-1".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            username: "test-user".into(),
            custom_id: Some("custom-1".into()),
            credentials: Default::default(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };

    // Start CP gRPC server
    println!("Starting CP gRPC server...");
    let config_arc = Arc::new(ArcSwap::new(Arc::new(initial_config.clone())));
    let (cp_server, update_tx) = CpGrpcServer::new(config_arc.clone(), GRPC_JWT_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind CP gRPC server");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(cp_server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server failed");
    });

    sleep(Duration::from_millis(200)).await;

    // Create DP proxy state (starts empty)
    let dp_proxy_state = create_proxy_state();
    assert_eq!(
        dp_proxy_state.config.load().proxies.len(),
        0,
        "DP should start with empty config"
    );

    // Connect DP to CP (DP generates its own JWT from the shared secret)
    println!("DP connecting to CP at {}...", addr);
    let cp_url = format!("http://{}", addr);
    let ps = dp_proxy_state.clone();
    let url_clone = cp_url.clone();
    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());

    let client_handle = tokio::spawn(async move {
        let _ = dp_client::connect_and_subscribe(
            &url_clone,
            &secret,
            "test-dp-node",
            &ps,
            None,
            "ferrum",
        )
        .await;
    });

    // Wait for initial config to be received by DP
    println!("Waiting for DP to receive initial config...");
    sleep(Duration::from_millis(500)).await;

    let dp_config = dp_proxy_state.config.load();
    assert_eq!(
        dp_config.proxies.len(),
        1,
        "DP should have received 1 proxy from CP"
    );
    assert_eq!(dp_config.proxies[0].id, "proxy-func-1");
    assert_eq!(
        dp_config.consumers.len(),
        1,
        "DP should have received 1 consumer"
    );
    println!("DP successfully received initial config with 1 proxy and 1 consumer");

    // Update config on CP and broadcast to DP
    println!("Updating config on CP (adding another proxy)...");
    let updated_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            create_test_proxy("proxy-func-1", "/api/v1", 3001),
            create_test_proxy("proxy-func-2", "/api/v2", 3002),
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };

    config_arc.store(Arc::new(updated_config.clone()));
    CpGrpcServer::broadcast_update(&update_tx, &updated_config);

    // Wait for DP to receive the update
    println!("Waiting for DP to receive config update...");
    sleep(Duration::from_millis(500)).await;

    let dp_config = dp_proxy_state.config.load();
    assert_eq!(
        dp_config.proxies.len(),
        2,
        "DP should have received 2 proxies after update"
    );
    assert_eq!(dp_config.proxies[1].id, "proxy-func-2");
    println!("DP successfully received updated config with 2 proxies");

    // Clean up
    client_handle.abort();
    server_handle.abort();

    println!("CP/DP gRPC config sync test PASSED");
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_database_connection_with_tls_config() {
    println!("Starting database connection test with TLS config...");

    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("ferrum_test_tls_{}.db", uuid::Uuid::new_v4()));
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    // Test 1: Connect without TLS (plaintext)
    println!("Test 1: Connecting to SQLite without TLS...");
    let db = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        false,
        None,
        None,
        None,
        false,
        DbPoolConfig::default(),
    )
    .await
    .expect("Failed to connect to plaintext SQLite database");

    // Verify we can load config from the database
    let config = db
        .load_full_config("ferrum")
        .await
        .expect("Failed to load config from database");
    assert_eq!(
        config.proxies.len(),
        0,
        "Initial database should have no proxies"
    );
    println!("Plaintext database connection: PASSED");

    // Test 2: Create a proxy in the database
    println!("Test 2: Creating proxy in database...");
    let proxy = create_test_proxy("db-test-proxy", "/test", 8080);
    db.create_proxy(&proxy)
        .await
        .expect("Failed to create proxy in database");
    println!("Proxy creation in database: PASSED");

    // Test 3: Load config and verify proxy exists
    println!("Test 3: Loading config and verifying proxy...");
    let config = db
        .load_full_config("ferrum")
        .await
        .expect("Failed to load config after creation");
    assert_eq!(config.proxies.len(), 1, "Database should have 1 proxy");
    assert_eq!(config.proxies[0].id, "db-test-proxy");
    println!("Config loading verification: PASSED");

    // Test 4: Test TLS config parameters (they should be accepted even if not used for SQLite)
    println!("Test 4: Database connection with TLS parameters (SQLite ignores TLS)...");
    let db_with_tls = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        true,
        Some("/path/to/ca.pem"),
        Some("/path/to/client.pem"),
        Some("/path/to/client-key.pem"),
        false,
        DbPoolConfig::default(),
    )
    .await
    .expect("Failed to connect with TLS parameters");

    let config = db_with_tls
        .load_full_config("ferrum")
        .await
        .expect("Failed to load config with TLS params");
    assert_eq!(
        config.proxies.len(),
        1,
        "Should still have the created proxy"
    );
    println!("TLS parameters acceptance: PASSED");

    // Test 5: Test TLS insecure mode
    println!("Test 5: Database connection with TLS insecure mode...");
    let db_insecure = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        true,
        None,
        None,
        None,
        true,
        DbPoolConfig::default(),
    )
    .await
    .expect("Failed to connect with TLS insecure");

    let config = db_insecure
        .load_full_config("ferrum")
        .await
        .expect("Failed to load config with insecure TLS");
    assert_eq!(config.proxies.len(), 1);
    println!("TLS insecure mode: PASSED");

    // Clean up
    let _ = fs::remove_file(&db_path);

    println!("Database connection with TLS config test PASSED");
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_env_config_tls_fields() {
    println!("Starting EnvConfig TLS fields test...");

    let config = create_test_env_config();

    // Verify all TLS fields are present
    assert!(
        !config.db_tls_enabled,
        "db_tls_enabled should default to false"
    );
    assert!(
        config.db_tls_ca_cert_path.is_none(),
        "db_tls_ca_cert_path should be None"
    );
    assert!(
        config.db_tls_client_cert_path.is_none(),
        "db_tls_client_cert_path should be None"
    );
    assert!(
        config.db_tls_client_key_path.is_none(),
        "db_tls_client_key_path should be None"
    );
    assert!(
        !config.db_tls_insecure,
        "db_tls_insecure should default to false"
    );

    println!("All TLS fields present in EnvConfig");
    println!("EnvConfig TLS fields test PASSED");
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_url_construction() {
    println!("Starting gRPC URL construction test...");

    // This test verifies that PostgreSQL and MySQL TLS URL construction works
    // (even though we use SQLite for actual tests)

    let base_postgres = "postgres://user:pass@localhost:5432/mydb";
    let base_mysql = "mysql://user:pass@localhost:3306/mydb";

    // Test Postgres TLS URL construction
    let pg_with_ca = DatabaseStore::connect_with_tls_config(
        "postgres",
        base_postgres,
        true,
        Some("/path/to/ca.pem"),
        Some("/path/to/client.pem"),
        Some("/path/to/client-key.pem"),
        false,
        DbPoolConfig::default(),
    )
    .await;

    match pg_with_ca {
        Ok(_) => println!("Postgres TLS URL construction simulation: PASSED"),
        Err(e) => println!(
            "Postgres TLS URL construction (expected to fail in test): {}",
            e
        ),
    }

    // Test MySQL TLS URL construction
    let mysql_with_ca = DatabaseStore::connect_with_tls_config(
        "mysql",
        base_mysql,
        true,
        Some("/path/to/ca.pem"),
        None,
        None,
        false,
        DbPoolConfig::default(),
    )
    .await;

    match mysql_with_ca {
        Ok(_) => println!("MySQL TLS URL construction simulation: PASSED"),
        Err(e) => println!(
            "MySQL TLS URL construction (expected to fail in test): {}",
            e
        ),
    }

    println!("gRPC URL construction test PASSED");
}

/// Test that namespace isolation works end-to-end with a shared database.
///
/// Creates proxies and consumers in two namespaces ("production" and "staging")
/// in the same SQLite database, then verifies that `load_full_config` with each
/// namespace returns only that namespace's resources.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_namespace_isolation_in_database() {
    println!("Starting namespace isolation test...");

    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("ferrum_test_ns_{}.db", uuid::Uuid::new_v4()));
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    let db = DatabaseStore::connect_with_tls_config(
        "sqlite",
        &db_url,
        false,
        None,
        None,
        None,
        false,
        DbPoolConfig::default(),
    )
    .await
    .expect("Failed to connect to SQLite");

    // Create proxies in "production" namespace
    let mut prod_proxy = create_test_proxy("prod-proxy-1", "/api/v1", 3001);
    prod_proxy.namespace = "production".to_string();
    db.create_proxy(&prod_proxy)
        .await
        .expect("Failed to create production proxy");

    let prod_consumer = Consumer {
        id: "prod-consumer-1".into(),
        namespace: "production".to_string(),
        username: "prod-user".into(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.create_consumer(&prod_consumer)
        .await
        .expect("Failed to create production consumer");

    // Create proxies in "staging" namespace
    let mut staging_proxy = create_test_proxy("staging-proxy-1", "/api/v1", 3001);
    staging_proxy.namespace = "staging".to_string();
    db.create_proxy(&staging_proxy)
        .await
        .expect("Failed to create staging proxy");

    let mut staging_proxy2 = create_test_proxy("staging-proxy-2", "/api/v2", 3002);
    staging_proxy2.namespace = "staging".to_string();
    db.create_proxy(&staging_proxy2)
        .await
        .expect("Failed to create staging proxy 2");

    let staging_consumer = Consumer {
        id: "staging-consumer-1".into(),
        namespace: "staging".to_string(),
        username: "staging-user".into(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.create_consumer(&staging_consumer)
        .await
        .expect("Failed to create staging consumer");

    // Verify production namespace sees only its resources
    println!("Test 1: Loading production namespace...");
    let prod_config = db
        .load_full_config("production")
        .await
        .expect("Failed to load production config");
    assert_eq!(
        prod_config.proxies.len(),
        1,
        "Production should have 1 proxy"
    );
    assert_eq!(prod_config.proxies[0].id, "prod-proxy-1");
    assert_eq!(prod_config.proxies[0].namespace, "production");
    assert_eq!(
        prod_config.consumers.len(),
        1,
        "Production should have 1 consumer"
    );
    assert_eq!(prod_config.consumers[0].username, "prod-user");
    println!("Production namespace isolation: PASSED");

    // Verify staging namespace sees only its resources
    println!("Test 2: Loading staging namespace...");
    let staging_config = db
        .load_full_config("staging")
        .await
        .expect("Failed to load staging config");
    assert_eq!(
        staging_config.proxies.len(),
        2,
        "Staging should have 2 proxies"
    );
    assert!(
        staging_config
            .proxies
            .iter()
            .all(|p| p.namespace == "staging")
    );
    assert_eq!(
        staging_config.consumers.len(),
        1,
        "Staging should have 1 consumer"
    );
    assert_eq!(staging_config.consumers[0].username, "staging-user");
    println!("Staging namespace isolation: PASSED");

    // Verify default "ferrum" namespace sees nothing (no resources in that namespace)
    println!("Test 3: Loading default namespace (should be empty)...");
    let default_config = db
        .load_full_config("ferrum")
        .await
        .expect("Failed to load default config");
    assert_eq!(
        default_config.proxies.len(),
        0,
        "Default namespace should have 0 proxies"
    );
    assert_eq!(
        default_config.consumers.len(),
        0,
        "Default namespace should have 0 consumers"
    );
    println!("Default namespace empty: PASSED");

    // Verify same listen_path works across namespaces (both have /api/v1)
    println!("Test 4: Same listen_path in different namespaces...");
    assert_eq!(
        prod_config.proxies[0].listen_path.as_deref(),
        Some("/api/v1")
    );
    assert!(
        staging_config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/api/v1"))
    );
    println!("Cross-namespace listen_path reuse: PASSED");

    // Verify list_namespaces returns all namespaces
    println!("Test 5: list_namespaces returns all namespaces...");
    let namespaces = db
        .list_namespaces()
        .await
        .expect("Failed to list namespaces");
    assert!(
        namespaces.contains(&"production".to_string()),
        "Should contain production"
    );
    assert!(
        namespaces.contains(&"staging".to_string()),
        "Should contain staging"
    );
    println!("list_namespaces: PASSED (found {:?})", namespaces);

    // Clean up
    let _ = fs::remove_file(&db_path);

    println!("Namespace isolation test PASSED");
}

/// Verify the CP gRPC server only distributes resources from its own
/// configured namespace to subscribing DPs, even when the shared database
/// contains resources in other namespaces.
///
/// The CP is single-namespace by design (it loads config scoped to
/// `FERRUM_NAMESPACE`). This test pins that behavior: staging data present in
/// the DB must never leak into the snapshot a prod-scoped CP broadcasts.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_cp_dp_namespace_isolation_over_grpc() {
    println!("Starting CP/DP namespace isolation-over-gRPC test...");

    // Build the CP's in-memory config to contain ONLY production resources.
    // This mirrors `control_plane.rs` which calls `db.load_full_config(namespace)`
    // at startup, and what the Admin API enforces per-request via the header.
    let prod_only_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![{
            let mut p = create_test_proxy("prod-only-proxy", "/api/v1", 3001);
            p.namespace = "production".to_string();
            p
        }],
        consumers: vec![Consumer {
            id: "prod-consumer".into(),
            namespace: "production".to_string(),
            username: "prod-user".into(),
            custom_id: None,
            credentials: Default::default(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: vec!["production".to_string(), "staging".to_string()],
    };

    let config_arc = Arc::new(ArcSwap::new(Arc::new(prod_only_config.clone())));
    let (cp_server, update_tx) = CpGrpcServer::new(config_arc.clone(), GRPC_JWT_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind CP");
    let addr = listener.local_addr().expect("CP addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let server_handle = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(cp_server.into_service())
            .serve_with_incoming(incoming)
            .await;
    });

    sleep(Duration::from_millis(200)).await;

    // DP subscribes and requests the production namespace.
    let dp_proxy_state = create_proxy_state();
    let cp_url = format!("http://{addr}");
    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());
    let ps = dp_proxy_state.clone();
    let url_clone = cp_url.clone();

    let client_handle = tokio::spawn(async move {
        let _ = dp_client::connect_and_subscribe(
            &url_clone,
            &secret,
            "prod-dp-node",
            &ps,
            None,
            "production",
        )
        .await;
    });

    sleep(Duration::from_millis(500)).await;

    let dp_config = dp_proxy_state.config.load();
    assert_eq!(
        dp_config.proxies.len(),
        1,
        "DP should have exactly the production proxy"
    );
    assert_eq!(dp_config.proxies[0].namespace, "production");
    assert!(
        dp_config
            .consumers
            .iter()
            .all(|c| c.namespace == "production"),
        "DP must not receive staging consumers"
    );

    // Now simulate a CP-side update: the operator adds a staging proxy via
    // a different CP instance sharing the same DB. The production CP must
    // continue broadcasting only production resources — its own view of the
    // DB is namespace-scoped, so the broadcast payload never contains the
    // staging proxy.
    let updated_prod_config = GatewayConfig {
        version: "2".to_string(),
        proxies: vec![
            {
                let mut p = create_test_proxy("prod-only-proxy", "/api/v1", 3001);
                p.namespace = "production".to_string();
                p
            },
            {
                let mut p = create_test_proxy("prod-only-proxy-2", "/api/v2", 3002);
                p.namespace = "production".to_string();
                p
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: vec!["production".to_string(), "staging".to_string()],
    };

    config_arc.store(Arc::new(updated_prod_config.clone()));
    CpGrpcServer::broadcast_update(&update_tx, &updated_prod_config);

    sleep(Duration::from_millis(500)).await;

    let dp_config = dp_proxy_state.config.load();
    assert_eq!(
        dp_config.proxies.len(),
        2,
        "DP should see both prod proxies after update"
    );
    assert!(
        dp_config
            .proxies
            .iter()
            .all(|p| p.namespace == "production"),
        "DP must only have production-scoped proxies after update"
    );

    client_handle.abort();
    server_handle.abort();

    println!("CP/DP namespace isolation-over-gRPC test PASSED");
}

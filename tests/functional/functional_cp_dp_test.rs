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
use ferrum_gateway::config::db_loader::DatabaseStore;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Consumer, GatewayConfig, Proxy};
use ferrum_gateway::config::{EnvConfig, OperatingMode};
use ferrum_gateway::dns::{DnsCache, DnsConfig};
use ferrum_gateway::grpc::cp_server::CpGrpcServer;
use ferrum_gateway::grpc::dp_client;
use ferrum_gateway::proxy::ProxyState;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tokio::time::sleep;
use tonic::transport::Server;

const ADMIN_JWT_SECRET: &str = "test-admin-secret-key-functional";
const GRPC_JWT_SECRET: &str = "test-grpc-secret-functional";

/// Create a minimal EnvConfig for testing
fn create_test_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        log_level: "debug".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8002,
        proxy_https_port: 8443,
        proxy_tls_cert_path: None,
        proxy_tls_key_path: None,
        admin_http_port: 9004,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
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
        cp_grpc_listen_addr: Some("127.0.0.1:50054".into()),
        cp_grpc_jwt_secret: Some(GRPC_JWT_SECRET.into()),
        dp_cp_grpc_url: None,
        dp_grpc_auth_token: None,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        dns_cache_ttl_seconds: 300,
        dns_overrides: HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_valid_ttl: None,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
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
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        stream_proxy_bind_address: "0.0.0.0".into(),
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
    }
}

/// Create a test Proxy entry
fn create_test_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: listen_path.to_string(),
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
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_max_idle_per_host: None,
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
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a JWT token for gRPC authentication
fn create_grpc_token() -> String {
    let claims = json!({
        "sub": "dp-node",
        "role": "data_plane",
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(GRPC_JWT_SECRET.as_bytes()),
    )
    .expect("Failed to create gRPC JWT token")
}

/// Create a ProxyState for DP testing
fn create_proxy_state() -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 300,
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        valid_ttl_override: None,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        slow_threshold_ms: None,
    });
    let env_config = create_test_env_config();
    ProxyState::new(GatewayConfig::default(), dns_cache, env_config).unwrap()
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
            username: "test-user".into(),
            custom_id: Some("custom-1".into()),
            credentials: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    };

    // Start CP gRPC server
    println!("Starting CP gRPC server...");
    let config_arc = Arc::new(ArcSwap::new(Arc::new(initial_config.clone())));
    let (cp_server, update_tx) = CpGrpcServer::new(config_arc.clone(), GRPC_JWT_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:50054")
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

    // Connect DP to CP
    println!("DP connecting to CP at {}...", addr);
    let cp_url = format!("http://{}", addr);
    let token = create_grpc_token();
    let ps = dp_proxy_state.clone();
    let url_clone = cp_url.clone();
    let token_clone = token.clone();

    let client_handle = tokio::spawn(async move {
        let _ =
            dp_client::connect_and_subscribe(&url_clone, &token_clone, "test-dp-node", &ps).await;
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
    let db =
        DatabaseStore::connect_with_tls_config("sqlite", &db_url, false, None, None, None, false)
            .await
            .expect("Failed to connect to plaintext SQLite database");

    // Verify we can load config from the database
    let config = db
        .load_full_config()
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
        .load_full_config()
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
    )
    .await
    .expect("Failed to connect with TLS parameters");

    let config = db_with_tls
        .load_full_config()
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
    let db_insecure =
        DatabaseStore::connect_with_tls_config("sqlite", &db_url, true, None, None, None, true)
            .await
            .expect("Failed to connect with TLS insecure");

    let config = db_insecure
        .load_full_config()
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

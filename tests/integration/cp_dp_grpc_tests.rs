//! Tests for Control Plane / Data Plane gRPC communication.
//!
//! These tests verify that the DP client connects to the CP server,
//! receives initial config snapshots, and processes streaming config updates.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tokio::time::timeout;
use tonic::transport::Server;

use ferrum_gateway::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::dns::{DnsCache, DnsConfig};
use ferrum_gateway::grpc::cp_server::CpGrpcServer;
use ferrum_gateway::grpc::dp_client;
use ferrum_gateway::proxy::ProxyState;

const TEST_JWT_SECRET: &str = "test-grpc-secret-key";

/// Create a JWT token signed with the test secret.
fn create_test_token() -> String {
    let claims = json!({
        "sub": "dp-node",
        "role": "data_plane",
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("Failed to create test JWT token")
}

/// Create a test Proxy entry.
fn create_test_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("Test Proxy {}", id)),
        listen_path: listen_path.to_string(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "localhost".to_string(),
        backend_port: 3000,
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
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a GatewayConfig with the given number of test proxies.
fn create_test_config(proxy_count: usize) -> GatewayConfig {
    let proxies: Vec<Proxy> = (0..proxy_count)
        .map(|i| create_test_proxy(&format!("proxy-{}", i), &format!("/api-{}", i)))
        .collect();
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    }
}

/// Create a minimal EnvConfig for testing (file mode with dummy path).
fn create_test_env_config() -> ferrum_gateway::config::EnvConfig {
    ferrum_gateway::config::EnvConfig {
        mode: ferrum_gateway::config::env_config::OperatingMode::File,
        log_level: "info".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8000,
        proxy_https_port: 8443,
        proxy_tls_cert_path: None,
        proxy_tls_key_path: None,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
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
        cp_grpc_listen_addr: None,
        cp_grpc_jwt_secret: None,
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
        backend_tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        backend_tls_no_verify: false,
        admin_read_only: false,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 100,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        real_ip_header: None,
    }
}

/// Create a ProxyState with empty config for DP testing.
fn create_test_proxy_state() -> ProxyState {
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
    });
    let env_config = create_test_env_config();
    ProxyState::new(GatewayConfig::default(), dns_cache, env_config).unwrap()
}

/// Start a CP gRPC server on a random port and return the address and broadcast sender.
async fn start_test_cp_server(
    config: GatewayConfig,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_gateway::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    // Bind to port 0 to get a random available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server failed");
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, update_tx, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_receives_initial_config_from_cp() {
    // Start CP server with 2 proxies
    let cp_config = create_test_config(2);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config.clone()).await;

    // Create DP proxy state (starts empty)
    let proxy_state = create_test_proxy_state();
    assert_eq!(proxy_state.config.load().proxies.len(), 0);

    // Connect to CP and receive initial config
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();
    let node_id = "test-node-1";

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(&cp_url, &token, node_id, &proxy_state),
    )
    .await;

    // The stream will end when the server shuts down, or we'll timeout.
    // Either way, the initial config should have been received.
    // connect_and_subscribe returns Ok(()) when the stream ends, or an error.
    // We check that the proxy_state was updated.

    // Give a moment for the initial config to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        2,
        "DP should have received 2 proxies from CP"
    );
    assert_eq!(current_config.proxies[0].id, "proxy-0");
    assert_eq!(current_config.proxies[1].id, "proxy-1");

    // Verify the result was Ok (stream ended gracefully or we timed out after receiving config)
    match result {
        Ok(Ok(())) => {} // Stream ended gracefully
        Ok(Err(e)) => panic!("connect_and_subscribe failed: {}", e),
        Err(_) => {} // Timeout is acceptable - we already verified config was received
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_receives_config_updates() {
    // Start CP server with initial config of 1 proxy
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Create DP proxy state (starts empty)
    let proxy_state = create_test_proxy_state();

    // Spawn the DP client in the background
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "test-node-2", &ps).await
    });

    // Wait for initial config to arrive
    let received_initial = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_initial.is_ok(),
        "DP should have received initial config with 1 proxy"
    );

    // Now broadcast an updated config with 3 proxies
    let updated_config = create_test_config(3);
    CpGrpcServer::broadcast_update(&update_tx, &updated_config);

    // Wait for the update to arrive
    let received_update = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_update.is_ok(),
        "DP should have received updated config with 3 proxies"
    );

    let current_config = proxy_state.config.load();
    assert_eq!(current_config.proxies.len(), 3);
    assert_eq!(current_config.proxies[2].id, "proxy-2");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_invalid_token() {
    // Start CP server
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    // Create a token signed with the WRONG secret
    let wrong_claims = json!({"sub": "attacker"});
    let wrong_token = encode(
        &Header::new(Algorithm::HS256),
        &wrong_claims,
        &EncodingKey::from_secret(b"wrong-secret-key"),
    )
    .unwrap();

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(&cp_url, &wrong_token, "bad-node", &proxy_state),
    )
    .await;

    match result {
        Ok(Err(e)) => {
            // Should get an authentication error
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("Unauthenticated")
                    || err_msg.contains("unauthenticated")
                    || err_msg.contains("token"),
                "Expected authentication error, got: {}",
                err_msg
            );
        }
        Ok(Ok(())) => panic!("Should have rejected invalid token"),
        Err(_) => panic!("Should have responded before timeout"),
    }

    // Verify proxy state was NOT updated
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        0,
        "Config should remain empty after auth failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_handles_malformed_config() {
    // Start CP server with valid initial config
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    // Spawn DP client
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "test-node-malformed", &ps).await
    });

    // Wait for initial config
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok(), "Should receive initial config");

    // Send a malformed config update (invalid JSON that can't deserialize to GatewayConfig)
    let malformed_update = ferrum_gateway::grpc::proto::ConfigUpdate {
        update_type: 0,
        config_json: "{invalid json!!!}".to_string(),
        version: "bad".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
    };
    let _ = update_tx.send(malformed_update);

    // Wait a bit then verify the config wasn't corrupted
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Config should still have the valid initial config (1 proxy)
    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        1,
        "Config should remain unchanged after malformed update"
    );

    // Now send a valid update to prove the client is still alive
    let valid_config = create_test_config(2);
    CpGrpcServer::broadcast_update(&update_tx, &valid_config);

    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "Client should recover and process valid updates after malformed one"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_preserves_config_after_cp_shutdown() {
    // This test verifies that when the CP goes down, the DP preserves its cached config
    // and the start_dp_client_with_shutdown loop keeps running (doesn't crash).

    // Start CP server with initial config
    let cp_config = create_test_config(2);
    let (addr, _update_tx, server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    // Use start_dp_client_with_shutdown which has auto-reconnect logic
    let ps = proxy_state.clone();
    let url_clone = cp_url.clone();
    let token_clone = token.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown(url_clone, token_clone, ps, None).await;
    });

    // Wait for initial config
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 2 proxies"
    );

    // Shut down CP server
    server_handle.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify cached config is preserved (the key behavior)
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        2,
        "Cached config should be preserved after CP shutdown"
    );
    assert_eq!(proxy_state.config.load().proxies[0].id, "proxy-0");
    assert_eq!(proxy_state.config.load().proxies[1].id, "proxy-1");

    // Verify the client task is still alive (not crashed) — it should be retrying
    assert!(
        !client_handle.is_finished(),
        "DP client should still be running (retrying connection)"
    );

    client_handle.abort();
}

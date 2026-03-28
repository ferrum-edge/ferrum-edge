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
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::{Certificate, Identity, Server};

use ferrum_gateway::config::db_loader::IncrementalResult;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::dns::{DnsCache, DnsConfig};
use ferrum_gateway::grpc::cp_server::CpGrpcServer;
use ferrum_gateway::grpc::dp_client::{self, DpGrpcTlsConfig};
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
        hosts: vec![],
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
        udp_idle_timeout_seconds: 60,
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
        db_config_backup_path: None,
        cp_grpc_listen_addr: None,
        cp_grpc_jwt_secret: None,
        dp_cp_grpc_url: None,
        dp_grpc_auth_token: None,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
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
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        pool_cleanup_interval_seconds: 30,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
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
        slow_threshold_ms: None,
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
        dp_client::connect_and_subscribe(&cp_url, &token, node_id, &proxy_state, None),
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
        dp_client::connect_and_subscribe(&cp_url, &token, "test-node-2", &ps, None).await
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
        dp_client::connect_and_subscribe(&cp_url, &wrong_token, "bad-node", &proxy_state, None),
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
        dp_client::connect_and_subscribe(&cp_url, &token, "test-node-malformed", &ps, None).await
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
        dp_client::start_dp_client_with_shutdown(url_clone, token_clone, ps, None, None).await;
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

// ── TLS / mTLS tests ─────────────────────────────────────────────────────────

/// Generate a self-signed CA + leaf certificate for testing.
/// Returns (ca_cert_pem, server_cert_pem, server_key_pem).
fn generate_test_ca_and_server_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate CA key pair and self-signed CA cert
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["Ferrum Test CA".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate server key pair and cert signed by the CA
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    (
        ca_cert.pem().into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}

/// Start a CP gRPC server with TLS on a random port.
async fn start_test_cp_server_with_tls(
    config: GatewayConfig,
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> (
    SocketAddr,
    tokio::sync::broadcast::Sender<ferrum_gateway::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::new(config_arc, TEST_JWT_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut tls_config =
        ServerTlsConfig::new().identity(Identity::from_pem(server_cert_pem, server_key_pem));
    if let Some(ca_pem) = client_ca_pem {
        tls_config = tls_config.client_ca_root(Certificate::from_pem(ca_pem));
    }

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .expect("Failed to configure TLS")
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC TLS server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, update_tx, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_connects_to_cp_with_tls() {
    // Generate CA + server cert
    let (ca_pem, server_cert_pem, server_key_pem) = generate_test_ca_and_server_cert();

    // Start CP server with TLS
    let cp_config = create_test_config(2);
    let (addr, _update_tx, _server_handle) =
        start_test_cp_server_with_tls(cp_config.clone(), &server_cert_pem, &server_key_pem, None)
            .await;

    // Create DP with TLS config (CA cert to verify server)
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(ca_pem),
        client_cert_pem: None,
        client_key_pem: None,
        no_verify: false,
    };

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &token,
            "tls-node-1",
            &proxy_state,
            Some(&tls_config),
        ),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        2,
        "DP should have received 2 proxies from CP over TLS"
    );

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("TLS connect_and_subscribe failed: {}", e),
        Err(_) => {} // Timeout acceptable after receiving config
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_connects_to_cp_with_mtls() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate CA for both server and client certs
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["Ferrum Test CA".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();

    // Generate server cert signed by CA
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();

    // Generate client cert signed by the same CA
    let client_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let client_params = rcgen::CertificateParams::new(vec!["dp-client".to_string()]).unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();

    // Start CP with mTLS (requires client certs verified against the CA)
    let cp_config = create_test_config(3);
    let (addr, _update_tx, _server_handle) = start_test_cp_server_with_tls(
        cp_config.clone(),
        &server_cert_pem,
        &server_key_pem,
        Some(&ca_pem),
    )
    .await;

    // Create DP with mTLS config (CA cert + client cert/key)
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(ca_pem),
        client_cert_pem: Some(client_cert_pem),
        client_key_pem: Some(client_key_pem),
        no_verify: false,
    };

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &token,
            "mtls-node-1",
            &proxy_state,
            Some(&tls_config),
        ),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let current_config = proxy_state.config.load();
    assert_eq!(
        current_config.proxies.len(),
        3,
        "DP should have received 3 proxies from CP over mTLS"
    );

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("mTLS connect_and_subscribe failed: {}", e),
        Err(_) => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_rejects_untrusted_cp_server_cert() {
    // Generate one CA for the server and a DIFFERENT CA for the client trust store
    let (_, server_cert_pem, server_key_pem) = generate_test_ca_and_server_cert();

    // Generate a different CA that the DP will trust (server cert NOT signed by this)
    let different_ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut different_ca_params =
        rcgen::CertificateParams::new(vec!["Different CA".to_string()]).unwrap();
    different_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let different_ca_cert = different_ca_params.self_signed(&different_ca_key).unwrap();
    let different_ca_pem = different_ca_cert.pem().into_bytes();

    // Start CP server with its own cert
    let cp_config = create_test_config(1);
    let (addr, _update_tx, _server_handle) =
        start_test_cp_server_with_tls(cp_config, &server_cert_pem, &server_key_pem, None).await;

    // DP trusts the WRONG CA — should fail to connect
    let proxy_state = create_test_proxy_state();
    let cp_url = format!("https://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let tls_config = DpGrpcTlsConfig {
        ca_cert_pem: Some(different_ca_pem),
        client_cert_pem: None,
        client_key_pem: None,
        no_verify: false,
    };

    let result = timeout(
        Duration::from_secs(5),
        dp_client::connect_and_subscribe(
            &cp_url,
            &token,
            "untrusted-node",
            &proxy_state,
            Some(&tls_config),
        ),
    )
    .await;

    // Connection should fail due to certificate verification
    match result {
        Ok(Err(_)) => {} // Expected: TLS handshake failure
        Ok(Ok(())) => panic!("Should have failed with untrusted CA"),
        Err(_) => panic!("Should have failed fast, not timed out"),
    }

    // Config should remain empty
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        0,
        "Config should remain empty when TLS verification fails"
    );
}

// ── Delta / Incremental update tests ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_update_adding_proxy() {
    // Start CP with initial config of 1 proxy
    let cp_config = create_test_config(1);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    // Spawn DP client
    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-node-1", &ps, None).await
    });

    // Wait for initial full snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 1 proxy"
    );

    // Now send a DELTA update that adds a new proxy
    let new_proxy = create_test_proxy("proxy-new", "/api-new");
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![new_proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for the delta to be applied
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta adding a proxy (expected 2 proxies)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    // Both original and new proxy should be present
    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(ids.contains(&"proxy-new"));

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_update_removing_proxy() {
    // Start CP with initial config of 3 proxies
    let cp_config = create_test_config(3);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-node-2", &ps, None).await
    });

    // Wait for initial snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Should receive initial config with 3 proxies"
    );

    // Send a DELTA that removes proxy-1
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec!["proxy-1".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta to be applied
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta removing proxy-1 (expected 2 proxies)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(!ids.contains(&"proxy-1")); // removed
    assert!(ids.contains(&"proxy-2"));

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_then_full_snapshot() {
    // Verify that a full snapshot after deltas produces the correct final state.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-node-3", &ps, None).await
    });

    // Wait for initial snapshot (2 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send a delta that adds proxy-extra
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-extra", "/api-extra")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received_delta.is_ok(), "Should have 3 proxies after delta");

    // Now send a full snapshot with only 1 proxy — should replace everything
    let final_config = create_test_config(1);
    CpGrpcServer::broadcast_update(&update_tx, &final_config);

    let received_full = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_full.is_ok(),
        "Full snapshot should override to 1 proxy"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].id, "proxy-0");

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_ignores_malformed_delta() {
    // Verify that a malformed delta doesn't corrupt existing config.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-node-4", &ps, None).await
    });

    // Wait for initial snapshot
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send malformed delta (invalid JSON for update_type=1)
    let malformed = ferrum_gateway::grpc::proto::ConfigUpdate {
        update_type: 1, // DELTA
        config_json: "{not valid delta json!!!}".to_string(),
        version: "bad".to_string(),
        timestamp: Utc::now().timestamp(),
    };
    let _ = update_tx.send(malformed);

    // Wait a bit, then verify config is unchanged
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        proxy_state.config.load().proxies.len(),
        2,
        "Config should remain unchanged after malformed delta"
    );

    // Send a valid delta to prove client is still alive
    let delta = IncrementalResult {
        added_or_modified_proxies: vec![create_test_proxy("proxy-after", "/api-after")],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v3");

    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "Client should recover and apply valid delta after malformed one"
    );

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_incremental_result_serde_roundtrip() {
    // Verify IncrementalResult survives JSON serialization/deserialization
    // (this is the wire format for DELTA updates).
    let original = IncrementalResult {
        added_or_modified_proxies: vec![
            create_test_proxy("proxy-a", "/api-a"),
            create_test_proxy("proxy-b", "/api-b"),
        ],
        removed_proxy_ids: vec!["proxy-old".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec!["consumer-gone".to_string()],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec!["upstream-x".to_string()],
        poll_timestamp: Utc::now(),
    };

    let json = serde_json::to_string(&original).expect("Failed to serialize IncrementalResult");
    let deserialized: IncrementalResult =
        serde_json::from_str(&json).expect("Failed to deserialize IncrementalResult");

    assert_eq!(deserialized.added_or_modified_proxies.len(), 2);
    assert_eq!(deserialized.added_or_modified_proxies[0].id, "proxy-a");
    assert_eq!(deserialized.added_or_modified_proxies[1].id, "proxy-b");
    assert_eq!(deserialized.removed_proxy_ids, vec!["proxy-old"]);
    assert_eq!(deserialized.removed_consumer_ids, vec!["consumer-gone"]);
    assert_eq!(deserialized.removed_upstream_ids, vec!["upstream-x"]);
    assert!(deserialized.added_or_modified_consumers.is_empty());
    assert!(deserialized.added_or_modified_plugin_configs.is_empty());
    assert!(deserialized.added_or_modified_upstreams.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_modifying_proxy() {
    // Verify that a delta with a modified proxy (same ID, different fields)
    // correctly updates the existing proxy in-place.
    let cp_config = create_test_config(2);
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-mod-node", &ps, None).await
    });

    // Wait for initial snapshot (2 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Verify initial backend port
    assert_eq!(proxy_state.config.load().proxies[0].backend_port, 3000);

    // Send delta that modifies proxy-0 (change backend_port)
    let mut modified_proxy = create_test_proxy("proxy-0", "/api-0");
    modified_proxy.backend_port = 9999;
    modified_proxy.updated_at = Utc::now(); // newer timestamp

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![modified_proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta — proxy count stays 2 but backend_port changes
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            let config = proxy_state.config.load();
            if let Some(p) = config.proxies.iter().find(|p| p.id == "proxy-0")
                && p.backend_port == 9999
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied delta modifying proxy-0 backend_port to 9999"
    );

    // Verify total proxy count unchanged
    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 2);
    // Verify the modification stuck
    let proxy_0 = config.proxies.iter().find(|p| p.id == "proxy-0").unwrap();
    assert_eq!(proxy_0.backend_port, 9999);
    // Verify proxy-1 is untouched
    let proxy_1 = config.proxies.iter().find(|p| p.id == "proxy-1").unwrap();
    assert_eq!(proxy_1.backend_port, 3000);

    client_handle.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dp_applies_delta_with_mixed_operations() {
    // A single delta that simultaneously adds, modifies, and removes proxies.
    let cp_config = create_test_config(3); // proxy-0, proxy-1, proxy-2
    let (addr, update_tx, _server_handle) = start_test_cp_server(cp_config).await;

    let proxy_state = create_test_proxy_state();
    let cp_url = format!("http://127.0.0.1:{}", addr.port());
    let token = create_test_token();

    let ps = proxy_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::connect_and_subscribe(&cp_url, &token, "delta-mixed-node", &ps, None).await
    });

    // Wait for initial snapshot (3 proxies)
    let received = timeout(Duration::from_secs(5), async {
        loop {
            if proxy_state.config.load().proxies.len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(received.is_ok());

    // Send a single delta that:
    // - Removes proxy-1
    // - Modifies proxy-0 (change backend_port)
    // - Adds proxy-new
    let mut modified = create_test_proxy("proxy-0", "/api-0");
    modified.backend_port = 5555;
    modified.updated_at = Utc::now();

    let delta = IncrementalResult {
        added_or_modified_proxies: vec![modified, create_test_proxy("proxy-new", "/api-new")],
        removed_proxy_ids: vec!["proxy-1".to_string()],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        poll_timestamp: Utc::now(),
    };
    CpGrpcServer::broadcast_delta(&update_tx, &delta, "v2");

    // Wait for delta — should go from 3 to 3 (remove 1, add 1, modify 1)
    let received_delta = timeout(Duration::from_secs(5), async {
        loop {
            let config = proxy_state.config.load();
            let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
            if ids.contains(&"proxy-new") && !ids.contains(&"proxy-1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        received_delta.is_ok(),
        "DP should have applied mixed delta (add + modify + remove)"
    );

    let config = proxy_state.config.load();
    assert_eq!(config.proxies.len(), 3); // -1 removed, +1 added = net 3

    let ids: Vec<&str> = config.proxies.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"proxy-0"));
    assert!(!ids.contains(&"proxy-1")); // removed
    assert!(ids.contains(&"proxy-2"));
    assert!(ids.contains(&"proxy-new")); // added

    // Verify modification
    let proxy_0 = config.proxies.iter().find(|p| p.id == "proxy-0").unwrap();
    assert_eq!(proxy_0.backend_port, 5555);

    client_handle.abort();
}

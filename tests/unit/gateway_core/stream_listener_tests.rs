//! Tests for the StreamListenerManager (TCP/UDP stream proxy lifecycle).
//!
//! Covers: reconciliation (start/stop/restart listeners), port conflict detection,
//! TLS/DTLS deferral, shutdown, and wait_until_started behavior.

use arc_swap::ArcSwap;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::proxy::stream_listener::StreamListenerManager;
use ferrum_edge::request_epoch::RequestEpochStore;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Helpers
// ============================================================================

fn create_stream_proxy(id: &str, scheme: BackendScheme, port: u16) -> Proxy {
    let mut proxy = Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        // Stream proxies must not set listen_path — they route on listen_port.
        listen_path: None,
        backend_scheme: Some(scheme),
        dispatch_kind: DispatchKind::from(scheme),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 9999,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: ferrum_edge::config::types::AuthMode::Single,
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
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    proxy
}

/// Allocate an ephemeral port by binding and immediately dropping.
async fn ephemeral_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral port");
    listener.local_addr().unwrap().port()
}

fn create_manager(config: GatewayConfig) -> StreamListenerManager {
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    create_manager_with_config_arc(config_arc, &config)
}

fn create_manager_with_config_arc(
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    config: &GatewayConfig,
) -> StreamListenerManager {
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(config).expect("PluginCache::new failed"));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        (*config).clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch,
        cb_cache,
        None, // no frontend TLS
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10,  // frontend_tls_handshake_timeout_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        2048,
        1,
        256,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        false, // record_mesh_mtls_metric
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    )
}

fn empty_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        upstreams: vec![],
        plugin_configs: vec![],
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

// ============================================================================
// Tests: Basic Reconciliation
// ============================================================================

#[tokio::test]
async fn test_reconcile_with_empty_config_returns_no_failures() {
    let manager = create_manager(empty_config());
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "Empty config should produce no bind failures"
    );
}

#[tokio::test]
async fn test_reconcile_starts_tcp_listener() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("tcp1", BackendScheme::Tcp, port)],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "TCP listener should start without failures: {:?}",
        failures
    );

    // Verify the port is now bound by trying to bind again (should fail)
    tokio::time::sleep(Duration::from_millis(200)).await;
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_err(),
        "Port {} should be in use after reconcile",
        port
    );

    // Cleanup
    manager.shutdown_all().await;
}

#[tokio::test]
async fn test_reconcile_starts_single_hosted_passthrough_as_sni_listener() {
    let port = ephemeral_port().await;
    let mut proxy = create_stream_proxy("tcp-sni", BackendScheme::Tcp, port);
    proxy.passthrough = true;
    proxy.hosts = vec!["secure.example.com".to_string()];
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "SNI passthrough listener should start without failures: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("single hosted passthrough proxy should use the SNI listener key");

    manager.shutdown_all().await;
}

#[tokio::test]
async fn test_reconcile_starts_udp_listener() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("udp1", BackendScheme::Udp, port)],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "UDP listener should start without failures: {:?}",
        failures
    );

    // Verify the UDP port is bound
    tokio::time::sleep(Duration::from_millis(200)).await;
    let probe = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_err(),
        "UDP port {} should be in use after reconcile",
        port
    );

    manager.shutdown_all().await;
}

// ============================================================================
// Tests: Port Conflict Detection
// ============================================================================

#[tokio::test]
async fn test_reconcile_detects_port_conflict() {
    // Bind a TCP port externally first
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind blocker");
    let blocked_port = blocker.local_addr().unwrap().port();

    let config = GatewayConfig {
        proxies: vec![create_stream_proxy(
            "tcp-conflict",
            BackendScheme::Tcp,
            blocked_port,
        )],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "Should detect exactly one port conflict: {:?}",
        failures
    );
    assert_eq!(failures[0].0, "tcp-conflict");
    assert_eq!(failures[0].1, blocked_port);
    assert!(
        failures[0].2.contains("already in use"),
        "Error should mention port in use: {}",
        failures[0].2
    );

    // Keep blocker alive until end of test
    drop(blocker);
}

#[tokio::test]
async fn test_reconcile_restarts_changed_tcp_listener_without_bind_failure() {
    let port = ephemeral_port().await;
    let proxy = create_stream_proxy("tcp-restart", BackendScheme::Tcp, port);
    let config = GatewayConfig {
        proxies: vec![proxy.clone()],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial TCP listener should start without failures: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial TCP listener should bind");

    let mut restarted_proxy = proxy;
    restarted_proxy.backend_scheme = Some(BackendScheme::Tcps);
    restarted_proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcps);
    restarted_proxy.backend_tls_verify_server_cert = false;
    let restarted_config = GatewayConfig {
        proxies: vec![restarted_proxy],
        ..empty_config()
    };
    config_arc.store(Arc::new(restarted_config));

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "same-port listener restart should wait for the old socket before probing: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("restarted TCP TLS listener should bind");

    manager.shutdown_all().await;
}

#[tokio::test]
async fn test_reconcile_skips_tcp_tls_listener_when_backend_tls_material_unreadable() {
    let port = ephemeral_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_ca_path = dir.path().join("missing-ca.pem");
    let mut proxy = create_stream_proxy("tcp-tls-bad-ca", BackendScheme::Tcps, port);
    proxy.backend_tls_verify_server_cert = true;
    proxy.backend_tls_server_ca_cert_path = Some(
        missing_ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "bad backend TLS material should fail only that stream listener: {:?}",
        failures
    );
    assert_eq!(failures[0].0, "tcp-tls-bad-ca");
    assert_eq!(failures[0].1, port);
    assert!(
        failures[0].2.contains("Backend TLS config failed"),
        "error should identify backend TLS validation: {}",
        failures[0].2
    );

    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "failed backend TLS validation must not leave a dead listener occupying port {}",
        port
    );
}

/// Generate a self-signed CA certificate PEM for backend TLS config builds.
fn generate_test_ca_pem(common_name: &str) -> String {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key pair");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA certificate params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.self_signed(&key_pair).expect("self-signed CA").pem()
}

/// In-place backend TLS rotation to invalid content must NOT tear down the
/// running listener: the replacement TLS config is validated BEFORE the old
/// listener is stopped, and on failure the old listener keeps serving with
/// its cached config. Fixing the material on a later reconcile restarts the
/// listener cleanly.
#[tokio::test]
async fn test_in_place_backend_tls_rotation_to_invalid_keeps_old_listener_serving() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let port = ephemeral_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, generate_test_ca_pem("Rotation CA A")).expect("write initial ca");

    let mut proxy = create_stream_proxy("tcp-tls-rotate", BackendScheme::Tcps, port);
    proxy.backend_tls_verify_server_cert = true;
    proxy.backend_tls_server_ca_cert_path = Some(
        ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial TCP TLS listener should start with valid CA material: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial TCP TLS listener should bind");

    // Rotate the CA file IN PLACE to unparseable garbage. The content
    // fingerprint changes the reload key, but the replacement TLS config
    // cannot be built — reconcile must keep the OLD listener serving instead
    // of tearing it down and leaving the port closed.
    std::fs::write(&ca_path, b"not-a-pem-certificate").expect("rotate ca to garbage");
    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "invalid in-place rotation should be reported: {:?}",
        failures
    );
    assert_eq!(failures[0].0, "tcp-tls-rotate");
    assert_eq!(failures[0].1, port);
    assert!(
        failures[0].2.contains("kept previous listener running"),
        "failure should state the old listener was kept: {}",
        failures[0].2
    );
    let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await;
    assert!(
        conn.is_ok(),
        "old listener must keep serving port {} after an invalid in-place TLS rotation",
        port
    );

    // A later reconcile with still-bad material keeps reporting and keeps
    // serving (the handle retains its previous reload key, so the drift is
    // re-detected every pass).
    let failures = manager.reconcile().await;
    assert_eq!(failures.len(), 1, "still-bad material keeps reporting");
    let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await;
    assert!(conn.is_ok(), "old listener must still be serving");

    // Fix the material (different valid CA) — the next reconcile restarts the
    // listener with the fresh cached config.
    std::fs::write(&ca_path, generate_test_ca_pem("Rotation CA B")).expect("rotate to valid ca");
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "valid rotation should restart the listener cleanly: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("restarted TCP TLS listener should bind");
    let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await;
    assert!(conn.is_ok(), "restarted listener must serve the port");

    manager.shutdown_all().await;
}

/// The backend TLS reload key must derive from `resolved_tls` — the
/// upstream-projected view (`resolve_upstream_tls()`) — not from the proxy's
/// own `backend_tls_*` fields. An upstream-only TLS change leaves the proxy
/// fields untouched, so a key built from them would never notice the change.
/// Detection is made observable by rotating to garbage material: reconcile
/// reports the validation failure (proving the key changed) while keeping the
/// old listener serving.
#[tokio::test]
async fn test_reconcile_detects_upstream_resolved_tls_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let port = ephemeral_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_a_path = dir.path().join("upstream-ca-a.pem");
    let ca_b_path = dir.path().join("upstream-ca-b.pem");
    std::fs::write(&ca_a_path, generate_test_ca_pem("Upstream CA A")).expect("write ca a");
    std::fs::write(&ca_b_path, b"garbage-rotated-by-upstream").expect("write ca b");

    // Proxy's own backend_tls_* fields stay empty; TLS arrives via
    // resolved_tls, exactly as resolve_upstream_tls() projects from a
    // referenced upstream.
    let mut proxy = create_stream_proxy("tcp-tls-upstream", BackendScheme::Tcps, port);
    proxy.resolved_tls = BackendTlsConfig {
        server_ca_cert_path: Some(
            ca_a_path
                .to_str()
                .expect("test temp path must be utf-8 for proxy config")
                .to_string(),
        ),
        verify_server_cert: true,
        ..BackendTlsConfig::default_verify()
    };
    let mut rotated_proxy = proxy.clone();
    rotated_proxy.resolved_tls.server_ca_cert_path = Some(
        ca_b_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial upstream-resolved TLS should start cleanly: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial TCP TLS listener should bind");

    // Upstream-only TLS change: identical proxy fields, new resolved_tls.
    let rotated_config = GatewayConfig {
        proxies: vec![rotated_proxy],
        ..empty_config()
    };
    config_arc.store(Arc::new(rotated_config));

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "upstream-resolved TLS change must be detected via the reload key: {:?}",
        failures
    );
    assert_eq!(failures[0].0, "tcp-tls-upstream");
    let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await;
    assert!(
        conn.is_ok(),
        "old listener must keep serving while the rotated upstream TLS material is invalid"
    );

    manager.shutdown_all().await;
}

// ============================================================================
// Tests: TLS Deferral
// ============================================================================

#[tokio::test]
async fn test_reconcile_defers_tcp_without_tls_config() {
    let port = ephemeral_port().await;
    let mut proxy = create_stream_proxy("tcp-tls", BackendScheme::Tcps, port);
    proxy.frontend_tls = true;

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };

    // Create manager without TLS config (None)
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    // No failures — the listener should be deferred, not failed
    assert!(
        failures.is_empty(),
        "Deferred listener should not produce bind failures: {:?}",
        failures
    );

    // Verify the port is NOT bound (listener was deferred)
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "Port {} should NOT be in use (listener was deferred)",
        port
    );
}

#[tokio::test]
async fn test_reconcile_defers_udp_without_dtls_config() {
    // Hold a UDP socket on an ephemeral port for the duration of the test.
    // ephemeral_port() allocates from TCP space, but a free TCP port number may
    // still be bound by another concurrent test in UDP space, so probing UDP at
    // that number after reconcile is flaky. Reserving the port in UDP space
    // ourselves both eliminates the cross-protocol race and gives us a stronger
    // deferral assertion: if reconcile correctly defers, it never reaches the
    // port probe and `failures` stays empty; if deferral regresses, the probe
    // collides with our held socket and surfaces as a bind failure.
    let holder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind UDP holder");
    let port = holder.local_addr().unwrap().port();

    let mut proxy = create_stream_proxy("udp-dtls", BackendScheme::Udp, port);
    proxy.frontend_tls = true;

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };

    // Create manager without DTLS config
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "Deferred DTLS listener should not produce bind failures: {:?}",
        failures
    );

    drop(holder);
}

// ============================================================================
// Tests: Shutdown
// ============================================================================

#[tokio::test]
async fn test_shutdown_all_releases_ports() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy(
            "tcp-shutdown",
            BackendScheme::Tcp,
            port,
        )],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(failures.is_empty());

    // Wait for listener to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Shutdown
    manager.shutdown_all().await;

    // Give the listener task time to stop
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Port should be free again
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "Port {} should be free after shutdown_all",
        port
    );
}

// ============================================================================
// Tests: wait_until_started
// ============================================================================

#[tokio::test]
async fn test_wait_until_started_with_empty_config() {
    let manager = create_manager(empty_config());
    manager.reconcile().await;

    // With no stream proxies, wait_until_started should return immediately
    let result = manager.wait_until_started(Duration::from_secs(1)).await;
    assert!(result.is_ok(), "Empty config should return Ok immediately");
}

#[tokio::test]
async fn test_wait_until_started_succeeds_for_tcp() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("tcp-wait", BackendScheme::Tcp, port)],
        ..empty_config()
    };

    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert!(failures.is_empty());

    let result = manager.wait_until_started(Duration::from_secs(5)).await;
    assert!(
        result.is_ok(),
        "TCP listener should start within timeout: {:?}",
        result.err()
    );

    manager.shutdown_all().await;
}

// ============================================================================
// Tests: global SIGTERM wiring (set_global_shutdown_rx)
// ============================================================================

/// Regression test for the bug where stream listeners ignored gateway-wide
/// SIGTERM and kept accepting connections during graceful drain.
///
/// Verifies that firing the global shutdown receiver wired into
/// `set_global_shutdown_rx` causes the spawned TCP accept loop to exit
/// promptly and release the bound port, even though the per-listener
/// `shutdown_tx` is never fired.
#[tokio::test]
async fn test_global_shutdown_stops_tcp_accept_loop() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("tcp-sigterm", BackendScheme::Tcp, port)],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch,
        cb_cache,
        None,
        false,
        None,
        300,
        300,
        10,
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        2048,
        1,
        256,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false,
        false,
        false,
        0,
        false,
        false,
        false,
    );

    // Inject the global shutdown receiver BEFORE reconcile so the spawned
    // listener picks it up. This mirrors the wiring in each mode's startup.
    let (global_tx, global_rx) = tokio::sync::watch::channel(false);
    manager.set_global_shutdown_rx(global_rx);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "TCP listener bind failed: {:?}",
        failures
    );

    // Wait for the listener to be fully started.
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("TCP listener should start within timeout");

    // Verify the port is bound (a fresh bind on the same port must fail).
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(probe.is_err(), "Port {} should be in use", port);

    // Fire the GLOBAL shutdown channel. This is what SIGTERM would do.
    // We do NOT call shutdown_all() here — the test is specifically checking
    // that the global channel ALONE is sufficient to stop the accept loop.
    let _ = global_tx.send(true);

    // Wait for the accept loop to actually exit and release the port.
    // The listener should react within milliseconds; give it a generous
    // budget for CI machines under load.
    let port_freed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(_) => return true,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        port_freed,
        "Port {} should be released after global shutdown signal",
        port
    );
}

/// Same as [`test_global_shutdown_stops_tcp_accept_loop`] but for UDP
/// listeners. UDP uses a separate accept-loop body in
/// `udp_proxy::start_udp_listener`, so it needs an independent regression
/// test to make sure the `tokio::select!` arm watching the global channel
/// fires correctly.
#[tokio::test]
async fn test_global_shutdown_stops_udp_recv_loop() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("udp-sigterm", BackendScheme::Udp, port)],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch,
        cb_cache,
        None,
        false,
        None,
        300,
        300,
        10,
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        2048,
        1,
        256,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false,
        false,
        false,
        0,
        false,
        false,
        false,
    );

    let (global_tx, global_rx) = tokio::sync::watch::channel(false);
    manager.set_global_shutdown_rx(global_rx);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "UDP listener bind failed: {:?}",
        failures
    );

    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("UDP listener should start within timeout");

    // Verify the port is bound — a fresh UDP bind on the same port must fail.
    let probe = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await;
    assert!(probe.is_err(), "UDP port {} should be in use", port);

    // Fire the GLOBAL shutdown channel and confirm the recv loop exits.
    let _ = global_tx.send(true);

    let port_freed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await {
                Ok(_) => return true,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        port_freed,
        "UDP port {} should be released after global shutdown signal",
        port
    );
}

// ============================================================================
// Tests: PeerAuthentication live reload (T3-A) — frontend TLS slot semantics
// ============================================================================

/// `swap_frontend_tls_config` is the cold-path entry point used by mesh
/// PeerAuthentication live reload. It must atomically replace the slot
/// without triggering a reconcile (existing TCP+TLS listeners snapshot the
/// slot per accept). Compare-by-pointer proves the swap actually replaced
/// the inner `Arc` rather than mutating in place.
#[tokio::test]
async fn swap_frontend_tls_config_replaces_slot_without_reconcile() {
    let manager = create_manager(empty_config());

    // Seed a fake `Arc<rustls::ServerConfig>` so we can prove the swap
    // replaced the pointer. Using a CryptoProvider-free ServerConfig isn't
    // possible, but we can compare two Option<Arc<...>> by Arc::as_ptr
    // after wrapping with Arc::new.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build two distinct `Arc<rustls::ServerConfig>` instances. The actual
    // crypto here doesn't matter — we never drive a handshake against it.
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg_a = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .expect("server-side protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoopCertResolver)),
    );
    let cfg_b = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .expect("server-side protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoopCertResolver)),
    );

    manager.swap_frontend_tls_config(Some(cfg_a.clone()));
    // No reconcile call. Even with the slot populated, no listeners means
    // we wouldn't have started anything; the test asserts the swap path
    // is cold-path-only and does not depend on reconcile being invoked.
    manager.swap_frontend_tls_config(Some(cfg_b.clone()));

    // Confirm the slot now holds cfg_b, not cfg_a.
    let observed = manager.snapshot_frontend_tls_config();
    let observed = observed.as_ref().expect("slot should hold a config");
    assert!(
        Arc::ptr_eq(observed, &cfg_b),
        "swap_frontend_tls_config must publish the most recent ServerConfig in the slot"
    );

    // Now swap to None — the slot must drop the config (PeerAuth Disable).
    manager.swap_frontend_tls_config(None);
    assert!(
        manager.snapshot_frontend_tls_config().is_none(),
        "swap to None should clear the slot"
    );
}

/// `swap_active_dtls_frontend_configs` is a no-op when there are no active
/// UDP+DTLS listeners. This proves the swap path doesn't crash on an empty
/// manager (the common case when a PeerAuth slice apply fires before any
/// stream listener has bound).
#[tokio::test]
async fn swap_active_dtls_frontend_configs_is_noop_with_no_listeners() {
    let manager = create_manager(empty_config());
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let swapped = manager
        .swap_active_dtls_frontend_configs(|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(anyhow::anyhow!(
                "build_config must not be called when no DTLS listeners exist"
            ))
        })
        .await;
    assert_eq!(swapped, 0, "no listeners should mean no swaps");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "build_config must not be invoked when there are no active DTLS listeners"
    );
}

/// Minimal cert resolver for the swap-pointer test. Never gets driven, so
/// the empty resolver result is fine — we only need a valid `ServerConfig`
/// shape to populate the slot.
#[derive(Debug)]
struct NoopCertResolver;

impl rustls::server::ResolvesServerCert for NoopCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

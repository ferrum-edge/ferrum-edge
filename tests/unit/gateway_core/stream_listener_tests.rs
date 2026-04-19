//! Tests for the StreamListenerManager (TCP/UDP stream proxy lifecycle).
//!
//! Covers: reconciliation (start/stop/restart listeners), port conflict detection,
//! TLS/DTLS deferral, shutdown, and wait_until_started behavior.

use arc_swap::ArcSwap;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{BackendProtocol, GatewayConfig, Proxy};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::proxy::stream_listener::StreamListenerManager;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Helpers
// ============================================================================

fn create_stream_proxy(id: &str, protocol: BackendProtocol, port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        // Stream proxies must not set listen_path — they route on listen_port.
        listen_path: None,
        backend_protocol: protocol,
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
        upstream_id: None,
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
    }
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
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None, // no frontend TLS
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
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
        proxies: vec![create_stream_proxy("tcp1", BackendProtocol::Tcp, port)],
        ..empty_config()
    };

    // Create manager with config containing the TCP proxy
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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
async fn test_reconcile_starts_udp_listener() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy("udp1", BackendProtocol::Udp, port)],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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
            BackendProtocol::Tcp,
            blocked_port,
        )],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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

// ============================================================================
// Tests: TLS Deferral
// ============================================================================

#[tokio::test]
async fn test_reconcile_defers_tcp_without_tls_config() {
    let port = ephemeral_port().await;
    let mut proxy = create_stream_proxy("tcp-tls", BackendProtocol::TcpTls, port);
    proxy.frontend_tls = true;

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    // Create manager without TLS config (None)
    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None, // No frontend TLS config
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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
    let port = ephemeral_port().await;
    let mut proxy = create_stream_proxy("udp-dtls", BackendProtocol::Udp, port);
    proxy.frontend_tls = true;

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    // Create manager without DTLS config
    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "Deferred DTLS listener should not produce bind failures: {:?}",
        failures
    );

    // Verify the UDP port is NOT bound (listener was deferred)
    let probe = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "UDP port {} should NOT be in use (listener was deferred)",
        port
    );
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
            BackendProtocol::Tcp,
            port,
        )],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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
        proxies: vec![create_stream_proxy("tcp-wait", BackendProtocol::Tcp, port)],
        ..empty_config()
    };

    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let dns_cache = DnsCache::new(DnsConfig::default());
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
    let plugin_cache = Arc::new(PluginCache::new(&config).expect("PluginCache::new failed"));
    let cb_cache = Arc::new(CircuitBreakerCache::new());

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        lb_cache,
        consumer_index,
        plugin_cache,
        cb_cache,
        None,
        false,
        None,
        300,
        300, // tcp_half_close_max_wait_seconds
        10_000,
        10,
        None,
        Arc::new(Vec::new()),
        Arc::new(ferrum_edge::adaptive_buffer::AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        64,
        true,
        Arc::new(ferrum_edge::overload::OverloadState::new()),
        false, // ktls_enabled
        false, // io_uring_splice_enabled
        0,     // so_busy_poll_us
        false, // udp_gro_enabled (use false in tests to avoid Linux-specific failures)
        false, // udp_gso_enabled
        false, // udp_pktinfo_enabled
    );

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

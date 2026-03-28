//! Tests for connection pool configuration

use chrono::Utc;
use ferrum_gateway::config::PoolConfig;
use ferrum_gateway::config::pool_config::{MAX_IDLE_PER_HOST, MIN_IDLE_PER_HOST};
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Proxy};

fn create_test_proxy() -> Proxy {
    Proxy {
        id: "test".to_string(),
        name: None,
        hosts: vec![],
        listen_path: "/test".to_string(),
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

#[test]
fn test_default_config() {
    let config = PoolConfig::default();
    assert_eq!(config.max_idle_per_host, 64);
    assert_eq!(config.idle_timeout_seconds, 90);
    assert_eq!(config.tcp_keepalive_seconds, 60);
    assert_eq!(config.http2_keep_alive_interval_seconds, 30);
    assert_eq!(config.http2_keep_alive_timeout_seconds, 45);
    assert!(config.enable_http_keep_alive);
    assert!(config.enable_http2);
}

#[test]
fn test_proxy_overrides() {
    let global = PoolConfig::default();
    let mut proxy = create_test_proxy();

    // Apply overrides
    proxy.pool_enable_http2 = Some(false);
    proxy.pool_tcp_keepalive_seconds = Some(30);
    proxy.pool_http2_keep_alive_interval_seconds = Some(15);
    proxy.pool_http2_keep_alive_timeout_seconds = Some(45);

    let config = global.for_proxy(&proxy);
    assert_eq!(config.max_idle_per_host, 64); // unchanged (global-only)
    assert_eq!(config.idle_timeout_seconds, 90); // unchanged
    assert_eq!(config.tcp_keepalive_seconds, 30); // overridden
    assert_eq!(config.http2_keep_alive_interval_seconds, 15); // overridden
    assert_eq!(config.http2_keep_alive_timeout_seconds, 45); // overridden
    assert!(config.enable_http_keep_alive); // unchanged
    assert!(!config.enable_http2); // overridden
}

#[test]
fn test_no_overrides() {
    let global = PoolConfig::default();
    let proxy = create_test_proxy();

    let config = global.for_proxy(&proxy);
    assert_eq!(config.max_idle_per_host, global.max_idle_per_host);
    assert_eq!(config.idle_timeout_seconds, global.idle_timeout_seconds);
    assert_eq!(config.tcp_keepalive_seconds, global.tcp_keepalive_seconds);
    assert_eq!(
        config.http2_keep_alive_interval_seconds,
        global.http2_keep_alive_interval_seconds
    );
    assert_eq!(
        config.http2_keep_alive_timeout_seconds,
        global.http2_keep_alive_timeout_seconds
    );
    assert_eq!(config.enable_http_keep_alive, global.enable_http_keep_alive);
    assert_eq!(config.enable_http2, global.enable_http2);
}

#[test]
fn test_validate_clamps_too_low() {
    let result = PoolConfig::validate_max_idle_per_host(1, "test");
    assert_eq!(result, MIN_IDLE_PER_HOST);
}

#[test]
fn test_validate_clamps_too_high() {
    let result = PoolConfig::validate_max_idle_per_host(5000, "test");
    assert_eq!(result, MAX_IDLE_PER_HOST);
}

#[test]
fn test_validate_accepts_valid_value() {
    let result = PoolConfig::validate_max_idle_per_host(100, "test");
    assert_eq!(result, 100);
}

#[test]
fn test_validate_accepts_boundary_values() {
    assert_eq!(
        PoolConfig::validate_max_idle_per_host(MIN_IDLE_PER_HOST, "test"),
        MIN_IDLE_PER_HOST
    );
    assert_eq!(
        PoolConfig::validate_max_idle_per_host(MAX_IDLE_PER_HOST, "test"),
        MAX_IDLE_PER_HOST
    );
}

//! Tests for pool key construction in `ConnectionPool` and `Http2ConnectionPool`.
//!
//! Pool keys determine whether two proxies can share a pooled connection.
//! Getting the key wrong causes either pool poisoning (missing a field) or
//! unnecessary fragmentation (including a field that doesn't affect identity).
//! These tests verify the key format, delimiter safety, and field inclusion.

use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendProtocol, BackendTlsConfig, Proxy, ResponseBodyMode,
};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::http3::client::Http3ConnectionPool;
use ferrum_edge::proxy::http2_pool::Http2ConnectionPool;
use std::sync::Arc;

/// Build a minimal `Proxy` with sensible defaults for pool key testing.
fn minimal_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "test-proxy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/test".to_string()),
        backend_protocol: BackendProtocol::Http,
        backend_host: "backend.example.com".to_string(),
        backend_port: 8080,
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
        resolved_tls: BackendTlsConfig::default_verify(),
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
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: now,
        updated_at: now,
    }
}

/// Build a `ConnectionPool` with default config for testing pool key generation.
/// Requires a tokio runtime because `ConnectionPool::new` spawns a cleanup task.
fn pool_with_defaults() -> ConnectionPool {
    let dns = DnsCache::new(DnsConfig::default());
    let env_config = ferrum_edge::config::EnvConfig::default();
    ConnectionPool::new(
        PoolConfig::default(),
        env_config,
        dns,
        None,
        Arc::new(Vec::new()),
    )
}

/// Build a `ConnectionPool` with custom global mTLS/TLS settings.
fn pool_with_global_tls(
    cert: Option<&str>,
    key: Option<&str>,
    ca: Option<&str>,
    no_verify: bool,
) -> ConnectionPool {
    let env_config = ferrum_edge::config::EnvConfig {
        backend_tls_client_cert_path: cert.map(|s| s.to_string()),
        backend_tls_client_key_path: key.map(|s| s.to_string()),
        tls_ca_bundle_path: ca.map(|s| s.to_string()),
        tls_no_verify: no_verify,
        ..Default::default()
    };
    let dns = DnsCache::new(DnsConfig::default());
    ConnectionPool::new(
        PoolConfig::default(),
        env_config,
        dns,
        None,
        Arc::new(Vec::new()),
    )
}

// ---------------------------------------------------------------------------
// ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connection_pool_key_direct_backend_format() {
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();
    let key = pool.pool_key_for_warmup(&proxy);
    // Direct backend: d=host:port|protocol|dns|ca|mtls|verify
    assert!(
        key.starts_with("d=backend.example.com:8080|"),
        "key should start with d= prefix: {key}"
    );
    // BackendProtocol::Http = 0
    assert!(key.contains("|0|"), "key should contain protocol 0: {key}");
    // No DNS override, no CA, no mTLS, verify=true (1)
    assert!(
        key.ends_with("|||1"),
        "key should end with empty dns/ca/mtls and verify=1: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_upstream_id_prefix() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.upstream_id = Some("my-upstream".to_string());
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.starts_with("u=my-upstream|"),
        "upstream-backed proxy should use u= prefix: {key}"
    );
    // Should NOT contain backend_host:port
    assert!(
        !key.contains("backend.example.com"),
        "upstream key should not contain backend_host"
    );
}

#[tokio::test]
async fn connection_pool_key_with_dns_override() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.dns_override = Some("10.0.0.1".to_string());
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|10.0.0.1|"),
        "key should contain DNS override: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_with_backend_ca_cert() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.backend_tls_server_ca_cert_path = Some("/path/to/ca.pem".to_string());
    proxy.resolved_tls.server_ca_cert_path = Some("/path/to/ca.pem".to_string());
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/path/to/ca.pem|"),
        "key should contain CA cert path: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_with_mtls_client_cert() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.backend_tls_client_cert_path = Some("/path/to/client.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/path/to/client.pem".to_string());
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/path/to/client.pem|"),
        "key should contain mTLS cert path: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_verify_disabled() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.ends_with("|0"),
        "key should end with verify=0 when disabled: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_global_no_verify_overrides_proxy() {
    let pool = pool_with_global_tls(None, None, None, true);
    let proxy = minimal_proxy(); // proxy has verify=true
    let key = pool.pool_key_for_warmup(&proxy);
    // Global tls_no_verify=true should force effective verify to false
    assert!(
        key.ends_with("|0"),
        "global no_verify should override proxy verify=true: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_pipe_delimiter_count() {
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();
    let key = pool.pool_key_for_warmup(&proxy);
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        pipe_count, 5,
        "6 fields need 5 pipe delimiters, got {pipe_count} in key: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_different_protocols_differ() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_protocol = BackendProtocol::Http;
    let mut p2 = minimal_proxy();
    p2.backend_protocol = BackendProtocol::Https;
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "different protocols should produce different keys"
    );
}

#[tokio::test]
async fn connection_pool_key_same_config_same_key() {
    let pool = pool_with_defaults();
    let p1 = minimal_proxy();
    let p2 = minimal_proxy();
    assert_eq!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "identical proxies should produce identical keys"
    );
}

#[tokio::test]
async fn connection_pool_key_global_mtls_fallback() {
    let pool = pool_with_global_tls(
        Some("/global/client.pem"),
        Some("/global/key.pem"),
        None,
        false,
    );
    let proxy = minimal_proxy(); // no per-proxy mTLS
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/global/client.pem|"),
        "should fall back to global mTLS cert: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_per_proxy_mtls_overrides_global() {
    let pool = pool_with_global_tls(
        Some("/global/client.pem"),
        Some("/global/key.pem"),
        None,
        false,
    );
    let mut proxy = minimal_proxy();
    proxy.backend_tls_client_cert_path = Some("/proxy/client.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/proxy/client.pem".to_string());
    let key = pool.pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/proxy/client.pem|"),
        "per-proxy cert should override global: {key}"
    );
    assert!(
        !key.contains("/global/client.pem"),
        "global cert should not appear when per-proxy is set"
    );
}

#[tokio::test]
async fn connection_pool_key_ipv6_backend_no_collision() {
    let pool = pool_with_defaults();
    let mut proxy = minimal_proxy();
    proxy.backend_host = "::1".to_string();
    proxy.backend_port = 8080;
    let key = pool.pool_key_for_warmup(&proxy);
    // IPv6 contains colons but delimiter is | so no ambiguity
    assert!(
        key.starts_with("d=::1:8080|"),
        "IPv6 address should be safe with pipe delimiter: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_different_hosts_differ() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_host = "host-a.example.com".to_string();
    let mut p2 = minimal_proxy();
    p2.backend_host = "host-b.example.com".to_string();
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "different hosts should produce different keys"
    );
}

#[tokio::test]
async fn connection_pool_key_different_ports_differ() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_port = 8080;
    let mut p2 = minimal_proxy();
    p2.backend_port = 9090;
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "different ports should produce different keys"
    );
}

#[tokio::test]
async fn connection_pool_key_different_ca_paths_differ() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_tls_server_ca_cert_path = Some("/ca/one.pem".to_string());
    p1.resolved_tls.server_ca_cert_path = Some("/ca/one.pem".to_string());
    let mut p2 = minimal_proxy();
    p2.backend_tls_server_ca_cert_path = Some("/ca/two.pem".to_string());
    p2.resolved_tls.server_ca_cert_path = Some("/ca/two.pem".to_string());
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "different CA paths should produce different keys"
    );
}

#[tokio::test]
async fn connection_pool_key_policy_fields_do_not_fragment() {
    // Timeouts and pool sizes should NOT affect the pool key
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.pool_idle_timeout_seconds = Some(30);
    p1.pool_enable_http2 = Some(true);
    p1.backend_connect_timeout_ms = 1000;
    let p2 = minimal_proxy();
    assert_eq!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "policy fields (timeouts, pool sizes) should not affect the key"
    );
}

// ---------------------------------------------------------------------------
// Http2ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[test]
fn h2_pool_key_basic_format() {
    let proxy = minimal_proxy();
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    // Format: host|port|dns|ca|mtls|verify
    assert_eq!(
        key, "backend.example.com|8080||||1",
        "basic H2 key format mismatch"
    );
}

#[test]
fn h2_pool_key_with_dns_override() {
    let mut proxy = minimal_proxy();
    proxy.dns_override = Some("10.0.0.5".to_string());
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|10.0.0.5|"),
        "H2 key should contain DNS override: {key}"
    );
}

#[test]
fn h2_pool_key_with_ca_cert() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_server_ca_cert_path = Some("/certs/ca.pem".to_string());
    proxy.resolved_tls.server_ca_cert_path = Some("/certs/ca.pem".to_string());
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/certs/ca.pem|"),
        "H2 key should contain CA path: {key}"
    );
}

#[test]
fn h2_pool_key_with_mtls_cert() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_client_cert_path = Some("/certs/client.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/certs/client.pem".to_string());
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.contains("|/certs/client.pem|"),
        "H2 key should contain mTLS cert path: {key}"
    );
}

#[test]
fn h2_pool_key_verify_disabled() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.ends_with("|0"),
        "H2 key should end with verify=0: {key}"
    );
}

#[test]
fn h2_pool_key_same_config_same_key() {
    let p1 = minimal_proxy();
    let p2 = minimal_proxy();
    assert_eq!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "identical proxies should produce identical H2 keys"
    );
}

#[test]
fn h2_pool_key_different_hosts_differ() {
    let mut p1 = minimal_proxy();
    p1.backend_host = "host-a.com".to_string();
    let mut p2 = minimal_proxy();
    p2.backend_host = "host-b.com".to_string();
    assert_ne!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "different hosts should produce different H2 keys"
    );
}

#[test]
fn h2_pool_key_different_ports_differ() {
    let mut p1 = minimal_proxy();
    p1.backend_port = 443;
    let mut p2 = minimal_proxy();
    p2.backend_port = 8443;
    assert_ne!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "different ports should produce different H2 keys"
    );
}

#[test]
fn h2_pool_key_pipe_delimiter_count() {
    let proxy = minimal_proxy();
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        pipe_count, 5,
        "6 fields need 5 pipe delimiters in H2 key, got {pipe_count}: {key}"
    );
}

#[test]
fn h2_pool_key_no_protocol_field() {
    // H2 pool is always TLS, so there's no protocol field in the key
    // (unlike ConnectionPool which includes backend_protocol)
    let mut p1 = minimal_proxy();
    p1.backend_protocol = BackendProtocol::Http;
    let mut p2 = minimal_proxy();
    p2.backend_protocol = BackendProtocol::Https;
    assert_eq!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "H2 pool key should not include protocol (always TLS)"
    );
}

#[test]
fn h2_pool_key_ipv6_no_collision() {
    let mut proxy = minimal_proxy();
    proxy.backend_host = "::1".to_string();
    proxy.backend_port = 443;
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.starts_with("::1|443|"),
        "IPv6 should be safe with pipe delimiter: {key}"
    );
}

#[test]
fn h2_pool_key_policy_fields_do_not_fragment() {
    let mut p1 = minimal_proxy();
    p1.pool_http2_keep_alive_interval_seconds = Some(10);
    p1.pool_http2_max_concurrent_streams = Some(200);
    p1.backend_connect_timeout_ms = 500;
    let p2 = minimal_proxy();
    assert_eq!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "policy fields should not affect H2 pool key"
    );
}

// ---------------------------------------------------------------------------
// Http2ConnectionPool::write_shard_key tests
// ---------------------------------------------------------------------------

#[test]
fn write_shard_key_single_digit() {
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, "base|key", 3);
    assert_eq!(buf, "base|key#3");
}

#[test]
fn write_shard_key_zero() {
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, "base|key", 0);
    assert_eq!(buf, "base|key#0");
}

#[test]
fn write_shard_key_nine() {
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, "base|key", 9);
    assert_eq!(buf, "base|key#9");
}

#[test]
fn write_shard_key_double_digit() {
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, "base|key", 15);
    assert_eq!(buf, "base|key#15");
}

#[test]
fn write_shard_key_large_shard() {
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, "base|key", 1024);
    assert_eq!(buf, "base|key#1024");
}

#[test]
fn write_shard_key_clears_buffer_before_writing() {
    let mut buf = String::from("stale data that should be cleared");
    Http2ConnectionPool::write_shard_key(&mut buf, "new|key", 7);
    assert_eq!(buf, "new|key#7", "buffer should be cleared before writing");
}

#[test]
fn write_shard_key_reuses_buffer_across_calls() {
    let mut buf = String::with_capacity(64);
    Http2ConnectionPool::write_shard_key(&mut buf, "first", 1);
    assert_eq!(buf, "first#1");

    Http2ConnectionPool::write_shard_key(&mut buf, "second", 2);
    assert_eq!(buf, "second#2");

    // Capacity should still be the original allocation (no realloc)
    assert!(
        buf.capacity() >= 64,
        "buffer should retain its pre-allocated capacity"
    );
}

#[test]
fn write_shard_key_with_realistic_pool_key() {
    let proxy = minimal_proxy();
    let base_key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    let mut buf = String::new();
    Http2ConnectionPool::write_shard_key(&mut buf, &base_key, 0);
    assert_eq!(
        buf,
        format!("{}#0", base_key),
        "shard key should be base_key#shard"
    );
}

// ---------------------------------------------------------------------------
// Cross-pool key consistency tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connection_pool_key_no_upstream_vs_upstream_namespace_collision() {
    // A proxy with backend_host="upstream" port=1234 should NOT collide with
    // a proxy that has upstream_id="upstream:1234"
    let pool = pool_with_defaults();

    let mut direct = minimal_proxy();
    direct.backend_host = "upstream".to_string();
    direct.backend_port = 1234;

    let mut upstream = minimal_proxy();
    upstream.upstream_id = Some("upstream:1234".to_string());

    let k1 = pool.pool_key_for_warmup(&direct);
    let k2 = pool.pool_key_for_warmup(&upstream);
    assert_ne!(
        k1, k2,
        "d= and u= prefixes should prevent namespace collisions"
    );
    assert!(k1.starts_with("d="));
    assert!(k2.starts_with("u="));
}

#[tokio::test]
async fn connection_pool_and_h2_pool_keys_have_same_delimiter() {
    // Both pools must use | as delimiter for IPv6 safety
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();

    let conn_key = pool.pool_key_for_warmup(&proxy);
    let h2_key = Http2ConnectionPool::pool_key_for_warmup(&proxy);

    // Neither should contain field-level colons (only in host:port which is expected)
    for key in [&conn_key, &h2_key] {
        let pipe_count = key.chars().filter(|c| *c == '|').count();
        assert_eq!(pipe_count, 5, "key should use | as delimiter: {key}");
    }
}

// ---------------------------------------------------------------------------
// Http3ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[test]
fn h3_pool_key_basic_format() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    // Format: host|port|index|ca|mtls|verify
    assert_eq!(
        key, "backend.example.com|8080|0|||1",
        "basic H3 key format mismatch"
    );
}

#[test]
fn h3_pool_key_with_index() {
    let proxy = minimal_proxy();
    let key0 = Http3ConnectionPool::pool_key(&proxy, 0);
    let key3 = Http3ConnectionPool::pool_key(&proxy, 3);
    assert_ne!(
        key0, key3,
        "different indices should produce different keys"
    );
    assert!(key0.contains("|0|"), "key should contain index 0: {key0}");
    assert!(key3.contains("|3|"), "key should contain index 3: {key3}");
}

#[test]
fn h3_pool_key_with_ca_cert() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_server_ca_cert_path = Some("/certs/ca.pem".to_string());
    proxy.resolved_tls.server_ca_cert_path = Some("/certs/ca.pem".to_string());
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.contains("|/certs/ca.pem|"),
        "H3 key should contain CA path: {key}"
    );
}

#[test]
fn h3_pool_key_with_mtls_cert() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_client_cert_path = Some("/certs/client.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/certs/client.pem".to_string());
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.contains("|/certs/client.pem|"),
        "H3 key should contain mTLS cert path: {key}"
    );
}

#[test]
fn h3_pool_key_verify_disabled() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.ends_with("|0"),
        "H3 key should end with verify=0: {key}"
    );
}

#[test]
fn h3_pool_key_verify_enabled() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.ends_with("|1"),
        "H3 key should end with verify=1: {key}"
    );
}

#[test]
fn h3_pool_key_same_config_same_key() {
    let p1 = minimal_proxy();
    let p2 = minimal_proxy();
    assert_eq!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "identical proxies should produce identical H3 keys"
    );
}

#[test]
fn h3_pool_key_different_hosts_differ() {
    let mut p1 = minimal_proxy();
    p1.backend_host = "host-a.com".to_string();
    let mut p2 = minimal_proxy();
    p2.backend_host = "host-b.com".to_string();
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "different hosts should produce different H3 keys"
    );
}

#[test]
fn h3_pool_key_different_ports_differ() {
    let mut p1 = minimal_proxy();
    p1.backend_port = 443;
    let mut p2 = minimal_proxy();
    p2.backend_port = 8443;
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "different ports should produce different H3 keys"
    );
}

#[test]
fn h3_pool_key_different_ca_paths_differ() {
    let mut p1 = minimal_proxy();
    p1.backend_tls_server_ca_cert_path = Some("/ca/one.pem".to_string());
    p1.resolved_tls.server_ca_cert_path = Some("/ca/one.pem".to_string());
    let mut p2 = minimal_proxy();
    p2.backend_tls_server_ca_cert_path = Some("/ca/two.pem".to_string());
    p2.resolved_tls.server_ca_cert_path = Some("/ca/two.pem".to_string());
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "different CA paths should produce different H3 keys"
    );
}

#[test]
fn h3_pool_key_pipe_delimiter_count() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        pipe_count, 5,
        "6 fields need 5 pipe delimiters in H3 key, got {pipe_count}: {key}"
    );
}

#[test]
fn h3_pool_key_no_protocol_field() {
    // H3 pool key does not include backend_protocol (always QUIC/TLS)
    let mut p1 = minimal_proxy();
    p1.backend_protocol = BackendProtocol::Http;
    let mut p2 = minimal_proxy();
    p2.backend_protocol = BackendProtocol::Https;
    assert_eq!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "H3 pool key should not include protocol (always QUIC)"
    );
}

#[test]
fn h3_pool_key_no_dns_override_field() {
    // H3 pool key does not include dns_override (unlike H2/HTTP pools)
    let mut p1 = minimal_proxy();
    p1.dns_override = Some("10.0.0.1".to_string());
    let p2 = minimal_proxy();
    assert_eq!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "H3 pool key should not include dns_override"
    );
}

#[test]
fn h3_pool_key_ipv6_no_collision() {
    let mut proxy = minimal_proxy();
    proxy.backend_host = "::1".to_string();
    proxy.backend_port = 443;
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.starts_with("::1|443|"),
        "IPv6 should be safe with pipe delimiter: {key}"
    );
}

#[test]
fn h3_pool_key_policy_fields_do_not_fragment() {
    let mut p1 = minimal_proxy();
    p1.pool_http3_connections_per_backend = Some(8);
    p1.backend_connect_timeout_ms = 500;
    p1.pool_idle_timeout_seconds = Some(30);
    let p2 = minimal_proxy();
    assert_eq!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "policy fields should not affect H3 pool key"
    );
}

#[test]
fn h3_pool_key_full_tls_config() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_server_ca_cert_path = Some("/ca/bundle.pem".to_string());
    proxy.backend_tls_client_cert_path = Some("/client/cert.pem".to_string());
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.server_ca_cert_path = Some("/ca/bundle.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/client/cert.pem".to_string());
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http3ConnectionPool::pool_key(&proxy, 2);
    assert_eq!(
        key, "backend.example.com|8080|2|/ca/bundle.pem|/client/cert.pem|0",
        "full TLS config H3 key format mismatch"
    );
}

// ---------------------------------------------------------------------------
// Http3ConnectionPool::pool_key_for_target tests
// ---------------------------------------------------------------------------

#[test]
fn h3_pool_key_for_target_basic_format() {
    let key = Http3ConnectionPool::pool_key_for_target("upstream.example.com", 443, 0);
    assert_eq!(
        key, "upstream.example.com|443|0",
        "target key should be host|port|index"
    );
}

#[test]
fn h3_pool_key_for_target_different_index() {
    let k0 = Http3ConnectionPool::pool_key_for_target("host.com", 443, 0);
    let k5 = Http3ConnectionPool::pool_key_for_target("host.com", 443, 5);
    assert_ne!(
        k0, k5,
        "different indices should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_different_hosts() {
    let k1 = Http3ConnectionPool::pool_key_for_target("host-a.com", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target("host-b.com", 443, 0);
    assert_ne!(
        k1, k2,
        "different hosts should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_different_ports() {
    let k1 = Http3ConnectionPool::pool_key_for_target("host.com", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target("host.com", 8443, 0);
    assert_ne!(
        k1, k2,
        "different ports should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_pipe_delimiter_count() {
    let key = Http3ConnectionPool::pool_key_for_target("host.com", 443, 0);
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        pipe_count, 2,
        "3 fields need 2 pipe delimiters in target key, got {pipe_count}: {key}"
    );
}

#[test]
fn h3_pool_key_for_target_ipv6() {
    let key = Http3ConnectionPool::pool_key_for_target("::1", 443, 0);
    assert_eq!(key, "::1|443|0", "IPv6 target key should be safe");
}

#[test]
fn h3_pool_key_vs_target_key_differ() {
    // A proxy key and a target key for the same host:port should differ
    // because the proxy key has 6 fields (including TLS fields) and the
    // target key has only 3 fields
    let proxy = minimal_proxy();
    let proxy_key = Http3ConnectionPool::pool_key(&proxy, 0);
    let target_key =
        Http3ConnectionPool::pool_key_for_target(&proxy.backend_host, proxy.backend_port, 0);
    assert_ne!(
        proxy_key, target_key,
        "proxy key and target key should differ (different field count)"
    );
}

// ---------------------------------------------------------------------------
// Cross-pool key consistency: H3 uses same delimiter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_three_pools_use_pipe_delimiter() {
    let conn_pool = pool_with_defaults();
    let proxy = minimal_proxy();

    let conn_key = conn_pool.pool_key_for_warmup(&proxy);
    let h2_key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    let h3_key = Http3ConnectionPool::pool_key(&proxy, 0);

    for (name, key) in [
        ("ConnectionPool", &conn_key),
        ("H2 pool", &h2_key),
        ("H3 pool", &h3_key),
    ] {
        assert!(
            key.contains('|'),
            "{name} key should use | delimiter: {key}"
        );
        assert!(
            !key.contains("||||||"),
            "{name} key should not have excessive empty fields: {key}"
        );
    }
}

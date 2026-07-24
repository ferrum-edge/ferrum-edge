//! Tests for pool key construction in `ConnectionPool` and `Http2ConnectionPool`.
//!
//! Pool keys determine whether two proxies can share a pooled connection.
//! Getting the key wrong causes either pool poisoning (missing a field) or
//! unnecessary fragmentation (including a field that doesn't affect identity).
//! These tests verify the key format, delimiter safety, and field inclusion.

use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResolvedPortOverride,
    ResponseBodyMode, UpstreamTarget,
};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::http3::client::Http3ConnectionPool;
use ferrum_edge::proxy::backend_capabilities::{
    BackendCapabilityProbeTarget, capability_key, capability_key_for_proxy_target,
};
use ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool;
use ferrum_edge::proxy::http2_pool::Http2ConnectionPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

/// Build a minimal `Proxy` with sensible defaults for pool key testing.
fn minimal_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "test-proxy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/test".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
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

fn pool_with_workload_svid_generation(generation: Arc<AtomicU64>) -> ConnectionPool {
    let env_config = ferrum_edge::config::EnvConfig {
        gateway_svid_cert_path: Some("/var/run/ferrum/svid.pem".to_string()),
        gateway_svid_key_path: Some("/var/run/ferrum/svid.key".to_string()),
        ..Default::default()
    };
    let dns = DnsCache::new(DnsConfig::default());
    ConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        env_config,
        dns,
        None,
        Arc::new(Vec::new()),
        generation,
    )
}

fn runtime_pool_keys(pool: &ConnectionPool, proxy: &Proxy) -> Vec<(&'static str, String)> {
    vec![
        ("ConnectionPool", pool.pool_key_for_warmup(proxy)),
        ("H2 pool", Http2ConnectionPool::pool_key_for_warmup(proxy)),
        ("gRPC pool", GrpcConnectionPool::pool_key_for_warmup(proxy)),
        ("H3 pool", Http3ConnectionPool::pool_key(proxy, 0)),
    ]
}

fn pool_family_keys(pool: &ConnectionPool, proxy: &Proxy) -> Vec<(&'static str, String)> {
    let mut keys = runtime_pool_keys(pool, proxy);
    keys.push(("capabilities", capability_key(proxy)));
    keys
}

// ---------------------------------------------------------------------------
// ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connection_pool_key_direct_backend_format() {
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();
    let key = pool.pool_key_for_warmup(&proxy);
    // Direct backend:
    // d=host:port|protocol|dns|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N
    assert!(
        key.starts_with("d=backend.example.com:8080|"),
        "key should start with d= prefix: {key}"
    );
    // BackendScheme::Http = 0
    assert!(key.contains("|0|"), "key should contain protocol 0: {key}");
    // No DNS override, no subset, no CA, no mTLS, no SNI, no SAN digest, verify=true (1),
    // default reqwest builder identity (idle=90, tcp ka=60, default H2 windows).
    assert!(
        key.ends_with("||||||||1|svidg=static|i90|k60|h2:30:45:8388608:33554432:1:1048576"),
        "key should end with TLS identity + default reqwest builder identity: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_uses_numeric_generation_only_for_workload_svid() {
    let generation = Arc::new(AtomicU64::new(7));
    let pool = pool_with_workload_svid_generation(generation);
    let mut svid_proxy = minimal_proxy();
    svid_proxy.resolved_tls.client_cert_path = Some("/var/run/ferrum/svid.pem".to_string());
    svid_proxy.resolved_tls.client_key_path = Some("/var/run/ferrum/svid.key".to_string());
    let svid_key = pool.pool_key_for_warmup(&svid_proxy);
    assert!(
        svid_key.contains("|svidg=7|"),
        "workload SVID client cert should partition by numeric generation: {svid_key}"
    );

    let mut static_proxy = minimal_proxy();
    static_proxy.resolved_tls.client_cert_path = Some("/operator/client.pem".to_string());
    static_proxy.resolved_tls.client_key_path = Some("/operator/client.key".to_string());
    let static_key = pool.pool_key_for_warmup(&static_proxy);
    assert!(
        static_key.contains("|svidg=static|"),
        "operator-supplied client cert should not partition on SVID rotation: {static_key}"
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

/// codex round-1 Finding 1: a `DO_NOT_UPGRADE` (force-H1) proxy builds a
/// reqwest client with ALPN restricted to `http/1.1`, which is a different,
/// protocol-incompatible client from the default (h2-capable) one — so it must
/// get a DISTINCT reqwest pool key (an `h1` discriminator), or the two would
/// share a connection and `DO_NOT_UPGRADE` would not actually force H1 on a
/// TLS backend.
#[tokio::test]
async fn connection_pool_key_force_http1_discriminator() {
    use ferrum_edge::config::types::H2UpgradePolicy;
    let pool = pool_with_defaults();

    let default_proxy = minimal_proxy();
    let default_key = pool.pool_key_for_warmup(&default_proxy);

    let mut force_h1_proxy = minimal_proxy();
    force_h1_proxy.h2_upgrade_policy = Some(H2UpgradePolicy::DoNotUpgrade);
    let force_h1_key = pool.pool_key_for_warmup(&force_h1_proxy);

    assert_ne!(
        default_key, force_h1_key,
        "DO_NOT_UPGRADE (force-H1) must NOT share a reqwest pool key with the \
         default h2-capable client: default={default_key} force_h1={force_h1_key}"
    );
    assert!(
        force_h1_key.contains("|h1|"),
        "force-H1 key must carry the h1 ALPN discriminator: {force_h1_key}"
    );
    assert!(
        !default_key.contains("|h1|"),
        "default key must NOT carry the h1 discriminator: {default_key}"
    );

    let mut default_https_proxy = minimal_proxy();
    default_https_proxy.backend_scheme = Some(BackendScheme::Https);
    default_https_proxy.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    default_https_proxy.backend_port = 443;
    let default_https_key = pool.pool_key_for_warmup(&default_https_proxy);

    let mut disabled_h2_proxy = default_https_proxy.clone();
    disabled_h2_proxy.pool_enable_http2 = Some(false);
    let disabled_h2_key = pool.pool_key_for_warmup(&disabled_h2_proxy);
    assert_ne!(
        default_https_key, disabled_h2_key,
        "pool_enable_http2=false on a TLS backend must not share the default \
         h2-capable reqwest key: default={default_https_key} disabled_h2={disabled_h2_key}"
    );
    assert!(
        disabled_h2_key.contains("|h1|"),
        "backend-H2-disabled TLS key must carry the h1 ALPN discriminator: {disabled_h2_key}"
    );

    let mut http_disabled_h2_proxy = minimal_proxy();
    http_disabled_h2_proxy.pool_enable_http2 = Some(false);
    let http_disabled_h2_key = pool.pool_key_for_warmup(&http_disabled_h2_proxy);
    assert_eq!(
        default_key, http_disabled_h2_key,
        "pool_enable_http2=false must not fragment plaintext HTTP reqwest pools; \
         reqwest does not speak h2c on this path"
    );

    // `Upgrade` and `Default` are probe-driven — they stay h2-capable and must
    // share the default client's key (no fragmentation, no force-H1).
    for probe_driven in [H2UpgradePolicy::Upgrade, H2UpgradePolicy::Default] {
        let mut p = minimal_proxy();
        p.h2_upgrade_policy = Some(probe_driven);
        let k = pool.pool_key_for_warmup(&p);
        assert_eq!(
            k, default_key,
            "{probe_driven:?} must share the default (h2-capable) reqwest key: {k}"
        );
    }
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
async fn connection_pool_key_with_backend_tls_sni_and_sans() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
    p1.resolved_tls.san_allow_list = vec!["reviews.mesh.internal".to_string()];
    p1.resolved_tls.recompute_san_digest();
    let mut p2 = p1.clone();
    p2.resolved_tls.sni = Some("ratings.mesh.internal".to_string());

    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "backend TLS SNI must separate generic HTTP pool keys"
    );

    p2.resolved_tls.sni = p1.resolved_tls.sni.clone();
    p2.resolved_tls.san_allow_list = vec!["ratings.mesh.internal".to_string()];
    p2.resolved_tls.recompute_san_digest();
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "backend TLS SAN allow-list must separate generic HTTP pool keys"
    );
}

#[tokio::test]
async fn connection_pool_key_canonicalizes_backend_tls_san_allow_list() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
    p1.resolved_tls.san_allow_list = vec![
        "ratings.mesh.internal".to_string(),
        "reviews.mesh.internal".to_string(),
        "reviews.mesh.internal".to_string(),
    ];
    p1.resolved_tls.recompute_san_digest();

    let mut p2 = p1.clone();
    p2.resolved_tls.san_allow_list = vec![
        "reviews.mesh.internal".to_string(),
        "ratings.mesh.internal".to_string(),
    ];
    p2.resolved_tls.recompute_san_digest();

    assert_eq!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "backend TLS SAN allow-list order and duplicates must not fragment generic HTTP pools"
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
        key.contains("|0|svidg=static|"),
        "key should contain verify=0 when disabled: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_global_no_verify_overrides_proxy() {
    let pool = pool_with_global_tls(None, None, None, true);
    let proxy = minimal_proxy(); // proxy has verify=true
    let key = pool.pool_key_for_warmup(&proxy);
    // Global tls_no_verify=true should force effective verify to false
    assert!(
        key.contains("|0|svidg=static|"),
        "global no_verify should override proxy verify=true: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_pipe_delimiter_count() {
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();
    let key = pool.pool_key_for_warmup(&proxy);
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    // Connection-identity fields (dest, protocol, force-H1 ALPN discriminator, dns,
    // subset, ca, mtls_cert, mtls_key, sni, san_digest, verify, svid_generation)
    // need 11 pipe delimiters, plus idle/tcp-keepalive/h2 builder-identity
    // segments add 3 more (`|i…|k…|h2:…`) when HTTP/2 is enabled.
    assert_eq!(
        pipe_count, 14,
        "expected 14 pipe delimiters with reqwest builder identity, got {pipe_count} in key: {key}"
    );
}

#[tokio::test]
async fn connection_pool_key_different_protocols_differ() {
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Http);
    let mut p2 = minimal_proxy();
    p2.backend_scheme = Some(BackendScheme::Https);
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
async fn connection_pool_key_per_request_timeouts_do_not_fragment() {
    // Connect/read timeouts are applied per-request and must NOT affect the pool key.
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.backend_connect_timeout_ms = 1000;
    p1.backend_read_timeout_ms = 2000;
    let p2 = minimal_proxy();
    assert_eq!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "per-request timeouts must not affect the reqwest pool key"
    );
}

#[tokio::test]
async fn connection_pool_key_builder_only_settings_partition_clients() {
    // Builder-only settings are baked into the shared reqwest::Client and must
    // partition identity so first-creator-wins leakage cannot occur (#2951).
    let pool = pool_with_defaults();
    let mut p1 = minimal_proxy();
    p1.pool_http2_initial_stream_window_size = Some(65_535);
    let mut p2 = minimal_proxy();
    p2.pool_http2_initial_stream_window_size = Some(8_388_608);
    assert_ne!(
        pool.pool_key_for_warmup(&p1),
        pool.pool_key_for_warmup(&p2),
        "divergent HTTP/2 stream window must produce distinct reqwest pool keys"
    );

    let mut idle_a = minimal_proxy();
    idle_a.pool_idle_timeout_seconds = Some(30);
    let mut idle_b = minimal_proxy();
    idle_b.pool_idle_timeout_seconds = Some(120);
    assert_ne!(
        pool.pool_key_for_warmup(&idle_a),
        pool.pool_key_for_warmup(&idle_b),
        "divergent idle timeout must produce distinct reqwest pool keys"
    );

    // Identical builder settings still share.
    let same_a = minimal_proxy();
    let same_b = minimal_proxy();
    assert_eq!(
        pool.pool_key_for_warmup(&same_a),
        pool.pool_key_for_warmup(&same_b),
        "identical builder settings must share a reqwest pool key"
    );
}

// ---------------------------------------------------------------------------
// Http2ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[test]
fn h2_pool_key_basic_format() {
    let proxy = minimal_proxy();
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    // Format: host|port|dns|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N
    assert_eq!(
        key, "backend.example.com|8080||||||||1|svidg=static",
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
fn h2_pool_key_with_backend_tls_sni_and_sans() {
    let mut p1 = minimal_proxy();
    p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
    p1.resolved_tls.san_allow_list = vec!["reviews.mesh.internal".to_string()];
    p1.resolved_tls.recompute_san_digest();
    let mut p2 = p1.clone();
    p2.resolved_tls.sni = Some("ratings.mesh.internal".to_string());

    assert_ne!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "backend TLS SNI must separate H2 pool keys"
    );

    p2.resolved_tls.sni = p1.resolved_tls.sni.clone();
    p2.resolved_tls.san_allow_list = vec!["ratings.mesh.internal".to_string()];
    p2.resolved_tls.recompute_san_digest();
    assert_ne!(
        Http2ConnectionPool::pool_key_for_warmup(&p1),
        Http2ConnectionPool::pool_key_for_warmup(&p2),
        "backend TLS SAN allow-list must separate H2 pool keys"
    );
}

#[test]
fn h2_pool_key_verify_disabled() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http2ConnectionPool::pool_key_for_warmup(&proxy);
    assert!(
        key.ends_with("|0|svidg=static"),
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
        pipe_count, 10,
        "11 fields need 10 pipe delimiters in H2 key, got {pipe_count}: {key}"
    );
}

#[test]
fn h2_pool_key_no_protocol_field() {
    // H2 pool is always TLS, so there's no protocol field in the key
    // (unlike ConnectionPool which includes the backend scheme).
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Http);
    let mut p2 = minimal_proxy();
    p2.backend_scheme = Some(BackendScheme::Https);
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
    // Both pools must use | as delimiter for IPv6 safety. The exact field count
    // differs (the reqwest key carries an extra force-H1 ALPN discriminator
    // segment added in F5.1 — the direct-H2 pool already partitions H1-vs-H2 by
    // construction, so it needs none), so assert delimiter USAGE, not an equal
    // pipe count between the two pools.
    let pool = pool_with_defaults();
    let proxy = minimal_proxy();

    let conn_key = pool.pool_key_for_warmup(&proxy);
    let h2_key = Http2ConnectionPool::pool_key_for_warmup(&proxy);

    // Both must use | as the field delimiter (>= the documented minimum field
    // counts), confirming neither switched to a colon-based delimiter that
    // would be IPv6-unsafe.
    let conn_pipes = conn_key.chars().filter(|c| *c == '|').count();
    let h2_pipes = h2_key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        conn_pipes, 14,
        "reqwest key should use | as delimiter (with builder identity): {conn_key}"
    );
    assert!(h2_pipes >= 9, "H2 key should use | as delimiter: {h2_key}");
}

// ---------------------------------------------------------------------------
// Http3ConnectionPool pool key tests
// ---------------------------------------------------------------------------

#[test]
fn h3_pool_key_basic_format() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    // Format: host|port|index|dns_override|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N
    // (all TLS fields empty by default, verify=true, static SVID segment)
    assert_eq!(
        key, "backend.example.com|8080|0||||||||1|svidg=static",
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
fn h3_warmup_shards_cover_configured_global_pool() {
    let proxy = minimal_proxy();

    let shards: Vec<_> = Http3ConnectionPool::warmup_shard_indices(&proxy, 4).collect();
    assert_eq!(shards, vec![0, 1, 2, 3]);

    let keys: Vec<_> = shards
        .iter()
        .map(|index| Http3ConnectionPool::pool_key(&proxy, *index))
        .collect();
    let unique_keys: std::collections::HashSet<_> = keys.iter().collect();
    assert_eq!(
        unique_keys.len(),
        keys.len(),
        "warmup should plan a distinct H3 pool key per shard"
    );
    assert!(
        keys.iter().any(|key| key.contains("|3|")),
        "warmup should include the highest configured shard: {keys:?}"
    );
}

#[test]
fn h3_warmup_shards_honor_proxy_override() {
    let mut proxy = minimal_proxy();
    proxy.pool_http3_connections_per_backend = Some(2);

    let shards: Vec<_> = Http3ConnectionPool::warmup_shard_indices(&proxy, 8).collect();
    assert_eq!(shards, vec![0, 1]);
}

#[test]
fn h3_warmup_shards_never_empty() {
    let mut proxy = minimal_proxy();
    proxy.pool_http3_connections_per_backend = Some(0);

    let shards: Vec<_> = Http3ConnectionPool::warmup_shard_indices(&proxy, 0).collect();
    assert_eq!(shards, vec![0]);
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
fn h3_pool_key_with_backend_tls_sni_and_sans() {
    let mut p1 = minimal_proxy();
    p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
    p1.resolved_tls.san_allow_list = vec!["reviews.mesh.internal".to_string()];
    p1.resolved_tls.recompute_san_digest();
    let mut p2 = p1.clone();
    p2.resolved_tls.sni = Some("ratings.mesh.internal".to_string());

    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "backend TLS SNI must separate H3 pool keys"
    );

    p2.resolved_tls.sni = p1.resolved_tls.sni.clone();
    p2.resolved_tls.san_allow_list = vec!["ratings.mesh.internal".to_string()];
    p2.resolved_tls.recompute_san_digest();
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "backend TLS SAN allow-list must separate H3 pool keys"
    );
}

#[test]
fn h3_pool_key_verify_disabled() {
    let mut proxy = minimal_proxy();
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.ends_with("|0|svidg=static"),
        "H3 key should end with verify=0: {key}"
    );
}

#[test]
fn h3_pool_key_verify_enabled() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        key.ends_with("|1|svidg=static"),
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
    // Shape: host|port|index|dns_override|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N = 12 fields → 11 pipes.
    assert_eq!(
        pipe_count, 11,
        "12 fields need 11 pipe delimiters in H3 key, got {pipe_count}: {key}"
    );
}

#[test]
fn h3_pool_key_no_protocol_field() {
    // H3 pool key does not include the backend scheme (always QUIC/TLS).
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Http);
    let mut p2 = minimal_proxy();
    p2.backend_scheme = Some(BackendScheme::Https);
    assert_eq!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "H3 pool key should not include protocol (always QUIC)"
    );
}

#[test]
fn h3_pool_key_distinguishes_dns_override() {
    // H3 pool key MUST include `dns_override` so a proxy pinning a specific
    // resolved IP does not share a QUIC connection with a proxy that
    // resolves through the default path. Mirrors HTTP and the backend
    // capability registry key.
    let mut p1 = minimal_proxy();
    p1.dns_override = Some("10.0.0.1".to_string());
    let p2 = minimal_proxy();
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "dns_override must separate H3 pool keys"
    );
}

#[test]
fn h3_pool_key_distinguishes_client_key_path() {
    // The `client_key_path` (mTLS private key) must be part of the H3 pool
    // key alongside `client_cert_path`, so two proxies presenting different
    // signed certs — but with the same cert file path or with swapped
    // cert/key pairings — don't inadvertently share a QUIC connection.
    let mut p1 = minimal_proxy();
    p1.resolved_tls.client_cert_path = Some("/mtls/same.pem".to_string());
    p1.resolved_tls.client_key_path = Some("/mtls/key-a.key".to_string());
    let mut p2 = p1.clone();
    p2.resolved_tls.client_key_path = Some("/mtls/key-b.key".to_string());
    assert_ne!(
        Http3ConnectionPool::pool_key(&p1, 0),
        Http3ConnectionPool::pool_key(&p2, 0),
        "client_key_path must separate H3 pool keys"
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
    proxy.backend_tls_client_key_path = Some("/client/key.pem".to_string());
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.server_ca_cert_path = Some("/ca/bundle.pem".to_string());
    proxy.resolved_tls.client_cert_path = Some("/client/cert.pem".to_string());
    proxy.resolved_tls.client_key_path = Some("/client/key.pem".to_string());
    proxy.resolved_tls.verify_server_cert = false;
    let key = Http3ConnectionPool::pool_key(&proxy, 2);
    // Shape: host|port|index|dns_override|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N
    // dns_override and subset are empty here, so we get two empty fields between index and CA.
    assert_eq!(
        key,
        "backend.example.com|8080|2|||/ca/bundle.pem|/client/cert.pem|/client/key.pem|||0|svidg=static",
        "full TLS config H3 key format mismatch"
    );
}

// ---------------------------------------------------------------------------
// Http3ConnectionPool::pool_key_for_target tests
// ---------------------------------------------------------------------------

#[test]
fn h3_pool_key_for_target_starts_with_host_port_index() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key_for_target(&proxy, "upstream.example.com", 443, 0);
    assert!(
        key.starts_with("upstream.example.com|443|0|"),
        "target key should start with host|port|index: {key}"
    );
}

#[test]
fn h3_pool_key_for_target_different_index() {
    let proxy = minimal_proxy();
    let k0 = Http3ConnectionPool::pool_key_for_target(&proxy, "host.com", 443, 0);
    let k5 = Http3ConnectionPool::pool_key_for_target(&proxy, "host.com", 443, 5);
    assert_ne!(
        k0, k5,
        "different indices should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_different_hosts() {
    let proxy = minimal_proxy();
    let k1 = Http3ConnectionPool::pool_key_for_target(&proxy, "host-a.com", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target(&proxy, "host-b.com", 443, 0);
    assert_ne!(
        k1, k2,
        "different hosts should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_different_ports() {
    let proxy = minimal_proxy();
    let k1 = Http3ConnectionPool::pool_key_for_target(&proxy, "host.com", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target(&proxy, "host.com", 8443, 0);
    assert_ne!(
        k1, k2,
        "different ports should produce different target keys"
    );
}

#[test]
fn h3_pool_key_for_target_pipe_delimiter_count() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key_for_target(&proxy, "host.com", 443, 0);
    // Shape: host|port|index|dns_override|subset|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=N = 11 pipes.
    let pipe_count = key.chars().filter(|c| *c == '|').count();
    assert_eq!(
        pipe_count, 11,
        "12 fields need 11 pipe delimiters in target key, got {pipe_count}: {key}"
    );
}

#[test]
fn h3_pool_key_for_target_ipv6() {
    let proxy = minimal_proxy();
    let key = Http3ConnectionPool::pool_key_for_target(&proxy, "::1", 443, 0);
    assert!(
        key.starts_with("::1|443|0|"),
        "IPv6 target key should be safe: {key}"
    );
}

#[test]
fn h3_pool_key_for_target_separates_distinct_dns_overrides() {
    // Regression guard: two proxies with different `dns_override` values
    // pointed at the same load-balanced target must NOT share a pooled
    // QUIC connection — they resolve to different backend IPs.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.dns_override = Some("10.0.0.1".to_string());

    let mut p2 = p1.clone();
    p2.dns_override = Some("10.0.0.2".to_string());

    let k1 = Http3ConnectionPool::pool_key_for_target(&p1, "shared.backend", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target(&p2, "shared.backend", 443, 0);
    assert_ne!(k1, k2, "dns_override must separate H3 target pool keys");
}

#[test]
fn h3_pool_key_for_target_separates_distinct_mtls_identities() {
    // Regression guard: two proxies with different mTLS client certs must
    // NOT share a QUIC connection — the backend sees a different client
    // identity on each.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.client_cert_path = Some("/mtls/tenant-a.pem".to_string());
    p1.resolved_tls.client_key_path = Some("/mtls/tenant-a.key".to_string());

    let mut p2 = p1.clone();
    p2.resolved_tls.client_cert_path = Some("/mtls/tenant-b.pem".to_string());
    p2.resolved_tls.client_key_path = Some("/mtls/tenant-b.key".to_string());

    let k1 = Http3ConnectionPool::pool_key_for_target(&p1, "shared.backend", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target(&p2, "shared.backend", 443, 0);
    assert_ne!(
        k1, k2,
        "mTLS client identity must separate H3 target pool keys"
    );
}

#[test]
fn h3_pool_key_for_target_separates_verify_toggle() {
    // Regression guard: a proxy with verify=true must not share a pooled
    // QUIC connection with a proxy that accepted the cert without
    // verification.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.verify_server_cert = true;
    let mut p2 = p1.clone();
    p2.resolved_tls.verify_server_cert = false;

    let k1 = Http3ConnectionPool::pool_key_for_target(&p1, "shared.backend", 443, 0);
    let k2 = Http3ConnectionPool::pool_key_for_target(&p2, "shared.backend", 443, 0);
    assert_ne!(
        k1, k2,
        "verify_server_cert must separate H3 target pool keys"
    );
}

#[test]
fn h3_pool_key_matches_target_key_when_host_port_match() {
    // The proxy-level H3 pool key and the target-level H3 pool key must
    // converge to the same string when the target is the proxy's own
    // backend_host/backend_port — otherwise the retry path and the
    // warmup path would create duplicate pool entries for the same
    // connection identity.
    let proxy = minimal_proxy();
    let proxy_key = Http3ConnectionPool::pool_key(&proxy, 0);
    let target_key = Http3ConnectionPool::pool_key_for_target(
        &proxy,
        &proxy.backend_host,
        proxy.backend_port,
        0,
    );
    assert_eq!(
        proxy_key, target_key,
        "proxy-level and target-level H3 keys must agree when host/port match"
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
            key.contains("||"),
            "{name} key should include empty SAN-digest field: {key}"
        );
    }
}

#[tokio::test]
async fn pool_keys_escape_reserved_dns_subset_components() {
    let conn_pool = pool_with_defaults();

    let mut left = minimal_proxy();
    left.upstream_id = Some("shared|upstream".to_string());
    left.dns_override = Some("10.0.0.1|blue".to_string());
    left.upstream_subset = Some("canary#1%live".to_string());

    let mut right = minimal_proxy();
    right.upstream_id = left.upstream_id.clone();
    right.dns_override = Some("10.0.0.1".to_string());
    right.upstream_subset = Some("blue|canary#1%live".to_string());

    let left_keys = runtime_pool_keys(&conn_pool, &left);
    let right_keys = runtime_pool_keys(&conn_pool, &right);

    for ((left_name, left_key), (right_name, right_key)) in left_keys.iter().zip(right_keys.iter())
    {
        assert_eq!(left_name, right_name);
        assert_ne!(
            left_key, right_key,
            "{left_name} must not let dns_override/upstream_subset delimiters collide: {left_key} vs {right_key}"
        );
        assert!(
            left_key.contains("%7C") && left_key.contains("%23") && left_key.contains("%25"),
            "{left_name} should escape reserved key delimiters: {left_key}"
        );
    }
}

#[tokio::test]
async fn pool_keys_escape_reserved_tls_identity_components() {
    let conn_pool = pool_with_defaults();

    let mut left = minimal_proxy();
    left.backend_scheme = Some(BackendScheme::Https);
    left.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    left.resolved_tls.server_ca_cert_path = Some("/ca|client".to_string());
    left.resolved_tls.client_cert_path = Some("/cert#blue".to_string());
    left.resolved_tls.client_key_path = Some("/key%raw".to_string());

    let mut right = minimal_proxy();
    right.backend_scheme = Some(BackendScheme::Https);
    right.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    right.resolved_tls.server_ca_cert_path = Some("/ca".to_string());
    right.resolved_tls.client_cert_path = Some("client|/cert#blue".to_string());
    right.resolved_tls.client_key_path = Some("/key%raw".to_string());

    let left_keys = pool_family_keys(&conn_pool, &left);
    let right_keys = pool_family_keys(&conn_pool, &right);

    for ((left_name, left_key), (right_name, right_key)) in left_keys.iter().zip(right_keys.iter())
    {
        assert_eq!(left_name, right_name);
        assert_ne!(
            left_key, right_key,
            "{left_name} must not let backend TLS identity delimiters collide: {left_key} vs {right_key}"
        );
        assert!(
            left_key.contains("%7C") && left_key.contains("%23") && left_key.contains("%25"),
            "{left_name} should escape reserved TLS key delimiters: {left_key}"
        );
    }
}

// ---------------------------------------------------------------------------
// Backend capability registry key tests
// ---------------------------------------------------------------------------

#[test]
fn backend_capability_key_uses_target_host_and_port() {
    let proxy = minimal_proxy();
    let target = UpstreamTarget {
        host: "target.backend.internal".to_string(),
        port: 9443,
        service_port_policy_key: None,
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    };

    let key = capability_key_for_proxy_target(&proxy, Some(&target));

    assert!(
        key.starts_with("http|target.backend.internal|9443|"),
        "capability key should be keyed by the real backend target identity: {key}"
    );
}

#[test]
fn backend_capability_key_includes_tls_identity_fields() {
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.server_ca_cert_path = Some("/ca/a.pem".to_string());
    p1.resolved_tls.client_cert_path = Some("/mtls/client.pem".to_string());
    p1.resolved_tls.client_key_path = Some("/mtls/client.key".to_string());

    let mut p2 = p1.clone();
    p2.resolved_tls.client_key_path = Some("/mtls/other.key".to_string());

    let key1 = capability_key(&p1);
    let key2 = capability_key(&p2);

    assert_ne!(
        key1, key2,
        "capability key must distinguish different TLS identities"
    );
}

#[test]
fn backend_capability_key_includes_backend_tls_sni_and_sans() {
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.sni = Some("reviews.mesh.internal".to_string());
    p1.resolved_tls.san_allow_list = vec!["reviews.mesh.internal".to_string()];
    p1.resolved_tls.recompute_san_digest();

    let mut p2 = p1.clone();
    p2.resolved_tls.sni = Some("ratings.mesh.internal".to_string());
    assert_ne!(
        capability_key(&p1),
        capability_key(&p2),
        "capability key must distinguish backend TLS SNI"
    );

    p2.resolved_tls.sni = p1.resolved_tls.sni.clone();
    p2.resolved_tls.san_allow_list = vec!["ratings.mesh.internal".to_string()];
    p2.resolved_tls.recompute_san_digest();
    assert_ne!(
        capability_key(&p1),
        capability_key(&p2),
        "capability key must distinguish backend TLS SAN allow-lists"
    );
}

#[test]
fn backend_capability_key_separates_distinct_dns_overrides() {
    // Two otherwise-identical proxies pointed at the same logical backend
    // must NOT share a capability entry when they pin different resolved
    // IPs via `dns_override`: the probe result for one resolution target
    // is not a valid proxy for the other.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.dns_override = Some("10.0.0.1".to_string());

    let mut p2 = p1.clone();
    p2.dns_override = Some("10.0.0.2".to_string());

    assert_ne!(
        capability_key(&p1),
        capability_key(&p2),
        "dns_override must segregate capability entries"
    );
}

#[test]
fn backend_capability_key_separates_verify_server_cert_toggles() {
    // Whether the backend cert is actually validated is part of the
    // trust chain; probes with and without verification are not
    // interchangeable observations.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.verify_server_cert = true;

    let mut p2 = p1.clone();
    p2.resolved_tls.verify_server_cert = false;

    assert_ne!(
        capability_key(&p1),
        capability_key(&p2),
        "verify_server_cert must segregate capability entries"
    );
}

#[test]
fn backend_capability_key_reuses_entry_across_equivalent_proxies() {
    // Two proxies with the same resolved identity (scheme, host, port,
    // dns_override, TLS fields) must hash to the exact same key so they
    // share one probe result in the registry.
    let mut p1 = minimal_proxy();
    p1.backend_scheme = Some(BackendScheme::Https);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p1.resolved_tls.server_ca_cert_path = Some("/ca/shared.pem".to_string());
    p1.resolved_tls.verify_server_cert = true;

    let mut p2 = p1.clone();
    p2.id = "different-proxy-id".to_string();
    p2.listen_path = Some("/other".to_string());
    p2.strip_listen_path = !p1.strip_listen_path;

    assert_eq!(
        capability_key(&p1),
        capability_key(&p2),
        "proxy identity / path fields must not leak into the capability key"
    );
}

#[test]
fn backend_capability_key_prefers_upstream_target_over_proxy_backend() {
    // When an upstream target is supplied, it completely replaces the
    // proxy's template host/port in the key. Probes are keyed by the
    // real connection endpoint, not the proxy's fallback values.
    let proxy = minimal_proxy();
    let target = UpstreamTarget {
        host: "lb-member.internal".to_string(),
        port: 7443,
        service_port_policy_key: None,
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    };

    let key_with_target = capability_key_for_proxy_target(&proxy, Some(&target));
    let key_without_target = capability_key_for_proxy_target(&proxy, None);

    assert!(
        key_with_target.starts_with("http|lb-member.internal|7443|"),
        "upstream target host/port should appear first: {key_with_target}"
    );
    assert!(
        key_without_target.starts_with("http|backend.example.com|8080|"),
        "proxy backend host/port should appear when no target is supplied: {key_without_target}"
    );
}

#[test]
fn backend_capability_probe_target_applies_per_port_tls_before_keying() {
    let mut proxy = minimal_proxy();
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    proxy.resolved_tls.sni = Some("base.mesh.internal".to_string());

    let mut per_port_tls = BackendTlsConfig::default_verify();
    per_port_tls.sni = Some("reviews.mesh.internal".to_string());
    per_port_tls.server_ca_cert_path = Some("/mesh/reviews-ca.pem".to_string());
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        8080,
        ResolvedPortOverride {
            tls: Some(per_port_tls),
            ..Default::default()
        },
    )]));

    let target = UpstreamTarget {
        host: "reviews-v1.mesh.internal".to_string(),
        port: 9443,
        service_port_policy_key: Some(8080),
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    };

    let probe = BackendCapabilityProbeTarget::from_proxy(&proxy, Some(&target));
    let base_key = capability_key_for_proxy_target(&proxy, Some(&target));

    assert_eq!(probe.host(), "reviews-v1.mesh.internal");
    assert_eq!(probe.port(), 9443);
    assert_eq!(
        probe.proxy.resolved_tls.sni.as_deref(),
        Some("reviews.mesh.internal"),
        "capability probes must use the same per-port backend TLS SNI as dispatch"
    );
    assert_eq!(
        probe.proxy.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/mesh/reviews-ca.pem")
    );
    assert_ne!(
        probe.key, base_key,
        "probe key must be built from the per-target effective proxy, not the base proxy"
    );
    assert_eq!(
        probe.key,
        capability_key(&probe.proxy),
        "ordinary probe target key should match the effective probe proxy identity"
    );
}

// ── Per-subset pool key partitioning (GAP-3B regression guard) ─────────
//
// Two proxies pointing at the same `(host, port, dns_override, tls)` but
// selecting different DestinationRule subsets MUST land on distinct pool
// entries. The subset segment is independently written by each of the four
// pool key builders (HTTP/H2/gRPC/H3); if any builder is refactored and
// forgets the segment, two subsets with distinct TLS material would silently
// share a connection. These four tests pin every builder.

#[tokio::test]
async fn connection_pool_key_partitions_by_upstream_subset() {
    let pool = pool_with_defaults();
    let mut p_v1 = minimal_proxy();
    p_v1.upstream_subset = Some("v1".to_string());
    let mut p_v2 = minimal_proxy();
    p_v2.upstream_subset = Some("v2".to_string());
    let mut p_none = minimal_proxy();
    p_none.upstream_subset = None;

    let key_v1 = pool.pool_key_for_warmup(&p_v1);
    let key_v2 = pool.pool_key_for_warmup(&p_v2);
    let key_none = pool.pool_key_for_warmup(&p_none);

    assert_ne!(
        key_v1, key_v2,
        "v1 and v2 subsets must not share HTTP pool entries: {key_v1} vs {key_v2}"
    );
    assert_ne!(
        key_v1, key_none,
        "v1 subset and no-subset must not share: {key_v1} vs {key_none}"
    );
    assert_ne!(
        key_v2, key_none,
        "v2 subset and no-subset must not share: {key_v2} vs {key_none}"
    );
}

#[test]
fn http2_pool_key_partitions_by_upstream_subset() {
    let mut p_v1 = minimal_proxy();
    p_v1.upstream_subset = Some("v1".to_string());
    let mut p_v2 = minimal_proxy();
    p_v2.upstream_subset = Some("v2".to_string());
    let mut p_none = minimal_proxy();
    p_none.upstream_subset = None;

    let key_v1 = Http2ConnectionPool::pool_key_for_warmup(&p_v1);
    let key_v2 = Http2ConnectionPool::pool_key_for_warmup(&p_v2);
    let key_none = Http2ConnectionPool::pool_key_for_warmup(&p_none);

    assert_ne!(
        key_v1, key_v2,
        "v1 and v2 subsets must not share H2 pool entries: {key_v1} vs {key_v2}"
    );
    assert_ne!(
        key_v1, key_none,
        "v1 subset and no-subset must not share H2 pool: {key_v1} vs {key_none}"
    );
    assert_ne!(
        key_v2, key_none,
        "v2 subset and no-subset must not share H2 pool: {key_v2} vs {key_none}"
    );
}

#[test]
fn grpc_pool_key_partitions_by_upstream_subset() {
    use ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool;

    let mut p_v1 = minimal_proxy();
    p_v1.upstream_subset = Some("v1".to_string());
    let mut p_v2 = minimal_proxy();
    p_v2.upstream_subset = Some("v2".to_string());
    let mut p_none = minimal_proxy();
    p_none.upstream_subset = None;

    let key_v1 = GrpcConnectionPool::pool_key_for_warmup(&p_v1);
    let key_v2 = GrpcConnectionPool::pool_key_for_warmup(&p_v2);
    let key_none = GrpcConnectionPool::pool_key_for_warmup(&p_none);

    assert_ne!(
        key_v1, key_v2,
        "v1 and v2 subsets must not share gRPC pool entries: {key_v1} vs {key_v2}"
    );
    assert_ne!(
        key_v1, key_none,
        "v1 subset and no-subset must not share gRPC pool: {key_v1} vs {key_none}"
    );
    assert_ne!(
        key_v2, key_none,
        "v2 subset and no-subset must not share gRPC pool: {key_v2} vs {key_none}"
    );
}

#[test]
fn http3_pool_key_partitions_by_upstream_subset() {
    let mut p_v1 = minimal_proxy();
    p_v1.upstream_subset = Some("v1".to_string());
    let mut p_v2 = minimal_proxy();
    p_v2.upstream_subset = Some("v2".to_string());
    let mut p_none = minimal_proxy();
    p_none.upstream_subset = None;

    let key_v1 = Http3ConnectionPool::pool_key(&p_v1, 0);
    let key_v2 = Http3ConnectionPool::pool_key(&p_v2, 0);
    let key_none = Http3ConnectionPool::pool_key(&p_none, 0);

    assert_ne!(
        key_v1, key_v2,
        "v1 and v2 subsets must not share H3 pool entries: {key_v1} vs {key_v2}"
    );
    assert_ne!(
        key_v1, key_none,
        "v1 subset and no-subset must not share H3 pool: {key_v1} vs {key_none}"
    );
    assert_ne!(
        key_v2, key_none,
        "v2 subset and no-subset must not share H3 pool: {key_v2} vs {key_none}"
    );
}

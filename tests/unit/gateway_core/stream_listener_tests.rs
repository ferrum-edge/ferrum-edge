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
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::stream_listener::{StreamListenerDegradation, StreamListenerManager};
use ferrum_edge::proxy::stream_match::{StreamMatchArm, StreamMatchCriteria};
use ferrum_edge::request_epoch::RequestEpochStore;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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
        dispatch_port_override_fallback: None,
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
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
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        pending_limit_scope: None,
    };
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    proxy
}

fn constrain_to_loopback(proxy: &mut Proxy) {
    proxy.stream_match = Some(StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_subnets: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        }],
    });
    proxy.normalize_fields();
}

fn tls_client_hello(hostname: &str) -> Vec<u8> {
    let name = hostname.as_bytes();
    let list_len = 3 + name.len();
    let extension_data_len = 2 + list_len;
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(extension_data_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(name);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![
        0x01,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Allocate an ephemeral port by binding and immediately dropping.
async fn ephemeral_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Start a TCP stream-listener fixture on a fresh port, retrying only the
/// demonstrated bind-and-release race from `ephemeral_port()`.
///
/// The production manager owns its listener bind, so the test cannot hand it a
/// reservation. Another parallel test can therefore claim the released port
/// between allocation and `reconcile()`. A failed attempt is retryable only
/// when every reported failure is the expected `Port ... is already in use`
/// error for that exact port; configuration, TLS, and lifecycle failures remain
/// immediate test failures. Each attempt uses a new kernel-assigned port.
async fn start_manager_on_fresh_tcp_port<F>(mut build_config: F) -> (StreamListenerManager, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    const MAX_BIND_ATTEMPTS: usize = 8;

    let mut bind_races = Vec::new();
    for attempt in 1..=MAX_BIND_ATTEMPTS {
        let port = ephemeral_port().await;
        let config = build_config(port);
        assert!(config.validate_stream_proxies().is_ok());

        let manager = create_manager(config);
        let failures = manager.reconcile().await;
        if failures.is_empty() {
            let started = manager.wait_until_started(Duration::from_secs(5)).await;
            if started.is_ok() {
                return (manager, port);
            }

            // Reconcile first probes the port, then the listener task performs
            // the owning bind. A competing test can win that second, even
            // narrower interval. Retry only when the manager's structured
            // snapshot proves that exact EADDRINUSE class; a generic startup
            // timeout or any other degradation remains a hard assertion.
            let async_failures = manager.stream_bind_failures();
            let only_async_port_collision = !async_failures.is_empty()
                && async_failures.iter().all(|failure| {
                    failure.listen_port == port
                        && matches!(failure.kind, StreamListenerDegradation::BindFailed)
                        && failure.error.contains("already in use")
                });
            manager.shutdown_all().await;
            assert!(
                only_async_port_collision,
                "stream listener on fresh port {port} did not start: {started:?}; \
                 failures={async_failures:?}"
            );
            bind_races.push(format!(
                "attempt {attempt}, port {port}, async failures: {async_failures:?}"
            ));
            continue;
        }

        let expected_prefix = format!("Port {port} is already in use on ");
        let only_released_port_collision = failures.iter().all(|(_, failed_port, message)| {
            *failed_port == port && message.starts_with(&expected_prefix)
        });
        manager.shutdown_all().await;
        assert!(
            only_released_port_collision,
            "stream-listener setup failed for a reason other than the released-port race: {failures:?}"
        );
        bind_races.push(format!(
            "attempt {attempt}, port {port}, reconcile failures: {failures:?}"
        ));
    }

    panic!(
        "could not acquire a frontend port after {MAX_BIND_ATTEMPTS} fresh, narrowly classified attempts: {bind_races:?}"
    );
}

fn create_manager(config: GatewayConfig) -> StreamListenerManager {
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    create_manager_with_config_arc(config_arc, &config)
}

fn create_manager_with_config_arc(
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    config: &GatewayConfig,
) -> StreamListenerManager {
    create_manager_runtime(config_arc, config).manager
}

/// Runtime pieces needed when a test reloads config the way production does:
/// publish a new request epoch (backend dial source) and swap the manager's
/// config ArcSwap (reconcile / SNI-group membership source) together.
struct StreamManagerRuntime {
    manager: StreamListenerManager,
    request_epoch: Arc<RequestEpochStore>,
    plugin_cache: Arc<PluginCache>,
    consumer_index: Arc<ConsumerIndex>,
    lb_cache: Arc<LoadBalancerCache>,
}

fn create_manager_runtime(
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    config: &GatewayConfig,
) -> StreamManagerRuntime {
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

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch.clone(),
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
        Arc::new(TrustedProxies::none()),
    );
    StreamManagerRuntime {
        manager,
        request_epoch,
        plugin_cache,
        consumer_index,
        lb_cache,
    }
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
async fn shared_l4_catchall_is_grouped_and_preserves_declaration_order() {
    let constrained_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let catchall_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let constrained_backend_port = constrained_backend.local_addr().unwrap().port();
    let catchall_backend_port = catchall_backend.local_addr().unwrap().port();

    // Put the catch-all first deliberately. Runtime planning must group it on
    // the shared socket without changing VirtualService first-match order.
    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        let mut catchall = create_stream_proxy("catchall", BackendScheme::Tcp, frontend_port);
        catchall.backend_port = catchall_backend_port;
        let mut constrained = create_stream_proxy("constrained", BackendScheme::Tcp, frontend_port);
        constrained.backend_port = constrained_backend_port;
        constrain_to_loopback(&mut constrained);
        GatewayConfig {
            proxies: vec![catchall, constrained],
            ..empty_config()
        }
    })
    .await;
    let _client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    let selected = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = constrained_backend.accept() => {
                result.unwrap();
                "constrained"
            }
            result = catchall_backend.accept() => {
                result.unwrap();
                "catchall"
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(selected, "catchall");
    manager.shutdown_all().await;
}

#[tokio::test]
async fn shared_l4_double_digit_ids_preserve_declaration_order() {
    let match_two_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let match_ten_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let match_two_backend_port = match_two_backend.local_addr().unwrap().port();
    let match_ten_backend_port = match_ten_backend.local_addr().unwrap().port();

    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        let mut match_two = create_stream_proxy("route-match-2", BackendScheme::Tcp, frontend_port);
        match_two.backend_port = match_two_backend_port;
        constrain_to_loopback(&mut match_two);
        let mut match_ten =
            create_stream_proxy("route-match-10", BackendScheme::Tcp, frontend_port);
        match_ten.backend_port = match_ten_backend_port;
        constrain_to_loopback(&mut match_ten);
        GatewayConfig {
            proxies: vec![match_two, match_ten],
            ..empty_config()
        }
    })
    .await;
    let _client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    let selected = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = match_two_backend.accept() => {
                result.unwrap();
                "match-2"
            }
            result = match_ten_backend.accept() => {
                result.unwrap();
                "match-10"
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(selected, "match-2");
    manager.shutdown_all().await;
}

#[tokio::test]
async fn passthrough_same_sni_double_digit_ids_preserve_declaration_order() {
    let match_two_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let match_ten_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let match_two_backend_port = match_two_backend.local_addr().unwrap().port();
    let match_ten_backend_port = match_ten_backend.local_addr().unwrap().port();

    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        let mut match_two = create_stream_proxy("route-match-2", BackendScheme::Tcp, frontend_port);
        match_two.backend_port = match_two_backend_port;
        match_two.passthrough = true;
        match_two.hosts = vec!["secure.example.com".to_string()];
        constrain_to_loopback(&mut match_two);
        let mut match_ten =
            create_stream_proxy("route-match-10", BackendScheme::Tcp, frontend_port);
        match_ten.backend_port = match_ten_backend_port;
        match_ten.passthrough = true;
        match_ten.hosts = vec!["secure.example.com".to_string()];
        match_ten.stream_match = Some(StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_subnets: vec!["127.0.0.1/32".to_string()],
                ..Default::default()
            }],
        });
        match_ten.normalize_fields();
        GatewayConfig {
            proxies: vec![match_two, match_ten],
            ..empty_config()
        }
    })
    .await;
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    client
        .write_all(&tls_client_hello("secure.example.com"))
        .await
        .unwrap();
    let selected = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = match_two_backend.accept() => {
                result.unwrap();
                "match-2"
            }
            result = match_ten_backend.accept() => {
                result.unwrap();
                "match-10"
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(selected, "match-2");
    manager.shutdown_all().await;
}

// ── Issue #3264: opaque-TLS SNI routing on ordinary `tcp` listeners ──────────

/// Two ordinary `tcp` listeners (`passthrough: false`, `frontend_tls: false`)
/// share one port and are separated only by SNI. Before #3264 this shape was
/// rejected at config admission, so opaque TLS fanout required `passthrough`.
///
/// Exercises the tier ladder end to end on a live listener: exact host, then
/// wildcard, then the single declared catch-all.
#[tokio::test]
async fn opaque_tcp_listeners_route_by_sni_across_every_tier() {
    let exact_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wildcard_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let default_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exact_port = exact_backend.local_addr().unwrap().port();
    let wildcard_port = wildcard_backend.local_addr().unwrap().port();
    let default_port = default_backend.local_addr().unwrap().port();

    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        // Declare the wildcard FIRST so the assertion proves tier order, not
        // declaration order.
        let mut wildcard = create_stream_proxy("wildcard", BackendScheme::Tcp, frontend_port);
        wildcard.backend_port = wildcard_port;
        wildcard.hosts = vec!["*.example.com".to_string()];
        let mut exact = create_stream_proxy("exact", BackendScheme::Tcp, frontend_port);
        exact.backend_port = exact_port;
        exact.hosts = vec!["tenant-a.example.com".to_string()];
        let mut default_route = create_stream_proxy("default", BackendScheme::Tcp, frontend_port);
        default_route.backend_port = default_port;
        GatewayConfig {
            proxies: vec![wildcard, exact, default_route],
            ..empty_config()
        }
    })
    .await;

    for (hostname, expected) in [
        ("tenant-a.example.com", "exact"),
        ("tenant-z.example.com", "wildcard"),
        ("unclaimed.org", "default"),
    ] {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
            .await
            .unwrap();
        client.write_all(&tls_client_hello(hostname)).await.unwrap();
        let selected = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = exact_backend.accept() => { result.unwrap(); "exact" }
                result = wildcard_backend.accept() => { result.unwrap(); "wildcard" }
                result = default_backend.accept() => { result.unwrap(); "default" }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no backend selected for SNI {hostname}"));
        assert_eq!(selected, expected, "SNI {hostname} selected the wrong tier");
    }

    manager.shutdown_all().await;
}

/// Security regression for the core #3264 defect. On an SNI-routed listener a
/// ClientHello that never finishes arriving used to fall through to the
/// catch-all, putting one tenant's connection on the default tenant's backend.
/// It must now be refused before any backend is dialed, while a complete hello
/// on the same listener still routes.
#[tokio::test]
async fn opaque_tcp_sni_listener_refuses_a_truncated_client_hello() {
    let named_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let default_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let named_port = named_backend.local_addr().unwrap().port();
    let default_port = default_backend.local_addr().unwrap().port();

    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        let mut named = create_stream_proxy("named", BackendScheme::Tcp, frontend_port);
        named.backend_port = named_port;
        named.hosts = vec!["tenant-a.example.com".to_string()];
        let mut default_route = create_stream_proxy("default", BackendScheme::Tcp, frontend_port);
        default_route.backend_port = default_port;
        GatewayConfig {
            proxies: vec![named, default_route],
            ..empty_config()
        }
    })
    .await;

    let hello = tls_client_hello("tenant-a.example.com");
    let mut truncated = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    // Cut inside the random bytes, before the server_name extension.
    truncated.write_all(&hello[..20]).await.unwrap();
    truncated.flush().await.unwrap();

    // The manager's handshake deadline is 10s in tests; assert no backend is
    // dialed well inside it. A pre-#3264 gateway dials the catch-all as soon as
    // the first (truncated) peek returns.
    let leaked = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = named_backend.accept() => { result.unwrap(); "named" }
            result = default_backend.accept() => { result.unwrap(); "default" }
        }
    })
    .await;
    assert!(
        leaked.is_err(),
        "a truncated ClientHello must not be routed at all, got {leaked:?}"
    );

    // The listener is fail-closed, not broken.
    let mut good = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    good.write_all(&hello).await.unwrap();
    let selected = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = named_backend.accept() => { result.unwrap(); "named" }
            result = default_backend.accept() => { result.unwrap(); "default" }
        }
    })
    .await
    .expect("a complete ClientHello must still route");
    assert_eq!(selected, "named");

    manager.shutdown_all().await;
}

/// Provably non-TLS opening bytes are refused by default on an SNI-routed
/// listener even though the group declares a catch-all: the default route is a
/// TLS default, not an "anything goes" route.
#[tokio::test]
async fn opaque_tcp_sni_listener_refuses_non_tls_bytes_by_default() {
    let default_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let default_port = default_backend.local_addr().unwrap().port();

    let (manager, frontend_port) = start_manager_on_fresh_tcp_port(|frontend_port| {
        let mut named = create_stream_proxy("named", BackendScheme::Tcp, frontend_port);
        named.hosts = vec!["tenant-a.example.com".to_string()];
        let mut default_route = create_stream_proxy("default", BackendScheme::Tcp, frontend_port);
        default_route.backend_port = default_port;
        GatewayConfig {
            proxies: vec![named, default_route],
            ..empty_config()
        }
    })
    .await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: tenant-a.example.com\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();

    let leaked = tokio::time::timeout(Duration::from_secs(2), default_backend.accept()).await;
    assert!(
        leaked.is_err(),
        "non-TLS bytes must fail closed without an authorized plaintext fallback"
    );

    manager.shutdown_all().await;
}

/// Reload atomicity: rehoming an SNI route to a different backend and deleting
/// a route must both take effect on the shared listener. The listener key is
/// `__sni_{port}` for the whole group, so a membership or host change has to
/// restart it rather than keep serving the previous route table.
///
/// Production `ProxyState::update_config` publishes the request epoch (the
/// accept-path dial source) and mirrors it into the shared config ArcSwap
/// (reconcile's membership source) before restarting the group. This harness
/// must do the same: swapping only the ArcSwap leaves a rebuilt listener
/// dialing the previous backend from the stale epoch.
#[tokio::test]
async fn opaque_tcp_sni_group_rebuilds_on_reload_and_delete() {
    let first_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_port = first_backend.local_addr().unwrap().port();
    let second_port = second_backend.local_addr().unwrap().port();

    let frontend_port = ephemeral_port().await;
    let build = |backend_port: u16, include_default: bool| {
        let mut named = create_stream_proxy("named", BackendScheme::Tcp, frontend_port);
        named.backend_port = backend_port;
        named.hosts = vec!["tenant-a.example.com".to_string()];
        let mut proxies = vec![named];
        if include_default {
            let mut default_route =
                create_stream_proxy("default", BackendScheme::Tcp, frontend_port);
            default_route.backend_port = backend_port;
            proxies.push(default_route);
        }
        GatewayConfig {
            proxies,
            ..empty_config()
        }
    };

    let initial = build(first_port, true);
    assert!(initial.validate_stream_proxies().is_ok());
    let config_arc = Arc::new(ArcSwap::from_pointee(initial.clone()));
    let runtime = create_manager_runtime(config_arc.clone(), &initial);
    let manager = &runtime.manager;
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial reconcile failed: {failures:?}"
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("SNI group listener should start");

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    client
        .write_all(&tls_client_hello("tenant-a.example.com"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), first_backend.accept())
        .await
        .expect("named route must reach the first backend")
        .unwrap();

    // Reload: rehome the named route AND delete the catch-all. Publish the
    // request epoch first so accept-path dials see the new backend_port, then
    // swap the ArcSwap and reconcile so `__sni_{port}` restarts without the
    // deleted catch-all in its captured candidate list.
    let updated = build(second_port, false);
    assert!(updated.validate_stream_proxies().is_ok());
    runtime
        .request_epoch
        .republish_from_runtime_parts_for_test(
            updated.clone(),
            &runtime.plugin_cache,
            &runtime.consumer_index,
            &runtime.lb_cache,
        )
        .expect("request epoch must republish the reloaded stream route table");
    config_arc.store(Arc::new(updated));
    let failures = manager.reconcile().await;
    assert!(failures.is_empty(), "reload reconcile failed: {failures:?}");
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("rebuilt SNI group listener should start");

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    client
        .write_all(&tls_client_hello("tenant-a.example.com"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), second_backend.accept())
        .await
        .expect("the reloaded route table must dial the new backend")
        .unwrap();

    // The catch-all is gone, so an unclaimed hostname is now unroutable.
    let mut orphan = tokio::net::TcpStream::connect(("127.0.0.1", frontend_port))
        .await
        .unwrap();
    orphan
        .write_all(&tls_client_hello("unclaimed.example.org"))
        .await
        .unwrap();
    let leaked = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = first_backend.accept() => { result.unwrap(); "first" }
            result = second_backend.accept() => { result.unwrap(); "second" }
        }
    })
    .await;
    assert!(
        leaked.is_err(),
        "a deleted catch-all must not keep absorbing traffic: {leaked:?}"
    );

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

/// Issue #2117: a non-fatal stream-listener bind failure must be surfaced as
/// structured state (count + per-resource list) on the admin `/overload`
/// surface, not only warn-logged. Verifies the failure is recorded and that a
/// later clean reconcile clears it (the snapshot reflects the latest reconcile).
#[tokio::test]
async fn test_bind_failure_surfaced_in_overload_snapshot() {
    // Occupy a port so the reconcile below cannot bind it.
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
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    // Before any reconcile the snapshot is empty.
    let before = manager.overload_snapshot();
    assert_eq!(before.bind_failures_total, 0);
    assert!(before.bind_failures.is_empty());

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "expected one bind failure: {:?}",
        failures
    );

    // The failure must now be visible in the structured `/overload` snapshot.
    let snapshot = manager.overload_snapshot();
    assert_eq!(snapshot.bind_failures_total, 1);
    assert_eq!(snapshot.bind_failures.len(), 1);
    assert_eq!(snapshot.bind_failures[0].proxy_id, "tcp-conflict");
    assert_eq!(snapshot.bind_failures[0].listen_port, blocked_port);
    assert!(
        snapshot.bind_failures[0].error.contains("already in use"),
        "bind failure error should mention port in use: {}",
        snapshot.bind_failures[0].error
    );
    assert!(
        matches!(
            snapshot.bind_failures[0].kind,
            StreamListenerDegradation::BindFailed
        ),
        "port-in-use must be classified as BindFailed, got {:?}",
        snapshot.bind_failures[0].kind
    );

    // The direct getter mirrors the overload snapshot.
    let direct = manager.stream_bind_failures();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].proxy_id, "tcp-conflict");

    // Free the port and reconcile with an empty config: the stale failure must
    // clear, proving the snapshot tracks the most recent reconcile.
    drop(blocker);
    config_arc.store(Arc::new(empty_config()));
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "expected no failures after clearing conflict"
    );
    let cleared = manager.overload_snapshot();
    assert_eq!(cleared.bind_failures_total, 0);
    assert!(cleared.bind_failures.is_empty());
}

#[tokio::test]
async fn test_shared_sni_bind_failure_reports_every_proxy() {
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind blocker");
    let blocked_port = blocker.local_addr().unwrap().port();

    let mut first = create_stream_proxy("sni-api", BackendScheme::Tcp, blocked_port);
    first.passthrough = true;
    first.hosts = vec!["api.example.com".to_string()];
    let mut second = create_stream_proxy("sni-db", BackendScheme::Tcp, blocked_port);
    second.passthrough = true;
    second.hosts = vec!["db.example.com".to_string()];
    let config = GatewayConfig {
        proxies: vec![first, second],
        ..empty_config()
    };
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert_eq!(failures.len(), 2, "both shared-SNI proxies are affected");

    let snapshot = manager.overload_snapshot();
    assert_eq!(snapshot.bind_failures_total, 2);
    let mut proxy_ids: Vec<&str> = snapshot
        .bind_failures
        .iter()
        .map(|failure| failure.proxy_id.as_str())
        .collect();
    proxy_ids.sort_unstable();
    assert_eq!(proxy_ids, vec!["sni-api", "sni-db"]);
    assert!(snapshot.bind_failures.iter().all(|failure| {
        failure.listen_port == blocked_port
            && matches!(failure.kind, StreamListenerDegradation::BindFailed)
    }));

    drop(blocker);
}

/// PR #2128 (finding 3): a configured stream listener that is skipped for a
/// config reason — here a `frontend_tls` TCP proxy whose rustls `ServerConfig`
/// has not been loaded, so the listener defers — must be reflected in the
/// `/overload` snapshot with an honest count and a classifying `kind`, even
/// though it is NOT a hard bind failure and is therefore not returned to the
/// startup path. Regression guard: a skip that never pushed to the snapshot
/// used to show `bind_failures_total == 0`.
#[tokio::test]
async fn test_config_skip_surfaced_in_overload_snapshot() {
    let port = ephemeral_port().await;
    let mut proxy = create_stream_proxy("tcp-tls-deferred", BackendScheme::Tcp, port);
    // frontend_tls with no ServerConfig loaded on the manager (created with
    // `None` frontend TLS) forces the deferral skip path.
    proxy.frontend_tls = true;

    let config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    let manager = create_manager(config);

    // A deferred (non-hard) skip must NOT be returned as a startup bind failure —
    // the startup path would otherwise treat a listener merely waiting on TLS
    // material as fatal.
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "deferred config-skip must not be returned to the startup path: {:?}",
        failures
    );

    // ...but it MUST be visible in the /overload snapshot with an honest count.
    let snapshot = manager.overload_snapshot();
    assert_eq!(
        snapshot.bind_failures_total, 1,
        "config-skip must be counted, not hidden as bind_failures_total=0"
    );
    assert_eq!(snapshot.bind_failures.len(), 1);
    assert_eq!(snapshot.bind_failures[0].proxy_id, "tcp-tls-deferred");
    assert_eq!(snapshot.bind_failures[0].listen_port, port);
    assert!(
        matches!(
            snapshot.bind_failures[0].kind,
            StreamListenerDegradation::FrontendTlsDeferred
        ),
        "deferred frontend TLS listener must be classified as FrontendTlsDeferred, got {:?}",
        snapshot.bind_failures[0].kind
    );
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

/// A mixed config update that rotates backend TLS material to invalid content
/// IN PLACE *and* changes backend routing (fields outside listener identity,
/// read live per connection) must NOT take the keep-old-listener path: keeping
/// the old listener would pair its stale cached TLS config with connections
/// that now route to the NEW backend. Expected behavior: normal teardown, the
/// invalid TLS surfaces as a clean bind failure, and the port is left closed
/// (visible failure) until the material is fixed.
#[tokio::test]
async fn test_mixed_routing_change_and_invalid_tls_rotation_tears_down_listener() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let port = ephemeral_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, generate_test_ca_pem("Mixed Update CA")).expect("write initial ca");

    let mut proxy = create_stream_proxy("tcp-tls-mixed", BackendScheme::Tcps, port);
    proxy.backend_tls_verify_server_cert = true;
    proxy.backend_tls_server_ca_cert_path = Some(
        ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    let config = GatewayConfig {
        proxies: vec![proxy.clone()],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial TCP TLS listener should start cleanly: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial TCP TLS listener should bind");

    // Single update: same-path rotation to garbage AND a backend routing
    // change. Listener identity (port/scheme/frontend_tls/passthrough) is
    // unchanged, so without the routing gate this would hit the
    // keep-old-listener path.
    std::fs::write(&ca_path, b"not-a-pem-certificate").expect("rotate ca to garbage");
    let mut updated = proxy;
    updated.backend_port = 19999;
    let updated_config = GatewayConfig {
        proxies: vec![updated],
        ..empty_config()
    };
    config_arc.store(Arc::new(updated_config));

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "invalid TLS in a mixed update must surface a failure: {:?}",
        failures
    );
    assert_eq!(failures[0].0, "tcp-tls-mixed");
    assert!(
        failures[0].2.contains("Backend TLS config failed"),
        "failure should be the TLS validation error: {}",
        failures[0].2
    );
    assert!(
        !failures[0].2.contains("kept previous listener running"),
        "mixed routing+TLS update must not keep the old listener: {}",
        failures[0].2
    );
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "port {} must be closed (clean failure) instead of serving stale TLS against the new backend",
        port
    );

    manager.shutdown_all().await;
}

/// A deliberate TLS *source* change (new CA path, not an in-place content
/// rotation of the same source) whose new material is invalid must fall
/// through to normal teardown — fail loudly with the port closed — rather
/// than silently keep serving material from the previous source.
#[tokio::test]
async fn test_tls_source_change_to_invalid_material_tears_down_listener() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let port = ephemeral_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_a_path = dir.path().join("ca-a.pem");
    std::fs::write(&ca_a_path, generate_test_ca_pem("Source Change CA A")).expect("write ca a");
    let ca_b_path = dir.path().join("ca-b-missing.pem");

    let mut proxy = create_stream_proxy("tcp-tls-source-change", BackendScheme::Tcps, port);
    proxy.backend_tls_verify_server_cert = true;
    proxy.backend_tls_server_ca_cert_path = Some(
        ca_a_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );
    proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
    let config = GatewayConfig {
        proxies: vec![proxy.clone()],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial TCP TLS listener should start cleanly: {:?}",
        failures
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial TCP TLS listener should bind");

    // Operator points the proxy at a DIFFERENT CA source that is unreadable.
    // Routing is unchanged, but the source identity changed, so this is not
    // an in-place rotation and must not take the keep-old path.
    let mut updated = proxy;
    updated.backend_tls_server_ca_cert_path = Some(
        ca_b_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config")
            .to_string(),
    );
    updated.resolved_tls = BackendTlsConfig::from_proxy(&updated);
    let updated_config = GatewayConfig {
        proxies: vec![updated],
        ..empty_config()
    };
    config_arc.store(Arc::new(updated_config));

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        1,
        "invalid new TLS source must surface a failure: {:?}",
        failures
    );
    assert!(
        failures[0].2.contains("Backend TLS config failed")
            && !failures[0].2.contains("kept previous listener running"),
        "source change must tear down, not keep the old listener: {}",
        failures[0].2
    );
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "port {} must be closed after a deliberate source change to invalid material",
        port
    );

    manager.shutdown_all().await;
}

/// The backend TLS reload key must derive from `resolved_tls` — the
/// upstream-projected view (`resolve_upstream_tls()`) — not from the proxy's
/// own `backend_tls_*` fields. An upstream-only TLS change leaves the proxy
/// fields untouched, so a key built from them would never notice the change.
/// Detection is made observable by switching to a garbage CA at a different
/// path: reconcile reports the validation failure (proving the key changed).
/// Because the *source* changed (not an in-place content rotation), the
/// listener is torn down and the port left closed — the keep-old path is
/// reserved for same-source content rotation.
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
    assert!(
        failures[0].2.contains("Backend TLS config failed")
            && !failures[0].2.contains("kept previous listener running"),
        "an upstream TLS source change must tear down rather than keep the old listener: {}",
        failures[0].2
    );
    let probe = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await;
    assert!(
        probe.is_ok(),
        "port {} must be closed after an upstream TLS source change to invalid material",
        port
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
    let mut last_failures = Vec::new();
    let mut started = None;
    for _ in 0..3 {
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
        if failures.is_empty() {
            started = Some((manager, port));
            break;
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    let (manager, port) = started.unwrap_or_else(|| {
        panic!("TCP listener did not start after 3 fresh-port attempts: {last_failures:?}")
    });

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
        Arc::new(TrustedProxies::none()),
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
        Arc::new(TrustedProxies::none()),
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
// Tests: dead listener task self-healing (TOCTOU prebuild/bind failures)
// ============================================================================

/// A listener whose spawned task has exited (TLS prebuild or bind failed
/// after reconcile's validation/probe passed, accept loop errored, etc.)
/// leaves a handle in the manager whose keys still match the desired config.
/// Reconcile must detect the finished task and restart the listener instead
/// of treating the dead handle as healthy forever.
///
/// The task is killed deterministically by firing a global shutdown channel
/// (any exit path looks identical to the manager: the JoinHandle finishes
/// while the handle stays in the map); a fresh, unfired channel is injected
/// before the recovery reconcile so the restarted listener stays up. The same
/// manager-level check covers TCP, UDP, and DTLS listeners — they share the
/// reconcile loop.
#[tokio::test]
async fn test_reconcile_restarts_listener_whose_task_exited() {
    let port = ephemeral_port().await;
    let config = GatewayConfig {
        proxies: vec![create_stream_proxy(
            "tcp-dead-task",
            BackendScheme::Tcp,
            port,
        )],
        ..empty_config()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc, &config);

    let (first_tx, first_rx) = tokio::sync::watch::channel(false);
    manager.set_global_shutdown_rx(first_rx);

    let failures = manager.reconcile().await;
    assert!(failures.is_empty(), "initial bind failed: {:?}", failures);
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("TCP listener should start");

    // Kill the listener task out from under the manager. The handle stays in
    // the map with keys that still match the desired config.
    let _ = first_tx.send(true);
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
    assert!(port_freed, "listener task should have exited");

    // Fresh, unfired global channel so the restarted listener stays alive.
    let (_second_tx, second_rx) = tokio::sync::watch::channel(false);
    manager.set_global_shutdown_rx(second_rx);

    // Reconcile must notice the finished task and restart the listener.
    // Retry: there is a small window between the port being released and the
    // spawned task fully finishing (JoinHandle::is_finished flipping), and a
    // probe here can also race the restarted listener's own bind.
    let mut restarted = false;
    for _ in 0..50 {
        let failures = manager.reconcile().await;
        assert!(
            failures.is_empty(),
            "restart reconcile should not fail: {:?}",
            failures
        );
        if tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .is_err()
        {
            restarted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        restarted,
        "reconcile must restart a listener whose task exited (port {} stayed free)",
        port
    );

    manager.shutdown_all().await;
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

/// `swap_active_dtls_frontend_configs` validates the candidate once and
/// publishes it as the accepted generation even when no DTLS listeners are
/// active yet, so a later-started listener converges on the same material.
#[tokio::test]
async fn swap_active_dtls_frontend_configs_publishes_generation_without_listeners() {
    let manager = create_manager(empty_config());
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let swapped = manager
        .swap_active_dtls_frontend_configs(|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(ephemeral_frontend_dtls_config())
        })
        .await;
    assert_eq!(swapped, 0, "no listeners should mean no live swaps");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "build_config must run exactly once so the accepted generation is published"
    );
    let generation = manager
        .snapshot_frontend_dtls_generation()
        .expect("generation published with zero listeners");
    assert_eq!(generation.generation, 1);
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "accepted");
    assert_eq!(status.generation, 1);
    let overload = manager.overload_snapshot();
    assert_eq!(overload.frontend_dtls_reload.generation, 1);
    assert_eq!(overload.frontend_dtls_reload.last_outcome, "accepted");
}

#[tokio::test]
async fn concurrent_dtls_publishers_cannot_regress_the_accepted_generation() {
    let manager = create_manager(empty_config());
    let first_config = ephemeral_frontend_dtls_config();
    let second_config = ephemeral_frontend_dtls_config();

    let (first, second) = tokio::join!(
        manager.publish_frontend_dtls_generation(first_config),
        manager.publish_frontend_dtls_generation(second_config)
    );
    let mut published = [first.0.generation, second.0.generation];
    published.sort_unstable();
    assert_eq!(published, [1, 2]);
    assert_eq!(
        manager
            .snapshot_frontend_dtls_generation()
            .expect("accepted generation")
            .generation,
        2
    );
}

#[tokio::test]
async fn collected_dtls_server_cannot_publish_an_older_generation_after_rotation() {
    let manager = Arc::new(create_manager(empty_config()));
    manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config())
        .await;

    // Hold the shared fence, queue generation 2 first, then queue the collector
    // observation. Tokio's mutex is FIFO, so after release the publisher must
    // complete before the collector can apply and expose its server. A collector
    // that loaded the generation outside this fence would observe 1 here and
    // could restore it after the generation-2 publisher missed its empty slot.
    let publish_lock = manager.frontend_dtls_publish_lock_for_test();
    let guard = publish_lock.lock().await;

    let (publisher_started_tx, publisher_started_rx) = tokio::sync::oneshot::channel();
    let publisher_manager = Arc::clone(&manager);
    let publisher = tokio::spawn(async move {
        let _ = publisher_started_tx.send(());
        publisher_manager
            .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config())
            .await
            .0
            .generation
    });
    publisher_started_rx.await.expect("publisher started");

    let (collector_started_tx, collector_started_rx) = tokio::sync::oneshot::channel();
    let collector_manager = Arc::clone(&manager);
    let collector = tokio::spawn(async move {
        let _ = collector_started_tx.send(());
        collector_manager
            .collected_frontend_dtls_generation_for_test()
            .await
    });
    collector_started_rx.await.expect("collector started");
    drop(guard);

    assert_eq!(publisher.await.expect("publisher task"), 2);
    assert_eq!(
        collector.await.expect("collector task"),
        Some(2),
        "collector must apply the generation that won the shared publication fence"
    );
}

#[tokio::test]
async fn rejected_dtls_candidate_retains_previous_generation() {
    let manager = create_manager(empty_config());
    let (_gen, swapped) = manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config())
        .await;
    assert_eq!(swapped, 0);
    let before = manager
        .snapshot_frontend_dtls_generation()
        .expect("initial generation");

    let swapped = manager
        .swap_active_dtls_frontend_configs(|| Err(anyhow::anyhow!("simulated bad candidate")))
        .await;
    assert_eq!(swapped, 0);
    let after = manager
        .snapshot_frontend_dtls_generation()
        .expect("previous generation retained");
    assert_eq!(before.generation, after.generation);
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "rejected");
    assert_eq!(status.generation, before.generation);
    assert!(status.last_failure_unix.is_some());
}

fn ephemeral_frontend_dtls_config() -> ferrum_edge::dtls::FrontendDtlsConfig {
    let certificate = ferrum_edge::dtls::generate_ephemeral_cert_public().expect("ephemeral cert");
    let config = dimpl::Config::builder().build().expect("dtls config");
    ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: std::sync::Arc::new(config),
        certificate,
        client_cert_verifier: None,
    }
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

fn config_with_sidecar_bind(proxy: Proxy, port: u16, bind: IpAddr) -> GatewayConfig {
    let mut mesh = MeshConfig::default();
    mesh.sidecar_ingress_bind_overrides.insert(port, bind);
    GatewayConfig {
        proxies: vec![proxy],
        mesh: Some(Box::new(mesh)),
        ..empty_config()
    }
}

/// A dedicated Sidecar ingress bind-address change must register as listener
/// drift and rebind — port/scheme alone are not enough restart identity.
#[tokio::test]
async fn test_reconcile_restarts_on_dedicated_bind_address_change() {
    let port = ephemeral_port().await;
    let first: IpAddr = "127.0.0.1".parse().expect("ip");
    let second: IpAddr = "127.0.0.2".parse().expect("ip");
    let proxy = create_stream_proxy("tcp-bind-rebind", BackendScheme::Tcp, port);
    let config = config_with_sidecar_bind(proxy.clone(), port, first);
    let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &config);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "initial dedicated-bind listener should start: {failures:?}"
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("initial dedicated-bind listener should bind");
    assert_eq!(
        manager.active_binds().await,
        vec![(
            format!(
                "{}|tcp-bind-rebind",
                ferrum_edge::config::types::default_namespace()
            ),
            first
        )]
    );

    // Prove the old address is reachable before the rebind.
    tokio::net::TcpStream::connect((first, port))
        .await
        .expect("pre-rebind connect to first bind must succeed");

    config_arc.store(Arc::new(config_with_sidecar_bind(proxy, port, second)));
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "bind-address restart should wait for the old socket before probing: {failures:?}"
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("rebound dedicated-bind listener should bind");
    assert_eq!(
        manager.active_binds().await,
        vec![(
            format!(
                "{}|tcp-bind-rebind",
                ferrum_edge::config::types::default_namespace()
            ),
            second
        )],
        "bind-address drift must rebind the live stream listener"
    );

    // Old ownership must be gone; new ownership must accept.
    assert!(
        tokio::net::TcpStream::connect((first, port)).await.is_err(),
        "old dedicated bind must not keep accepting after rebind"
    );
    tokio::net::TcpStream::connect((second, port))
        .await
        .expect("new dedicated bind must accept after rebind");

    manager.shutdown_all().await;
}

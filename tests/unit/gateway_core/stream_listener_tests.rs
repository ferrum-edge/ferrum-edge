//! Tests for the StreamListenerManager (TCP/UDP stream proxy lifecycle).
//!
//! Covers: reconciliation (start/stop/restart listeners), port conflict detection,
//! TLS/DTLS deferral, shutdown, and wait_until_started behavior.

use arc_swap::ArcSwap;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::fips::approved::HmacSha256Key;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::datagram_client_address::{
    DatagramEnvelopeAuth, DatagramEnvelopeForm, DatagramFreshness, DatagramListenerBinding,
    DatagramListenerProtocol, encode_datagram_with_metadata, unix_now_millis,
};
use ferrum_edge::proxy::node_waypoint_udp_destination::NodeWaypointUdpDestinationRoute;
use ferrum_edge::proxy::node_waypoint_udp_steering::{
    NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering,
};
use ferrum_edge::proxy::stream_listener::{
    NodeWaypointUdpSteerHold, StreamListenerDegradation, StreamListenerManager,
};
use ferrum_edge::proxy::stream_match::{StreamMatchArm, StreamMatchCriteria};
use ferrum_edge::request_epoch::RequestEpochStore;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const STREAM_LISTENER_SOURCE: &str = include_str!("../../../src/proxy/stream_listener.rs");

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

#[test]
fn stream_listener_material_preparation_precedes_lock_without_await_in_critical_section() {
    let reconcile = STREAM_LISTENER_SOURCE
        .split_once("pub async fn reconcile(&self)")
        .map(|(_, reconcile)| reconcile)
        .expect("reconcile implementation");
    let preparation = reconcile
        .find("let backend_tls_reload_key = if prepares_backend_tls")
        .expect("reconciliation prepares backend TLS material");
    let lock_text = "let listeners = self.listeners.lock().await;";
    let lock = reconcile
        .find(lock_text)
        .expect("reconciliation listener-map lock");
    assert!(
        preparation < lock,
        "TLS preparation must precede the listener-map lock"
    );

    let after_lock = &reconcile[lock + lock_text.len()..];
    let drop = after_lock
        .find("drop(listeners);")
        .expect("listener-map guard is explicitly dropped");
    assert!(
        !after_lock[..drop].contains(".await"),
        "the listener-map MutexGuard must never cross an await"
    );
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

/// Allocate an ephemeral TCP port by binding and immediately dropping.
async fn ephemeral_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Allocate an ephemeral UDP port by binding and immediately dropping.
///
/// TCP and UDP port spaces are independent: a number free in TCP may already
/// be bound in UDP. UDP fixtures must reserve from UDP space.
async fn ephemeral_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral UDP port");
    socket.local_addr().unwrap().port()
}

#[derive(Clone, Copy)]
enum FreshPortFamily {
    Tcp,
    Udp,
}

/// Start a stream-listener fixture on a fresh port, retrying only the
/// demonstrated bind-and-release race from `ephemeral_port()` /
/// `ephemeral_udp_port()`.
///
/// The production manager owns its listener bind, so the test cannot hand it a
/// reservation. Another parallel test can therefore claim the released port
/// between allocation and `reconcile()`. A failed attempt is retryable only
/// when every reported failure is the expected `Port ... is already in use`
/// error for that exact port; configuration, TLS, and lifecycle failures remain
/// immediate test failures. Each attempt uses a new kernel-assigned port.
///
/// `make_runtime` builds the manager (plain, request-epoch, or datagram-secret
/// fixtures). When `shutdown_rx` is `Some`, it is installed before `reconcile`
/// so the spawned accept loop observes the global SIGTERM channel.
async fn start_runtime_on_fresh_port<F, M>(
    family: FreshPortFamily,
    mut build_config: F,
    mut make_runtime: M,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> (StreamManagerRuntime, Arc<ArcSwap<GatewayConfig>>, u16)
where
    F: FnMut(u16) -> GatewayConfig,
    M: FnMut(Arc<ArcSwap<GatewayConfig>>, &GatewayConfig) -> StreamManagerRuntime,
{
    const MAX_BIND_ATTEMPTS: usize = 8;

    let mut bind_races = Vec::new();
    for attempt in 1..=MAX_BIND_ATTEMPTS {
        let port = match family {
            FreshPortFamily::Tcp => ephemeral_port().await,
            FreshPortFamily::Udp => ephemeral_udp_port().await,
        };
        let config = build_config(port);
        assert!(config.validate_stream_proxies().is_ok());

        let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
        let runtime = make_runtime(config_arc.clone(), &config);
        if let Some(rx) = &shutdown_rx {
            runtime.manager.set_global_shutdown_rx(rx.clone());
        }
        let failures = runtime.manager.reconcile().await;
        if failures.is_empty() {
            let started = runtime
                .manager
                .wait_until_started(Duration::from_secs(5))
                .await;
            if started.is_ok() {
                return (runtime, config_arc, port);
            }

            // Reconcile first probes the port, then the listener task performs
            // the owning bind. A competing test can win that second, even
            // narrower interval. Retry only when the manager's structured
            // snapshot proves that exact EADDRINUSE class; a generic startup
            // timeout or any other degradation remains a hard assertion.
            let async_failures = runtime.manager.stream_bind_failures();
            let only_async_port_collision = !async_failures.is_empty()
                && async_failures.iter().all(|failure| {
                    failure.listen_port == port
                        && matches!(failure.kind, StreamListenerDegradation::BindFailed)
                        && failure.error.contains("already in use")
                });
            runtime.manager.shutdown_all().await;
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
        runtime.manager.shutdown_all().await;
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

async fn start_manager_with_config_arc_on_fresh_port<F>(
    family: FreshPortFamily,
    build_config: F,
) -> (StreamListenerManager, Arc<ArcSwap<GatewayConfig>>, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    let (runtime, config_arc, port) =
        start_runtime_on_fresh_port(family, build_config, create_manager_runtime, None).await;
    (runtime.manager, config_arc, port)
}

/// Start a TCP stream-listener fixture on a fresh port, retrying only the
/// demonstrated bind-and-release race from `ephemeral_port()`.
async fn start_manager_on_fresh_tcp_port<F>(build_config: F) -> (StreamListenerManager, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    let (manager, _config_arc, port) =
        start_manager_with_config_arc_on_fresh_port(FreshPortFamily::Tcp, build_config).await;
    (manager, port)
}

/// Like [`start_manager_on_fresh_tcp_port`], but keeps the config `ArcSwap` so
/// tests that reload listener identity can store a replacement `GatewayConfig`.
async fn start_manager_with_config_arc_on_fresh_tcp_port<F>(
    build_config: F,
) -> (StreamListenerManager, Arc<ArcSwap<GatewayConfig>>, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    start_manager_with_config_arc_on_fresh_port(FreshPortFamily::Tcp, build_config).await
}

/// UDP analogue of [`start_manager_on_fresh_tcp_port`]. Allocates from UDP
/// space so a free TCP number that is already bound in UDP cannot steal the
/// first attempt (see `test_reconcile_defers_udp_without_dtls_config`).
async fn start_manager_on_fresh_udp_port<F>(build_config: F) -> (StreamListenerManager, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    let (manager, _config_arc, port) =
        start_manager_with_config_arc_on_fresh_port(FreshPortFamily::Udp, build_config).await;
    (manager, port)
}

/// Like [`start_manager_with_config_arc_on_fresh_tcp_port`], but keeps the
/// [`StreamManagerRuntime`] so reload tests can republish the request epoch
/// together with the config ArcSwap.
async fn start_manager_runtime_on_fresh_tcp_port<F>(
    build_config: F,
) -> (StreamManagerRuntime, Arc<ArcSwap<GatewayConfig>>, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    start_runtime_on_fresh_port(
        FreshPortFamily::Tcp,
        build_config,
        create_manager_runtime,
        None,
    )
    .await
}

/// UDP start helper that installs the datagram client-address secret before
/// reconcile. `start_manager_on_fresh_udp_port` cannot serve these tests: it
/// drops the runtime (needed to republish the request epoch on reload) and
/// never calls `set_datagram_client_address_secret`.
async fn start_datagram_reload_manager_on_fresh_udp_port<F>(
    build_config: F,
) -> (StreamManagerRuntime, Arc<ArcSwap<GatewayConfig>>, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    start_runtime_on_fresh_port(
        FreshPortFamily::Udp,
        build_config,
        create_datagram_reload_manager_runtime,
        None,
    )
    .await
}

/// TCP start helper that wires `set_global_shutdown_rx` before reconcile so
/// the spawned accept loop observes the channel. A post-start install would
/// miss the already-spawned listener.
async fn start_manager_with_shutdown_rx_on_fresh_tcp_port<F>(
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    build_config: F,
) -> (StreamListenerManager, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    let (runtime, _config_arc, port) = start_runtime_on_fresh_port(
        FreshPortFamily::Tcp,
        build_config,
        create_manager_runtime,
        Some(shutdown_rx),
    )
    .await;
    (runtime.manager, port)
}

/// UDP analogue of [`start_manager_with_shutdown_rx_on_fresh_tcp_port`].
async fn start_manager_with_shutdown_rx_on_fresh_udp_port<F>(
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    build_config: F,
) -> (StreamListenerManager, u16)
where
    F: FnMut(u16) -> GatewayConfig,
{
    let (runtime, _config_arc, port) = start_runtime_on_fresh_port(
        FreshPortFamily::Udp,
        build_config,
        create_manager_runtime,
        Some(shutdown_rx),
    )
    .await;
    (runtime.manager, port)
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

const DATAGRAM_RELOAD_SECRET: &str = "0123456789abcdef0123456789abcdef";
const UDP_RECV_WINDOW: Duration = Duration::from_millis(500);
const UDP_DROP_WINDOW: Duration = Duration::from_millis(250);
const UDP_PORT_FREE_TIMEOUT: Duration = Duration::from_secs(3);

fn datagram_hmac_key() -> HmacSha256Key {
    HmacSha256Key::new_from_slice(DATAGRAM_RELOAD_SECRET.as_bytes()).expect("hmac key")
}

/// The domain identity `StreamListenerManager` builds for a plain-UDP listener
/// bound on loopback: receive-boundary protocol, canonical bind address, port.
/// A reload must reconstruct exactly this, or nothing the balancer mints would
/// verify (issue #3856).
fn datagram_binding(port: u16) -> DatagramListenerBinding {
    DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        "127.0.0.1".parse().expect("loopback bind addr"),
        port,
    )
}

/// Mint one authenticated envelope for `binding`, declaring `destination` and
/// carrying the freshness record the gate requires (issue #3862).
fn datagram_envelope(
    binding: &DatagramListenerBinding,
    destination: SocketAddr,
    payload: &[u8],
    sequence: u64,
) -> Vec<u8> {
    let key = datagram_hmac_key();
    let freshness = DatagramFreshness {
        sender_id: 1,
        epoch: 1,
        sequence,
        timestamp_ms: unix_now_millis(),
    };
    let auth = DatagramEnvelopeAuth {
        key: &key,
        binding,
        freshness,
    };
    let form = DatagramEnvelopeForm::Forwarded {
        source: "203.0.113.9:41234".parse().expect("forwarded client"),
        destination,
    };
    encode_datagram_with_metadata(form, payload, Some(&auth))
}

fn udp_proxy_for_datagram_reload(
    listen_port: u16,
    backend_port: u16,
    stream_proxy_protocol: Option<bool>,
) -> Proxy {
    let mut proxy = create_stream_proxy("udp-dgram-reload", BackendScheme::Udp, listen_port);
    proxy.backend_port = backend_port;
    proxy.stream_proxy_protocol = stream_proxy_protocol;
    proxy
}

async fn spawn_udp_echo_backend(socket: Arc<tokio::net::UdpSocket>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    });
}

async fn spawn_udp_fixed_response_backend(
    socket: Arc<tokio::net::UdpSocket>,
    response: &'static [u8],
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((_, peer)) => {
                    let _ = socket.send_to(response, peer).await;
                }
                Err(_) => return,
            }
        }
    });
}

async fn recv_udp_within(socket: &tokio::net::UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(window, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn udp_roundtrip(
    socket: &tokio::net::UdpSocket,
    target: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    socket.send_to(payload, target).await.ok()?;
    recv_udp_within(socket, UDP_RECV_WINDOW).await
}

fn create_datagram_reload_manager_runtime(
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
    let trusted_proxies =
        Arc::new(TrustedProxies::parse_strict("127.0.0.1", "test").expect("trust list"));

    let manager = StreamListenerManager::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        config_arc,
        dns_cache,
        request_epoch.clone(),
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
        trusted_proxies,
    );
    manager.set_datagram_client_address_secret(Some(DATAGRAM_RELOAD_SECRET.to_string()));

    StreamManagerRuntime {
        manager,
        request_epoch,
        plugin_cache,
        consumer_index,
        lb_cache,
    }
}

async fn publish_stream_config(
    runtime: &StreamManagerRuntime,
    config_arc: &Arc<ArcSwap<GatewayConfig>>,
    config: GatewayConfig,
) {
    assert!(config.validate_stream_proxies().is_ok());
    runtime
        .request_epoch
        .republish_from_runtime_parts_for_test(
            config.clone(),
            &runtime.plugin_cache,
            &runtime.consumer_index,
            &runtime.lb_cache,
        )
        .expect("request epoch must republish the reloaded stream route table");
    config_arc.store(Arc::new(config));
    let failures = runtime.manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "stream listener reconcile failed: {failures:?}"
    );
    runtime
        .manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("stream listener should start after reconcile");
}

async fn wait_until_udp_port_free(port: u16) -> bool {
    tokio::time::timeout(UDP_PORT_FREE_TIMEOUT, async {
        loop {
            match tokio::net::UdpSocket::bind(format!("127.0.0.1:{port}")).await {
                Ok(_) => return true,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Wait on an exact shared listener key when a test also needs to inspect the
/// retained generation rather than only exercise the production readiness
/// gate.
async fn wait_until_shared_nw_udp_listener_started(
    manager: &StreamListenerManager,
    key: &str,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
        if owners.iter().any(|(listener_key, _, started)| {
            listener_key == key && started.load(Ordering::Acquire)
        }) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
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
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| GatewayConfig {
        proxies: vec![create_stream_proxy("tcp1", BackendScheme::Tcp, port)],
        ..empty_config()
    })
    .await;

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
    let (manager, _port) = start_manager_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tcp-sni", BackendScheme::Tcp, port);
        proxy.passthrough = true;
        proxy.hosts = vec!["secure.example.com".to_string()];
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;
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

    let build = |frontend_port: u16, backend_port: u16, include_default: bool| {
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

    let (runtime, config_arc, frontend_port) =
        start_manager_runtime_on_fresh_tcp_port(|frontend_port| {
            build(frontend_port, first_port, true)
        })
        .await;
    let manager = &runtime.manager;

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
    let updated = build(frontend_port, second_port, false);
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
    let (manager, port) = start_manager_on_fresh_udp_port(|port| GatewayConfig {
        proxies: vec![create_stream_proxy("udp1", BackendScheme::Udp, port)],
        ..empty_config()
    })
    .await;

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
    // Does not bind: `frontend_tls` with no ServerConfig takes the
    // FrontendTlsDeferred `continue` in `reconcile` before the port probe, so
    // a stolen ephemeral number cannot produce the EADDRINUSE class that
    // flaked #4217. Retrying would not be meaningful and is not used.
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
    let (manager, config_arc, port) =
        start_manager_with_config_arc_on_fresh_tcp_port(|port| GatewayConfig {
            proxies: vec![create_stream_proxy("tcp-restart", BackendScheme::Tcp, port)],
            ..empty_config()
        })
        .await;

    let mut restarted_proxy = create_stream_proxy("tcp-restart", BackendScheme::Tcp, port);
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
    // Backend TLS validation fails and `continue`s before the bind probe, so
    // reconcile cannot return the EADDRINUSE class. The occupancy probe below
    // cannot be retried: a dead listener occupying the port (the regression)
    // is indistinguishable from a competitor bind.
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
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, generate_test_ca_pem("Rotation CA A")).expect("write initial ca");
    let ca_path_str = ca_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();

    let (manager, port) = start_manager_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tcp-tls-rotate", BackendScheme::Tcps, port);
        proxy.backend_tls_verify_server_cert = true;
        proxy.backend_tls_server_ca_cert_path = Some(ca_path_str.clone());
        proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;

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
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, generate_test_ca_pem("Mixed Update CA")).expect("write initial ca");
    let ca_path_str = ca_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();

    let (manager, config_arc, port) = start_manager_with_config_arc_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tcp-tls-mixed", BackendScheme::Tcps, port);
        proxy.backend_tls_verify_server_cert = true;
        proxy.backend_tls_server_ca_cert_path = Some(ca_path_str.clone());
        proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;

    // Single update: same-path rotation to garbage AND a backend routing
    // change. Listener identity (port/scheme/frontend_tls/passthrough) is
    // unchanged, so without the routing gate this would hit the
    // keep-old-listener path.
    std::fs::write(&ca_path, b"not-a-pem-certificate").expect("rotate ca to garbage");
    let mut updated = create_stream_proxy("tcp-tls-mixed", BackendScheme::Tcps, port);
    updated.backend_tls_verify_server_cert = true;
    updated.backend_tls_server_ca_cert_path = Some(ca_path_str);
    updated.resolved_tls = BackendTlsConfig::from_proxy(&updated);
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
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_a_path = dir.path().join("ca-a.pem");
    std::fs::write(&ca_a_path, generate_test_ca_pem("Source Change CA A")).expect("write ca a");
    let ca_a_path_str = ca_a_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();
    let ca_b_path = dir.path().join("ca-b-missing.pem");
    let ca_b_path_str = ca_b_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();

    let (manager, config_arc, port) = start_manager_with_config_arc_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tcp-tls-source-change", BackendScheme::Tcps, port);
        proxy.backend_tls_verify_server_cert = true;
        proxy.backend_tls_server_ca_cert_path = Some(ca_a_path_str.clone());
        proxy.resolved_tls = BackendTlsConfig::from_proxy(&proxy);
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;

    // Operator points the proxy at a DIFFERENT CA source that is unreadable.
    // Routing is unchanged, but the source identity changed, so this is not
    // an in-place rotation and must not take the keep-old path.
    let mut updated = create_stream_proxy("tcp-tls-source-change", BackendScheme::Tcps, port);
    updated.backend_tls_verify_server_cert = true;
    updated.backend_tls_server_ca_cert_path = Some(ca_b_path_str);
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
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_a_path = dir.path().join("upstream-ca-a.pem");
    let ca_b_path = dir.path().join("upstream-ca-b.pem");
    std::fs::write(&ca_a_path, generate_test_ca_pem("Upstream CA A")).expect("write ca a");
    std::fs::write(&ca_b_path, b"garbage-rotated-by-upstream").expect("write ca b");
    let ca_a_path_str = ca_a_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();
    let ca_b_path_str = ca_b_path
        .to_str()
        .expect("test temp path must be utf-8 for proxy config")
        .to_string();

    // Proxy's own backend_tls_* fields stay empty; TLS arrives via
    // resolved_tls, exactly as resolve_upstream_tls() projects from a
    // referenced upstream.
    let (manager, config_arc, port) = start_manager_with_config_arc_on_fresh_tcp_port(|port| {
        let mut proxy = create_stream_proxy("tcp-tls-upstream", BackendScheme::Tcps, port);
        proxy.resolved_tls = BackendTlsConfig {
            server_ca_cert_path: Some(ca_a_path_str.clone()),
            verify_server_cert: true,
            ..BackendTlsConfig::default_verify()
        };
        GatewayConfig {
            proxies: vec![proxy],
            ..empty_config()
        }
    })
    .await;

    // Upstream-only TLS change: identical proxy fields, new resolved_tls.
    let mut rotated_proxy = create_stream_proxy("tcp-tls-upstream", BackendScheme::Tcps, port);
    rotated_proxy.resolved_tls = BackendTlsConfig {
        server_ca_cert_path: Some(ca_b_path_str),
        verify_server_cert: true,
        ..BackendTlsConfig::default_verify()
    };
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
    // Does not bind: `frontend_tls` with no ServerConfig takes the
    // FrontendTlsDeferred `continue` in `reconcile` before the port probe.
    // The occupancy probe below cannot be retried: a listener that wrongly
    // bound (the regression) is indistinguishable from a competitor bind.
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
    let (manager, port) = start_manager_on_fresh_tcp_port(|port| GatewayConfig {
        proxies: vec![create_stream_proxy(
            "tcp-shutdown",
            BackendScheme::Tcp,
            port,
        )],
        ..empty_config()
    })
    .await;

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
    let (manager, _port) = start_manager_on_fresh_tcp_port(|port| GatewayConfig {
        proxies: vec![create_stream_proxy("tcp-wait", BackendScheme::Tcp, port)],
        ..empty_config()
    })
    .await;

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
    let (global_tx, global_rx) = tokio::sync::watch::channel(false);
    let (manager, port) =
        start_manager_with_shutdown_rx_on_fresh_tcp_port(global_rx, |port| GatewayConfig {
            proxies: vec![create_stream_proxy("tcp-sigterm", BackendScheme::Tcp, port)],
            ..empty_config()
        })
        .await;

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
    // Held so Drop cannot stop the accept loop before the global channel is observed.
    drop(manager);
}

/// Same as [`test_global_shutdown_stops_tcp_accept_loop`] but for UDP
/// listeners. UDP uses a separate accept-loop body in
/// `udp_proxy::start_udp_listener`, so it needs an independent regression
/// test to make sure the `tokio::select!` arm watching the global channel
/// fires correctly.
#[tokio::test]
async fn test_global_shutdown_stops_udp_recv_loop() {
    let (global_tx, global_rx) = tokio::sync::watch::channel(false);
    let (manager, port) =
        start_manager_with_shutdown_rx_on_fresh_udp_port(global_rx, |port| GatewayConfig {
            proxies: vec![create_stream_proxy("udp-sigterm", BackendScheme::Udp, port)],
            ..empty_config()
        })
        .await;

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
    // Held so Drop cannot stop the recv loop before the global channel is observed.
    drop(manager);
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
    let (first_tx, first_rx) = tokio::sync::watch::channel(false);
    let (manager, port) =
        start_manager_with_shutdown_rx_on_fresh_tcp_port(first_rx, |port| GatewayConfig {
            proxies: vec![create_stream_proxy(
                "tcp-dead-task",
                BackendScheme::Tcp,
                port,
            )],
            ..empty_config()
        })
        .await;

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

/// The ordinary `FERRUM_DTLS_*` publish records an accepted generation even
/// when no DTLS listeners are active yet, so a later-started listener converges
/// on the same material.
#[tokio::test]
async fn frontend_dtls_publish_records_generation_without_listeners() {
    let manager = create_manager(empty_config());
    let (_generation, swapped) = manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
        .await;
    assert_eq!(swapped, 0, "no listeners should mean no live swaps");
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

/// Mesh PeerAuthentication live reload still swaps the shared TCP+TLS slot, but
/// that path must not seed the ordinary `FERRUM_DTLS_*` generation when no DTLS
/// listener exists.
#[tokio::test]
async fn mesh_tcp_tls_swap_does_not_seed_ordinary_dtls_generation_without_listeners() {
    let manager = create_manager(empty_config());
    let _ = rustls::crypto::ring::default_provider().install_default();
    manager.swap_frontend_tls_config(Some(dummy_server_config()));

    assert!(
        manager.snapshot_frontend_dtls_generation().is_none(),
        "mesh TCP+TLS swap must not seed the ordinary DTLS generation"
    );
    assert!(
        manager
            .active_dtls_frontend_identities_for_test()
            .await
            .is_empty(),
        "no DTLS listener should be present"
    );
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "none");
    assert_eq!(status.generation, 0);
}

/// An ordinary UDP+DTLS listener keeps its dedicated generation and client-CA
/// policy when mesh PeerAuthentication reloads the TCP+TLS slot.
#[tokio::test]
async fn ordinary_dtls_listener_keeps_dedicated_policy_across_mesh_tcp_tls_swap() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_pem_pair(dir.path(), "dtls-dedicated");
    let (ca_path, _) = write_ecdsa_pem_pair(dir.path(), "dtls-client-ca");

    let holder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp holder");
    let port = holder.local_addr().unwrap().port();
    drop(holder);

    let mut proxy = create_stream_proxy("udp-dtls-ordinary", BackendScheme::Udp, port);
    proxy.frontend_tls = true;
    let manager = create_manager(GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    });
    manager
        .set_frontend_dtls_cert_key(cert_path, key_path, Some(ca_path), false)
        .await;
    manager
        .wait_until_started(Duration::from_secs(2))
        .await
        .expect("ordinary DTLS listener should start");

    let before_gen = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation published");
    let before_ids = wait_for_active_dtls_identities(&manager).await;
    assert_eq!(before_ids.len(), 1);
    assert!(
        before_ids[0].1,
        "dedicated DTLS listener must require a client certificate"
    );

    manager.swap_frontend_tls_config(Some(dummy_server_config()));

    let after_gen = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation retained");
    assert_eq!(after_gen.generation, before_gen.generation);
    assert!(
        Arc::ptr_eq(&after_gen, &before_gen),
        "mesh TCP+TLS swap must not replace the ordinary DTLS generation slot"
    );
    let after_ids = manager.active_dtls_frontend_identities_for_test().await;
    assert_eq!(
        after_ids, before_ids,
        "active ordinary DTLS server must retain exact dedicated config/security policy"
    );
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "accepted");
    assert_eq!(status.generation, before_gen.generation);

    manager.shutdown_all().await;
}

/// Failed ordinary DTLS candidate evaluation keeps last-known-good generation
/// status even when a mesh TCP+TLS swap also runs.
#[tokio::test]
async fn ordinary_dtls_build_failure_keeps_last_good_across_mesh_tcp_tls_swap() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let manager = create_manager(empty_config());
    let (_gen, _) = manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
        .await;
    let before = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation published");

    manager.record_frontend_dtls_candidate_failure();
    manager.swap_frontend_tls_config(Some(dummy_server_config()));

    let after = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation retained");
    assert_eq!(after.generation, before.generation);
    assert!(Arc::ptr_eq(&after, &before));
    let status = manager.frontend_dtls_reload_status();
    assert_eq!(status.last_outcome, "rejected");
    assert_eq!(status.generation, before.generation);
    assert!(status.last_failure_unix.is_some());
}

/// Issue #3858 composition contract: the two DTLS ownership classes have
/// SEPARATE generation slots and separate publish entry points. An owner-scoped
/// mesh publication must never seed, advance, or overwrite the ordinary
/// operator `FERRUM_DTLS_*` generation, and the reverse must hold too. There is
/// no process-wide DTLS fanout for either owner to reach the other through.
#[tokio::test]
async fn mesh_node_waypoint_dtls_publish_never_touches_the_ordinary_generation() {
    let manager = create_manager(empty_config());
    let (_generation, _swapped) = manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
        .await;
    let ordinary_before = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation published");

    let mut configs = std::collections::BTreeMap::new();
    configs.insert(
        "ferrum|__mesh-nw-udp-team-a-dns-a-5353".to_string(),
        ephemeral_frontend_dtls_config(),
    );
    let (mesh_generation, swapped) = manager
        .publish_mesh_node_waypoint_dtls_generation(configs)
        .await;
    assert_eq!(mesh_generation, 1);
    assert_eq!(swapped, 0, "no generated listener is bound in this test");

    let ordinary_after = manager
        .snapshot_frontend_dtls_generation()
        .expect("ordinary generation retained");
    assert!(
        std::sync::Arc::ptr_eq(&ordinary_before, &ordinary_after),
        "an owner-scoped mesh publish must not replace the ordinary DTLS generation"
    );
    assert_eq!(
        manager.frontend_dtls_reload_status().generation,
        ordinary_before.generation,
        "the ordinary reload status must not move on a mesh publish"
    );
    let mesh_status = manager.mesh_node_waypoint_dtls_reload_status();
    assert_eq!(mesh_status.last_outcome, "accepted");
    assert_eq!(mesh_status.generation, 1);

    // ... and the reverse direction: an ordinary rotation leaves the accepted
    // owner-scoped generation exactly where it was.
    let mesh_before = manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("mesh generation published");
    let (_generation, _swapped) = manager
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
        .await;
    let mesh_after = manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("mesh generation retained");
    assert!(
        std::sync::Arc::ptr_eq(&mesh_before, &mesh_after),
        "an ordinary DTLS rotation must not replace the owner-scoped mesh generation"
    );
}

/// A generated listener is covered ONLY by its own exact key. A generation that
/// does not name it leaves it uncovered — it never borrows another owner's (or
/// another route's) material.
#[tokio::test]
async fn mesh_node_waypoint_dtls_generation_covers_only_its_named_listeners() {
    let manager = create_manager(empty_config());
    let mut configs = std::collections::BTreeMap::new();
    configs.insert(
        "ferrum|__mesh-nw-udp-team-a-dns-a-5353".to_string(),
        ephemeral_frontend_dtls_config(),
    );
    manager
        .publish_mesh_node_waypoint_dtls_generation(configs)
        .await;
    let generation = manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("mesh generation published");
    assert_eq!(
        generation.covered_listener_keys(),
        vec!["ferrum|__mesh-nw-udp-team-a-dns-a-5353".to_string()]
    );

    // Withdraw: an EMPTY accepted generation is a positive statement, so a
    // re-added listener cannot resurrect the previous owner-scoped config.
    manager
        .publish_mesh_node_waypoint_dtls_generation(std::collections::BTreeMap::new())
        .await;
    let withdrawn = manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("empty generation is still an accepted generation");
    assert!(withdrawn.covered_listener_keys().is_empty());
    assert_eq!(withdrawn.generation(), 2);
}

#[tokio::test]
async fn concurrent_dtls_publishers_cannot_regress_the_accepted_generation() {
    let manager = create_manager(empty_config());
    let first_config = ephemeral_frontend_dtls_config();
    let second_config = ephemeral_frontend_dtls_config();

    let (first, second) = tokio::join!(
        manager.publish_frontend_dtls_generation(first_config, false),
        manager.publish_frontend_dtls_generation(second_config, false)
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
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
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
            .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
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
        .publish_frontend_dtls_generation(ephemeral_frontend_dtls_config(), false)
        .await;
    assert_eq!(swapped, 0);
    let before = manager
        .snapshot_frontend_dtls_generation()
        .expect("initial generation");

    manager.record_frontend_dtls_candidate_failure();
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
        client_trust: None,
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

fn dummy_server_config() -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .expect("server-side protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoopCertResolver)),
    )
}

fn write_ecdsa_pem_pair(dir: &std::path::Path, name: &str) -> (String, String) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![format!("{name}.example")]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (
        cert_path.to_str().expect("utf8").to_string(),
        key_path.to_str().expect("utf8").to_string(),
    )
}

async fn wait_for_active_dtls_identities(manager: &StreamListenerManager) -> Vec<(usize, bool)> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ids = manager.active_dtls_frontend_identities_for_test().await;
            if !ids.is_empty() {
                return ids;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DTLS server should publish into the listener slot")
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
    let first: IpAddr = "127.0.0.1".parse().expect("ip");
    let second: IpAddr = "127.0.0.2".parse().expect("ip");
    let (manager, config_arc, port) = start_manager_with_config_arc_on_fresh_tcp_port(|port| {
        let proxy = create_stream_proxy("tcp-bind-rebind", BackendScheme::Tcp, port);
        config_with_sidecar_bind(proxy, port, first)
    })
    .await;
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

    config_arc.store(Arc::new(config_with_sidecar_bind(
        create_stream_proxy("tcp-bind-rebind", BackendScheme::Tcp, port),
        port,
        second,
    )));
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

// ============================================================================
// Tests: NodeWaypoint UDP Service-path steering ownership (issue #3286)
// ============================================================================

struct NoopSteerBackend;

impl NodeWaypointUdpSteerBackend for NoopSteerBackend {
    fn run_script(&self, _script: &str) -> Result<(), String> {
        Ok(())
    }
}

fn attach_steering(manager: &StreamListenerManager) -> Arc<NodeWaypointUdpSteering> {
    let steering = Arc::new(NodeWaypointUdpSteering::new(Arc::new(NoopSteerBackend)));
    manager.set_node_waypoint_udp_steering(steering.clone());
    steering
}

fn node_waypoint_udp_proxy_named(service: &str, port: u16) -> Proxy {
    let id = ferrum_edge::modes::mesh::node_waypoint_udp_proxy_id(
        &ferrum_edge::config::types::default_namespace(),
        service,
        port,
    )
    .expect("test service names are admitted Kubernetes identities");
    create_stream_proxy(&id, BackendScheme::Udp, port)
}

fn node_waypoint_udp_proxy(port: u16) -> Proxy {
    node_waypoint_udp_proxy_named("dns", port)
}

fn nw_udp_destination_route(ip: &str, port: u16, service: &str) -> NodeWaypointUdpDestinationRoute {
    let namespace = ferrum_edge::config::types::default_namespace();
    NodeWaypointUdpDestinationRoute::new(
        ip.parse().expect("destination ip"),
        port,
        NamespacedResourceId::new(
            namespace.clone(),
            ferrum_edge::modes::mesh::node_waypoint_udp_proxy_id(&namespace, service, port)
                .expect("test service names are admitted Kubernetes identities"),
        ),
        false,
    )
}

fn config_with_same_port_nw_udp(port: u16, services: &[(&str, &str)]) -> GatewayConfig {
    let proxies = services
        .iter()
        .map(|(service, _)| node_waypoint_udp_proxy_named(service, port))
        .collect();
    let steer_destinations = services
        .iter()
        .map(|(_, ip)| steer_destination(ip, port))
        .collect();
    let destination_routes = services
        .iter()
        .map(|(service, ip)| nw_udp_destination_route(ip, port, service))
        .collect();
    GatewayConfig {
        proxies,
        node_waypoint_udp_steer_destinations: steer_destinations,
        node_waypoint_udp_destination_routes: destination_routes,
        ..empty_config()
    }
}

fn steer_destination(ip: &str, port: u16) -> ferrum_edge::capture::NodeWaypointUdpSteerDestination {
    ferrum_edge::capture::NodeWaypointUdpSteerDestination {
        ip: ip.parse().expect("destination ip"),
        port,
    }
}

fn config_with_nw_udp(
    port: u16,
    destinations: Vec<ferrum_edge::capture::NodeWaypointUdpSteerDestination>,
) -> GatewayConfig {
    GatewayConfig {
        proxies: vec![node_waypoint_udp_proxy(port)],
        node_waypoint_udp_steer_destinations: destinations,
        ..empty_config()
    }
}

#[tokio::test]
async fn node_waypoint_udp_steering_is_not_published_until_the_listener_binds() {
    let holder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp holder");
    let port = holder.local_addr().unwrap().port();
    let dest = vec![steer_destination("10.96.0.10", port)];
    let config = config_with_nw_udp(port, dest);
    let manager = create_manager(config);
    let steering = attach_steering(&manager);

    manager.sync_node_waypoint_udp_steering().await;
    assert!(
        steering.bound_destinations().is_empty(),
        "desired metadata on an unbound listener must not be steered"
    );
    assert!(
        !steering.serving(),
        "an unbound listener must not activate the relay sender proof"
    );

    let failures = manager.reconcile().await;
    assert!(
        !failures.is_empty(),
        "the held UDP port must fail the bind probe: {failures:?}"
    );
    assert!(
        steering.bound_destinations().is_empty(),
        "a failed bind must never be steered"
    );
    assert!(
        !steering.serving(),
        "a failed bind must not activate the relay sender proof"
    );
    manager.shutdown_all().await;
}

#[tokio::test]
async fn node_waypoint_udp_steering_is_not_published_for_deferred_dtls() {
    let holder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp holder");
    let port = holder.local_addr().unwrap().port();
    let mut proxy = node_waypoint_udp_proxy(port);
    proxy.frontend_tls = true;
    let config = GatewayConfig {
        proxies: vec![proxy],
        node_waypoint_udp_steer_destinations: vec![steer_destination("10.96.0.10", port)],
        ..empty_config()
    };
    let manager = create_manager(config);
    let steering = attach_steering(&manager);

    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "deferred DTLS must not be a hard bind failure: {failures:?}"
    );
    assert!(
        steering.bound_destinations().is_empty(),
        "a deferred DTLS listener must never be steered"
    );
    drop(holder);
    manager.shutdown_all().await;
}

#[tokio::test]
async fn node_waypoint_udp_successful_bind_publishes_and_shutdown_retracts() {
    let dest_ip = "10.96.0.10";
    let mut started = None;
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dest = vec![steer_destination(dest_ip, port)];
        let config = config_with_nw_udp(port, dest.clone());
        let manager = create_manager(config);
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
        {
            started = Some((manager, steering, dest));
            break;
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    let (manager, steering, dest) = started
        .unwrap_or_else(|| panic!("NodeWaypoint UDP listener did not start: {last_failures:?}"));

    assert_eq!(
        steering.bound_destinations(),
        dest,
        "a successful bind must publish the accepted destination"
    );
    let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
    assert!(
        owners
            .iter()
            .all(|(key, _, _)| !key.starts_with("__nwudp_")),
        "a first-time single claimant must stay an individual listener: {owners:?}"
    );

    manager.shutdown_all().await;
    assert!(
        steering.bound_destinations().is_empty(),
        "shutdown must retract the serving plan before sockets go away"
    );
}

/// A headless/VIP-less NodeWaypoint UDP listener is still SERVING: it publishes
/// no ClusterIP tuples but must not look withdrawn. Bind failure stays inactive.
#[tokio::test]
async fn node_waypoint_udp_headless_bind_publishes_serving_without_clusterip_tuples() {
    let mut started = None;
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let config = config_with_nw_udp(port, Vec::new());
        let manager = create_manager(config);
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
        {
            started = Some((manager, steering));
            break;
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    let (manager, steering) = started.unwrap_or_else(|| {
        panic!("headless NodeWaypoint UDP listener did not start: {last_failures:?}")
    });

    assert!(
        steering.serving(),
        "a successfully bound headless listener must activate the relay sender proof"
    );
    assert!(
        steering.bound_destinations().is_empty(),
        "a headless listener publishes no ClusterIP steering destinations"
    );

    manager.shutdown_all().await;
    assert!(
        !steering.serving() && steering.bound_destinations().is_empty(),
        "shutdown must withdraw serving state, not leave an active-empty generation behind"
    );
}

/// Retracting Service A on a shared same-port listener must keep `__nwudp_{port}`
/// bound and republish only B. Dissolving the group would stop the socket and
/// race a rebind of B, which hosted live proved can fail `EADDRINUSE`
/// (`node_waypoint.udp.same_port_demux_retract_a_keeps_b`).
#[tokio::test]
async fn node_waypoint_udp_retract_a_keeps_shared_listener_and_b_route() {
    let mut started = None;
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let initial = config_with_same_port_nw_udp(
            port,
            &[("udp-demux-a", "10.96.0.10"), ("udp-demux-b", "10.96.0.11")],
        );
        let config_arc = Arc::new(ArcSwap::from_pointee(initial.clone()));
        let runtime = create_manager_runtime(config_arc.clone(), &initial);
        let steering = attach_steering(&runtime.manager);
        let failures = runtime.manager.reconcile().await;
        let shared_key = format!("__nwudp_{port}");
        if failures.is_empty()
            && wait_until_shared_nw_udp_listener_started(
                &runtime.manager,
                &shared_key,
                Duration::from_secs(5),
            )
            .await
        {
            started = Some((runtime, steering, port, config_arc, shared_key));
            break;
        }
        last_failures = failures;
        runtime.manager.shutdown_all().await;
    }
    let (runtime, steering, port, config_arc, shared_key) = started.unwrap_or_else(|| {
        panic!("shared NodeWaypoint UDP listener did not start: {last_failures:?}")
    });
    let owners_before = runtime
        .manager
        .node_waypoint_udp_listener_owners_for_test()
        .await;
    assert_eq!(
        owners_before.len(),
        1,
        "two same-port claimants must share one listener: {owners_before:?}"
    );
    assert_eq!(owners_before[0].0, shared_key);
    let generation_before = owners_before[0].1;
    let (table_generation_before, destinations_before, _) = runtime
        .manager
        .node_waypoint_udp_destination_snapshot_for_test(port)
        .expect("shared destination table must exist");
    assert_eq!(
        destinations_before,
        vec![
            "10.96.0.10".parse::<IpAddr>().expect("ip a"),
            "10.96.0.11".parse::<IpAddr>().expect("ip b"),
        ]
    );
    assert!(
        steering
            .bound_destinations()
            .iter()
            .any(|destination| destination.ip.to_string() == "10.96.0.11"),
        "B must be steered before A is retracted"
    );

    let only_b = config_with_same_port_nw_udp(port, &[("udp-demux-b", "10.96.0.11")]);
    runtime
        .request_epoch
        .republish_from_runtime_parts_for_test(
            only_b.clone(),
            &runtime.plugin_cache,
            &runtime.consumer_index,
            &runtime.lb_cache,
        )
        .expect("request epoch must republish B after A is retracted");
    config_arc.store(Arc::new(only_b));

    let failures = runtime.manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "retracting A must not unbind B: {failures:?}"
    );
    assert!(
        runtime
            .manager
            .wait_until_started(Duration::from_secs(5))
            .await
            .is_ok(),
        "a retained one-member shared listener must satisfy startup readiness"
    );

    let owners_after = runtime
        .manager
        .node_waypoint_udp_listener_owners_for_test()
        .await;
    assert_eq!(
        owners_after.len(),
        1,
        "retracting A must not replace the shared listener: {owners_after:?}"
    );
    assert_eq!(owners_after[0].0, shared_key);
    assert_eq!(
        owners_after[0].1, generation_before,
        "retracting A must not restart the shared socket"
    );
    let (table_generation_after, destinations_after, owners_after_table) = runtime
        .manager
        .node_waypoint_udp_destination_snapshot_for_test(port)
        .expect("shared destination table must survive A's retraction");
    assert!(
        table_generation_after > table_generation_before,
        "A's retraction must republish the destination table in place"
    );
    assert_eq!(
        destinations_after,
        vec!["10.96.0.11".parse::<IpAddr>().expect("ip b")],
        "only B's ClusterIP may remain after A is retracted"
    );
    let namespace = ferrum_edge::config::types::default_namespace();
    let expected_b = NamespacedResourceId::new(
        namespace.clone(),
        ferrum_edge::modes::mesh::node_waypoint_udp_proxy_id(&namespace, "udp-demux-b", port)
            .expect("test service names are admitted Kubernetes identities"),
    );
    assert_eq!(
        owners_after_table,
        vec![expected_b],
        "the surviving route owner must be exactly B"
    );
    assert!(
        steering
            .bound_destinations()
            .iter()
            .any(|destination| destination.ip.to_string() == "10.96.0.11"),
        "B must stay steered after A is retracted"
    );
    assert!(
        steering
            .bound_destinations()
            .iter()
            .all(|destination| destination.ip.to_string() != "10.96.0.10"),
        "A's ClusterIP must leave the serving steer set"
    );
    let still_bound = tokio::net::UdpSocket::bind(format!("127.0.0.1:{port}")).await;
    assert!(
        still_bound.is_err(),
        "the shared UDP socket must still own the port after A is retracted"
    );

    runtime.manager.shutdown_all().await;
}

#[tokio::test]
async fn node_waypoint_udp_headless_survivor_returns_to_individual_listener() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp probe");
    let port = probe.local_addr().expect("probe address").port();
    drop(probe);

    let initial = config_with_same_port_nw_udp(
        port,
        &[("udp-demux-a", "10.96.0.10"), ("udp-demux-b", "10.96.0.11")],
    );
    let config_arc = Arc::new(ArcSwap::from_pointee(initial.clone()));
    let manager = create_manager_with_config_arc(config_arc.clone(), &initial);
    assert!(manager.reconcile().await.is_empty());
    let shared_key = format!("__nwudp_{port}");
    assert!(
        wait_until_shared_nw_udp_listener_started(&manager, &shared_key, Duration::from_secs(5),)
            .await,
        "the initial VIP claimants must share the port"
    );

    let headless = GatewayConfig {
        proxies: vec![node_waypoint_udp_proxy_named("udp-demux-headless", port)],
        ..empty_config()
    };
    config_arc.store(Arc::new(headless));
    assert!(manager.reconcile().await.is_empty());
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("headless survivor must bind its individual listener");

    let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
    assert_eq!(owners.len(), 1);
    assert_ne!(
        owners[0].0, shared_key,
        "headless service cannot use exact destination routing"
    );
    assert!(
        manager
            .node_waypoint_udp_destination_snapshot_for_test(port)
            .is_none(),
        "an individual headless listener must not install an empty destination router"
    );

    manager.shutdown_all().await;
}

/// A shared listener reports one durable bind failure for every member. Once
/// the shared socket successfully rebinds, all of those member-scoped failures
/// must clear together; retaining B's failure after representative A recovered
/// would keep readiness falsely degraded indefinitely.
#[tokio::test]
async fn node_waypoint_udp_shared_rebind_clears_every_member_failure() {
    let blocker = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind shared-listener blocker");
    let port = blocker.local_addr().expect("blocker address").port();
    let config = config_with_same_port_nw_udp(
        port,
        &[
            ("udp-demux-recover-a", "10.96.0.20"),
            ("udp-demux-recover-b", "10.96.0.21"),
        ],
    );
    let manager = create_manager(config);

    let failures = manager.reconcile().await;
    assert_eq!(
        failures.len(),
        2,
        "every shared member must report the bind failure"
    );
    assert_eq!(
        manager.stream_bind_failures().len(),
        2,
        "both member-scoped failures must remain durable until rebind"
    );

    drop(blocker);
    let failures = manager.reconcile().await;
    assert!(
        failures.is_empty(),
        "shared listener must rebind: {failures:?}"
    );
    manager
        .wait_until_started(Duration::from_secs(5))
        .await
        .expect("a rebound shared NodeWaypoint UDP listener must satisfy startup readiness");
    assert!(
        manager.stream_bind_failures().is_empty(),
        "successful shared rebind must clear every member's durable failure"
    );

    manager.shutdown_all().await;
}

#[tokio::test]
async fn node_waypoint_udp_withdrawal_retracts_steering() {
    let dest_ip = "10.96.0.10";
    let mut started = None;
    let mut last_failures = Vec::new();
    let mut config_arc = None;
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dest = vec![steer_destination(dest_ip, port)];
        let config = config_with_nw_udp(port, dest);
        let arc = Arc::new(ArcSwap::from_pointee(config.clone()));
        let manager = create_manager_with_config_arc(arc.clone(), &config);
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
        {
            started = Some((manager, steering));
            config_arc = Some(arc);
            break;
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    let (manager, steering) = started
        .unwrap_or_else(|| panic!("NodeWaypoint UDP listener did not start: {last_failures:?}"));
    assert!(
        !steering.bound_destinations().is_empty(),
        "the bound listener must be steered before withdrawal"
    );

    config_arc
        .expect("config arc")
        .store(Arc::new(empty_config()));
    let _ = manager.reconcile().await;
    assert!(
        steering.bound_destinations().is_empty(),
        "withdrawing the listener must retract its destination before the socket is gone"
    );
    manager.shutdown_all().await;
}

async fn start_steered_nw_udp() -> (
    Arc<StreamListenerManager>,
    Arc<NodeWaypointUdpSteering>,
    Vec<ferrum_edge::capture::NodeWaypointUdpSteerDestination>,
) {
    let dest_ip = "10.96.0.10";
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dest = vec![steer_destination(dest_ip, port)];
        let config = config_with_nw_udp(port, dest.clone());
        let manager = Arc::new(create_manager(config));
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
            && !steering.bound_destinations().is_empty()
        {
            return (manager, steering, dest);
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    panic!("NodeWaypoint UDP listener did not start: {last_failures:?}");
}

/// A listener-task failure between eligibility and plan install must not leave
/// the dead port marked. The last event is the non-serving mark: publication
/// re-reads serving flags after the fence.
#[tokio::test]
async fn node_waypoint_udp_failure_between_eligibility_and_publish_does_not_install() {
    let (manager, steering, dest) = start_steered_nw_udp().await;
    assert_eq!(steering.bound_destinations(), dest);

    let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
    assert_eq!(owners.len(), 1, "one generated NodeWaypoint UDP owner");
    let (_key, _generation, started) = &owners[0];

    let hold = NodeWaypointUdpSteerHold::new();
    manager.set_node_waypoint_udp_steer_holds_for_test(None, Some(hold.clone()));

    let sync_manager = manager.clone();
    let sync = tokio::spawn(async move {
        sync_manager.sync_node_waypoint_udp_steering().await;
    });
    hold.wait_entered().await;
    started.store(false, Ordering::Release);
    hold.wait_release().await;
    sync.await.expect("sync task");

    assert!(
        steering.bound_destinations().is_empty(),
        "a failure between eligibility and publish must not install the dead port"
    );
    manager.shutdown_all().await;
}

/// A failed older generation must not retract a successfully bound replacement
/// on the same key.
#[tokio::test]
async fn node_waypoint_udp_old_generation_failure_does_not_retract_replacement() {
    let (manager, steering, dest) = start_steered_nw_udp().await;
    let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
    let (key, generation, _) = owners
        .into_iter()
        .next()
        .expect("bound NodeWaypoint UDP owner");

    manager
        .retract_node_waypoint_udp_listener_generation_for_test(&key, generation.wrapping_sub(1))
        .await;
    assert_eq!(
        steering.bound_destinations(),
        dest,
        "a stale generation must not retract the serving replacement"
    );

    manager
        .retract_node_waypoint_udp_listener_generation_for_test(&key, generation)
        .await;
    assert!(
        steering.bound_destinations().is_empty(),
        "retracting the serving generation must clear bound destinations"
    );
    manager.shutdown_all().await;
}

/// A failed older generation after a same-key replacement must not retract the
/// successor's serving plan.
#[tokio::test]
async fn node_waypoint_udp_old_generation_failure_after_replacement_keeps_successor() {
    let dest_ip = "10.96.0.10";
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dest = vec![steer_destination(dest_ip, port)];
        let config = config_with_nw_udp(port, dest.clone());
        let config_arc = Arc::new(ArcSwap::from_pointee(config.clone()));
        let manager = Arc::new(create_manager_with_config_arc(config_arc.clone(), &config));
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if !(failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
            && !steering.bound_destinations().is_empty())
        {
            last_failures = failures;
            manager.shutdown_all().await;
            continue;
        }

        let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
        let (key, generation, _) = owners
            .into_iter()
            .next()
            .expect("bound NodeWaypoint UDP owner");

        let mut replacement = config_with_nw_udp(port, dest.clone());
        replacement.proxies[0].passthrough = true;
        config_arc.store(Arc::new(replacement));
        let _ = manager.reconcile().await;
        if manager
            .wait_until_started(Duration::from_secs(5))
            .await
            .is_err()
        {
            last_failures = manager
                .stream_bind_failures()
                .iter()
                .map(|failure| {
                    (
                        failure.proxy_id.clone(),
                        failure.listen_port,
                        failure.error.clone(),
                    )
                })
                .collect();
            manager.shutdown_all().await;
            continue;
        }

        let owners = manager.node_waypoint_udp_listener_owners_for_test().await;
        let successor = owners
            .iter()
            .find(|(owner_key, _, _)| owner_key == &key)
            .map(|(_, generation, _)| *generation);
        let Some(successor_generation) = successor else {
            last_failures = vec![("missing-successor".into(), port, "no owner".into())];
            manager.shutdown_all().await;
            continue;
        };
        assert_ne!(
            successor_generation, generation,
            "passthrough flip must spawn a new listener generation on the same key"
        );
        assert_eq!(
            steering.bound_destinations(),
            dest,
            "the replacement must be steered before the old generation fails"
        );

        manager
            .retract_node_waypoint_udp_listener_generation_for_test(&key, generation)
            .await;
        assert_eq!(
            steering.bound_destinations(),
            dest,
            "a failed old generation must not retract a successfully bound replacement"
        );
        manager.shutdown_all().await;
        return;
    }
    panic!("NodeWaypoint UDP replacement did not start: {last_failures:?}");
}

/// Shutdown fences bind-success watchers, retracts, then closes sockets. A
/// watcher that observed `started` before teardown must not republish after it.
#[tokio::test]
async fn node_waypoint_udp_shutdown_is_the_final_datapath_operation() {
    let dest_ip = "10.96.0.10";
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dest = vec![steer_destination(dest_ip, port)];
        let config = config_with_nw_udp(port, dest);
        let manager = Arc::new(create_manager(config));
        let steering = attach_steering(&manager);
        let hold = NodeWaypointUdpSteerHold::new();
        manager.set_node_waypoint_udp_steer_holds_for_test(Some(hold.clone()), None);

        let reconcile_manager = manager.clone();
        let reconcile = tokio::spawn(async move { reconcile_manager.reconcile().await });

        let entered = tokio::time::timeout(Duration::from_secs(5), hold.wait_entered()).await;
        if entered.is_err() {
            last_failures = reconcile.await.unwrap_or_default();
            manager.shutdown_all().await;
            continue;
        }

        manager.shutdown_all().await;
        hold.wait_release().await;
        let _ = reconcile.await;
        assert!(
            steering.bound_destinations().is_empty(),
            "teardown must be the final datapath operation; a bind-watch must not republish"
        );
        return;
    }
    panic!("NodeWaypoint UDP listener did not reach the bind-watch fence: {last_failures:?}");
}

/// A tenant namespace that happens to contain the reserved listener prefix
/// must not steal NodeWaypoint UDP steering ownership. Ownership is the
/// generated proxy id, not a substring of the runtime key.
#[tokio::test]
async fn node_waypoint_udp_steering_ignores_runtime_key_substring() {
    let dest_ip = "10.96.0.10";
    let mut last_failures = Vec::new();
    for _ in 0..8 {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut proxy = create_stream_proxy("ordinary-udp", BackendScheme::Udp, port);
        proxy.namespace = format!(
            "tenant{}trap",
            ferrum_edge::modes::mesh::MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX
        );
        let config = GatewayConfig {
            proxies: vec![proxy],
            node_waypoint_udp_steer_destinations: vec![steer_destination(dest_ip, port)],
            ..empty_config()
        };
        let manager = create_manager(config);
        let steering = attach_steering(&manager);
        let failures = manager.reconcile().await;
        if failures.is_empty()
            && manager
                .wait_until_started(Duration::from_secs(5))
                .await
                .is_ok()
        {
            assert!(
                steering.bound_destinations().is_empty(),
                "a namespace-qualified runtime key containing the reserved prefix must not own steering"
            );
            assert!(
                manager
                    .node_waypoint_udp_listener_owners_for_test()
                    .await
                    .is_empty(),
                "ordinary UDP listeners must not be marked as generated NodeWaypoint owners"
            );
            manager.shutdown_all().await;
            return;
        }
        last_failures = failures;
        manager.shutdown_all().await;
    }
    panic!("ordinary UDP listener did not start: {last_failures:?}");
}

// ============================================================================
// Tests: datagram client-address gate reload (issue #3289)
// ============================================================================

/// `stream_proxy_protocol` is part of the UDP listener restart identity. A
/// reconcile that toggles it must stop the old recv loop and bind a replacement
/// with the new gate decision — not merely validate config or leave a stale
/// listener serving the previous posture.
#[tokio::test]
async fn udp_stream_proxy_protocol_reload_restarts_listener_and_toggles_gate() {
    let backend = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP echo backend"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let (runtime, config_arc, frontend_port) =
        start_datagram_reload_manager_on_fresh_udp_port(|frontend_port| GatewayConfig {
            proxies: vec![udp_proxy_for_datagram_reload(
                frontend_port,
                backend_port,
                None,
            )],
            ..empty_config()
        })
        .await;
    let gateway_addr = SocketAddr::from(([127, 0, 0, 1], frontend_port));
    let manager = &runtime.manager;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP client");

    // Envelope disabled: bare payloads follow ordinary UDP proxy behavior.
    let reply = udp_roundtrip(&client, gateway_addr, b"bare-phase1")
        .await
        .expect("bare UDP must reach the echo backend before the gate is enabled");
    assert_eq!(reply, b"bare-phase1");

    // Enable the datagram client-address gate; reconcile must restart the listener.
    publish_stream_config(
        &runtime,
        &config_arc,
        GatewayConfig {
            proxies: vec![udp_proxy_for_datagram_reload(
                frontend_port,
                backend_port,
                Some(true),
            )],
            ..empty_config()
        },
    )
    .await;

    client
        .send_to(b"bare-phase2", gateway_addr)
        .await
        .expect("send bare datagram on gated listener");
    assert!(
        recv_udp_within(&client, UDP_DROP_WINDOW).await.is_none(),
        "bare UDP must be dropped after stream_proxy_protocol is enabled"
    );

    // A correctly shaped, authenticated envelope proves the replacement listener
    // is serving rather than merely down after the restart — and that the
    // reconstructed gate rebuilt this listener's exact domain binding.
    let binding = datagram_binding(frontend_port);
    let envelope = datagram_envelope(&binding, gateway_addr, b"gated-envelope", 0);
    client
        .send_to(&envelope, gateway_addr)
        .await
        .expect("send authenticated envelope");
    let reply = recv_udp_within(&client, UDP_RECV_WINDOW)
        .await
        .expect("the restarted gated listener must admit an authenticated envelope");
    assert_eq!(reply, b"gated-envelope");

    // The reconstructed gate carries a live replay window, not just a key: the
    // same bytes again are dropped (issue #3862).
    client
        .send_to(&envelope, gateway_addr)
        .await
        .expect("replay the authenticated envelope");
    assert!(
        recv_udp_within(&client, UDP_DROP_WINDOW).await.is_none(),
        "a verbatim replay must be dropped by the reconstructed listener's replay window"
    );

    // And the reconstructed binding is this listener's: an envelope minted for
    // another listener's binding under the same root secret is refused before a
    // session is allocated (issue #3856).
    let other_port = frontend_port.wrapping_add(1).max(1);
    let other_binding = datagram_binding(other_port);
    let other_addr = SocketAddr::from(([127, 0, 0, 1], other_port));
    let portable = datagram_envelope(&other_binding, other_addr, b"wrong-listener", 1);
    client
        .send_to(&portable, gateway_addr)
        .await
        .expect("send portable envelope");
    assert!(
        recv_udp_within(&client, UDP_DROP_WINDOW).await.is_none(),
        "an authenticated envelope for another listener must be dropped after reload"
    );

    // A fresh sequence still works, so neither refusal wedged the listener.
    let fresh = datagram_envelope(&binding, gateway_addr, b"still-serving", 2);
    client
        .send_to(&fresh, gateway_addr)
        .await
        .expect("send a fresh sequence");
    let reply = recv_udp_within(&client, UDP_RECV_WINDOW)
        .await
        .expect("a fresh sequence must still round-trip");
    assert_eq!(reply, b"still-serving");

    // Clearing the field must restart again and restore bare UDP behavior.
    publish_stream_config(
        &runtime,
        &config_arc,
        GatewayConfig {
            proxies: vec![udp_proxy_for_datagram_reload(
                frontend_port,
                backend_port,
                None,
            )],
            ..empty_config()
        },
    )
    .await;

    let reply = udp_roundtrip(&client, gateway_addr, b"bare-phase3")
        .await
        .expect("bare UDP must round-trip again after the gate is cleared");
    assert_eq!(reply, b"bare-phase3");

    // Deleting the proxy must withdraw the listener and release the port.
    publish_stream_config(&runtime, &config_arc, empty_config()).await;
    assert!(
        wait_until_udp_port_free(frontend_port).await,
        "UDP port {frontend_port} must be released after the proxy is deleted"
    );

    manager.shutdown_all().await;
}

/// A UDP session copies the response-amplification factor at admission. A
/// policy update must therefore restart the listener and retire its session
/// map; otherwise an already-established unlimited session could keep
/// forwarding amplified responses after the same proxy becomes finite.
#[tokio::test]
async fn udp_amplification_policy_reload_retires_sessions_with_stale_budget() {
    let backend = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP amplification backend"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let amplified_response = b"amplified";
    spawn_udp_fixed_response_backend(Arc::clone(&backend), amplified_response).await;

    let (runtime, config_arc, frontend_port) =
        start_datagram_reload_manager_on_fresh_udp_port(|frontend_port| {
            let mut unlimited = udp_proxy_for_datagram_reload(frontend_port, backend_port, None);
            unlimited.udp_max_response_amplification_factor = None;
            GatewayConfig {
                proxies: vec![unlimited],
                ..empty_config()
            }
        })
        .await;
    let gateway_addr = SocketAddr::from(([127, 0, 0, 1], frontend_port));
    let manager = &runtime.manager;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP client");
    let reply = udp_roundtrip(&client, gateway_addr, b"x")
        .await
        .expect("unlimited session must relay the amplified response");
    assert_eq!(reply, amplified_response);

    let mut finite = udp_proxy_for_datagram_reload(frontend_port, backend_port, None);
    finite.udp_max_response_amplification_factor = Some(1.0);
    publish_stream_config(
        &runtime,
        &config_arc,
        GatewayConfig {
            proxies: vec![finite],
            ..empty_config()
        },
    )
    .await;

    client
        .send_to(b"x", gateway_addr)
        .await
        .expect("send through the tightened UDP listener");
    assert!(
        recv_udp_within(&client, UDP_DROP_WINDOW).await.is_none(),
        "the same source must not retain its stale unlimited session after policy tightening"
    );

    manager.shutdown_all().await;
}

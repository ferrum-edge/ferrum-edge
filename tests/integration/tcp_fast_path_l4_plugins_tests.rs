//! Regression tests proving that L4 stream-lifecycle plugins
//! (`on_stream_connect` / `on_stream_disconnect`) fire on the TCP
//! fast path — i.e. when both `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` and
//! `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS` (and the per-direction
//! backend timeouts) are 0 and the relay delegates straight to
//! `tokio::io::copy_bidirectional_with_sizes`.
//!
//! The fast-path branch lives inside `bidirectional_copy()`. Plugin
//! invocation happens earlier in `handle_tcp_connection()` — *before*
//! the relay starts — which means the fast path does not bypass
//! plugins. These tests pin that invariant down so a future refactor
//! that, say, pushes plugin invocation into the relay (or removes it
//! under the assumption that the fast path doesn't need it) fails
//! immediately.
//!
//! The tests use `tcp_connection_throttle` as the canary plugin
//! because admission and teardown are observable through its rejection
//! behaviour: `on_stream_connect` acquires a per-key permit (and rejects
//! when it would exceed the limit), while connection-context teardown
//! drops that permit. With `max_connections_per_key: 1` we can probe both
//! boundaries via plain TCP connect-attempt observations — no plugin
//! introspection or counter-readback API required.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::ProxyProtocol;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics, start_tcp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_port;

const PROXY_ID: &str = "fast-path-throttle-proxy";
const PLUGIN_CONFIG_ID: &str = "throttle-1";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Bind-drop-rebind retry budget. CLAUDE.md mandates that any test
/// dropping a reserved port before re-binding must retry, because a
/// parallel test can grab the freed port in that window. Three
/// attempts mirrors the existing `start_gateway_with_retry` helpers
/// elsewhere in the suite.
const MAX_GATEWAY_ATTEMPTS: u32 = 3;
/// Per-attempt deadline for `start_tcp_listener` to set
/// `started=true`. Successful binds flip the flag in well under
/// 100ms; anything past two seconds means the bind lost a race or
/// hung, so we tear the task down and retry on a fresh port.
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);

/// Build a TCP proxy that exercises the fast path: every relay timeout
/// is 0, which is what `bidirectional_copy()` checks before delegating
/// to `tokio::io::copy_bidirectional_with_sizes` (the zero-overhead
/// path that has no plugin loop of its own).
fn fast_path_tcp_proxy(listen_port: u16, backend_port: u16, plugin_config_ids: &[String]) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("fast-path tcp throttle".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: DispatchKind::from(BackendScheme::Tcp),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        // Forces `bidirectional_copy()` into the
        // `copy_bidirectional_with_sizes` fast path. All four of these
        // (the two relay timeouts and the two per-direction backend
        // timeouts) must be zero. If any are non-zero the relay opts
        // into the direction-tracking slow path and this test no
        // longer covers what its name says.
        backend_connect_timeout_ms: 1_000,
        backend_read_timeout_ms: 0,
        backend_write_timeout_ms: 0,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        // The proxy must explicitly reference any proxy-scoped plugin
        // by its PluginConfig.id; the cache only attaches plugins that
        // appear in this association list (see `PluginCache::build_cache`).
        plugins: plugin_config_ids
            .iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.clone(),
            })
            .collect(),
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        // Per-proxy fast-path opt-in: paired with the global flag in
        // `TcpListenerConfig` below.
        tcp_idle_timeout_seconds: Some(0),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Wire `tcp_connection_throttle` (`max_connections_per_key: 1`) onto
/// the test proxy. The throttle's IP-keyed counter is the
/// observability surface we use to verify both lifecycle hooks fired.
fn throttle_plugin_config() -> PluginConfig {
    PluginConfig {
        id: PLUGIN_CONFIG_ID.to_string(),
        plugin_name: "tcp_connection_throttle".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "max_connections_per_key": 1,
            // Disable the background sweep so the test isn't racing
            // against periodic cleanup of zero-count entries.
            "cleanup_interval_seconds": 0
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Spin up a tiny in-process TCP echo backend on the supplied bound
/// listener. Used as the upstream the gateway dials.
async fn spawn_echo_backend(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    })
}

/// Bring up an in-process TCP gateway listener configured for the fast
/// path with `tcp_connection_throttle` attached, retrying on the
/// bind-drop-rebind race that occurs when another parallel test grabs
/// our reserved port between `drop_and_take_port()` and
/// `start_tcp_listener`'s own bind. Each attempt reserves a fresh
/// port. Returns the live listen port, a shutdown sender, the listener
/// task handle, and the metrics so callers can sanity-check connection
/// accounting.
async fn spawn_fast_path_gateway_with_retry(
    backend_port: u16,
) -> (
    u16,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<TcpProxyMetrics>,
) {
    spawn_fast_path_gateway_with_options(backend_port, vec![throttle_plugin_config()], 1).await
}

async fn spawn_fast_path_gateway_with_options(
    backend_port: u16,
    plugin_configs: Vec<PluginConfig>,
    accept_threads: usize,
) -> (
    u16,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<TcpProxyMetrics>,
) {
    let mut last_port: u16 = 0;
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_port().await.expect("reserve frontend port");
        let frontend_port = frontend.drop_and_take_port();
        last_port = frontend_port;
        if let Some(handles) = try_spawn_fast_path_gateway(
            backend_port,
            frontend_port,
            plugin_configs.clone(),
            accept_threads,
        )
        .await
        {
            return handles;
        }
        eprintln!(
            "fast-path gateway start attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on port \
             {frontend_port} failed (likely bind-drop-rebind race) — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!(
        "TCP gateway listener never reported started=true after \
         {MAX_GATEWAY_ATTEMPTS} attempts; last attempted port: {last_port}"
    );
}

/// One attempt at bringing up the gateway listener on the given port.
/// Returns `None` if the listener task either exited before binding
/// (typically EADDRINUSE because a parallel test stole the port) or
/// failed to set `started=true` within `PER_ATTEMPT_STARTED_TIMEOUT`.
/// On `None` the inner task is reaped before returning so retries do
/// not leak background tasks.
async fn try_spawn_fast_path_gateway(
    backend_port: u16,
    listen_port: u16,
    plugin_configs: Vec<PluginConfig>,
    accept_threads: usize,
) -> Option<(
    u16,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<TcpProxyMetrics>,
)> {
    let plugin_config_ids: Vec<String> = plugin_configs
        .iter()
        .map(|plugin_config| plugin_config.id.clone())
        .collect();
    let proxy = fast_path_tcp_proxy(listen_port, backend_port, &plugin_config_ids);
    let gateway_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plugin_cache = Arc::new(
        PluginCache::new(&gateway_config)
            .expect("PluginCache should build with valid stream plugin config"),
    );
    if !gateway_config.plugin_configs.is_empty() {
        // Sanity check: configured plugins must actually be wired to the proxy.
        // If PluginScope / proxy_id wiring drifts, lifecycle tests below could
        // pass vacuously because no plugin is attached.
        let attached =
            plugin_cache.get_plugins_for_protocol("ferrum", PROXY_ID, ProxyProtocol::Tcp);
        let attached_names: Vec<&str> = attached.iter().map(|p| p.name()).collect();
        for plugin_config in &gateway_config.plugin_configs {
            assert!(
                attached_names.contains(&plugin_config.plugin_name.as_str()),
                "{} should be attached to the test proxy via the cache; got {:?}",
                plugin_config.plugin_name,
                attached_names
            );
        }
    }
    let consumer_index = Arc::new(ConsumerIndex::new(&gateway_config.consumers));
    let load_balancer_cache = Arc::new(LoadBalancerCache::new(&gateway_config));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        gateway_config.clone(),
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ));
    let circuit_breaker_cache = Arc::new(CircuitBreakerCache::new());
    let dns_cache = DnsCache::new(DnsConfig::default());
    let metrics = Arc::new(TcpProxyMetrics::default());
    let started = Arc::new(AtomicBool::new(false));
    // Tracker shape mirrors the production defaults used elsewhere in
    // the integration suite (see `http3_integration_tests`).
    let adaptive_buffer = Arc::new(AdaptiveBufferTracker::new(
        true, true, 300, 8192, 262_144, 65_536, 6000,
    ));
    let overload = Arc::new(OverloadState::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config_swap = Arc::new(ArcSwap::from_pointee(gateway_config));

    let listener_started = started.clone();
    let listener_metrics = metrics.clone();
    let join = {
        let cfg = TcpListenerConfig {
            port: listen_port,
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            proxy_id: PROXY_ID.to_string(),
            proxy_namespace: ferrum_edge::config::types::default_namespace(),
            config: config_swap,
            dns_cache,
            request_epoch,
            health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
            frontend_tls_slot: Arc::new(ArcSwap::new(Arc::new(None))),
            shutdown: shutdown_rx,
            global_shutdown: None,
            metrics: listener_metrics,
            tls_no_verify: false,
            tls_ca_bundle_path: None,
            // Globals MUST also be 0 to keep `bidirectional_copy()` on
            // the fast path. The per-proxy override on `Proxy` only
            // helps if it isn't ceiling'd by a non-zero global.
            tcp_idle_timeout_seconds: 0,
            tcp_half_close_max_wait_seconds: 0,
            frontend_tls_handshake_timeout_seconds: 10,
            circuit_breaker_cache,
            tls_policy: None,
            crls: Arc::new(Vec::new()),
            started: listener_started,
            sni_proxy_ids: None,
            adaptive_buffer,
            tcp_fastopen_enabled: false,
            tcp_listen_backlog: 2048,
            accept_threads,
            tcp_fastopen_queue_len: 256,
            overload,
            ktls_enabled: false,
            io_uring_splice_enabled: false,
            record_mesh_mtls_metric: false,
            mesh_outbound_enforcement: ferrum_edge::modes::mesh::outbound_enforcement::empty_slot(),
            node_waypoint_identity_resolver: None,
            trusted_proxies: Arc::new(TrustedProxies::none()),
        };
        tokio::spawn(async move {
            // Errors here would abort the test by leaving `started`
            // false; the `wait_started` loop below times out and
            // panics with a clear message.
            let _ = start_tcp_listener(cfg).await;
        })
    };

    // Race three terminal conditions:
    //   - started = true                 → bind succeeded.
    //   - join.is_finished() && !started → task exited without binding,
    //                                      typically EADDRINUSE from a
    //                                      parallel test grabbing the
    //                                      port between our drop and
    //                                      `start_tcp_listener`'s bind.
    //   - deadline exceeded              → bind hung; treat as failure.
    // Returning `None` on the latter two lets the outer retry loop try
    // a fresh port instead of panicking.
    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some((listen_port, shutdown_tx, join, metrics));
        }
        if join.is_finished() {
            // Reap so the failed task does not leak across retries.
            let _ = join.await;
            return None;
        }
        if std::time::Instant::now() > deadline {
            let _ = shutdown_tx.send(true);
            join.abort();
            let _ = join.await;
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Drop the gateway listener cleanly and surface any shutdown
/// regression. Failure here means the listener task panicked, hung,
/// or exited before we asked it to — all of which would otherwise
/// leak a background task into the next test or silently mask a
/// shutdown-path bug.
async fn shutdown_gateway_or_panic(
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
) {
    shutdown_tx
        .send(true)
        .expect("listener task should still be holding the shutdown receiver");
    match tokio::time::timeout(TEST_TIMEOUT, join).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("listener task panicked during shutdown: {e:?}"),
        Err(_) => panic!("listener task did not exit within {TEST_TIMEOUT:?} of shutdown signal"),
    }
}

/// Connect to the gateway, exchange one round-trip, and confirm the
/// echo came back.
async fn round_trip_through_gateway(addr: SocketAddr, payload: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("gateway must accept first connection");
    stream
        .write_all(payload)
        .await
        .expect("write to gateway must succeed");
    let mut buf = vec![0u8; payload.len()];
    let read = tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo read must not stall")
        .expect("echo read must succeed");
    assert_eq!(read, payload.len());
    assert_eq!(&buf, payload, "echo backend should mirror the payload");
    stream
}

/// True when the connection has been closed by the peer (the gateway).
/// `tcp_connection_throttle` rejects in `on_stream_connect` by
/// returning `PluginResult::Reject`, which causes the gateway to drop
/// the freshly-accepted socket. From the client's side that surfaces
/// as an immediate EOF (or, on some platforms, an ECONNRESET).
async fn is_closed_by_peer(stream: &mut TcpStream) -> bool {
    let mut probe = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut probe)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[cfg(unix)]
#[tokio::test]
async fn tcp_stream_accept_threads_two_binds_and_relays_connections() {
    // Backend echo server.
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend_task = spawn_echo_backend(backend.into_listener()).await;

    // This exercises the real `start_tcp_listener` path where the first
    // listener and one extra SO_REUSEPORT listener both bind before started=true.
    // If the extra bind fails, the helper never observes started=true and retries
    // until it panics with the attempted port.
    let (listen_port, shutdown_tx, join, metrics) =
        spawn_fast_path_gateway_with_options(backend_port, Vec::new(), 2).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
        let conn = round_trip_through_gateway(gateway_addr, payload).await;
        drop(conn);
    }

    assert!(
        metrics.total_connections.load(Ordering::Relaxed) >= 3,
        "multi-accept TCP listener should accept and proxy all test connections"
    );

    shutdown_gateway_or_panic(shutdown_tx, join).await;
}

#[tokio::test]
async fn fast_path_invokes_on_stream_connect_to_reject_throttled_connection() {
    // Backend echo server.
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend_task = spawn_echo_backend(backend.into_listener()).await;

    // Gateway listener — `spawn_fast_path_gateway_with_retry` handles
    // the bind-drop-rebind race against parallel tests internally.
    let (listen_port, shutdown_tx, join, metrics) =
        spawn_fast_path_gateway_with_retry(backend_port).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    // Connection #1 — should pass the throttle because the per-IP
    // counter goes 0 → 1.
    let _conn1 = round_trip_through_gateway(gateway_addr, b"first").await;

    // Connection #2 from the same IP — `on_stream_connect` runs (this
    // is the invariant under test), the throttle's per-key counter is
    // already at the limit, the plugin returns `Reject`, and the
    // gateway closes the just-accepted socket. The client observes
    // immediate EOF on read.
    let mut conn2 = TcpStream::connect(gateway_addr)
        .await
        .expect("kernel SYN/ACK still completes — gateway closes after accept");
    assert!(
        is_closed_by_peer(&mut conn2).await,
        "throttle plugin must reject connection #2 in on_stream_connect even on the fast path; \
         if this fails, the fast path is silently bypassing plugin invocation"
    );

    // Sanity check that the listener really did handle two accepts —
    // i.e. the rejection happened post-accept (proving plugins ran),
    // not pre-accept (which would indicate something else wedged the
    // listener).
    assert!(
        metrics.total_connections.load(Ordering::Relaxed) >= 2,
        "listener should have accepted both attempts before rejecting #2; \
         total_connections = {}",
        metrics.total_connections.load(Ordering::Relaxed)
    );

    drop(_conn1);
    shutdown_gateway_or_panic(shutdown_tx, join).await;
}

#[tokio::test]
async fn fast_path_releases_throttle_permit_on_connection_teardown() {
    // Backend echo server.
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend_task = spawn_echo_backend(backend.into_listener()).await;

    let (listen_port, shutdown_tx, join, _metrics) =
        spawn_fast_path_gateway_with_retry(backend_port).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    // Hold one slot.
    let conn1 = round_trip_through_gateway(gateway_addr, b"hold").await;

    // Pre-drop sanity check: while conn1 is alive, a second connection
    // from the same IP MUST be rejected. Without this assertion the
    // post-drop "connection succeeds" check below would also pass if
    // the throttle never engaged in the first place (i.e. on_stream_connect
    // was silently bypassed) — the test would prove nothing about
    // connection-permit teardown.
    let mut blocked = TcpStream::connect(gateway_addr)
        .await
        .expect("kernel SYN/ACK still completes — gateway closes after accept");
    assert!(
        is_closed_by_peer(&mut blocked).await,
        "while conn1 holds the throttle slot, a second connection must be \
         rejected by on_stream_connect — confirming the throttle is engaged \
         before we test connection teardown release"
    );
    drop(blocked);

    // Drop the holding connection. The gateway's accept-loop spawns
    // each connection in its own task. Once the relay future returns, the
    // gateway releases the opaque throttle permit before disconnect logging.
    // Wait for that with a short retry loop on a fresh connection.
    drop(conn1);

    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    let mut last_err: Option<String> = None;
    loop {
        if std::time::Instant::now() > deadline {
            panic!(
                "throttle slot never released within {TEST_TIMEOUT:?}; connection teardown \
                 likely did not release the permit on the fast path. Last attempt: {:?}",
                last_err
            );
        }
        let mut probe = match TcpStream::connect(gateway_addr).await {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        // If the slot is still held, the throttle rejects in
        // `on_stream_connect` and the gateway closes — same EOF
        // signature as the previous test's reject probe.
        if is_closed_by_peer(&mut probe).await {
            last_err = Some("connection closed by gateway (slot still held)".to_string());
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        // Slot has been released — confirm the new connection actually
        // proxies traffic end-to-end before declaring success.
        probe
            .write_all(b"after-release")
            .await
            .expect("post-release write must succeed");
        let mut buf = [0u8; b"after-release".len()];
        tokio::time::timeout(TEST_TIMEOUT, probe.read_exact(&mut buf))
            .await
            .expect("post-release echo read must not stall")
            .expect("post-release echo read must succeed");
        assert_eq!(&buf, b"after-release");
        break;
    }

    shutdown_gateway_or_panic(shutdown_tx, join).await;
}

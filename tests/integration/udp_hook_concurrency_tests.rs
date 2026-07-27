//! Regression for issue #2956: UDP `on_udp_datagram` hooks must not run
//! inline in the shared listener recv loop.
//!
//! A gated hook blocks client A's established-session datagram while client B
//! completes an echo round-trip *before* A's gate is released. Ordering and
//! allow/deny verdicts are asserted with oneshot barriers (no fragile
//! wall-clock latency thresholds).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot, watch};

use ferrum_edge::_test_support::prepend_proxy_plugin_for_test;
use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext, UdpDatagramVerdict,
};
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_udp_port;

const PROXY_ID: &str = "udp-hook-concurrency";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;

/// Blocks client A's `BLOCK` datagram until `release` fires (after signaling
/// `entered`). Other payloads and other clients continue immediately.
/// `DENY` payloads are dropped; everything else is forwarded.
struct GatedClientADatagramHook {
    slow_client_ip: Arc<str>,
    entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
    /// Payloads observed for the slow client (post-gate ordering).
    seen_slow: Mutex<Vec<Vec<u8>>>,
    /// Payloads observed for the fast client.
    seen_fast: Mutex<Vec<Vec<u8>>>,
    /// Count of explicit deny verdicts (fail-closed drops).
    denied: AtomicU64,
}

impl GatedClientADatagramHook {
    fn new(
        slow_client_ip: Arc<str>,
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            slow_client_ip,
            entered: std::sync::Mutex::new(Some(entered)),
            release: Mutex::new(Some(release)),
            seen_slow: Mutex::new(Vec::new()),
            seen_fast: Mutex::new(Vec::new()),
            denied: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl Plugin for GatedClientADatagramHook {
    fn name(&self) -> &str {
        "test_gated_client_a_udp_datagram"
    }

    fn priority(&self) -> u16 {
        0
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        if ctx.direction != ferrum_edge::plugins::UdpDatagramDirection::ClientToBackend {
            return UdpDatagramVerdict::Forward;
        }

        if ctx.payload == b"DENY" {
            self.denied.fetch_add(1, Ordering::Relaxed);
            return UdpDatagramVerdict::Drop;
        }

        let is_slow = ctx.client_ip.as_ref() == self.slow_client_ip.as_ref();
        if is_slow && ctx.payload == b"BLOCK" {
            if let Some(tx) = self
                .entered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                let _ = tx.send(());
            }
            let release = self
                .release
                .lock()
                .await
                .take()
                .expect("BLOCK datagram must own the release receiver");
            let _ = release.await;
        }

        if is_slow {
            self.seen_slow.lock().await.push(ctx.payload.to_vec());
        } else {
            self.seen_fast.lock().await.push(ctx.payload.to_vec());
        }
        UdpDatagramVerdict::Forward
    }
}

fn udp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("udp hook concurrency".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Udp),
        dispatch_kind: DispatchKind::from(BackendScheme::Udp),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        tcp_idle_timeout_seconds: Some(0),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

async fn spawn_udp_echo_backend(socket: Arc<UdpSocket>) -> tokio::task::JoinHandle<()> {
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
    })
}

struct SpawnedUdpGateway {
    listen_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    metrics: Arc<UdpProxyMetrics>,
    plugin: Arc<GatedClientADatagramHook>,
    entered_rx: oneshot::Receiver<()>,
    release_tx: oneshot::Sender<()>,
}

async fn try_spawn_udp_gateway(
    backend_port: u16,
    listen_port: u16,
    slow_client_ip: Arc<str>,
) -> Option<SpawnedUdpGateway> {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let plugin = Arc::new(GatedClientADatagramHook::new(
        slow_client_ip,
        entered_tx,
        release_rx,
    ));

    let proxy = udp_proxy(listen_port, backend_port);
    let proxy_namespace = proxy.namespace.clone();
    let gateway_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plugin_cache =
        Arc::new(PluginCache::new(&gateway_config).expect("PluginCache builds with no plugins"));
    prepend_proxy_plugin_for_test(
        &plugin_cache,
        &proxy_namespace,
        PROXY_ID,
        Arc::clone(&plugin) as Arc<dyn Plugin>,
    )
    .expect("inject gated datagram plugin");
    let attached =
        plugin_cache.get_plugins_for_protocol(&proxy_namespace, PROXY_ID, ProxyProtocol::Udp);
    assert!(
        attached
            .iter()
            .any(|p| p.name() == "test_gated_client_a_udp_datagram"),
        "gated plugin must be attached to the UDP proxy chain"
    );

    let consumer_index = Arc::new(ferrum_edge::consumer_index::ConsumerIndex::new(
        &gateway_config.consumers,
    ));
    let load_balancer_cache = Arc::new(ferrum_edge::load_balancer::LoadBalancerCache::new(
        &gateway_config,
    ));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        gateway_config,
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ));
    let circuit_breaker_cache = Arc::new(CircuitBreakerCache::new());
    let dns_cache = DnsCache::new(DnsConfig::default());
    let metrics = Arc::new(UdpProxyMetrics::default());
    let started = Arc::new(AtomicBool::new(false));
    let adaptive_buffer = Arc::new(AdaptiveBufferTracker::new(
        true, true, 300, 8192, 262_144, 65_536, 6000,
    ));
    let overload = Arc::new(OverloadState::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_started = started.clone();
    let listener_metrics = Arc::clone(&metrics);
    let cfg = UdpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: PROXY_ID.to_string(),
        proxy_namespace,
        dns_cache,
        request_epoch,
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        shutdown: shutdown_rx,
        global_shutdown: None,
        metrics: listener_metrics,
        frontend_dtls_config: None,
        dtls_server_tx: None,
        tls_no_verify: false,
        tls_ca_bundle_path: None,
        max_sessions: 1024,
        frontend_tls_handshake_timeout_seconds: 10,
        cleanup_interval_seconds: 10,
        session_shard_amount: 0,
        circuit_breaker_cache,
        crls: Arc::new(Vec::new()),
        backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
        started: listener_started,
        sni_proxy_ids: None,
        adaptive_buffer,
        recvmmsg_batch_size: 64,
        overload,
        so_busy_poll_us: 0,
        udp_gro_enabled: false,
        udp_gso_enabled: false,
        udp_pktinfo_enabled: false,
        mesh_outbound_enforcement: empty_slot(),
    };
    let join = tokio::spawn(async move {
        let _ = start_udp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some(SpawnedUdpGateway {
                listen_port,
                shutdown_tx,
                join,
                metrics,
                plugin,
                entered_rx,
                release_tx,
            });
        }
        if join.is_finished() {
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

async fn spawn_udp_gateway_with_retry(
    backend_port: u16,
    slow_client_ip: Arc<str>,
) -> SpawnedUdpGateway {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve frontend UDP port");
        let listen_port = frontend.drop_and_take_port();
        if let Some(gateway) =
            try_spawn_udp_gateway(backend_port, listen_port, Arc::clone(&slow_client_ip)).await
        {
            return gateway;
        }
        eprintln!(
            "udp hook concurrency spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             {listen_port} failed — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!("udp listener never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts");
}

async fn echo_round_trip(
    client: &UdpSocket,
    gateway: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    client
        .send_to(payload, gateway)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(TEST_TIMEOUT, client.recv_from(&mut buf))
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;
    Ok(buf[..n].to_vec())
}

#[tokio::test]
async fn slow_udp_datagram_hook_for_client_a_does_not_block_client_b() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    // Bind client A first so we know its source IP for the gated plugin.
    // Client B uses a distinct loopback address (127.0.0.2): `UdpDatagramContext`
    // exposes client IP only, while sessions are keyed by full SocketAddr, so two
    // sockets on 127.0.0.1 would share an IP identity and poison seen_fast/seen_slow
    // even though their per-session hook workers remain independent.
    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("client A bind");
    let client_a_ip = Arc::from(
        client_a
            .local_addr()
            .expect("client A addr")
            .ip()
            .to_canonical()
            .to_string(),
    );

    let gateway = spawn_udp_gateway_with_retry(backend_port, Arc::clone(&client_a_ip)).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);

    let client_b = UdpSocket::bind("127.0.0.2:0").await.expect("client B bind");
    assert_ne!(
        client_a
            .local_addr()
            .expect("client A addr")
            .ip()
            .to_canonical(),
        client_b
            .local_addr()
            .expect("client B addr")
            .ip()
            .to_canonical(),
        "clients must have distinct IPs so the gated hook can attribute payloads"
    );

    // Establish both sessions with fast (non-gated) datagrams first. The bug
    // is in the established-session recv path, not first-datagram setup.
    let setup_a = echo_round_trip(&client_a, gateway_addr, b"setup-a")
        .await
        .expect("client A setup echo");
    assert_eq!(setup_a, b"setup-a");
    let setup_b = echo_round_trip(&client_b, gateway_addr, b"setup-b")
        .await
        .expect("client B setup echo");
    assert_eq!(setup_b, b"setup-b");

    // Park client A's next datagram inside the hook (per-session worker),
    // then prove client B still round-trips before release.
    client_a
        .send_to(b"BLOCK", gateway_addr)
        .await
        .expect("send BLOCK");
    // Queue follow-ups behind the gated datagram so release drains them in order.
    client_a
        .send_to(b"A2", gateway_addr)
        .await
        .expect("send A2");
    client_a
        .send_to(b"A3", gateway_addr)
        .await
        .expect("send A3");

    tokio::time::timeout(TEST_TIMEOUT, gateway.entered_rx)
        .await
        .expect("wait for gated hook entry")
        .expect("entered signal");

    let fast = echo_round_trip(&client_b, gateway_addr, b"fast-b")
        .await
        .expect("client B must complete while client A is gated");
    assert_eq!(fast, b"fast-b");

    // Deny must never reach the backend; allow must.
    client_b
        .send_to(b"DENY", gateway_addr)
        .await
        .expect("send DENY");
    let allowed = echo_round_trip(&client_b, gateway_addr, b"ALLOW")
        .await
        .expect("ALLOW must echo");
    assert_eq!(allowed, b"ALLOW");

    // Release A and collect its ordered echoes (BLOCK, A2, A3).
    gateway.release_tx.send(()).expect("release gated hook");
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65535];
    for _ in 0..3 {
        let (n, _) = tokio::time::timeout(TEST_TIMEOUT, client_a.recv_from(&mut buf))
            .await
            .expect("client A echo timeout")
            .expect("client A recv");
        got.push(buf[..n].to_vec());
    }
    assert_eq!(
        got,
        vec![b"BLOCK".to_vec(), b"A2".to_vec(), b"A3".to_vec()],
        "client A datagrams must preserve per-session ordering across the gate"
    );

    let seen_slow = gateway.plugin.seen_slow.lock().await.clone();
    let seen_fast = gateway.plugin.seen_fast.lock().await.clone();
    assert!(
        seen_slow.iter().any(|p| p == b"BLOCK")
            && seen_slow.iter().any(|p| p == b"A2")
            && seen_slow.iter().any(|p| p == b"A3"),
        "slow-client hook must observe BLOCK then follow-ups: {seen_slow:?}"
    );
    assert!(
        seen_fast.iter().any(|p| p == b"fast-b") && seen_fast.iter().any(|p| p == b"ALLOW"),
        "fast-client hook must observe forwarded payloads: {seen_fast:?}"
    );
    assert!(
        !seen_fast.iter().any(|p| p == b"DENY"),
        "DENY must not be recorded as forwarded: {seen_fast:?}"
    );
    assert_eq!(
        gateway.plugin.denied.load(Ordering::Relaxed),
        1,
        "DENY payload must produce exactly one Drop verdict"
    );
    assert_eq!(
        gateway.metrics.hook_ingress_drops.load(Ordering::Relaxed),
        0,
        "steady two-client traffic must not trip hook-ingress overload drops"
    );

    gateway.shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, gateway.join).await;
}

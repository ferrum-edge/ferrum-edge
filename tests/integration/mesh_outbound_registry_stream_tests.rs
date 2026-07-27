//! Integration tests for T5-B stream-family `REGISTRY_ONLY` enforcement.
//!
//! These tests exercise the TCP and UDP enforcement paths added by
//! `MeshOutboundEnforcement` directly through [`start_tcp_listener`] and
//! [`start_udp_listener`] — no full mesh harness is needed because the
//! enforcement check sits BEFORE backend dispatch and only consults the
//! enforcement slot. Driving it through the listener exercises the actual
//! call sites in `tcp_proxy::handle_tcp_connection_inner` and
//! `udp_proxy::process_datagram`.
//!
//! Coverage:
//!   - TCP admitted → connection completes round-trip through gateway.
//!   - TCP unadmitted → connection closes before backend dial; backend
//!     never sees a connect attempt; stream-decision counter increments
//!     with `protocol="tcp"`, `decision="deny"`.
//!   - UDP admitted → datagram round-trips through gateway.
//!   - UDP unadmitted → first datagram silently dropped; backend never
//!     sees it; stream-decision counter increments with `protocol="udp"`,
//!     `decision="deny"`.
//!   - Enforcement Skip path (non-outbound-capture listen_port) → traffic
//!     flows through unchanged so the policy never gates inbound listeners.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::outbound_enforcement::{
    MeshOutboundEnforcement, SharedMeshOutboundEnforcement, empty_slot,
};
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugins::mesh::outbound_registry::OutboundRegistry;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics, start_tcp_listener};
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;
use serde_json::json;

use crate::scaffolding::ports::reserve_port;

// Each test that asserts on the Prometheus stream-decision counter MUST
// scope its enforcement to a unique namespace label. The Prometheus
// registry is a process-wide global; sharing a namespace across
// parallel tests races the admit/deny snapshots taken by each test.
// Tests that don't read the counter (round-trip and Skip cases) can
// reuse a generic namespace tag.
const PASSTHROUGH_NAMESPACE: &str = "t5b-stream-tests-passthrough";
const TCP_DENY_NAMESPACE: &str = "t5b-stream-tests-tcp-deny";
const UDP_DENY_NAMESPACE: &str = "t5b-stream-tests-udp-deny";
const PROXY_ID: &str = "t5b-stream-proxy";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;

// ── Shared fixtures ───────────────────────────────────────────────────────

fn tcp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("t5b stream tcp proxy".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: DispatchKind::from(BackendScheme::Tcp),
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

fn udp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    let mut p = tcp_proxy(listen_port, backend_port);
    p.backend_scheme = Some(BackendScheme::Udp);
    p.dispatch_kind = DispatchKind::from(BackendScheme::Udp);
    p.id = format!("{PROXY_ID}-udp");
    p.name = Some("t5b stream udp proxy".to_string());
    p.udp_idle_timeout_seconds = 30;
    p
}

fn make_enforcement(
    namespace: &str,
    registry_entries: &[&str],
    capture_ports: Vec<u16>,
) -> SharedMeshOutboundEnforcement {
    let registry =
        OutboundRegistry::new(&json!({ "registry": registry_entries })).expect("valid registry");
    let enforcement =
        MeshOutboundEnforcement::from_registry(namespace.to_string(), capture_ports, registry);
    let slot = empty_slot();
    slot.store(Arc::new(Some(Arc::new(enforcement))));
    slot
}

/// Lightweight TCP echo backend on a bound listener. Used to verify
/// whether the gateway dialed the backend or rejected first.
async fn spawn_tcp_echo_backend(
    listener: TcpListener,
    accept_counter: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            accept_counter.fetch_add(1, Ordering::Relaxed);
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

/// Lightweight UDP echo backend on a bound socket. Returns the join
/// handle and a `bytes_received` counter so tests can verify whether
/// the backend ever saw a datagram.
async fn spawn_udp_echo_backend(
    socket: Arc<UdpSocket>,
    bytes_counter: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    })
}

// ── TCP enforcement ───────────────────────────────────────────────────────

/// Try once to spawn a TCP listener on `listen_port` with the supplied
/// enforcement slot. Returns `Some(...)` on successful bind, `None` on
/// bind-drop-rebind race or timeout (retried by the outer loop).
async fn try_spawn_tcp_listener(
    listen_port: u16,
    backend_port: u16,
    enforcement: SharedMeshOutboundEnforcement,
) -> Option<(
    u16,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<TcpProxyMetrics>,
)> {
    let proxy = tcp_proxy(listen_port, backend_port);
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
    let plugin_cache = Arc::new(
        ferrum_edge::plugin_cache::PluginCache::new(&gateway_config)
            .expect("PluginCache builds with no plugins"),
    );
    let consumer_index = Arc::new(ferrum_edge::consumer_index::ConsumerIndex::new(
        &gateway_config.consumers,
    ));
    let load_balancer_cache = Arc::new(ferrum_edge::load_balancer::LoadBalancerCache::new(
        &gateway_config,
    ));
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
    let adaptive_buffer = Arc::new(AdaptiveBufferTracker::new(
        true, true, 300, 8192, 262_144, 65_536, 6000,
    ));
    let overload = Arc::new(OverloadState::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config_swap = Arc::new(ArcSwap::from_pointee(gateway_config));

    let listener_started = started.clone();
    let listener_metrics = metrics.clone();
    let cfg = TcpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: PROXY_ID.to_string(),
        proxy_namespace: ferrum_edge::config::types::default_namespace(),
        config: config_swap,
        dns_cache,
        request_epoch,
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        frontend_tls_slot: Arc::new(ArcSwap::from_pointee(None)),
        shutdown: shutdown_rx,
        global_shutdown: None,
        metrics: listener_metrics,
        tls_no_verify: false,
        tls_ca_bundle_path: None,
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
        accept_threads: 1,
        tcp_fastopen_queue_len: 256,
        overload,
        ktls_enabled: false,
        io_uring_splice_enabled: false,
        record_mesh_mtls_metric: false,
        mesh_outbound_enforcement: enforcement,
        node_waypoint_identity_resolver: None,
        trusted_proxies: Arc::new(TrustedProxies::none()),
    };
    let join = tokio::spawn(async move {
        let _ = start_tcp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some((listen_port, shutdown_tx, join, metrics));
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

async fn spawn_tcp_listener_with_retry(
    backend_port: u16,
    enforcement: SharedMeshOutboundEnforcement,
) -> (
    u16,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<TcpProxyMetrics>,
) {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_port().await.expect("reserve frontend port");
        let frontend_port = frontend.drop_and_take_port();
        if let Some(handles) =
            try_spawn_tcp_listener(frontend_port, backend_port, enforcement.clone()).await
        {
            return handles;
        }
        eprintln!(
            "tcp listener spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             {frontend_port} failed — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!("tcp listener never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts");
}

#[tokio::test]
async fn tcp_admitted_destination_passes_through_to_backend() {
    // Backend bound + held so the gateway can dial it. The registry
    // contains `127.0.0.1:<backend_port>` so the destination is admitted.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("backend bind");
    let backend_addr = backend_listener.local_addr().expect("backend addr");
    let accept_counter = Arc::new(AtomicU64::new(0));
    let _backend = spawn_tcp_echo_backend(backend_listener, accept_counter.clone()).await;

    // Build enforcement: gateway will bind on a fresh port (set by retry),
    // and we mark that port as a mesh outbound capture port. The registry
    // admits the backend.
    let frontend = reserve_port().await.expect("reserve port for enforcement");
    let frontend_port = frontend.drop_and_take_port();
    let registry_entry = format!("127.0.0.1:{}", backend_addr.port());
    let enforcement = make_enforcement(
        PASSTHROUGH_NAMESPACE,
        &[&registry_entry],
        vec![frontend_port],
    );

    let (listen_port, shutdown_tx, join, _metrics) =
        try_spawn_tcp_listener(frontend_port, backend_addr.port(), enforcement)
            .await
            .expect("gateway listener bound");
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to gateway");
    stream.write_all(b"hello").await.expect("write payload");
    let mut buf = [0u8; 5];
    let read_result = tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut buf)).await;
    assert!(
        read_result.is_ok() && read_result.unwrap().is_ok(),
        "admitted destination must round-trip through gateway"
    );
    assert_eq!(&buf, b"hello", "echo backend should mirror payload");

    // Backend must have observed the connection.
    assert_eq!(
        accept_counter.load(Ordering::Relaxed),
        1,
        "admitted destination must reach backend"
    );

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

#[tokio::test]
async fn tcp_unadmitted_destination_is_dropped_before_backend_dial() {
    // Backend exists but the registry does NOT contain its address.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("backend bind");
    let backend_addr = backend_listener.local_addr().expect("backend addr");
    let accept_counter = Arc::new(AtomicU64::new(0));
    let _backend = spawn_tcp_echo_backend(backend_listener, accept_counter.clone()).await;

    // Registry admits a different host:port; backend is unadmitted.
    let frontend = reserve_port().await.expect("reserve port for enforcement");
    let frontend_port = frontend.drop_and_take_port();
    let enforcement = make_enforcement(
        TCP_DENY_NAMESPACE,
        &["mongo.allowed.io:27017"],
        vec![frontend_port],
    );

    let (listen_port, shutdown_tx, join, _metrics) =
        try_spawn_tcp_listener(frontend_port, backend_addr.port(), enforcement)
            .await
            .expect("gateway listener bound");
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    // Snapshot the prometheus deny counter before the attempt so we
    // can verify it increments by exactly one. Per-test namespace scoping
    // (TCP_DENY_NAMESPACE) keeps these counters independent of the admit
    // tests that may run in parallel.
    let deny_before = stream_deny_count(TCP_DENY_NAMESPACE, "tcp");
    let admit_before = stream_admit_count(TCP_DENY_NAMESPACE, "tcp");

    // Connect succeeds (TCP accept happens regardless), but then the
    // gateway closes after the enforcement check. The read side sees EOF.
    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("tcp accept must complete");
    let _ = stream.write_all(b"hello").await;
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut buf)).await;
    // The relay never starts, so the read returns EOF (Ok(0)) or an
    // error after close. Either way, no echo bytes arrive.
    match read {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) => panic!("expected EOF/error on unadmitted dest, got {n} bytes"),
    }

    // Backend MUST NOT have observed the connection — the enforcement
    // check runs BEFORE the backend dial.
    assert_eq!(
        accept_counter.load(Ordering::Relaxed),
        0,
        "unadmitted destination must NOT reach backend"
    );

    // Counter incremented for the deny path; admit did not (admit is
    // scoped to its own namespace so cross-test races are impossible).
    let deny_after = stream_deny_count(TCP_DENY_NAMESPACE, "tcp");
    let admit_after = stream_admit_count(TCP_DENY_NAMESPACE, "tcp");
    assert_eq!(
        deny_after - deny_before,
        1,
        "tcp deny counter must increment exactly once; before={deny_before}, after={deny_after}"
    );
    assert_eq!(
        admit_after - admit_before,
        0,
        "tcp admit counter must NOT increment for rejected dest"
    );

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

#[tokio::test]
async fn tcp_skips_enforcement_when_listener_not_in_capture_ports() {
    // Same backend + unadmitted-by-registry destination as the deny test,
    // but the enforcement's capture-port list does NOT contain our
    // gateway port. Result: `Decision::Skip` → traffic flows through.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("backend bind");
    let backend_addr = backend_listener.local_addr().expect("backend addr");
    let accept_counter = Arc::new(AtomicU64::new(0));
    let _backend = spawn_tcp_echo_backend(backend_listener, accept_counter.clone()).await;

    // Enforcement points at a DIFFERENT port (15006 — conventional inbound).
    // The gateway will bind on a fresh port → Skip applies.
    let enforcement = make_enforcement(
        PASSTHROUGH_NAMESPACE,
        &["mongo.allowed.io:27017"],
        vec![15006],
    );

    let (listen_port, shutdown_tx, join, _metrics) =
        spawn_tcp_listener_with_retry(backend_addr.port(), enforcement).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to gateway");
    stream.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    let _ = tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("Skip path must round-trip")
        .expect("read");
    assert_eq!(&buf, b"hello");
    assert_eq!(
        accept_counter.load(Ordering::Relaxed),
        1,
        "Skip path: backend must be dialed"
    );

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

// ── UDP enforcement ───────────────────────────────────────────────────────

async fn try_spawn_udp_listener(
    listen_port: u16,
    backend_port: u16,
    enforcement: SharedMeshOutboundEnforcement,
) -> Option<(u16, watch::Sender<bool>, tokio::task::JoinHandle<()>)> {
    let proxy = udp_proxy(listen_port, backend_port);
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
    let plugin_cache = Arc::new(
        ferrum_edge::plugin_cache::PluginCache::new(&gateway_config)
            .expect("PluginCache builds with no plugins"),
    );
    let consumer_index = Arc::new(ferrum_edge::consumer_index::ConsumerIndex::new(
        &gateway_config.consumers,
    ));
    let load_balancer_cache = Arc::new(ferrum_edge::load_balancer::LoadBalancerCache::new(
        &gateway_config,
    ));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        gateway_config.clone(),
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
    let cfg = UdpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: format!("{PROXY_ID}-udp"),
        proxy_namespace: ferrum_edge::config::types::default_namespace(),
        dns_cache,
        request_epoch,
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        shutdown: shutdown_rx,
        global_shutdown: None,
        metrics,
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
        mesh_outbound_enforcement: enforcement,
    };
    let join = tokio::spawn(async move {
        let _ = start_udp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some((listen_port, shutdown_tx, join));
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

async fn spawn_udp_listener_with_retry(
    backend_port: u16,
    enforcement: SharedMeshOutboundEnforcement,
) -> (u16, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_port().await.expect("reserve frontend port");
        let frontend_port = frontend.drop_and_take_port();
        if let Some(handles) =
            try_spawn_udp_listener(frontend_port, backend_port, enforcement.clone()).await
        {
            return handles;
        }
        eprintln!(
            "udp listener spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             {frontend_port} failed — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!("udp listener never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts");
}

#[tokio::test]
async fn udp_admitted_destination_passes_through_to_backend() {
    let backend_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_addr = backend_socket.local_addr().expect("backend addr");
    let backend_bytes = Arc::new(AtomicU64::new(0));
    let _backend = spawn_udp_echo_backend(backend_socket, backend_bytes.clone()).await;

    let frontend = reserve_port().await.expect("reserve frontend port");
    let frontend_port = frontend.drop_and_take_port();
    let registry_entry = format!("127.0.0.1:{}", backend_addr.port());
    let enforcement = make_enforcement(
        PASSTHROUGH_NAMESPACE,
        &[&registry_entry],
        vec![frontend_port],
    );

    let (listen_port, shutdown_tx, join) =
        try_spawn_udp_listener(frontend_port, backend_addr.port(), enforcement)
            .await
            .expect("udp listener bound");
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client.send_to(b"ping", gateway_addr).await.expect("send");
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(TEST_TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("admitted UDP must round-trip");
    let (n, _) = read.expect("UDP recv");
    assert_eq!(n, 4);
    assert_eq!(&buf, b"ping");
    assert!(
        backend_bytes.load(Ordering::Relaxed) >= 4,
        "admitted destination must reach backend"
    );

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

#[tokio::test]
async fn udp_unadmitted_destination_is_silently_dropped() {
    // Backend bound — but registry does NOT admit it.
    let backend_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_addr = backend_socket.local_addr().expect("backend addr");
    let backend_bytes = Arc::new(AtomicU64::new(0));
    let _backend = spawn_udp_echo_backend(backend_socket, backend_bytes.clone()).await;

    let frontend = reserve_port().await.expect("reserve frontend port");
    let frontend_port = frontend.drop_and_take_port();
    let enforcement = make_enforcement(
        UDP_DENY_NAMESPACE,
        &["redis.allowed.io:6379"],
        vec![frontend_port],
    );

    let (listen_port, shutdown_tx, join) =
        try_spawn_udp_listener(frontend_port, backend_addr.port(), enforcement)
            .await
            .expect("udp listener bound");
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let deny_before = stream_deny_count(UDP_DENY_NAMESPACE, "udp");
    let admit_before = stream_admit_count(UDP_DENY_NAMESPACE, "udp");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client.send_to(b"ping", gateway_addr).await.expect("send");
    let mut buf = [0u8; 64];
    // No echo should come back — silent drop. Use a short timeout to
    // bound test duration.
    let read = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await;
    assert!(
        read.is_err(),
        "UDP rejected datagram must not produce a backend echo"
    );
    assert_eq!(
        backend_bytes.load(Ordering::Relaxed),
        0,
        "unadmitted destination must NOT reach backend"
    );

    let deny_after = stream_deny_count(UDP_DENY_NAMESPACE, "udp");
    let admit_after = stream_admit_count(UDP_DENY_NAMESPACE, "udp");
    assert_eq!(
        deny_after - deny_before,
        1,
        "udp deny counter must increment exactly once"
    );
    assert_eq!(
        admit_after - admit_before,
        0,
        "udp admit counter must NOT increment for rejected dest"
    );

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

#[tokio::test]
async fn udp_skips_enforcement_when_listener_not_in_capture_ports() {
    let backend_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_addr = backend_socket.local_addr().expect("backend addr");
    let backend_bytes = Arc::new(AtomicU64::new(0));
    let _backend = spawn_udp_echo_backend(backend_socket, backend_bytes.clone()).await;

    // Enforcement points at a DIFFERENT port; gateway port is not in
    // the capture set → Skip → traffic flows through.
    let enforcement = make_enforcement(
        PASSTHROUGH_NAMESPACE,
        &["redis.allowed.io:6379"],
        vec![15006],
    );

    let (listen_port, shutdown_tx, join) =
        spawn_udp_listener_with_retry(backend_addr.port(), enforcement).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client.send_to(b"ping", gateway_addr).await.expect("send");
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(TEST_TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("Skip path must round-trip");
    let (n, _) = read.expect("UDP recv");
    assert_eq!(n, 4);

    shutdown_tx.send(true).expect("shutdown");
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
}

// ── Prometheus assertion helpers ──────────────────────────────────────────

/// Look up the current count for the stream-decision counter scoped to
/// the given test namespace. Returns 0 when the counter row does not
/// yet exist (e.g., before the first decision). Tests MUST pass distinct
/// namespaces when asserting on the counter to avoid racing with parallel
/// tests against the shared process-wide Prometheus registry.
fn stream_decision_count(mesh_namespace: &str, protocol: &str, decision: &str) -> u64 {
    let rendered = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    // Render shape:
    //   ferrum_mesh_outbound_registry_stream_decisions_total{mesh_namespace="…",protocol="…",decision="…"} N
    let needle = format!(
        "ferrum_mesh_outbound_registry_stream_decisions_total{{mesh_namespace=\"{}\",protocol=\"{}\",decision=\"{}\"",
        mesh_namespace, protocol, decision
    );
    for line in rendered.lines() {
        if let Some(rest) = line.strip_prefix(needle.as_str())
            && let Some(value_str) = rest.split_whitespace().last()
            && let Ok(value) = value_str.parse::<u64>()
        {
            return value;
        }
    }
    0
}

fn stream_admit_count(mesh_namespace: &str, protocol: &str) -> u64 {
    stream_decision_count(mesh_namespace, protocol, "admit")
}

fn stream_deny_count(mesh_namespace: &str, protocol: &str) -> u64 {
    stream_decision_count(mesh_namespace, protocol, "deny")
}

//! Live-path coverage for issue #3293: non-blocking UDP/DTLS fault injection.
//!
//! Delays and aborts run on isolated per-session (or first-datagram setup)
//! work, never inside the shared listener recv loop. Client B must complete
//! while client A is parked on an injected delay.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::ProxyProtocol;
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_udp_port;

const PROXY_ID: &str = "udp-fault-injection";
const PLUGIN_CONFIG_ID: &str = "udp-fault-plugin";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;

fn fault_plugin_config(config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: PLUGIN_CONFIG_ID.to_string(),
        plugin_name: "fault_injection".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn udp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("udp fault injection".to_string()),
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
        plugins: vec![PluginAssociation {
            plugin_config_id: PLUGIN_CONFIG_ID.to_string(),
        }],
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
}

async fn try_spawn_udp_gateway(
    backend_port: u16,
    listen_port: u16,
    fault_config: serde_json::Value,
) -> Option<SpawnedUdpGateway> {
    let proxy = udp_proxy(listen_port, backend_port);
    let proxy_namespace = proxy.namespace.clone();
    let gateway_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs: vec![fault_plugin_config(fault_config)],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plugin_cache = Arc::new(
        PluginCache::new(&gateway_config).expect("PluginCache builds with fault_injection"),
    );
    let attached =
        plugin_cache.get_plugins_for_protocol(&proxy_namespace, PROXY_ID, ProxyProtocol::Udp);
    assert!(
        attached.iter().any(|p| p.name() == "fault_injection"),
        "fault_injection must attach to UDP"
    );
    assert!(
        attached.iter().any(|p| p.requires_udp_datagram_hooks()),
        "fault_injection must opt into on_udp_datagram"
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
    fault_config: serde_json::Value,
) -> SpawnedUdpGateway {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve frontend UDP port");
        let listen_port = frontend.drop_and_take_port();
        if let Some(gateway) =
            try_spawn_udp_gateway(backend_port, listen_port, fault_config.clone()).await
        {
            return gateway;
        }
        eprintln!(
            "udp fault injection spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
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

async fn expect_no_echo(client: &UdpSocket, gateway: SocketAddr, payload: &[u8]) {
    client
        .send_to(payload, gateway)
        .await
        .expect("send aborted datagram");
    let mut buf = vec![0u8; 65535];
    let timed_out = tokio::time::timeout(Duration::from_millis(400), client.recv_from(&mut buf))
        .await
        .is_err();
    assert!(
        timed_out,
        "aborted client→backend datagram must not produce an echo"
    );
}

#[tokio::test]
async fn udp_abort_drops_datagram_without_echo() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    let gateway = spawn_udp_gateway_with_retry(
        backend_port,
        json!({ "abort": { "status_code": 503, "percentage": 100.0 } }),
    )
    .await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    expect_no_echo(&client, gateway_addr, b"drop-me").await;

    let _ = gateway.shutdown_tx.send(true);
    let _ = gateway.join.await;
}

#[tokio::test]
async fn udp_delay_for_client_a_does_not_block_client_b() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    // Long delay so overlapping peers prove isolation. With shared-loop HOL,
    // B would wait for A's remaining delay plus B's own delay (~4s). Isolated
    // session workers overlap, so B completes in ~2s from its own send.
    let gateway = spawn_udp_gateway_with_retry(
        backend_port,
        json!({ "delay": { "duration_ms": 2_000, "percentage": 100.0 } }),
    )
    .await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);

    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("client A bind");
    let client_b = UdpSocket::bind("127.0.0.2:0").await.expect("client B bind");

    client_a
        .send_to(b"slow-a", gateway_addr)
        .await
        .expect("send slow-a");

    // Give A's isolated worker time to enter the fault delay.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let b_start = std::time::Instant::now();
    let fast = echo_round_trip(&client_b, gateway_addr, b"fast-b")
        .await
        .expect("client B must complete on its own delay budget");
    let b_elapsed = b_start.elapsed();
    assert_eq!(fast, b"fast-b");
    assert!(
        b_elapsed >= Duration::from_millis(1_500) && b_elapsed < Duration::from_millis(3_200),
        "client B must wait only its own ~2s delay while A is also delayed, got {b_elapsed:?}"
    );

    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(TEST_TIMEOUT, client_a.recv_from(&mut buf))
        .await
        .expect("client A delayed echo timeout")
        .expect("client A recv");
    assert_eq!(&buf[..n], b"slow-a");

    let _ = gateway.shutdown_tx.send(true);
    let _ = gateway.join.await;
}

#[tokio::test]
async fn udp_session_connect_abort_refuses_new_session() {
    let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("backend bind"));
    let backend_port = backend.local_addr().expect("backend addr").port();
    let _backend = spawn_udp_echo_backend(Arc::clone(&backend)).await;

    // 100% abort on stream connect and datagram: first datagram is dropped by
    // on_udp_datagram before session setup can complete an echo.
    let gateway = spawn_udp_gateway_with_retry(
        backend_port,
        json!({ "abort": { "status_code": 503, "percentage": 100.0 } }),
    )
    .await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway.listen_port);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    expect_no_echo(&client, gateway_addr, b"never").await;
    expect_no_echo(&client, gateway_addr, b"still-never").await;

    let _ = gateway.shutdown_tx.send(true);
    let _ = gateway.join.await;
}

#[tokio::test]
async fn plugin_cache_reload_removes_udp_fault_injection() {
    let proxy = udp_proxy(19_001, 19_002);
    let with_fault = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy.clone()],
        consumers: vec![],
        plugin_configs: vec![fault_plugin_config(json!({
            "abort": { "status_code": 503, "percentage": 100.0 }
        }))],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let cache = PluginCache::new(&with_fault).expect("cache with fault");
    let ns = proxy.namespace.clone();
    assert!(
        cache
            .get_plugins_for_protocol(&ns, PROXY_ID, ProxyProtocol::Udp)
            .iter()
            .any(|p| p.name() == "fault_injection")
    );

    let without_fault = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![Proxy {
            plugins: vec![],
            ..proxy
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    cache
        .rebuild(&without_fault)
        .expect("rebuild without fault");
    assert!(
        cache
            .get_plugins_for_protocol(&ns, PROXY_ID, ProxyProtocol::Udp)
            .iter()
            .all(|p| p.name() != "fault_injection"),
        "delete/reload must detach fault_injection from UDP"
    );
}

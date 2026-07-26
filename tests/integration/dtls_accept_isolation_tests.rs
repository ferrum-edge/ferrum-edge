//! Regression for issue #2960: DTLS `on_stream_connect` admission must not
//! run inline in the shared accept loop.
//!
//! A gated first admission holds a channel barrier inside `on_stream_connect`
//! while a second client is accepted and completes an echo round-trip. The
//! second client's progress is asserted *before* the first admission is
//! released, proving accept-loop isolation without wall-clock-only timing.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};

use ferrum_edge::_test_support::prepend_proxy_plugin_for_test;
use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamConnectionContext, UDP_ONLY_PROTOCOLS,
};
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::clients::dtls::DtlsClient;
use crate::scaffolding::ports::{reserve_port, reserve_udp_port};

const PROXY_ID: &str = "dtls-accept-isolation";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;

/// Blocks the first `on_stream_connect` until `release` fires, after signaling
/// `entered`. Later admissions continue immediately.
struct GatedFirstStreamConnect {
    entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    first_taken: AtomicBool,
}

impl GatedFirstStreamConnect {
    fn new(entered: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            entered: std::sync::Mutex::new(Some(entered)),
            release: tokio::sync::Mutex::new(Some(release)),
            first_taken: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl Plugin for GatedFirstStreamConnect {
    fn name(&self) -> &str {
        "test_gated_first_stream_connect"
    }

    fn priority(&self) -> u16 {
        0
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        if self
            .first_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return PluginResult::Continue;
        }

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
            .expect("first admission must own the release receiver");
        let _ = release.await;
        PluginResult::Continue
    }
}

fn dtls_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("dtls accept isolation".to_string()),
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
        frontend_tls: true,
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

fn write_frontend_dtls_material(temp_dir: &tempfile::TempDir) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate DTLS frontend key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("DTLS frontend cert params");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-sign DTLS frontend cert");
    let cert_path = temp_dir.path().join("dtls-frontend-cert.pem");
    let key_path = temp_dir.path().join("dtls-frontend-key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write DTLS cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write DTLS key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

struct SpawnedDtlsGateway {
    listen_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    metrics: Arc<UdpProxyMetrics>,
    entered_rx: oneshot::Receiver<()>,
    release_tx: oneshot::Sender<()>,
}

async fn try_spawn_dtls_gateway(
    backend_port: u16,
    listen_port: u16,
    cert_path: &str,
    key_path: &str,
) -> Option<SpawnedDtlsGateway> {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let gate = Arc::new(GatedFirstStreamConnect::new(entered_tx, release_rx));

    let proxy = dtls_proxy(listen_port, backend_port);
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
    prepend_proxy_plugin_for_test(&plugin_cache, PROXY_ID, gate)
        .expect("inject gated stream-connect plugin");
    let attached = plugin_cache.get_plugins_for_protocol(PROXY_ID, ProxyProtocol::Udp);
    assert!(
        attached
            .iter()
            .any(|plugin| plugin.name() == "test_gated_first_stream_connect"),
        "gated plugin must be attached to the DTLS proxy Udp chain"
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
    let frontend_dtls_config =
        ferrum_edge::dtls::build_frontend_dtls_config(cert_path, key_path, None, &[])
            .expect("build frontend DTLS config");

    let listener_started = started.clone();
    let listener_metrics = metrics.clone();
    let cfg = UdpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: PROXY_ID.to_string(),
        dns_cache,
        request_epoch,
        health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
        shutdown: shutdown_rx,
        global_shutdown: None,
        metrics: listener_metrics,
        frontend_dtls_config: Some(frontend_dtls_config),
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
            return Some(SpawnedDtlsGateway {
                listen_port,
                shutdown_tx,
                join,
                metrics,
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

async fn spawn_dtls_gateway_with_retry(
    backend_port: u16,
    cert_path: &str,
    key_path: &str,
) -> SpawnedDtlsGateway {
    let mut last_port = 0u16;
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_port().await.expect("reserve frontend port");
        let frontend_port = frontend.drop_and_take_port();
        last_port = frontend_port;
        if let Some(handles) =
            try_spawn_dtls_gateway(backend_port, frontend_port, cert_path, key_path).await
        {
            return handles;
        }
        eprintln!(
            "DTLS accept-isolation gateway start attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             port {frontend_port} failed (likely bind race) — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!(
        "DTLS gateway never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts; \
         last attempted port: {last_port}"
    );
}

#[tokio::test]
async fn dtls_accept_loop_progresses_while_first_stream_connect_is_blocked() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let backend = reserve_udp_port().await.expect("reserve backend UDP port");
    let backend_port = backend.port;
    let backend_socket = Arc::new(backend.into_socket());
    let echo = spawn_udp_echo_backend(backend_socket).await;

    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let (cert_path, key_path) = write_frontend_dtls_material(&temp_dir);

    let SpawnedDtlsGateway {
        listen_port,
        shutdown_tx,
        join,
        metrics,
        entered_rx,
        release_tx,
    } = spawn_dtls_gateway_with_retry(backend_port, &cert_path, &key_path).await;
    let gateway_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, listen_port));

    // Client 1: handshake completes, then blocks inside on_stream_connect.
    let blocked_client = tokio::spawn(async move {
        let client = DtlsClient::connect(gateway_addr)
            .await
            .expect("blocked client DTLS handshake");
        // Application data is only forwarded after admission; this send may
        // complete locally while the gateway task is still gated.
        let _ = client.send_datagram(b"blocked-client").await;
        client
    });

    tokio::time::timeout(TEST_TIMEOUT, entered_rx)
        .await
        .expect("first admission must enter on_stream_connect")
        .expect("entered signal must be sent");

    // Client 2 must be accepted and echo while client 1 is still gated.
    let second = DtlsClient::connect(gateway_addr)
        .await
        .expect("second client DTLS handshake must not wait on first admission");
    second
        .send_datagram(b"second-client")
        .await
        .expect("second client send");
    let echoed = second
        .recv_datagram_with_timeout(TEST_TIMEOUT)
        .await
        .expect("second client must receive echo while first admission is blocked");
    assert_eq!(
        echoed.as_slice(),
        b"second-client",
        "second DTLS client must progress independently of a blocked peer admission"
    );
    second.close().await;

    // Ordering seam: only now release the first admission.
    release_tx
        .send(())
        .expect("release first admission after second client progressed");

    // Wait until the previously gated session is counted as admitted.
    let admitted = tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if metrics.total_sessions.load(Ordering::Relaxed) >= 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "first DTLS session must complete admission after release; total_sessions={}",
        metrics.total_sessions.load(Ordering::Relaxed)
    );

    let blocked = tokio::time::timeout(TEST_TIMEOUT, blocked_client)
        .await
        .expect("blocked client task must finish")
        .expect("blocked client task must not panic");
    // After release, the first session may still complete forwarding; drain
    // any late echo without asserting on wall-clock latency.
    let _ = blocked
        .recv_datagram_with_timeout(Duration::from_millis(250))
        .await;
    blocked.close().await;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(TEST_TIMEOUT, join).await;
    echo.abort();
}

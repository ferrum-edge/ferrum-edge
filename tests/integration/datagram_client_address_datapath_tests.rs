//! Live UDP and DTLS datapaths for the datagram client-address envelope
//! (issues #3289, #3856, #3862).
//!
//! A real `start_udp_listener` runs with the gate engaged, a real UDP client
//! plays the trusted datagram load balancer, and a real echo backend answers.
//! What is asserted is what the feature exists for: the authenticated forwarded
//! address becomes the plugin-visible `client_ip` while `direct_client_ip`
//! stays the balancer's socket peer, the backend receives the payload with the
//! envelope stripped, and every unauthenticated, malformed, cross-listener, or
//! replayed variant is dropped with nothing reaching the backend.
//!
//! Two listeners run side by side under one root secret so the #3856 contract is
//! exercised the way an operator would hit it: an envelope minted for listener A
//! and replayed byte-for-byte at listener B must be refused for every envelope
//! form, including `LOCAL` and `AF_UNSPEC`, which carry no forwarded identity.
//! A same-listener verbatim replay is refused by the #3862 window, and the
//! backend must see the payload exactly once.
//!
//! The DTLS listener has its own pre-demux path, so it is covered separately
//! against a real `DtlsServer`: a wrapping relay drives a real `dimpl`
//! handshake through the gate, proving the envelope is validated and stripped
//! before the record layer and that the authenticated forwarded client reaches
//! the accepted `DtlsServerConn`, while handshake-shaped datagrams that fail
//! the gate — bare, unsigned, foreign-keyed, cross-listener, or replayed —
//! allocate no association at all.

use crate::scaffolding::port_registry::TestSocket;
use crate::scaffolding::ports::bind_dtls_with_limits;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};

use ferrum_edge::_test_support::prepend_proxy_plugin_for_test;
use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::dtls::{BackendDtlsParams, DtlsConnection, DtlsServerLimits, FrontendDtlsConfig};
use ferrum_edge::fips::approved::HmacSha256Key;
use ferrum_edge::modes::mesh::outbound_enforcement::empty_slot;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamConnectionContext, UDP_ONLY_PROTOCOLS,
    UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::datagram_client_address::{
    DatagramClientAddressGate, DatagramEnvelopeAuth, DatagramEnvelopeForm, DatagramFreshness,
    DatagramListenerBinding, DatagramListenerProtocol, FRESHNESS_HORIZON_MS,
    encode_datagram_with_metadata, unix_now_millis,
};
use ferrum_edge::proxy::udp_proxy::{UdpListenerConfig, UdpProxyMetrics, start_udp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;

use crate::scaffolding::ports::reserve_udp_port;

const PROXY_ID: &str = "udp-datagram-client-address";
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const RECV_TIMEOUT: Duration = Duration::from_secs(5);
const DROP_OBSERVATION_WINDOW: Duration = Duration::from_millis(250);
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;
/// Every envelope form an authenticated balancer may emit. All four must be
/// bound to the receiving listener (#3856) and replay-protected (#3862).
const ALL_FORMS: [&str; 4] = ["LOCAL", "AF_UNSPEC", "IPv4", "IPv6"];

/// Records the identities the gateway published for admitted traffic.
#[derive(Default)]
struct IdentityRecorder {
    /// `(client_ip, direct_client_ip)` from `on_stream_connect`.
    stream: Mutex<Vec<(String, String)>>,
    /// `client_ip` from each client→backend `on_udp_datagram`.
    datagram: Mutex<Vec<String>>,
    datagram_count: AtomicU64,
}

#[async_trait]
impl Plugin for IdentityRecorder {
    fn name(&self) -> &str {
        "test_datagram_identity_recorder"
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

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.stream
            .lock()
            .await
            .push((ctx.client_ip.clone(), ctx.direct_client_ip.clone()));
        PluginResult::Continue
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        if ctx.direction == UdpDatagramDirection::ClientToBackend {
            self.datagram_count.fetch_add(1, Ordering::Relaxed);
            self.datagram.lock().await.push(ctx.client_ip.to_string());
        }
        UdpDatagramVerdict::Forward
    }
}

fn udp_proxy(listen_port: u16, backend_port: u16) -> Proxy {
    Proxy {
        labels: Default::default(),
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Datagram client address".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Udp),
        dispatch_kind: DispatchKind::UdpRaw,
        backend_host: "127.0.0.1".to_string(),
        backend_port,
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
        // The datagram client-address envelope is required on this listener.
        stream_proxy_protocol: Some(true),
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        tcp_idle_timeout_seconds: Some(0),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

/// An echo backend that also counts how many datagrams it was actually handed,
/// so "the backend saw this payload exactly once" is an observation rather than
/// an inference from a missing reply.
async fn spawn_counting_echo_backend(
    socket: Arc<UdpSocket>,
    received: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    received.fetch_add(1, Ordering::Relaxed);
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    })
}

struct SpawnedGateway {
    listen_port: u16,
    binding: DatagramListenerBinding,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    metrics: Arc<UdpProxyMetrics>,
    recorder: Arc<IdentityRecorder>,
}

impl SpawnedGateway {
    fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.listen_port)
    }

    fn drops(&self) -> u64 {
        self.metrics
            .client_address_metadata_drops
            .load(Ordering::Relaxed)
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(RECV_TIMEOUT, self.join).await;
    }
}

async fn try_spawn_gateway(
    backend_port: u16,
    listen_port: u16,
    authenticated: bool,
) -> Option<SpawnedGateway> {
    let recorder = Arc::new(IdentityRecorder::default());
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
        Arc::clone(&recorder) as Arc<dyn Plugin>,
    )
    .expect("inject identity recorder");

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
    let metrics = Arc::new(UdpProxyMetrics::default());
    let started = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // The test client plays the trusted load balancer on loopback.
    let trusted_proxies =
        Arc::new(TrustedProxies::parse_strict("127.0.0.1", "test").expect("trust list"));
    // The binding the production listener would build for this spawn: plain-UDP
    // receive boundary, the loopback bind address, this listener's port.
    let binding = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        listen_port,
    );
    let gate = Arc::new(DatagramClientAddressGate::new(
        trusted_proxies,
        authenticated.then_some(SECRET),
        binding,
        0,
    ));

    let listener_started = Arc::clone(&started);
    let listener_metrics = Arc::clone(&metrics);
    let cfg = UdpListenerConfig {
        port: listen_port,
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_id: PROXY_ID.to_string(),
        proxy_namespace,
        dns_cache: DnsCache::new(DnsConfig::default()),
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
        circuit_breaker_cache: Arc::new(CircuitBreakerCache::new()),
        crls: Arc::new(Vec::new()),
        backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
        tls_policy: None,
        started: listener_started,
        sni_proxy_ids: None,
        adaptive_buffer: Arc::new(AdaptiveBufferTracker::new(
            true, true, 300, 8192, 262_144, 65_536, 6000,
        )),
        recvmmsg_batch_size: 64,
        overload: Arc::new(OverloadState::new()),
        so_busy_poll_us: 0,
        udp_gro_enabled: false,
        udp_gso_enabled: false,
        udp_pktinfo_enabled: false,
        mesh_outbound_enforcement: empty_slot(),
        node_waypoint_udp_source_scoping: None,
        node_waypoint_udp_owner: false,
        node_waypoint_udp_destinations: None,
        datagram_client_address: Some(gate),
    };
    let join = tokio::spawn(async move {
        let _ = start_udp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some(SpawnedGateway {
                listen_port,
                binding,
                shutdown_tx,
                join,
                metrics,
                recorder,
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

async fn spawn_gateway(backend_port: u16, authenticated: bool) -> SpawnedGateway {
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve frontend UDP port");
        let listen_port = frontend.drop_and_take_port();
        if let Some(gateway) = try_spawn_gateway(backend_port, listen_port, authenticated).await {
            return gateway;
        }
        eprintln!(
            "datagram client-address spawn attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
             {listen_port} failed — retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    panic!("udp listener never reported started=true after {MAX_GATEWAY_ATTEMPTS} attempts");
}

fn key() -> HmacSha256Key {
    HmacSha256Key::new_from_slice(SECRET.as_bytes()).expect("hmac key")
}

/// The forwarded client every fixture speaks for.
fn forwarded_client() -> SocketAddr {
    "203.0.113.9:41234".parse().expect("client addr")
}

/// The trusted datagram load balancer: one stable sender id and epoch, a
/// monotonic sequence, and the root secret.
struct Balancer {
    key: HmacSha256Key,
    sender_id: u32,
    epoch: u64,
    next_sequence: u64,
}

impl Balancer {
    fn new(sender_id: u32) -> Self {
        Self::with_key(sender_id, key())
    }

    fn with_key(sender_id: u32, key: HmacSha256Key) -> Self {
        Self {
            key,
            sender_id,
            epoch: 1,
            next_sequence: 0,
        }
    }

    /// Wrap `payload` for `binding` at an explicit sequence and timestamp.
    fn wrap_at(
        &self,
        binding: &DatagramListenerBinding,
        form: DatagramEnvelopeForm,
        payload: &[u8],
        sequence: u64,
        timestamp_ms: u64,
    ) -> Vec<u8> {
        let freshness = DatagramFreshness {
            sender_id: self.sender_id,
            epoch: self.epoch,
            sequence,
            timestamp_ms,
        };
        let auth = DatagramEnvelopeAuth {
            key: &self.key,
            binding,
            freshness,
        };
        encode_datagram_with_metadata(form, payload, Some(&auth))
    }

    /// Wrap `payload` for `binding`, consuming the next sequence.
    fn wrap(
        &mut self,
        binding: &DatagramListenerBinding,
        form: DatagramEnvelopeForm,
        payload: &[u8],
    ) -> Vec<u8> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.wrap_at(binding, form, payload, sequence, unix_now_millis())
    }
}

/// The address-bearing IPv4 form aimed at `destination`.
fn v4_form(destination: SocketAddr) -> DatagramEnvelopeForm {
    DatagramEnvelopeForm::Forwarded {
        source: forwarded_client(),
        destination,
    }
}

/// The address-bearing IPv6 form declaring `destination`'s port.
fn v6_form(destination: SocketAddr) -> DatagramEnvelopeForm {
    let dest = format!("[2001:db8::1]:{}", destination.port());
    DatagramEnvelopeForm::Forwarded {
        source: "[2001:db8::10]:41234".parse().expect("v6 client"),
        destination: dest.parse().expect("v6 destination"),
    }
}

/// The four envelope forms, selected by label so every form-parameterized test
/// reads the same way.
fn envelope_form(label: &str, destination: SocketAddr) -> DatagramEnvelopeForm {
    match label {
        "LOCAL" => DatagramEnvelopeForm::Local,
        "AF_UNSPEC" => DatagramEnvelopeForm::Unspec,
        "IPv4" => v4_form(destination),
        "IPv6" => v6_form(destination),
        other => panic!("unknown envelope form {other}"),
    }
}

/// An unauthenticated envelope: the address-trust posture only.
fn plain(form: DatagramEnvelopeForm, payload: &[u8]) -> Vec<u8> {
    encode_datagram_with_metadata(form, payload, None)
}

/// Run a datagram load-balancer shim between one DTLS client and Ferrum's DTLS
/// demuxer. The first ClientHello is deliberately replayed without an envelope
/// and must be dropped; every retransmission and application packet is wrapped
/// with authenticated client-address metadata carrying a fresh sequence. Server
/// packets travel back unchanged because the envelope is an inbound
/// load-balancer contract.
async fn spawn_dtls_metadata_relay(
    server_addr: SocketAddr,
    binding: DatagramListenerBinding,
    forwarded: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind DTLS metadata relay"),
    );
    let relay_addr = socket.local_addr().expect("DTLS metadata relay addr");
    let task = tokio::spawn(async move {
        let mut balancer = Balancer::new(7);
        let mut client_addr = None;
        let mut replayed_bare_client_hello = false;
        let mut buf = vec![0u8; 65_535];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if peer == server_addr {
                if let Some(client_addr) = client_addr {
                    let _ = socket.send_to(&buf[..len], client_addr).await;
                }
                continue;
            }

            if client_addr.is_some_and(|established| established != peer) {
                continue;
            }
            client_addr = Some(peer);

            if !replayed_bare_client_hello {
                replayed_bare_client_hello = true;
                let _ = socket.send_to(&buf[..len], server_addr).await;
                continue;
            }

            let form = DatagramEnvelopeForm::Forwarded {
                source: forwarded,
                destination: server_addr,
            };
            let wrapped = balancer.wrap(&binding, form, &buf[..len]);
            let _ = socket.send_to(&wrapped, server_addr).await;
        }
    });
    (relay_addr, task)
}

/// Receive one datagram, or `None` if the observation window elapses. Used both
/// for success (a reply must arrive) and for refusal (nothing may arrive).
async fn recv_within(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(window, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Wait, bounded, until the listener's drop counter reaches `expected`, so the
/// accounting assertions observe a settled recv loop rather than racing it.
async fn wait_for_drops(counter: &AtomicU64, expected: u64) {
    let deadline = std::time::Instant::now() + RECV_TIMEOUT;
    while counter.load(Ordering::Relaxed) < expected && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn authenticated_envelope_drives_the_live_dtls_demux_and_binds_identity() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut server = None;
    let mut drops = Arc::new(AtomicU64::new(0));
    let mut binding = DatagramListenerBinding::new(
        DatagramListenerProtocol::Dtls,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    );
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_udp_port().await.expect("reserve DTLS port");
        let listen_port = frontend.drop_and_take_port();
        let frontend_config = FrontendDtlsConfig {
            dimpl_config: Arc::new(
                dimpl::Config::builder()
                    .build()
                    .expect("DTLS server config"),
            ),
            certificate: dimpl::certificate::generate_self_signed_certificate()
                .expect("DTLS server certificate")
                .into(),
            client_cert_verifier: None,
            client_trust: None,
        };
        let attempt_drops = Arc::new(AtomicU64::new(0));
        // The DTLS receive boundary is its own protocol domain, so a valid
        // envelope for the plain-UDP listener on this port could never verify
        // here either.
        let attempt_binding = DatagramListenerBinding::new(
            DatagramListenerProtocol::Dtls,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            listen_port,
        );
        let gate = Arc::new(DatagramClientAddressGate::new(
            Arc::new(TrustedProxies::parse_strict("127.0.0.1", "test").expect("trust list")),
            Some(SECRET),
            attempt_binding,
            0,
        ));
        match bind_dtls_with_limits(
            SocketAddr::from(([127, 0, 0, 1], listen_port)),
            frontend_config,
            DtlsServerLimits {
                max_sessions: Some(16),
                handshake_timeout: Some(Duration::from_secs(15)),
                datagram_client_address: Some(gate),
                datagram_client_address_drops: Some(Arc::clone(&attempt_drops)),
                datagram_client_address_listener: Some((Arc::from(PROXY_ID), listen_port)),
                ..Default::default()
            },
        )
        .await
        {
            Ok(bound) => {
                drops = attempt_drops;
                binding = attempt_binding;
                server = Some(bound);
                break;
            }
            Err(error) => {
                eprintln!(
                    "gated DTLS bind attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on \
                     {listen_port} failed: {error}"
                );
            }
        }
    }
    let server = Arc::new(server.expect("bind gated DTLS server"));
    let server_addr = server.local_addr();
    let server_runner = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    let forwarded = forwarded_client();

    // Pre-association refusal: a handshake-shaped datagram is exactly what the
    // demuxer would otherwise spawn a session for, so each of these proves the
    // envelope decision happens before any per-peer state exists. They come
    // from a trusted loopback peer, so only the envelope can refuse them.
    let hostile = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("bind hostile sender");
    let foreign_key =
        HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("foreign key");
    let client_hello_shaped = {
        let mut packet = vec![0x16u8, 0xfe, 0xfd];
        packet.extend_from_slice(&[0u8; 42]);
        packet
    };
    let hello_form = DatagramEnvelopeForm::Forwarded {
        source: forwarded,
        destination: server_addr,
    };
    // A different listener sharing the one root secret: a valid envelope minted
    // for it must not authenticate here (#3856).
    let other_listener = DatagramListenerBinding::new(
        DatagramListenerProtocol::Dtls,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_addr.port().wrapping_add(1).max(1),
    );
    // The same numeric port on the plain-UDP receive boundary: also a different
    // domain, so a UDP-listener envelope cannot be laundered into the demuxer.
    let udp_boundary = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_addr.port(),
    );
    let hostile_balancer = Balancer::new(99);
    let foreign_balancer = Balancer::with_key(98, foreign_key);
    let now = unix_now_millis();
    let pre_association_refusals: Vec<Vec<u8>> = vec![
        // Bare: no envelope at all on a gated listener.
        client_hello_shaped.clone(),
        // Correctly shaped envelope, no authentication.
        plain(hello_form, &client_hello_shaped),
        // Tag minted under a foreign secret.
        foreign_balancer.wrap_at(&binding, hello_form, &client_hello_shaped, 0, now),
        // Valid tag, but minted for a different DTLS listener.
        hostile_balancer.wrap_at(&other_listener, hello_form, &client_hello_shaped, 1, now),
        // Valid tag, but minted for the plain-UDP boundary on this same port.
        hostile_balancer.wrap_at(&udp_boundary, hello_form, &client_hello_shaped, 2, now),
        // Authenticated but stale beyond the freshness horizon.
        hostile_balancer.wrap_at(
            &binding,
            hello_form,
            &client_hello_shaped,
            3,
            now - FRESHNESS_HORIZON_MS - 1_000,
        ),
    ];
    // A correctly minted envelope, then its byte-for-byte replay. The first is
    // admitted into the handshake path (it never completes, so it allocates and
    // then times out); the replay must be refused at the metadata boundary
    // (#3862). Sent last so the admitted one cannot mask the replay's refusal.
    let replayable = hostile_balancer.wrap_at(&binding, hello_form, &client_hello_shaped, 4, now);
    let expected_drops = pre_association_refusals.len() as u64;
    for datagram in &pre_association_refusals {
        hostile
            .send_to(datagram, server_addr)
            .await
            .expect("send refused datagram");
    }
    wait_for_drops(&drops, expected_drops).await;
    // Nothing may come back, and nothing may be allocated for the sender.
    assert!(
        recv_within(&hostile, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a refused datagram must not be answered"
    );
    assert_eq!(
        server.active_session_count(),
        0,
        "a refused datagram must not allocate a DTLS association"
    );
    assert_eq!(
        drops.load(Ordering::Relaxed),
        expected_drops,
        "every pre-association refusal must be counted"
    );

    // Now the replay pair, from a fresh socket so the association the first one
    // opens cannot be confused with the relay's below.
    let replayer = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("bind replay sender");
    replayer
        .send_to(&replayable, server_addr)
        .await
        .expect("send the genuine datagram");
    replayer
        .send_to(&replayable, server_addr)
        .await
        .expect("send its verbatim replay");
    wait_for_drops(&drops, expected_drops + 1).await;
    assert_eq!(
        drops.load(Ordering::Relaxed),
        expected_drops + 1,
        "a same-listener verbatim replay must be refused at the metadata boundary"
    );
    assert!(
        server.active_session_count() <= 1,
        "the replay must not allocate a second DTLS association"
    );

    let (relay_addr, relay_task) = spawn_dtls_metadata_relay(server_addr, binding, forwarded).await;
    let client_socket = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("bind DTLS client");
    client_socket
        .connect(relay_addr)
        .await
        .expect("connect DTLS client to relay");
    let client_params = BackendDtlsParams {
        config: Arc::new(
            dimpl::Config::builder()
                .build()
                .expect("DTLS client config"),
        ),
        certificate: dimpl::certificate::generate_self_signed_certificate()
            .expect("DTLS client certificate")
            .into(),
        server_name: None,
        server_cert_verifier: None,
        connect_timeout_ms: 15_000,
    };
    let client = tokio::time::timeout(
        Duration::from_secs(20),
        DtlsConnection::connect(client_socket, client_params),
    )
    .await
    .expect("authenticated DTLS handshake timed out")
    .expect("authenticated DTLS handshake failed");

    let (server_conn, direct_peer) = tokio::time::timeout(RECV_TIMEOUT, server.accept())
        .await
        .expect("DTLS accept timed out")
        .expect("DTLS accept failed");
    assert_eq!(
        direct_peer, relay_addr,
        "the socket peer must remain the relay"
    );
    assert_eq!(
        server_conn.forwarded_client_addr,
        Some(forwarded),
        "the authenticated envelope must bind the forwarded client to the DTLS association"
    );
    assert!(
        drops.load(Ordering::Relaxed) >= expected_drops + 2,
        "the deliberately bare first ClientHello must be refused before association allocation"
    );

    client
        .send(b"dtls-through-envelope")
        .await
        .expect("DTLS send");
    assert_eq!(
        tokio::time::timeout(RECV_TIMEOUT, server_conn.recv())
            .await
            .expect("server receive timed out")
            .expect("server receive failed"),
        b"dtls-through-envelope",
        "the demuxer must strip every envelope before DTLS decryption"
    );
    server_conn.send(b"dtls-reply").await.expect("DTLS reply");
    assert_eq!(
        tokio::time::timeout(RECV_TIMEOUT, client.recv())
            .await
            .expect("client receive timed out")
            .expect("client receive failed"),
        b"dtls-reply",
        "server ciphertext must traverse the relay unchanged"
    );

    client.close().await;
    server.close().await;
    relay_task.abort();
    let _ = tokio::time::timeout(RECV_TIMEOUT, server_task).await;
}

#[tokio::test]
async fn authenticated_envelope_publishes_the_forwarded_client_and_strips_the_payload() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = gateway.addr();

    // The balancer's own socket peer; the client it speaks for is elsewhere.
    let balancer_socket = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("balancer bind");
    let balancer_ip = balancer_socket
        .local_addr()
        .expect("balancer addr")
        .ip()
        .to_canonical()
        .to_string();

    let mut balancer = Balancer::new(1);
    let datagram = balancer.wrap(&gateway.binding, v4_form(gateway_addr), b"q");
    balancer_socket
        .send_to(&datagram, gateway_addr)
        .await
        .expect("send wrapped datagram");

    // The backend echoes the payload, so a reply proves the envelope was
    // stripped before the backend send (the backend echoes whatever it got).
    let reply = recv_within(&balancer_socket, RECV_TIMEOUT)
        .await
        .expect("an authenticated datagram must round-trip");
    assert_eq!(
        reply, b"q",
        "the backend must see the payload with the envelope stripped"
    );

    let stream = gateway.recorder.stream.lock().await.clone();
    assert_eq!(stream.len(), 1, "exactly one session must be admitted");
    assert_eq!(
        stream[0].0, "203.0.113.9",
        "client_ip must be the authenticated forwarded client"
    );
    assert_eq!(
        stream[0].1, balancer_ip,
        "direct_client_ip must remain the balancer's socket peer"
    );

    let datagrams = gateway.recorder.datagram.lock().await.clone();
    assert_eq!(
        datagrams,
        vec!["203.0.113.9".to_string()],
        "per-datagram hooks must see the forwarded client too"
    );
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        1,
        "the backend must be handed the payload exactly once"
    );

    gateway.shutdown().await;
}

/// The #3862 headline on the live datapath: a byte-for-byte replay of an
/// admitted authenticated datagram must reach neither the plugin hooks nor the
/// backend a second time, and must not refresh the session it belongs to.
#[tokio::test]
async fn a_verbatim_replay_reaches_the_backend_exactly_once() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = gateway.addr();
    let sender = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("sender bind");

    let mut balancer = Balancer::new(1);
    let datagram = balancer.wrap(&gateway.binding, v4_form(gateway_addr), b"charge");
    sender
        .send_to(&datagram, gateway_addr)
        .await
        .expect("send the genuine datagram");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"charge"[..]),
        "the genuine datagram must round-trip"
    );

    // Replay the exact same bytes several times through the same admissible
    // trusted-proxy path. Every one must be dropped at the metadata boundary.
    const REPLAYS: u64 = 4;
    for _ in 0..REPLAYS {
        sender
            .send_to(&datagram, gateway_addr)
            .await
            .expect("send verbatim replay");
        assert!(
            recv_within(&sender, DROP_OBSERVATION_WINDOW)
                .await
                .is_none(),
            "a verbatim replay must not be answered"
        );
    }
    wait_for_drops(&gateway.metrics.client_address_metadata_drops, REPLAYS).await;

    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        1,
        "the backend must observe the replayed payload exactly once"
    );
    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        1,
        "a replay must not re-run the per-datagram hooks"
    );
    assert_eq!(
        gateway.recorder.stream.lock().await.len(),
        1,
        "a replay must not admit a second session"
    );
    assert_eq!(
        gateway.drops(),
        REPLAYS,
        "every replay must be counted as a client-address metadata drop"
    );

    // A fresh sequence from the same balancer still works, so the window refuses
    // duplicates without wedging the flow.
    let next = balancer.wrap(&gateway.binding, v4_form(gateway_addr), b"next");
    sender
        .send_to(&next, gateway_addr)
        .await
        .expect("send the next sequence");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"next"[..]),
        "a fresh sequence must still be admitted"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 2);

    gateway.shutdown().await;
}

/// Bounded reordering must be tolerated on the live path without letting a
/// duplicate or a stale sequence through.
#[tokio::test]
async fn in_window_reordering_is_admitted_once_and_stale_sequences_are_dropped() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = gateway.addr();
    let sender = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("sender bind");
    let balancer = Balancer::new(1);
    let form = v4_form(gateway_addr);
    let now = unix_now_millis();

    // Unique sequences delivered out of order but inside the window.
    for sequence in [300u64, 298, 302, 299] {
        let datagram = balancer.wrap_at(&gateway.binding, form, b"ok", sequence, now);
        sender
            .send_to(&datagram, gateway_addr)
            .await
            .expect("send reordered datagram");
        assert_eq!(
            recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
            Some(&b"ok"[..]),
            "unique in-window sequence {sequence} must be admitted"
        );
    }
    assert_eq!(backend_hits.load(Ordering::Relaxed), 4);

    // A duplicate inside the window and a sequence far behind it are both
    // dropped, and neither reaches the backend.
    let duplicate = balancer.wrap_at(&gateway.binding, form, b"dup", 299, now);
    let stale = balancer.wrap_at(&gateway.binding, form, b"stale", 1, now);
    for (label, datagram) in [("duplicate", duplicate), ("stale", stale)] {
        sender
            .send_to(&datagram, gateway_addr)
            .await
            .expect("send refused datagram");
        assert!(
            recv_within(&sender, DROP_OBSERVATION_WINDOW)
                .await
                .is_none(),
            "{label} must be dropped"
        );
    }
    wait_for_drops(&gateway.metrics.client_address_metadata_drops, 2).await;

    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        4,
        "no refused sequence may reach the backend"
    );
    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        4,
        "no refused sequence may run the per-datagram hooks"
    );
    assert_eq!(gateway.drops(), 2);

    gateway.shutdown().await;
}

/// #3856 on the live datapath: two listeners in one process share one root
/// secret, and an envelope minted for A must be refused byte-for-byte at B for
/// **every** envelope form — including `LOCAL` and `AF_UNSPEC`, which carry no
/// forwarded identity and therefore no declared destination to compare — while a
/// correctly minted envelope for B is still admitted.
#[tokio::test]
async fn two_live_listeners_sharing_one_secret_refuse_cross_listener_replay() {
    let backend_a = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_a_port = backend_a.local_addr().expect("backend addr").port();
    let hits_a = Arc::new(AtomicU64::new(0));
    let _echo_a = spawn_counting_echo_backend(Arc::clone(&backend_a), Arc::clone(&hits_a)).await;

    let backend_b = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_b_port = backend_b.local_addr().expect("backend addr").port();
    let hits_b = Arc::new(AtomicU64::new(0));
    let _echo_b = spawn_counting_echo_backend(Arc::clone(&backend_b), Arc::clone(&hits_b)).await;

    let gateway_a = spawn_gateway(backend_a_port, true).await;
    let gateway_b = spawn_gateway(backend_b_port, true).await;
    let addr_a = gateway_a.addr();
    let addr_b = gateway_b.addr();
    assert_ne!(addr_a.port(), addr_b.port());

    // Every cross-listener replay is dropped before a session exists, so they
    // can all share one socket peer.
    let replayer = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("sender bind");
    // One balancer for listener-B admissions: replay protection is keyed by
    // authenticated sender_id, so each form must consume the next sequence.
    let mut balancer_b = Balancer::new(2);
    let mut expected_b_drops = 0u64;
    let mut expected_b_admissions = 0u64;
    // Hold every admitted-flow socket until the listeners shut down.
    //
    // UDP sessions live for `udp_idle_timeout_seconds` (60s here) and are
    // keyed by the balancer's socket 4-tuple, then pinned to the forwarded
    // identity of the first admitted datagram. Dropping `native` at the end
    // of an iteration frees that ephemeral source port; the kernel can reuse
    // it on the next `bind("127.0.0.1:0")`. The new envelope then hits the
    // still-live session, fails the identity pin, and is dropped — which
    // surfaces as the positive admit returning `None`. IPv6 is last in
    // `ALL_FORMS`, so it is the form that observes a reused 4-tuple. Keeping
    // the sockets bound makes each 4-tuple unique for the whole test, which
    // is also how a real balancer allocates one source port per client flow.
    let mut native_flows: Vec<UdpSocket> = Vec::with_capacity(ALL_FORMS.len());

    for label in ALL_FORMS {
        let mut balancer = Balancer::new(1);
        let form_a = envelope_form(label, addr_a);
        let for_a = balancer.wrap(&gateway_a.binding, form_a, b"cross");

        // Byte-for-byte at listener B: only the outer UDP destination port
        // differs, which is outside the envelope.
        replayer
            .send_to(&for_a, addr_b)
            .await
            .expect("replay the envelope at listener B");
        assert!(
            recv_within(&replayer, DROP_OBSERVATION_WINDOW)
                .await
                .is_none(),
            "{label} minted for A must be dropped at B"
        );
        expected_b_drops += 1;
        wait_for_drops(
            &gateway_b.metrics.client_address_metadata_drops,
            expected_b_drops,
        )
        .await;
        assert_eq!(
            hits_b.load(Ordering::Relaxed),
            expected_b_admissions,
            "{label} cross-listener replay must not reach B's backend"
        );
        assert_eq!(
            gateway_b.recorder.datagram_count.load(Ordering::Relaxed),
            expected_b_admissions,
            "{label} cross-listener replay must not run B's per-datagram hooks"
        );
        assert_eq!(
            gateway_b.drops(),
            expected_b_drops,
            "{label} cross-listener replay must be counted at B"
        );

        // A correctly minted envelope for B is still admitted, so the refusal
        // above is about the binding and not about listener B being broken. It
        // needs its own socket peer: one admitted 4-tuple pins one forwarded
        // identity, and these four forms assert different ones.
        let native = UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind a fresh balancer flow");
        let form_b = envelope_form(label, addr_b);
        let for_b = balancer_b.wrap(&gateway_b.binding, form_b, b"native");
        native
            .send_to(&for_b, addr_b)
            .await
            .expect("send B's own envelope");
        assert_eq!(
            recv_within(&native, RECV_TIMEOUT).await.as_deref(),
            Some(&b"native"[..]),
            "{label} minted for B must be admitted at B"
        );
        expected_b_admissions += 1;
        assert_eq!(hits_b.load(Ordering::Relaxed), expected_b_admissions);
        assert_eq!(
            gateway_b.drops(),
            expected_b_drops,
            "{label} admission must not have been counted as a drop"
        );
        // Keep the source port bound so a later form cannot reuse this
        // 4-tuple against a still-pinned session.
        native_flows.push(native);
    }

    // Listener A never saw any of it: the replays were aimed at B.
    assert_eq!(
        gateway_a.recorder.stream.lock().await.len(),
        0,
        "listener A must not have admitted anything"
    );
    assert_eq!(hits_a.load(Ordering::Relaxed), 0);
    assert_eq!(
        gateway_a.drops(),
        0,
        "listener A saw no traffic at all, refused or otherwise"
    );
    assert_eq!(
        gateway_b.recorder.stream.lock().await.len(),
        ALL_FORMS.len(),
        "one admitted flow per form, each on its own socket peer"
    );

    gateway_a.shutdown().await;
    gateway_b.shutdown().await;
    // Source ports stay bound until the listeners (and their sessions) are gone.
    drop(native_flows);
}

/// A stale authenticated envelope — outside the freshness horizon — is refused
/// before a session exists at all, which is the strongest form of "before
/// pending-session insertion, hooks, and backend I/O".
#[tokio::test]
async fn a_stale_envelope_is_refused_before_any_session_or_hook() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = gateway.addr();
    let sender = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("sender bind");
    let balancer = Balancer::new(1);
    let form = v4_form(gateway_addr);
    let long_ago = unix_now_millis() - FRESHNESS_HORIZON_MS - 5_000;

    let stale = balancer.wrap_at(&gateway.binding, form, b"ancient", 0, long_ago);
    sender
        .send_to(&stale, gateway_addr)
        .await
        .expect("send stale envelope");
    assert!(
        recv_within(&sender, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a stale envelope must be dropped"
    );
    wait_for_drops(&gateway.metrics.client_address_metadata_drops, 1).await;

    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "a stale envelope must not admit a session"
    );
    assert_eq!(
        gateway.metrics.active_sessions.load(Ordering::Relaxed),
        0,
        "a stale envelope must not allocate a session"
    );
    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        0,
        "a stale envelope must not reach the per-datagram hooks"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 0);
    assert_eq!(gateway.drops(), 1);

    // The listener is unharmed: a fresh envelope still round-trips.
    let mut fresh_balancer = Balancer::new(1);
    let good = fresh_balancer.wrap(&gateway.binding, form, b"ok");
    sender
        .send_to(&good, gateway_addr)
        .await
        .expect("send fresh envelope");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"ok"[..]),
        "a stale refusal must not wedge the listener"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_and_malformed_datagrams_are_dropped_before_the_backend() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, true).await;
    let gateway_addr = gateway.addr();
    let sender = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("sender bind");
    let form = v4_form(gateway_addr);
    let foreign = HmacSha256Key::new_from_slice(b"ffffffffffffffffffffffffffffffff").expect("key");
    let foreign_balancer = Balancer::with_key(5, foreign);
    let balancer = Balancer::new(1);
    let now = unix_now_millis();
    let wrong_dest = SocketAddr::new(
        gateway_addr.ip(),
        gateway_addr.port().wrapping_add(1).max(1),
    );
    let other_binding = DatagramListenerBinding::new(
        DatagramListenerProtocol::Udp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        wrong_dest.port(),
    );

    let refused: Vec<(&str, Vec<u8>)> = vec![
        // A bare payload on an enabled listener: no silent pass-through.
        ("bare payload", b"query".to_vec()),
        // Correct envelope, no authentication at all.
        ("untagged envelope", plain(form, b"query")),
        // Tag minted under a different secret.
        (
            "foreign tag",
            foreign_balancer.wrap_at(&gateway.binding, form, b"query", 0, now),
        ),
        // Valid tag, but minted for a different listener's binding.
        (
            "cross-listener envelope",
            balancer.wrap_at(&other_binding, v4_form(wrong_dest), b"query", 1, now),
        ),
        // Truncated header.
        ("truncated header", b"\r\n\r\n\x00\r\nQUI".to_vec()),
    ];

    for (label, datagram) in &refused {
        sender
            .send_to(datagram, gateway_addr)
            .await
            .expect("send refused datagram");
        assert!(
            recv_within(&sender, DROP_OBSERVATION_WINDOW)
                .await
                .is_none(),
            "{label} must be dropped, not forwarded"
        );
    }

    assert_eq!(
        gateway.recorder.datagram_count.load(Ordering::Relaxed),
        0,
        "no refused datagram may reach the per-datagram hooks"
    );
    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "no refused datagram may admit a session"
    );
    assert_eq!(
        gateway.metrics.active_sessions.load(Ordering::Relaxed),
        0,
        "no refused datagram may create a session"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        gateway.drops(),
        refused.len() as u64,
        "every refusal must be counted"
    );

    // The listener is still healthy: a correctly authenticated datagram after
    // the refusals still round-trips.
    let mut good_balancer = Balancer::new(1);
    let good = good_balancer.wrap(&gateway.binding, form, b"ok");
    sender
        .send_to(&good, gateway_addr)
        .await
        .expect("send authenticated datagram");
    assert_eq!(
        recv_within(&sender, RECV_TIMEOUT).await.as_deref(),
        Some(&b"ok"[..]),
        "refusals must not wedge the listener"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_second_forwarded_client_on_one_socket_peer_is_refused() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    // Address-trust posture (no secret): the session-binding rule is
    // independent of authentication.
    let gateway = spawn_gateway(backend_port, false).await;
    let gateway_addr = gateway.addr();
    let balancer = UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("balancer bind");

    let first = DatagramEnvelopeForm::Forwarded {
        source: forwarded_client(),
        destination: gateway_addr,
    };
    let second = DatagramEnvelopeForm::Forwarded {
        source: "198.51.100.7:41234".parse().expect("client addr"),
        destination: gateway_addr,
    };

    balancer
        .send_to(&plain(first, b"first"), gateway_addr)
        .await
        .expect("send first client");
    assert_eq!(
        recv_within(&balancer, RECV_TIMEOUT).await.as_deref(),
        Some(&b"first"[..]),
        "the first client establishes the session"
    );

    balancer
        .send_to(&plain(second, b"second"), gateway_addr)
        .await
        .expect("send second client");
    assert!(
        recv_within(&balancer, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "a different forwarded client on the same socket peer must be dropped, not \
         attributed to the established session"
    );

    let datagrams = gateway.recorder.datagram.lock().await.clone();
    assert_eq!(
        datagrams,
        vec!["203.0.113.9".to_string()],
        "only the admitted client's datagram may reach the hooks"
    );
    assert_eq!(
        gateway.drops(),
        1,
        "the mismatch must be counted as a client-address metadata drop"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 1);

    gateway.shutdown().await;
}

#[tokio::test]
async fn an_untrusted_peer_cannot_assert_a_client_address() {
    let backend = Arc::new(
        UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("backend bind"),
    );
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicU64::new(0));
    let _backend =
        spawn_counting_echo_backend(Arc::clone(&backend), Arc::clone(&backend_hits)).await;

    let gateway = spawn_gateway(backend_port, false).await;
    let gateway_addr = gateway.addr();

    // 127.0.0.2 is outside the configured trust list (`127.0.0.1`), so this
    // sender is an ordinary client forging balancer metadata.
    let Ok(untrusted) = UdpSocket::bind_test("127.0.0.2:0").await else {
        // Some CI images do not route the whole 127/8 range; the unit-level
        // trust test covers this case unconditionally.
        eprintln!("skipping: 127.0.0.2 is not bindable on this host");
        gateway.shutdown().await;
        return;
    };

    let spoofed = plain(v4_form(gateway_addr), b"spoofed");
    untrusted
        .send_to(&spoofed, gateway_addr)
        .await
        .expect("send spoofed datagram");

    assert!(
        recv_within(&untrusted, DROP_OBSERVATION_WINDOW)
            .await
            .is_none(),
        "an untrusted peer's datagram must be dropped"
    );
    assert!(
        gateway.recorder.stream.lock().await.is_empty(),
        "an untrusted peer must not admit a session"
    );
    assert_eq!(backend_hits.load(Ordering::Relaxed), 0);
    assert_eq!(gateway.drops(), 1, "the untrusted peer must be counted");

    gateway.shutdown().await;
}

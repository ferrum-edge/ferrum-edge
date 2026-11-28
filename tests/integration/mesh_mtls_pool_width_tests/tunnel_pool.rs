//! Pooled Sidecar raw-TCP egress tunnels (issue #7537).
//!
//! `MeshMtlsConnectionPool::open_connect_tunnel` used to dial one fresh
//! SVID-mTLS HTTP/2 connection per captured raw-TCP stream. It now multiplexes
//! bare CONNECT streams over pooled carriers. These tests drive the real pool
//! against an in-process SPIFFE-mTLS raw-`h2` peer (the same wire shape a peer
//! sidecar's `:15006` terminator speaks) that counts accepted connections and
//! open CONNECT streams per connection, and check every acceptance bullet:
//!
//! - N concurrent tunnels to one destination use at most `⌈N / cap⌉`
//!   connections, never more streams per connection than the cap;
//! - a reset stream leaves its siblings and the carrier intact;
//! - SVID rotation, trust-bundle change, CRL revocation, peer certificate
//!   expiry and gateway trust withdrawal never reuse a retired connection;
//! - a different pinned identity, trust scope, SNI or authority never shares a
//!   connection;
//! - back-pressure holds under a stalled reader in both directions without
//!   starving a sibling on the same connection.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use bytes::Bytes;
use ferrum_edge::backend_conn_limit::BackendConnectionLimiter;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResolvedPortOverride, ResponseBodyMode,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::hbone_pool::{
    ConnectMultiplexFlowControl, H2_MAX_FLOW_CONTROL_WINDOW, H2ConnectTunnel, HbonePoolError,
    connect_multiplex_flow_control,
};
use ferrum_edge::proxy::mesh_mtls_pool::{
    MeshMtlsConnectionPool, mesh_mtls_tunnel_pool_key_for_tests,
    tunnel_carrier_flow_control_for_tests,
};
use ferrum_edge::proxy::mesh_trust_registry::{MeshTrustRegistry, TrustWithdrawalReason};
use ferrum_edge::time_compat::UtcTimestamp;
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::CertificateRevocationListDer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const APP_PORT: u16 = 8080;
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const PEER_SERIAL: u64 = 0x7537;
/// The in-process peer's receive windows: a small stream window so the
/// send-direction stall test reaches back-pressure quickly, and a connection
/// window that fits many such streams.
const PEER_STREAM_WINDOW: u32 = 256 * 1024;
const PEER_CONNECTION_WINDOW: u32 = 8 * 1024 * 1024;

// ===== identity fixtures =====

struct Ca {
    td: TrustDomain,
    root_der: Vec<u8>,
    root_pem: String,
    root_key_pem: String,
}

impl Ca {
    fn new(td: &str) -> Self {
        let td = TrustDomain::new(td).expect("trust domain");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{}-test-root", td.as_str()));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
        let cert = params.self_signed(&key).expect("root cert");
        Self {
            td,
            root_der: cert.der().to_vec(),
            root_pem: cert.pem(),
            root_key_pem: key.serialize_pem(),
        }
    }

    fn issuer(&self) -> Issuer<'static, KeyPair> {
        let key = KeyPair::from_pem(&self.root_key_pem).expect("issuer key");
        Issuer::from_ca_cert_pem(&self.root_pem, key).expect("issuer")
    }

    fn id(&self, path: &str) -> SpiffeId {
        SpiffeId::from_parts(&self.td, path).expect("spiffe id")
    }

    /// Leaf DER + PKCS#8 key DER, valid from a minute ago for `lifetime`.
    fn issue(&self, id: &SpiffeId, serial: u64, lifetime: time::Duration) -> (Vec<u8>, Vec<u8>) {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(id).expect("spiffe san"));
        params.is_ca = IsCa::ExplicitNoCa;
        params.serial_number = Some(SerialNumber::from(serial));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + lifetime;
        let cert = params
            .signed_by(&leaf_key, &self.issuer())
            .expect("leaf cert");
        (cert.der().to_vec(), leaf_key.serialize_der())
    }

    fn bundle(&self, id: SpiffeId, leaf_der: Vec<u8>, key_der: Vec<u8>) -> SvidBundle {
        SvidBundle {
            spiffe_id: id,
            cert_chain_der: vec![leaf_der],
            private_key_pkcs8_der: key_der.into(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: self.td.clone(),
                x509_authorities: vec![self.root_der.clone()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }),
        }
    }

    /// A CRL from this root revoking `serial`.
    fn crl_revoking(&self, serial: u64) -> CertificateRevocationListDer<'static> {
        self.crl(&[serial], time::Duration::days(1))
    }

    /// A CRL from this root revoking `serials`, valid for `lifetime` more.
    fn crl(
        &self,
        serials: &[u64],
        lifetime: time::Duration,
    ) -> CertificateRevocationListDer<'static> {
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now - time::Duration::minutes(1),
            next_update: now + lifetime,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: now - time::Duration::minutes(1),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params
            .signed_by(&self.issuer())
            .expect("sign CRL")
            .der()
            .clone()
    }
}

fn svid_slot(bundle: SvidBundle) -> SharedSvidBundle {
    Arc::new(ArcSwap::new(Arc::new(Some(bundle))))
}

fn proxy_for_test() -> Proxy {
    let now = UtcTimestamp::now();
    Proxy {
        labels: Default::default(),
        id: "mesh-mtls-tunnel-pool".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh mTLS tunnel pool".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: DispatchKind::from(BackendScheme::Tcp),
        backend_host: "127.0.0.1".to_string(),
        backend_port: APP_PORT,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 5_000,
        backend_write_timeout_ms: 5_000,
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
        websocket_permessage_deflate: Default::default(),
        allow_path_parameters: false,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: now,
        updated_at: now,
        pending_limit_scope: None,
    }
}

// ===== in-process peer sidecar terminator =====

/// SPIFFE-mTLS raw-`h2` server answering every CONNECT with `200`. The first
/// line the client writes selects the stream's behaviour:
///
/// - `ECHO` echoes every later byte;
/// - `RESET` resets the stream with `RST_STREAM(CONNECT_ERROR)`, as a
///   destination relay does when its backend fails;
/// - `FLOOD` pushes bytes as fast as the client's flow-control window allows,
///   counting what it pushed;
/// - `SINK` answers `OK\n` and then never reads again.
struct Peer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    per_connection_active: Arc<Mutex<Vec<Arc<AtomicUsize>>>>,
    flood_pushed: Arc<Mutex<Vec<Arc<AtomicUsize>>>>,
    /// While `true`, accepted connections wait before their TLS handshake, so
    /// a dial stays in flight until the test releases it.
    hold: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Peer {
    async fn start(server_slot: SharedSvidBundle, max_concurrent_streams: u32) -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind peer");
        let port = listener.local_addr().expect("peer addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let per_connection_active: Arc<Mutex<Vec<Arc<AtomicUsize>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let flood_pushed: Arc<Mutex<Vec<Arc<AtomicUsize>>>> = Arc::new(Mutex::new(Vec::new()));
        let accepted_task = accepted.clone();
        let per_connection_task = per_connection_active.clone();
        let flood_task = flood_pushed.clone();
        let hold = Arc::new(tokio::sync::watch::channel(false).0);
        let hold_task = hold.clone();
        tokio::spawn(async move {
            let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
                .expect("server config");
            let acceptor = TlsAcceptor::from(inbound);
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let active = Arc::new(AtomicUsize::new(0));
                per_connection_task
                    .lock()
                    .expect("peer registry")
                    .push(active.clone());
                let acceptor = acceptor.clone();
                let flood = flood_task.clone();
                let mut hold_rx = hold_task.subscribe();
                tokio::spawn(async move {
                    while *hold_rx.borrow_and_update() {
                        if hold_rx.changed().await.is_err() {
                            return;
                        }
                    }
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut builder = h2::server::Builder::new();
                    builder
                        .max_concurrent_streams(max_concurrent_streams)
                        .initial_window_size(PEER_STREAM_WINDOW)
                        .initial_connection_window_size(PEER_CONNECTION_WINDOW);
                    let Ok(mut h2) = builder.handshake(tls).await else {
                        return;
                    };
                    while let Some(next) = h2.accept().await {
                        let Ok((request, respond)) = next else {
                            break;
                        };
                        if request.method() != http::Method::CONNECT {
                            continue;
                        }
                        let active = active.clone();
                        let flood = flood.clone();
                        tokio::spawn(async move {
                            active.fetch_add(1, Ordering::SeqCst);
                            serve_connect_stream(request, respond, flood).await;
                            active.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                });
            }
        });
        Self {
            port,
            accepted,
            per_connection_active,
            flood_pushed,
            hold,
        }
    }

    fn hold_handshakes(&self, hold: bool) {
        self.hold.send_replace(hold);
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn active_per_connection(&self) -> Vec<usize> {
        self.per_connection_active
            .lock()
            .expect("peer registry")
            .iter()
            .map(|active| active.load(Ordering::SeqCst))
            .collect()
    }

    async fn wait_for_active(&self, expected: &[usize]) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let observed = self.active_per_connection();
            if observed == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "peer never observed {expected:?} open streams per connection; last {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn flood_counter(&self, index: usize) -> Arc<AtomicUsize> {
        self.flood_pushed.lock().expect("flood registry")[index].clone()
    }
}

async fn serve_connect_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    flood: Arc<Mutex<Vec<Arc<AtomicUsize>>>>,
) {
    let mut recv = request.into_body();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("connect response");
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    // Read the command line.
    let mut line = Vec::new();
    let rest = loop {
        match recv.data().await {
            Some(Ok(chunk)) => {
                let _ = recv.flow_control().release_capacity(chunk.len());
                line.extend_from_slice(&chunk);
                if let Some(at) = line.iter().position(|byte| *byte == b'\n') {
                    let rest = line.split_off(at + 1);
                    line.truncate(at);
                    break rest;
                }
            }
            _ => return,
        }
    };
    match line.as_slice() {
        b"ECHO" => {
            if !rest.is_empty() && send.send_data(Bytes::from(rest), false).is_err() {
                return;
            }
            while let Some(Ok(chunk)) = recv.data().await {
                let _ = recv.flow_control().release_capacity(chunk.len());
                if send.send_data(chunk, false).is_err() {
                    return;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        }
        b"RESET" => send.send_reset(h2::Reason::CONNECT_ERROR),
        b"FLOOD" => {
            let pushed = Arc::new(AtomicUsize::new(0));
            flood.lock().expect("flood registry").push(pushed.clone());
            let chunk = Bytes::from(vec![0x5a_u8; 16 * 1024]);
            loop {
                send.reserve_capacity(chunk.len());
                let capacity = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(capacity)) => capacity,
                    _ => return,
                };
                if capacity == 0 {
                    continue;
                }
                let n = capacity.min(chunk.len());
                if send.send_data(chunk.slice(..n), false).is_err() {
                    return;
                }
                pushed.fetch_add(n, Ordering::SeqCst);
            }
        }
        b"SINK" => {
            if send.send_data(Bytes::from_static(b"OK\n"), false).is_err() {
                return;
            }
            // Hold the request body without ever reading it again, so the
            // client's writes stop at this stream's window.
            let _held = recv;
            std::future::pending::<()>().await;
        }
        _ => send.send_reset(h2::Reason::PROTOCOL_ERROR),
    }
}

// ===== fixture =====

struct Options {
    width: usize,
    proxy_stream_cap: Option<u32>,
    peer_max_streams: u32,
    peer_lifetime: time::Duration,
    connect_timeout_ms: u64,
    max_connections: Option<u32>,
    proxy_windows: Option<(u32, u32)>,
    idle_timeout_seconds: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            width: 4,
            proxy_stream_cap: None,
            peer_max_streams: 1024,
            peer_lifetime: time::Duration::hours(1),
            connect_timeout_ms: 5_000,
            max_connections: None,
            proxy_windows: None,
            idle_timeout_seconds: None,
        }
    }
}

struct Fixture {
    ca: Ca,
    pool: MeshMtlsConnectionPool,
    proxy: Proxy,
    peer: Peer,
    peer_id: SpiffeId,
    gateway_id: SpiffeId,
    gateway_leaf: Vec<u8>,
    gateway_key: Vec<u8>,
    gateway_slot: SharedSvidBundle,
    crls: ferrum_edge::tls::SharedCrlList,
    pool_config: PoolConfig,
}

impl Fixture {
    async fn new(options: Options) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = Ca::new("cluster.local");
        let gateway_id = ca.id("ns/edge/sa/gateway");
        let peer_id = ca.id("ns/default/sa/orders");
        let (gateway_leaf, gateway_key) = ca.issue(&gateway_id, 1, time::Duration::hours(1));
        let (peer_leaf, peer_key) = ca.issue(&peer_id, PEER_SERIAL, options.peer_lifetime);
        let gateway_slot = svid_slot(ca.bundle(
            gateway_id.clone(),
            gateway_leaf.clone(),
            gateway_key.clone(),
        ));
        let peer_slot = svid_slot(ca.bundle(peer_id.clone(), peer_leaf, peer_key));
        let peer = Peer::start(peer_slot, options.peer_max_streams).await;
        let mut pool_config = PoolConfig {
            http2_connections_per_host: options.width,
            ..PoolConfig::default()
        };
        if let Some(idle) = options.idle_timeout_seconds {
            pool_config.idle_timeout_seconds = idle;
        }
        let crls = ferrum_edge::tls::shared_crl_list(Arc::new(Vec::new()));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation_and_shared_crls(
            pool_config.clone(),
            DnsCache::new(DnsConfig::default()),
            gateway_slot.clone(),
            crls.clone(),
            4,
            Arc::new(AtomicU64::new(0)),
        );
        let limiter = Arc::new(BackendConnectionLimiter::new());
        pool.attach_backend_conn_limit(limiter);
        let mut proxy = proxy_for_test();
        proxy.backend_connect_timeout_ms = options.connect_timeout_ms;
        proxy.pool_http2_max_concurrent_streams = options.proxy_stream_cap;
        if let Some((stream, connection)) = options.proxy_windows {
            proxy.pool_http2_initial_stream_window_size = Some(stream);
            proxy.pool_http2_initial_connection_window_size = Some(connection);
        }
        if let Some(cap) = options.max_connections {
            let mut overrides = HashMap::new();
            overrides.insert(
                APP_PORT,
                ResolvedPortOverride {
                    max_connections: Some(cap),
                    ..Default::default()
                },
            );
            proxy.dispatch_port_overrides = Some(overrides);
        }
        Self {
            ca,
            pool,
            proxy,
            peer,
            peer_id,
            gateway_id,
            gateway_leaf,
            gateway_key,
            gateway_slot,
            crls,
            pool_config,
        }
    }

    async fn open_as(
        &self,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        authority_host: &str,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        tokio::time::timeout(
            OPEN_TIMEOUT,
            self.pool.open_connect_tunnel(
                &self.proxy,
                "127.0.0.1",
                authority_host,
                APP_PORT,
                APP_PORT,
                self.peer.port,
                expected_peer,
                expected_trust_domain,
                sni_override,
            ),
        )
        .await
        .expect("open returns within its own budget")
    }

    /// Same-cluster dial pinned to the peer's real identity.
    async fn open(&self) -> Result<H2ConnectTunnel, HbonePoolError> {
        self.open_as(Some(&self.peer_id), None, None, "127.0.0.1")
            .await
    }

    async fn open_ok(&self) -> H2ConnectTunnel {
        self.open().await.expect("open pooled tunnel")
    }

    async fn open_echo(&self) -> H2ConnectTunnel {
        let mut tunnel = self.open_ok().await;
        tunnel.write_all(b"ECHO\n").await.expect("echo command");
        tunnel
    }

    fn rotate_gateway_leaf(&self) {
        let (leaf, key) = self.ca.issue(&self.gateway_id, 2, time::Duration::hours(1));
        self.gateway_slot.store(Arc::new(Some(self.ca.bundle(
            self.gateway_id.clone(),
            leaf,
            key,
        ))));
    }

    /// Republish the SAME leaf in a new slot value: a trust-bundle-only
    /// rotation the fingerprint cannot see.
    fn republish_gateway_trust(&self) {
        self.gateway_slot.store(Arc::new(Some(self.ca.bundle(
            self.gateway_id.clone(),
            self.gateway_leaf.clone(),
            self.gateway_key.clone(),
        ))));
    }
}

async fn echo_round_trip(tunnel: &mut H2ConnectTunnel, payload: &[u8]) {
    tunnel.write_all(payload).await.expect("write tunnel");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(OPEN_TIMEOUT, tunnel.read_exact(&mut buf))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(buf, payload);
}

// ===== N concurrent streams use at most ⌈N / cap⌉ connections =====

#[tokio::test(flavor = "multi_thread")]
async fn sequential_tunnels_fill_each_connection_to_its_stream_cap() {
    let fixture = Fixture::new(Options {
        proxy_stream_cap: Some(4),
        ..Options::default()
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..10 {
        held.push(fixture.open_echo().await);
    }
    // ⌈10 / 4⌉ = 3: each connection fills to the cap before the next dial.
    fixture.peer.wait_for_active(&[4, 4, 2]).await;
    assert_eq!(fixture.peer.accepted(), 3);
    assert_eq!(fixture.pool.tunnel_pool_size(), 3);
    for tunnel in held.iter_mut() {
        echo_round_trip(tunnel, b"still-up").await;
    }
    let stats = fixture.pool.tunnel_pool_stats();
    assert_eq!(stats.connections, 3);
    assert_eq!(stats.active_streams, 10);
    assert_eq!(stats.connections_opened, 3);
    assert_eq!(stats.streams_new_connection, 3);
    assert_eq!(stats.streams_reused, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_tunnels_use_at_most_ceil_n_over_cap_connections() {
    const N: usize = 10;
    const CAP: u32 = 4;
    let fixture = Fixture::new(Options {
        proxy_stream_cap: Some(CAP),
        ..Options::default()
    })
    .await;
    let opens = (0..N).map(|_| fixture.open_echo());
    let mut held = futures_util::future::join_all(opens).await;
    let max_connections = N.div_ceil(CAP as usize);
    let accepted = fixture.peer.accepted();
    assert!(
        accepted <= max_connections,
        "{N} concurrent tunnels at a cap of {CAP} dialed {accepted} connections"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let active = fixture.peer.active_per_connection();
        if active.iter().sum::<usize>() == N {
            assert!(
                active.iter().all(|streams| *streams <= CAP as usize),
                "a connection carried more than {CAP} streams: {active:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "peer never saw {N} open streams: {active:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fixture.pool.tunnel_pool_size(), accepted);
    for tunnel in held.iter_mut() {
        echo_round_trip(tunnel, b"multiplexed").await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_width_capped_key_waits_for_a_stream_slot_and_never_widens() {
    let fixture = Fixture::new(Options {
        width: 1,
        proxy_stream_cap: Some(2),
        ..Options::default()
    })
    .await;
    let first = fixture.open_echo().await;
    let _second = fixture.open_echo().await;
    fixture.peer.wait_for_active(&[2]).await;

    let mut third = Box::pin(fixture.open());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut third)
            .await
            .is_err(),
        "the third tunnel must wait for a stream slot"
    );
    assert_eq!(fixture.peer.accepted(), 1, "no dial past the width");

    drop(first);
    let mut third = third.await.expect("queued tunnel opens once a slot frees");
    third.write_all(b"ECHO\n").await.expect("echo command");
    echo_round_trip(&mut third, b"slot").await;
    assert_eq!(fixture.peer.accepted(), 1);
    assert_eq!(
        fixture.pool.tunnel_pool_stats().saturation_waits_admitted,
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saturation_wait_is_bounded_by_the_connect_timeout() {
    let fixture = Fixture::new(Options {
        width: 1,
        proxy_stream_cap: Some(1),
        connect_timeout_ms: 400,
        ..Options::default()
    })
    .await;
    let _held = fixture.open_echo().await;
    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("no slot frees inside the connect timeout");
    assert!(
        matches!(err, HbonePoolError::ConnectStream { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 1);
    assert_eq!(
        fixture.pool.tunnel_pool_stats().saturation_waits_timed_out,
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_connections_charges_carriers_not_streams() {
    let fixture = Fixture::new(Options {
        proxy_stream_cap: Some(2),
        max_connections: Some(1),
        ..Options::default()
    })
    .await;
    // Two streams ride the one admitted connection.
    let _a = fixture.open_echo().await;
    let _b = fixture.open_echo().await;
    assert_eq!(fixture.peer.accepted(), 1);
    // A third stream needs a second connection, which the cap refuses.
    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("second carrier is over cap");
    assert!(
        matches!(err, HbonePoolError::MaxConnectionsExceeded { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 1);
}

// ===== stream reset is local to the stream =====

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_stream_leaves_its_siblings_and_the_connection_intact() {
    let fixture = Fixture::new(Options::default()).await;
    let mut sibling = fixture.open_echo().await;
    let mut doomed = fixture.open_ok().await;
    fixture.peer.wait_for_active(&[2]).await;

    doomed.write_all(b"RESET\n").await.expect("reset command");
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(OPEN_TIMEOUT, doomed.read(&mut buf))
        .await
        .expect("reset reaches the tunnel");
    assert!(read.is_err(), "a reset stream reads as an error: {read:?}");

    echo_round_trip(&mut sibling, b"sibling-survives").await;

    // A client-side drop mid-stream resets only that stream, too.
    let mut dropped = fixture.open_echo().await;
    echo_round_trip(&mut dropped, b"about-to-drop").await;
    drop(dropped);
    echo_round_trip(&mut sibling, b"still-there").await;

    // The connection stays pooled and serves the next tunnel.
    let mut next = fixture.open_echo().await;
    echo_round_trip(&mut next, b"reused").await;
    assert_eq!(fixture.peer.accepted(), 1);
    assert_eq!(fixture.pool.tunnel_pool_size(), 1);
}

// ===== identity and trust scope never share a connection =====

#[tokio::test(flavor = "multi_thread")]
async fn a_different_pinned_identity_never_reuses_a_connection() {
    let fixture = Fixture::new(Options::default()).await;
    let mut legit = fixture.open_echo().await;
    assert_eq!(fixture.peer.accepted(), 1);

    // Same dial target, same authority, different pinned identity. Were the
    // verified connection shared, this would succeed; it must dial its own
    // and fail verification against the peer's real SVID.
    let impostor = fixture.ca.id("ns/default/sa/payments");
    let err = fixture
        .open_as(Some(&impostor), None, None, "127.0.0.1")
        .await
        .map(drop)
        .expect_err("pin mismatch must fail closed");
    assert!(
        matches!(err, HbonePoolError::TlsHandshake { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the mismatched pin dialed its own"
    );
    assert_eq!(fixture.pool.tunnel_pool_size(), 1);
    echo_round_trip(&mut legit, b"pinned").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_scope_and_sni_partition_connections() {
    let fixture = Fixture::new(Options::default()).await;
    let _pinned = fixture.open_echo().await;
    assert_eq!(fixture.peer.accepted(), 1);

    // Cross-cluster shape, wrong remote trust domain: never rides the pinned
    // connection, and its own dial fails trust-domain scoping.
    let other_td = TrustDomain::new("other.example").expect("td");
    let err = fixture
        .open_as(
            None,
            Some(&other_td),
            Some("p8080.orders.default.svc.cluster.local"),
            "127.0.0.1",
        )
        .await
        .map(drop)
        .expect_err("wrong trust domain must fail closed");
    assert!(
        matches!(err, HbonePoolError::TlsHandshake { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 2);

    // Correct trust domain: succeeds, but on its OWN connection.
    let td = fixture.ca.td.clone();
    let mut scoped = fixture
        .open_as(
            None,
            Some(&td),
            Some("p8080.orders.default.svc.cluster.local"),
            "127.0.0.1",
        )
        .await
        .expect("trust-domain-scoped tunnel");
    scoped.write_all(b"ECHO\n").await.expect("echo command");
    echo_round_trip(&mut scoped, b"td-only").await;
    assert_eq!(fixture.peer.accepted(), 3);

    // A different SNI override in the same trust scope gets another one.
    let mut other_sni = fixture
        .open_as(
            None,
            Some(&td),
            Some("p8080.reviews.default.svc.cluster.local"),
            "127.0.0.1",
        )
        .await
        .expect("second SNI");
    other_sni.write_all(b"ECHO\n").await.expect("echo command");
    echo_round_trip(&mut other_sni, b"sni").await;
    assert_eq!(fixture.peer.accepted(), 4);
    assert_eq!(fixture.pool.tunnel_pool_size(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_connect_authority_gets_its_own_connection() {
    let fixture = Fixture::new(Options::default()).await;
    let _a = fixture.open_echo().await;
    let mut b = fixture
        .open_as(Some(&fixture.peer_id), None, None, "workload-b.test")
        .await
        .expect("second authority");
    b.write_all(b"ECHO\n").await.expect("echo command");
    echo_round_trip(&mut b, b"authority").await;
    assert_eq!(fixture.peer.accepted(), 2);
    assert_eq!(fixture.pool.tunnel_pool_size(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_delimiter_in_dial_metadata_fails_closed_before_any_dial() {
    let fixture = Fixture::new(Options::default()).await;
    let err = fixture
        .open_as(Some(&fixture.peer_id), None, None, "workload|forged")
        .await
        .map(drop)
        .expect_err("a delimiter in the authority must be refused");
    assert!(
        matches!(err, HbonePoolError::InvalidDialHostTag { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_gateway_svid_fails_closed_before_any_dial() {
    let fixture = Fixture::new(Options::default()).await;
    fixture.gateway_slot.store(Arc::new(None));
    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("no SVID, no tunnel");
    assert!(
        matches!(err, HbonePoolError::NoSvid),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 0);
}

#[test]
fn tunnel_pool_key_carries_every_peer_pinning_field() {
    let td = TrustDomain::new("cluster.local").expect("td");
    let remote = TrustDomain::new("remote.example").expect("td");
    let a = SpiffeId::from_parts(&td, "ns/default/sa/a").expect("id");
    let b = SpiffeId::from_parts(&td, "ns/default/sa/b").expect("id");
    let config = PoolConfig::default();
    let key = |peer: Option<&SpiffeId>,
               td: Option<&TrustDomain>,
               sni: Option<&str>,
               authority: &str,
               dial: &str,
               port: u16,
               policy: u16,
               fingerprint: &str| {
        mesh_mtls_tunnel_pool_key_for_tests(
            dial,
            port,
            15006,
            fingerprint,
            peer,
            sni,
            td,
            authority,
            policy,
            &config,
        )
    };
    let base = key(
        Some(&a),
        None,
        None,
        "10.0.0.1",
        "10.0.0.1",
        8080,
        80,
        "fp1",
    );
    for (label, other) in [
        (
            "pinned identity",
            key(
                Some(&b),
                None,
                None,
                "10.0.0.1",
                "10.0.0.1",
                8080,
                80,
                "fp1",
            ),
        ),
        (
            "trust-domain-only scope",
            key(
                None,
                Some(&td),
                Some("p80.svc"),
                "10.0.0.1",
                "10.0.0.1",
                8080,
                80,
                "fp1",
            ),
        ),
        (
            "authority host",
            key(
                Some(&a),
                None,
                None,
                "10.0.0.2",
                "10.0.0.1",
                8080,
                80,
                "fp1",
            ),
        ),
        (
            "dial host",
            key(
                Some(&a),
                None,
                None,
                "10.0.0.1",
                "10.0.0.9",
                8080,
                80,
                "fp1",
            ),
        ),
        (
            "target port",
            key(
                Some(&a),
                None,
                None,
                "10.0.0.1",
                "10.0.0.1",
                8081,
                80,
                "fp1",
            ),
        ),
        (
            "policy port",
            key(
                Some(&a),
                None,
                None,
                "10.0.0.1",
                "10.0.0.1",
                8080,
                81,
                "fp1",
            ),
        ),
        (
            "gateway SVID",
            key(
                Some(&a),
                None,
                None,
                "10.0.0.1",
                "10.0.0.1",
                8080,
                80,
                "fp2",
            ),
        ),
    ] {
        assert_ne!(base, other, "{label} must partition the tunnel pool key");
    }
    let td_b = key(None, Some(&td), Some("p80.svc"), "h", "gw", 8080, 80, "fp1");
    assert_ne!(
        td_b,
        key(
            None,
            Some(&remote),
            Some("p80.svc"),
            "h",
            "gw",
            8080,
            80,
            "fp1"
        ),
        "remote trust domain must partition the key"
    );
    assert_ne!(
        td_b,
        key(None, Some(&td), Some("p81.svc"), "h", "gw", 8080, 80, "fp1"),
        "SNI override must partition the key"
    );
    // The SVID fingerprint is field 5, where the rotation drain reads it.
    assert_eq!(base.split('|').nth(5), Some("fp1"));
    assert!(base.starts_with("mesh-mtls-tcp|"));
}

// ===== rotation and revocation cut over without reusing a retired connection =====

#[tokio::test(flavor = "multi_thread")]
async fn svid_rotation_cuts_over_and_drains_the_retired_connection() {
    let fixture = Fixture::new(Options::default()).await;
    let mut before = fixture.open_echo().await;
    assert_eq!(fixture.peer.accepted(), 1);

    fixture.rotate_gateway_leaf();
    let mut after = fixture.open_echo().await;
    echo_round_trip(&mut after, b"rotated").await;
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the rotated SVID never rides the old connection"
    );

    // The rotation drain removes the retired-fingerprint connection; the
    // current one stays and keeps serving.
    fixture.pool.force_drain_svid_generation(0);
    assert_eq!(fixture.pool.tunnel_pool_size(), 1);
    let mut next = fixture.open_echo().await;
    echo_round_trip(&mut next, b"current").await;
    assert_eq!(fixture.peer.accepted(), 2);

    // A tunnel already open on the drained connection keeps running, as it
    // did with one connection per tunnel; nothing new lands on it.
    echo_round_trip(&mut before, b"in-flight").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_bundle_only_rotation_retires_the_connection_at_the_drain() {
    let fixture = Fixture::new(Options::default()).await;
    let _first = fixture.open_echo().await;
    fixture.republish_gateway_trust();
    // Same leaf, so the same key until the drain retires it.
    let _second = fixture.open_echo().await;
    assert_eq!(fixture.peer.accepted(), 1);
    fixture.pool.force_drain_svid_generation(0);
    assert_eq!(fixture.pool.tunnel_pool_size(), 0);
    let mut third = fixture.open_echo().await;
    echo_round_trip(&mut third, b"fresh").await;
    assert_eq!(fixture.peer.accepted(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn crl_revocation_of_the_peer_never_reuses_its_pooled_connection() {
    let fixture = Fixture::new(Options::default()).await;
    let mut before = fixture.open_echo().await;
    echo_round_trip(&mut before, b"pre-revocation").await;
    assert_eq!(fixture.peer.accepted(), 1);

    // What `ProxyState::reload_backend_tls_material` does on a CRL reload:
    // publish the CRLs, then drain every pool family.
    fixture
        .crls
        .store(Arc::new(vec![fixture.ca.crl_revoking(PEER_SERIAL)]));
    fixture.pool.force_drain_all();
    assert_eq!(fixture.pool.tunnel_pool_size(), 0);

    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("a revoked peer gets no new tunnel");
    assert!(
        matches!(err, HbonePoolError::TlsHandshake { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the revoked peer's pooled connection was not reused"
    );
}

#[test]
fn backend_tls_reload_drains_the_tunnel_lane() {
    // The CRL drain above is the production path only if a reload reaches
    // the tunnel lane through `force_drain_all`.
    let proxy_mod = include_str!("../../../src/proxy/mod.rs");
    let reload = proxy_mod
        .split("fn reload_backend_tls_material(&self)")
        .nth(1)
        .expect("reload_backend_tls_material")
        .split("\n    fn ")
        .next()
        .expect("bounded reload");
    assert!(reload.contains("pools.force_drain_all()"));
    let family = proxy_mod
        .split("impl BackendPoolFamily {")
        .nth(1)
        .expect("BackendPoolFamily impl")
        .split("    fn force_drain_all(&self) {")
        .nth(1)
        .expect("BackendPoolFamily::force_drain_all")
        .split("\n    }\n")
        .next()
        .expect("bounded BackendPoolFamily::force_drain_all");
    assert!(family.contains("self.mesh_mtls_pool.force_drain_all()"));
    let pool = include_str!("../../../src/proxy/mesh_mtls_pool.rs");
    let drain_all = pool
        .split("pub fn force_drain_all(&self) {")
        .nth(1)
        .expect("MeshMtlsConnectionPool::force_drain_all")
        .split("\n    }\n")
        .next()
        .expect("bounded force_drain_all");
    assert!(drain_all.contains("self.tunnel_entries.clear()"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_peer_certificate_never_reuses_its_pooled_connection() {
    let fixture = Fixture::new(Options {
        peer_lifetime: time::Duration::seconds(3),
        ..Options::default()
    })
    .await;
    let mut before = fixture.open_echo().await;
    echo_round_trip(&mut before, b"pre-expiry").await;
    assert_eq!(fixture.peer.accepted(), 1);

    // Past the peer leaf's `notAfter`, the carrier is never handed out again:
    // the next tunnel dials, and the expired certificate fails verification.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("an expired peer gets no new tunnel");
    assert!(
        matches!(err, HbonePoolError::TlsHandshake { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(fixture.peer.accepted(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_trust_withdrawal_retires_pooled_tunnels_and_redials() {
    let fixture = Fixture::new(Options::default()).await;
    let registry = MeshTrustRegistry::new();
    fixture.pool.attach_mesh_trust_registry(registry.clone());
    let mut a = fixture.open_echo().await;
    let mut b = fixture.open_echo().await;
    echo_round_trip(&mut a, b"a").await;
    echo_round_trip(&mut b, b"b").await;
    assert_eq!(fixture.peer.accepted(), 1);

    let outcome =
        registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);
    assert!(outcome.retired_total() >= 1);
    // Every stream on the withdrawn connection fails on its next poll.
    let mut buf = [0u8; 1];
    assert!(a.read(&mut buf).await.is_err());
    assert!(b.write_all(b"x").await.is_err());

    // The retired connection is never handed out again.
    let mut c = fixture.open_echo().await;
    echo_round_trip(&mut c, b"after-withdrawal").await;
    assert_eq!(fixture.peer.accepted(), 2);
}

// ===== flow control: back-pressure under a stalled reader =====

#[test]
fn flow_control_covers_every_admitted_stream_at_a_full_window() {
    let ceiling = u64::from(H2_MAX_FLOW_CONTROL_WINDOW);
    let covers = |flow: ConnectMultiplexFlowControl| {
        u64::from(flow.max_streams) * u64::from(flow.stream_window)
            <= u64::from(flow.connection_window)
            && u64::from(flow.connection_window) <= ceiling
            && flow.max_streams >= 1
            && flow.stream_window >= 65_535
    };
    for stream in [65_535u32, 262_144, 1 << 20, 8 << 20, 128 << 20] {
        for connection in [65_535u32, 2 << 20, 32 << 20, 128 << 20] {
            for cap in [None, Some(1), Some(4), Some(100), Some(1000), Some(100_000)] {
                let flow = connect_multiplex_flow_control(stream, connection, cap);
                assert!(covers(flow), "{stream}/{connection}/{cap:?} -> {flow:?}");
                assert!(
                    u64::from(flow.connection_window) >= u64::from(connection).min(ceiling),
                    "never lowers the configured connection window"
                );
                if let Some(cap) = cap {
                    assert!(flow.max_streams <= cap.max(1));
                }
            }
        }
    }

    // Destination defaults (frontend 256 KiB / 2 MiB, 1000 streams): only the
    // connection window grows.
    let destination = connect_multiplex_flow_control(256 * 1024, 2 << 20, Some(1000));
    assert_eq!(destination.stream_window, 256 * 1024);
    assert_eq!(destination.max_streams, 1000);
    assert_eq!(destination.connection_window, 1000 * 256 * 1024);
    // Equal stream and connection windows (a valid frontend configuration).
    let tight = connect_multiplex_flow_control(65_535, 65_535, Some(1000));
    assert_eq!(tight.connection_window, 1000 * 65_535);

    // Source carrier defaults: 1000 streams cannot each hold 8 MiB within the
    // HTTP/2 maximum, so the stream window shrinks to fit.
    let (stream, connection, streams) =
        tunnel_carrier_flow_control_for_tests(&PoolConfig::default());
    assert_eq!(streams, Some(1000));
    assert!(u64::from(stream) * 1000 <= u64::from(connection));
    assert!(stream >= 2 * 1024 * 1024 - 1024, "{stream}");

    let capped = PoolConfig {
        http2_max_concurrent_streams: Some(4),
        http2_initial_stream_window_size: 1024 * 1024,
        http2_initial_connection_window_size: 1024 * 1024,
        ..PoolConfig::default()
    };
    assert_eq!(
        tunnel_carrier_flow_control_for_tests(&capped),
        (1024 * 1024, 4 * 1024 * 1024, Some(4))
    );
}

/// Every stream but one on a carrier has a reader that never reads again;
/// the remaining tunnel keeps receiving at full speed, and each stalled
/// stream's buffered bytes stay within its own window (its writer blocks).
#[tokio::test(flavor = "multi_thread")]
async fn stalled_readers_on_every_other_stream_never_starve_the_live_one() {
    const WINDOW: u32 = 1024 * 1024;
    const CAP: u32 = 4;
    let fixture = Fixture::new(Options {
        proxy_stream_cap: Some(CAP),
        // Equal stream and connection windows: without the carrier sizing a
        // single stalled stream would hold the whole connection window.
        proxy_windows: Some((WINDOW, WINDOW)),
        ..Options::default()
    })
    .await;
    let (stream_window, connection_window, streams) =
        tunnel_carrier_flow_control_for_tests(&fixture.pool_config.for_proxy(&fixture.proxy));
    assert_eq!(
        (stream_window, connection_window, streams),
        (WINDOW, CAP * WINDOW, Some(CAP))
    );

    let mut stalled = Vec::new();
    for _ in 0..(CAP - 1) {
        let mut tunnel = fixture.open_ok().await;
        tunnel.write_all(b"FLOOD\n").await.expect("flood command");
        stalled.push(tunnel);
    }
    let mut live = fixture.open_ok().await;
    live.write_all(b"FLOOD\n").await.expect("flood command");
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "all tunnels share one connection"
    );

    // Let the stalled streams fill their windows first.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    let target = 8 * WINDOW as usize;
    tokio::time::timeout(Duration::from_secs(20), async {
        while received < target {
            let n = live.read(&mut buf).await.expect("live tunnel read");
            assert!(n > 0, "live tunnel ended early");
            received += n;
        }
    })
    .await
    .expect("the live tunnel keeps receiving beside stalled siblings");

    let counters: Vec<_> = (0..CAP as usize)
        .map(|i| fixture.peer.flood_counter(i))
        .collect();
    let stalled_counters: Vec<_> = counters
        .iter()
        .filter(|counter| counter.load(Ordering::SeqCst) <= stream_window as usize)
        .cloned()
        .collect();
    assert_eq!(stalled_counters.len(), (CAP - 1) as usize);
    let first: Vec<usize> = stalled_counters
        .iter()
        .map(|c| c.load(Ordering::SeqCst))
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second: Vec<usize> = stalled_counters
        .iter()
        .map(|c| c.load(Ordering::SeqCst))
        .collect();
    assert_eq!(first, second, "every stalled stream's writer is blocked");
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_destination_reader_back_pressures_the_writer_only() {
    let fixture = Fixture::new(Options::default()).await;
    let mut sink = fixture.open_ok().await;
    sink.write_all(b"SINK\n").await.expect("sink command");
    let mut ok = [0u8; 3];
    tokio::time::timeout(OPEN_TIMEOUT, sink.read_exact(&mut ok))
        .await
        .expect("sink ack")
        .expect("read sink ack");
    assert_eq!(&ok, b"OK\n");

    let written = Arc::new(AtomicUsize::new(0));
    let written_task = written.clone();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x42u8; 64 * 1024];
        loop {
            match sink.write(&chunk).await {
                Ok(n) => {
                    written_task.fetch_add(n, Ordering::SeqCst);
                }
                Err(_) => return,
            }
        }
    });

    // The writer stops at the destination's stream window.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let first = written.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = written.load(Ordering::SeqCst);
    assert_eq!(first, second, "writes into a stalled stream must block");
    assert!(
        second <= PEER_STREAM_WINDOW as usize,
        "wrote {second} bytes past a {PEER_STREAM_WINDOW}-byte stream window"
    );
    assert!(!writer.is_finished(), "the writer is blocked, not failed");

    // A sibling on the same connection is unaffected.
    let mut sibling = fixture.open_echo().await;
    echo_round_trip(&mut sibling, b"not-starved").await;
    assert_eq!(fixture.peer.accepted(), 1);
    writer.abort();
}

// ===== review follow-ups: drain fence, CRL expiry, DR overrides, idle, peer cap =====

/// A drain that runs while a carrier's dial is in flight (here a trust-change
/// `force_drain_all`, which changes neither the SVID nor the CRL slot) must
/// keep that carrier out of the pool: the dial serves its own tunnel only, and
/// the next tunnel dials afresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_drain_during_a_dial_keeps_the_dialed_connection_out_of_the_pool() {
    let fixture = Fixture::new(Options::default()).await;
    fixture.peer.hold_handshakes(true);
    let open = fixture.open();
    tokio::pin!(open);
    // Drive the open until its dial is parked on the held handshake.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut open)
            .await
            .is_err(),
        "the dial must be in flight"
    );
    assert_eq!(fixture.peer.accepted(), 1);

    fixture.pool.force_drain_all();
    fixture.peer.hold_handshakes(false);

    let mut first = open
        .await
        .expect("the in-flight dial serves its own tunnel");
    first.write_all(b"ECHO\n").await.expect("echo command");
    echo_round_trip(&mut first, b"own-tunnel").await;
    assert_eq!(
        fixture.pool.tunnel_pool_size(),
        0,
        "a carrier dialed before the drain is never published after it"
    );

    let mut second = fixture.open_echo().await;
    echo_round_trip(&mut second, b"fresh").await;
    assert_eq!(fixture.peer.accepted(), 2, "the next tunnel dialed afresh");
    assert_eq!(fixture.pool.tunnel_pool_size(), 1);
}

/// A carrier stops being handed out once an enforced CRL reaches its
/// `nextUpdate`, even with the CRL slot unchanged and both leaves valid: a
/// fresh handshake would be refused then, so a pooled one must not serve.
#[tokio::test(flavor = "multi_thread")]
async fn an_expiring_crl_retires_carriers_verified_under_it() {
    let fixture = Fixture::new(Options::default()).await;
    fixture.crls.store(Arc::new(vec![
        fixture.ca.crl(&[], time::Duration::seconds(3)),
    ]));
    let mut before = fixture.open_echo().await;
    echo_round_trip(&mut before, b"crl-valid").await;
    assert_eq!(fixture.peer.accepted(), 1);

    tokio::time::sleep(Duration::from_secs(5)).await;
    let err = fixture
        .open()
        .await
        .map(drop)
        .expect_err("an expired CRL refuses the next tunnel");
    assert!(
        matches!(err, HbonePoolError::TlsHandshake { .. }),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the carrier verified under the now-expired CRL was not reused"
    );
}

/// The captured-egress relay proxy carries DestinationRule `connectionPool`
/// settings as `dispatch_port_overrides` (per port) and
/// `dispatch_port_override_fallback` (inherited top level). The tunnel lane
/// honours `maxConcurrentStreams` from them exactly as the HTTP lane does.
#[tokio::test(flavor = "multi_thread")]
async fn destination_rule_stream_cap_on_the_relay_proxy_bounds_streams_per_carrier() {
    let mut fixture = Fixture::new(Options::default()).await;
    let mut overrides = HashMap::new();
    overrides.insert(
        APP_PORT,
        ResolvedPortOverride {
            h2_max_concurrent_streams: Some(1),
            ..Default::default()
        },
    );
    fixture.proxy.dispatch_port_overrides = Some(overrides);
    let _a = fixture.open_echo().await;
    let _b = fixture.open_echo().await;
    fixture.peer.wait_for_active(&[1, 1]).await;
    assert_eq!(fixture.peer.accepted(), 2);

    // The inherited top-level value applies when the port sets none.
    let mut fixture = Fixture::new(Options::default()).await;
    fixture.proxy.dispatch_port_override_fallback = Some(ResolvedPortOverride {
        h2_max_concurrent_streams: Some(2),
        ..Default::default()
    });
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(fixture.open_echo().await);
    }
    fixture.peer.wait_for_active(&[2, 1]).await;
    assert_eq!(fixture.peer.accepted(), 2);
}

#[test]
fn captured_egress_relay_proxies_carry_the_inherited_connection_pool_overlay() {
    let router = include_str!("../../../src/router_cache.rs");
    let synthesized = router
        .matches("relay_proxy.dispatch_port_override_fallback =")
        .count();
    let per_port = router
        .matches("relay_proxy.dispatch_port_overrides =")
        .count();
    assert!(per_port >= 2, "VIP and by-workload relay proxies");
    assert_eq!(
        synthesized, per_port,
        "every relay proxy that carries per-port overrides also carries the inherited overlay"
    );
}

/// A carrier with an open tunnel is never idle-evicted, so with
/// `maxConnections: 1` a second tunnel past the idle timeout still rides it
/// instead of being refused a second connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_with_an_open_tunnel_outlives_the_idle_timeout() {
    let fixture = Fixture::new(Options {
        idle_timeout_seconds: Some(1),
        max_connections: Some(1),
        ..Options::default()
    })
    .await;
    let mut busy = fixture.open_echo().await;
    echo_round_trip(&mut busy, b"busy").await;
    // Well past the idle timeout and several idle sweeps.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fixture.pool.tunnel_pool_size(), 1);
    let mut second = fixture.open_echo().await;
    echo_round_trip(&mut second, b"same-carrier").await;
    assert_eq!(fixture.peer.accepted(), 1);
    echo_round_trip(&mut busy, b"still-busy").await;

    // Once the last tunnel closes the idle clock starts and the carrier goes.
    drop(busy);
    drop(second);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fixture.pool.tunnel_pool_size(), 0);
}

/// A peer that advertises fewer concurrent streams than the client cap:
/// concurrent cold opens must widen to a second carrier rather than park the
/// second stream behind the first inside `h2` until its connect timeout.
#[tokio::test(flavor = "multi_thread")]
async fn cold_burst_respects_the_peers_advertised_stream_cap() {
    let fixture = Fixture::new(Options {
        peer_max_streams: 1,
        width: 2,
        connect_timeout_ms: 3_000,
        ..Options::default()
    })
    .await;
    let (a, b) = tokio::join!(fixture.open_echo(), fixture.open_echo());
    let (mut a, mut b) = (a, b);
    echo_round_trip(&mut a, b"a").await;
    echo_round_trip(&mut b, b"b").await;
    fixture.peer.wait_for_active(&[1, 1]).await;
    assert_eq!(fixture.peer.accepted(), 2);
}

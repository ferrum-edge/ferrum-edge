//! HBONE pool width under measured stream load (issue #5465).
//!
//! `h2::client::SendRequest::clone().ready()` is always `Ready` on a live
//! connection, so before #5465 every pooled CONNECT landed on the first
//! connection and a peer's `SETTINGS_MAX_CONCURRENT_STREAMS` silently parked
//! the next tunnel pending-open until the connect timeout fired. These tests
//! drive `HboneConnectionPool::get_tunnel_via` against an in-process
//! SPIFFE-mTLS h2 peer that counts connections and open CONNECT streams per
//! connection, and check that the pool spreads by measured load, widens on
//! stream-cap saturation and on pressure, and never past its configured bound.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::hbone_pool::{
    H2ConnectTunnel, HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION, HboneConnectionPool,
};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

const APP_PORT: u16 = 8080;
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{}-test-root", td.as_str()));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let cert = params.self_signed(&key).expect("root cert");
    (cert.der().to_vec(), cert.pem(), key.serialize_pem())
}

fn issue_svid(spiffe_id: &SpiffeId, root_pem: &str, root_key_pem: &str) -> (Vec<u8>, Vec<u8>) {
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(spiffe_id_to_san(spiffe_id).expect("spiffe san"));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::hours(1);
    let cert = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (cert.der().to_vec(), leaf_key.serialize_der())
}

fn bundle_for(id: SpiffeId, leaf_der: Vec<u8>, key_der: Vec<u8>, root_der: Vec<u8>) -> SvidBundle {
    SvidBundle {
        spiffe_id: id.clone(),
        cert_chain_der: vec![leaf_der],
        private_key_pkcs8_der: key_der.into(),
        trust_bundles: TrustBundleSet::local_only(TrustBundle {
            trust_domain: id.trust_domain().clone(),
            x509_authorities: vec![root_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }),
    }
}

fn svid_slot(bundle: SvidBundle) -> SharedSvidBundle {
    Arc::new(ArcSwap::new(Arc::new(Some(bundle))))
}

fn proxy_for_test() -> Proxy {
    let now = Utc::now();
    Proxy {
        labels: Default::default(),
        id: "hbone-width".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("HBONE width".to_string()),
        hosts: vec!["orders.example.com".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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

/// In-process HBONE peer: SPIFFE-mTLS + raw `h2` server that advertises a
/// configurable `SETTINGS_MAX_CONCURRENT_STREAMS`, answers every CONNECT with
/// `200` and echoes the tunnel bytes, and tracks the number of open CONNECT
/// streams on each accepted connection (in accept order — the same order the
/// pool appends entries under one key).
///
/// While `blackhole` is set, new connections are accepted (and counted) but
/// never get a TLS handshake, so a dial hangs until its own connect timeout;
/// they are not tracked as pooled connections, and `blackholed_closed` counts
/// those the client has since given up on.
///
/// While `hold_first` is set, CONNECTs on the first accepted connection are
/// counted as open but not answered until it is cleared.
struct Peer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    per_connection_active: Arc<Mutex<Vec<Arc<AtomicUsize>>>>,
    blackhole: Arc<AtomicBool>,
    blackholed_closed: Arc<AtomicUsize>,
    hold_first: watch::Sender<bool>,
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
        let accepted_for_task = accepted.clone();
        let per_connection_for_task = per_connection_active.clone();
        let blackhole = Arc::new(AtomicBool::new(false));
        let blackholed_closed = Arc::new(AtomicUsize::new(0));
        let blackhole_for_task = blackhole.clone();
        let blackholed_closed_for_task = blackholed_closed.clone();
        let (hold_first, hold_first_rx) = watch::channel(false);
        tokio::spawn(async move {
            let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
                .expect("server config");
            let acceptor = TlsAcceptor::from(inbound);
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let connection_index = accepted_for_task.fetch_add(1, Ordering::SeqCst);
                if blackhole_for_task.load(Ordering::SeqCst) {
                    let closed = blackholed_closed_for_task.clone();
                    tokio::spawn(async move {
                        // Swallow the ClientHello and never answer it.
                        let mut tcp = tcp;
                        let mut buf = [0u8; 1024];
                        while let Ok(read) = tcp.read(&mut buf).await {
                            if read == 0 {
                                break;
                            }
                        }
                        closed.fetch_add(1, Ordering::SeqCst);
                    });
                    continue;
                }
                let active = Arc::new(AtomicUsize::new(0));
                per_connection_for_task
                    .lock()
                    .expect("peer registry")
                    .push(active.clone());
                let acceptor = acceptor.clone();
                let hold_first_rx = hold_first_rx.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut h2 = match h2::server::Builder::new()
                        .max_concurrent_streams(max_concurrent_streams)
                        .handshake(tls)
                        .await
                    {
                        Ok(h2) => h2,
                        Err(_) => return,
                    };
                    while let Some(next) = h2.accept().await {
                        let Ok((request, mut respond)) = next else {
                            break;
                        };
                        if request.method() != http::Method::CONNECT {
                            continue;
                        }
                        let active = active.clone();
                        let mut hold_first_rx = hold_first_rx.clone();
                        tokio::spawn(async move {
                            active.fetch_add(1, Ordering::SeqCst);
                            if connection_index == 0 {
                                let _ = hold_first_rx.wait_for(|hold| !*hold).await;
                            }
                            let mut recv = request.into_body();
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .expect("connect response");
                            if let Ok(mut send) = respond.send_response(response, false) {
                                while let Some(Ok(chunk)) = recv.data().await {
                                    let _ = recv.flow_control().release_capacity(chunk.len());
                                    if send.send_data(chunk, false).is_err() {
                                        break;
                                    }
                                }
                                let _ = send.send_data(Bytes::new(), true);
                            }
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
            blackhole,
            blackholed_closed,
            hold_first,
        }
    }

    fn hold_first_connection(&self, hold: bool) {
        self.hold_first.send_replace(hold);
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn blackhole_new_connections(&self, blackhole: bool) {
        self.blackhole.store(blackhole, Ordering::SeqCst);
    }

    async fn wait_for_accepted(&self, expected: usize) {
        wait_until(|| self.accepted() == expected, "peer connection count").await;
    }

    async fn wait_for_blackholed_closed(&self, expected: usize) {
        wait_until(
            || self.blackholed_closed.load(Ordering::SeqCst) == expected,
            "abandoned blackholed dials",
        )
        .await;
    }

    fn active_per_connection(&self) -> Vec<usize> {
        self.per_connection_active
            .lock()
            .expect("peer registry")
            .iter()
            .map(|active| active.load(Ordering::SeqCst))
            .collect()
    }

    /// The peer learns about a dropped tunnel only once the client's RST /
    /// END_STREAM lands, so per-connection counts are asserted by polling.
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
}

/// Poll `done` until it holds; growth publishes from a detached task, so
/// width is asserted by polling rather than right after a checkout.
async fn wait_until(done: impl Fn() -> bool, what: &str) {
    // Longer than `BLACKHOLED_GROWTH_TIMEOUT_MS`, which one wait spans.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct Fixture {
    pool: Arc<HboneConnectionPool>,
    proxy: Proxy,
    peer: Peer,
    workload_id: SpiffeId,
}

impl Fixture {
    /// A pool shared like `ProxyState`'s, so growth runs detached.
    async fn new(width: usize, peer_max_streams: u32) -> Self {
        Self::build(width, peer_max_streams, true).await
    }

    /// A pool used by value (no `into_shared` handle), which grows inline.
    async fn new_by_value(width: usize, peer_max_streams: u32) -> Self {
        Self::build(width, peer_max_streams, false).await
    }

    async fn build(width: usize, peer_max_streams: u32, shared: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let td = TrustDomain::new("cluster.local").expect("trust domain");
        let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
        let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").expect("gateway id");
        let workload_id = SpiffeId::from_parts(&td, "ns/default/sa/workload").expect("workload");
        let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").expect("server id");
        let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
        let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);
        let gateway_slot = svid_slot(bundle_for(
            gateway_id,
            gateway_leaf,
            gateway_key,
            root_der.clone(),
        ));
        let server_slot = svid_slot(bundle_for(server_id, server_leaf, server_key, root_der));
        let peer = Peer::start(server_slot, peer_max_streams).await;
        let pool_config = PoolConfig {
            http2_connections_per_host: width,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config,
            DnsCache::new(DnsConfig::default()),
            gateway_slot,
            4,
        );
        // `Arc::new` alone records no self handle: that pool grows inline.
        let pool = if shared {
            pool.into_shared()
        } else {
            Arc::new(pool)
        };
        Self {
            pool,
            proxy: proxy_for_test(),
            peer,
            workload_id,
        }
    }

    fn open(
        &self,
    ) -> impl Future<Output = Result<H2ConnectTunnel, ferrum_edge::proxy::hbone_pool::HbonePoolError>> + '_
    {
        self.pool.get_tunnel_via(
            &self.proxy,
            "127.0.0.1",
            "127.0.0.1",
            APP_PORT,
            APP_PORT,
            self.peer.port,
            None,
            None,
            None,
            Some(&self.workload_id),
        )
    }

    async fn open_ok(&self) -> H2ConnectTunnel {
        self.open_within(OPEN_TIMEOUT).await
    }

    async fn open_within(&self, budget: Duration) -> H2ConnectTunnel {
        tokio::time::timeout(budget, self.open())
            .await
            .expect("timely tunnel open")
            .expect("open tunnel")
    }

    async fn wait_for_pool_size(&self, expected: usize) {
        wait_until(|| self.pool.pool_size() == expected, "pool width").await;
    }

    /// Wait until `expected` growth dials have finished (pooled or failed and
    /// backed off), so assertions never race a detached dial.
    async fn wait_for_growth_attempts(&self, expected: usize) {
        wait_until(
            || self.pool.growth_attempts_finished_for_test() == expected,
            "finished growth dials",
        )
        .await;
    }
}

async fn echo_round_trip(tunnel: &mut H2ConnectTunnel) {
    tunnel.write_all(b"ping").await.expect("write tunnel");
    let mut buf = [0u8; 4];
    tokio::time::timeout(OPEN_TIMEOUT, tunnel.read_exact(&mut buf))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(&buf, b"ping");
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_tunnels_stay_on_one_connection() {
    let fixture = Fixture::new(4, 1024).await;
    for _ in 0..(HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION * 4) {
        let mut tunnel = fixture.open_ok().await;
        echo_round_trip(&mut tunnel).await;
        drop(tunnel);
    }
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "one tunnel at a time never widens"
    );
    assert_eq!(fixture.pool.pool_size(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_cap_saturation_widens_the_pool() {
    // The peer allows 4 streams per connection; the key allows 4 connections.
    let fixture = Fixture::new(4, 4).await;
    let mut held = Vec::new();
    for _ in 0..9 {
        let mut tunnel = fixture.open_ok().await;
        echo_round_trip(&mut tunnel).await;
        held.push(tunnel);
    }
    // 4 + 4 + 1: a connection at its peer's cap is never chosen while the key
    // has room, and each new connection fills before the next is dialed.
    fixture.peer.wait_for_active(&[4, 4, 1]).await;
    assert_eq!(fixture.peer.accepted(), 3);
    assert_eq!(fixture.pool.pool_size(), 3);
    for tunnel in held.iter_mut() {
        echo_round_trip(tunnel).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pressure_widens_only_up_to_the_bound() {
    let fixture = Fixture::new(2, 1024).await;
    let mut held = Vec::new();
    // Fill the first connection to the growth threshold.
    for _ in 0..HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        held.push(fixture.open_ok().await);
    }
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION])
        .await;
    assert_eq!(fixture.peer.accepted(), 1);
    // The next checkout sees the threshold reached with room to widen: it
    // opens on the connection it already has and a second connection is
    // dialed in the background. The following tunnels follow the
    // least-loaded connection until both carry the same load.
    let busy = HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION + 1;
    held.push(fixture.open_ok().await);
    fixture.wait_for_pool_size(2).await;
    fixture.peer.wait_for_active(&[busy, 0]).await;
    assert_eq!(fixture.peer.accepted(), 2);
    for _ in 0..busy {
        held.push(fixture.open_ok().await);
    }
    fixture.peer.wait_for_active(&[busy, busy]).await;
    assert_eq!(fixture.peer.accepted(), 2);
    // At the configured width, pressure alone never adds a third connection;
    // an exact tie goes to the earliest connection.
    held.push(fixture.open_ok().await);
    fixture.peer.wait_for_active(&[busy + 1, busy]).await;
    assert_eq!(fixture.peer.accepted(), 2);
    assert_eq!(fixture.pool.pool_size(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn checkouts_go_to_the_least_loaded_connection() {
    let fixture = Fixture::new(2, 1024).await;
    let mut first_connection = Vec::new();
    // The last of these reaches the growth threshold: it still opens on the
    // first connection and the second is dialed in the background.
    for _ in 0..=HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        first_connection.push(fixture.open_ok().await);
    }
    fixture.wait_for_pool_size(2).await;
    let mut second_connection = vec![fixture.open_ok().await];
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION + 1, 1])
        .await;
    // Release most of the first connection: it is now the lighter one, so the
    // next tunnels go back to it until the two are level again.
    first_connection.truncate(2);
    fixture.peer.wait_for_active(&[2, 1]).await;
    second_connection.push(fixture.open_ok().await);
    fixture.peer.wait_for_active(&[2, 2]).await;
    first_connection.push(fixture.open_ok().await);
    fixture.peer.wait_for_active(&[3, 2]).await;
    second_connection.push(fixture.open_ok().await);
    fixture.peer.wait_for_active(&[3, 3]).await;
    assert_eq!(fixture.peer.accepted(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_and_bounded_key_queues_until_a_stream_frees() {
    // One connection allowed, two streams per connection: the third tunnel
    // waits for a sibling to close rather than dialing past the bound or
    // failing outright.
    let fixture = Fixture::new(1, 2).await;
    let first = fixture.open_ok().await;
    let _second = fixture.open_ok().await;
    fixture.peer.wait_for_active(&[2]).await;

    let mut third = Box::pin(fixture.open());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut third)
            .await
            .is_err(),
        "the third tunnel must park behind the peer's stream cap"
    );
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "no dial past the configured width"
    );

    drop(first);
    let mut third = tokio::time::timeout(OPEN_TIMEOUT, third)
        .await
        .expect("queued tunnel opens once a stream frees")
        .expect("queued tunnel");
    echo_round_trip(&mut third).await;
    fixture.peer.wait_for_active(&[2]).await;
    assert_eq!(fixture.peer.accepted(), 1);
    assert_eq!(fixture.pool.pool_size(), 1);
}

/// At least `HBONE_GROWTH_BACKOFF_SECS` (10 s), so a backoff measured from the
/// dial's start instead of its failure would already have expired.
const BLACKHOLED_GROWTH_TIMEOUT_MS: u64 = 11_000;

/// Pool growth never makes a tunnel wait for the dial (EDGE-DP-1). Against a
/// peer that blackholes new connections, the old inline growth held the
/// pressured tunnel for the whole connect timeout before falling back to the
/// connection it already had. The connect timeout outlasts the 10 s growth
/// backoff, which must therefore be measured from the dial's failure.
#[tokio::test(flavor = "multi_thread")]
async fn pressured_tunnel_never_waits_for_a_blackholed_growth_dial() {
    let mut fixture = Fixture::new(2, 1024).await;
    fixture.proxy.backend_connect_timeout_ms = BLACKHOLED_GROWTH_TIMEOUT_MS;
    let mut held = Vec::new();
    for _ in 0..HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        held.push(fixture.open_ok().await);
    }
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION])
        .await;
    fixture.peer.blackhole_new_connections(true);

    // Well inside the connect timeout the growth dial is stuck in.
    let mut tunnel = fixture.open_within(Duration::from_millis(1_000)).await;
    echo_round_trip(&mut tunnel).await;
    held.push(tunnel);
    fixture.peer.wait_for_accepted(2).await;

    // While that dial hangs, later pressured tunnels neither wait for it nor
    // start a second one for the key.
    for _ in 0..3 {
        held.push(fixture.open_within(Duration::from_millis(1_000)).await);
    }
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION + 4])
        .await;
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "one growth dial per key at a time"
    );

    // The dial gives up at its own connect timeout. The failure reaches no
    // tunnel, adds no connection, and backs the key off for the full window
    // from that failure: with the peer healthy again, a pressured tunnel
    // still dials nothing.
    fixture.wait_for_growth_attempts(1).await;
    fixture.peer.wait_for_blackholed_closed(1).await;
    fixture.peer.blackhole_new_connections(false);
    held.push(fixture.open_ok().await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(fixture.peer.accepted(), 2, "a failed growth dial backs off");
    assert_eq!(fixture.pool.growth_attempts_finished_for_test(), 1);
    assert_eq!(fixture.pool.pool_size(), 1);
    for tunnel in held.iter_mut() {
        echo_round_trip(tunnel).await;
    }
}

/// A pool used by value has no `Arc` a detached task could own, so it keeps
/// the inline growth: the pressured checkout dials and is served on the new
/// connection before it returns.
#[tokio::test(flavor = "multi_thread")]
async fn by_value_pool_grows_inline_and_serves_the_trigger_on_the_new_connection() {
    let fixture = Fixture::new_by_value(2, 1024).await;
    let mut held = Vec::new();
    for _ in 0..HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        held.push(fixture.open_ok().await);
    }
    assert_eq!(fixture.peer.accepted(), 1);

    let mut grown = fixture.open_ok().await;
    // No polling: the dial finished inside the checkout.
    assert_eq!(fixture.pool.growth_attempts_finished_for_test(), 1);
    assert_eq!(fixture.pool.pool_size(), 2);
    assert_eq!(fixture.peer.accepted(), 2);
    echo_round_trip(&mut grown).await;
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION, 1])
        .await;
    held.push(grown);
}

/// The pool's cached stream cap only moves on CONNECT responses, so a
/// connection can look available while h2 already enforces a lower cap from
/// the peer's SETTINGS (a peer that lowered it mid-connection looks the same).
/// A pressured checkout re-reads the live cap: a connection that is saturated
/// after all sends the tunnel down the awaited growth path, which hands it the
/// new connection, instead of queueing it behind the cap while a background
/// dial widens the pool.
#[tokio::test(flavor = "multi_thread")]
async fn pressured_tunnel_rereads_a_stale_stream_cap_and_lands_on_the_new_connection() {
    let threshold = HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION;
    // The peer allows exactly the growth threshold of streams per connection
    // and answers nothing on its first connection, so the pool never samples
    // that cap there and still caches it as unlimited.
    let mut fixture = Fixture::new(2, threshold as u32).await;
    // Long enough that the held tunnels outlive the test steps below.
    fixture.proxy.backend_connect_timeout_ms = 30_000;
    let fixture = Arc::new(fixture);
    fixture.peer.hold_first_connection(true);
    let mut parked = Vec::new();
    for _ in 0..threshold {
        let fixture = Arc::clone(&fixture);
        parked.push(tokio::spawn(async move { fixture.open().await }));
    }
    fixture.peer.wait_for_active(&[threshold]).await;
    // Let the client's h2 driver apply the peer's SETTINGS.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Trusting the cached cap, this tunnel would queue pending-open on the
    // first connection until a held tunnel closed (30 s here).
    let mut tunnel = fixture.open_within(Duration::from_secs(5)).await;
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the tunnel dialed a new connection"
    );
    assert_eq!(fixture.pool.pool_size(), 2);
    echo_round_trip(&mut tunnel).await;
    fixture.peer.wait_for_active(&[threshold, 1]).await;

    fixture.peer.hold_first_connection(false);
    for task in parked {
        let mut held = tokio::time::timeout(OPEN_TIMEOUT, task)
            .await
            .expect("held tunnel opens once released")
            .expect("open task")
            .expect("held tunnel");
        echo_round_trip(&mut held).await;
    }
    drop(tunnel);
}

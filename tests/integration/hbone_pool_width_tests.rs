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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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
struct Peer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    per_connection_active: Arc<Mutex<Vec<Arc<AtomicUsize>>>>,
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
        tokio::spawn(async move {
            let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
                .expect("server config");
            let acceptor = TlsAcceptor::from(inbound);
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                accepted_for_task.fetch_add(1, Ordering::SeqCst);
                let active = Arc::new(AtomicUsize::new(0));
                per_connection_for_task
                    .lock()
                    .expect("peer registry")
                    .push(active.clone());
                let acceptor = acceptor.clone();
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
                        tokio::spawn(async move {
                            active.fetch_add(1, Ordering::SeqCst);
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
        }
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

struct Fixture {
    pool: HboneConnectionPool,
    proxy: Proxy,
    peer: Peer,
    workload_id: SpiffeId,
}

impl Fixture {
    async fn new(width: usize, peer_max_streams: u32) -> Self {
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
        tokio::time::timeout(OPEN_TIMEOUT, self.open())
            .await
            .expect("timely tunnel open")
            .expect("open tunnel")
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
    // dials a second connection and lands there; the following ones follow the
    // least-loaded connection until both carry the threshold.
    for _ in 0..HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        held.push(fixture.open_ok().await);
    }
    fixture
        .peer
        .wait_for_active(&[
            HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION,
            HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION,
        ])
        .await;
    assert_eq!(fixture.peer.accepted(), 2);
    // At the configured width, pressure alone never adds a third connection;
    // an exact tie goes to the earliest connection.
    held.push(fixture.open_ok().await);
    fixture
        .peer
        .wait_for_active(&[
            HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION + 1,
            HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION,
        ])
        .await;
    assert_eq!(fixture.peer.accepted(), 2);
    assert_eq!(fixture.pool.pool_size(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn checkouts_go_to_the_least_loaded_connection() {
    let fixture = Fixture::new(2, 1024).await;
    let mut first_connection = Vec::new();
    for _ in 0..HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION {
        first_connection.push(fixture.open_ok().await);
    }
    let mut second_connection = vec![fixture.open_ok().await];
    fixture
        .peer
        .wait_for_active(&[HBONE_GROWTH_ACTIVE_STREAMS_PER_CONNECTION, 1])
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

//! Sidecar mesh-mTLS pool width under measured load (issue #5043).
//!
//! One hyper HTTP/2 connection is one driver task, so a key served from a
//! single connection has a hard throughput ceiling no matter how many streams
//! it multiplexes. The pool now adds connections — up to
//! `http2_connections_per_host` — only when a checkout finds the least-loaded
//! connection carrying at least `MESH_MTLS_GROWTH_PENDING_PER_CONNECTION`
//! unanswered requests, selects the least-loaded connection for every
//! checkout, and lets the extra connections idle out when the load is gone.
//!
//! Every test drives the real pool against a real SPIFFE-mTLS h2 server whose
//! responses can be held back, so "pending requests" is a deterministic
//! quantity rather than a race.

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::backend_conn_limit::BackendConnectionLimiter;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResolvedPortOverride, ResponseBodyMode,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::grpc_proxy::GrpcBody;
use ferrum_edge::proxy::mesh_mtls_pool::{
    MESH_MTLS_GROWTH_PENDING_PER_CONNECTION, MeshMtlsConnectionPool, MeshMtlsRequestBody,
    MeshMtlsSender,
};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

const APP_PORT: u16 = 8080;
/// Peer path answered with a 1 KiB body instead of the 2-byte `ok`.
const KIB_PATH: &str = "/kib";
const PEER_MAX_CONCURRENT_STREAMS: u32 = 1024;

// ===== identity fixtures =====

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

fn proxy_for_test(max_connections: Option<u32>) -> Proxy {
    let now = Utc::now();
    let dispatch_port_overrides = max_connections.map(|cap| {
        let mut overrides = HashMap::new();
        overrides.insert(
            APP_PORT,
            ResolvedPortOverride {
                max_connections: Some(cap),
                ..Default::default()
            },
        );
        overrides
    });
    Proxy {
        labels: Default::default(),
        id: "mesh-mtls-pool-width".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh mTLS pool width".to_string()),
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
        dispatch_port_overrides,
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

// ===== a peer whose responses can be held back =====

/// SPIFFE-mTLS h2 server that answers every request with `200` once `release`
/// is `true`, and parks the response until then. `connections` counts accepted
/// TCP connections, i.e. how many physical connections the pool dialed.
struct HoldingPeer {
    addr: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    release: watch::Sender<bool>,
    stop: watch::Sender<bool>,
}

impl HoldingPeer {
    fn hold(&self) {
        self.release.send_replace(false);
    }

    fn release_all(&self) {
        self.release.send_replace(true);
    }

    /// Stop accepting new connections; established ones keep serving.
    fn stop_accepting(&self) {
        self.stop.send_replace(true);
    }

    fn accepted(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn start_holding_peer(server_slot: SharedSvidBundle) -> HoldingPeer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let addr = listener.local_addr().expect("peer addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let (release, release_rx) = watch::channel(true);
    let (stop, mut stop_rx) = watch::channel(false);
    let connections_for_task = connections.clone();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = stop_rx.wait_for(|stopped| *stopped) => return,
            };
            let Ok((tcp, _)) = accepted else { return };
            connections_for_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let release_rx = release_rx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let mut release_rx = release_rx.clone();
                    let body = if request.uri().path() == KIB_PATH {
                        Bytes::from(vec![b'x'; 1024])
                    } else {
                        Bytes::from_static(b"ok")
                    };
                    async move {
                        let _ = request.into_body().collect().await;
                        let _ = release_rx.wait_for(|released| *released).await;
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(body)))
                    }
                });
                // Wider than any test's concurrency so the peer's stream cap never
                // masks what the pool's own connection does under load.
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .max_concurrent_streams(PEER_MAX_CONCURRENT_STREAMS)
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    HoldingPeer {
        addr,
        connections,
        release,
        stop,
    }
}

struct Fixture {
    pool: MeshMtlsConnectionPool,
    proxy: Proxy,
    peer: HoldingPeer,
    peer_id: SpiffeId,
}

async fn fixture(width: usize, max_connections: Option<u32>) -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let peer_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);
    let gateway_slot = svid_slot(bundle_for(
        gateway_id,
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let peer_slot = svid_slot(bundle_for(peer_id.clone(), peer_leaf, peer_key, root_der));
    let peer = start_holding_peer(peer_slot).await;

    let pool_config = PoolConfig {
        http2_connections_per_host: width,
        ..PoolConfig::default()
    };
    let pool = MeshMtlsConnectionPool::new(
        pool_config,
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    if max_connections.is_some() {
        pool.attach_backend_conn_limit(Arc::new(BackendConnectionLimiter::new()));
    }
    Fixture {
        pool,
        proxy: proxy_for_test(max_connections),
        peer,
        peer_id,
    }
}

impl Fixture {
    async fn checkout(&self) -> MeshMtlsSender {
        tokio::time::timeout(
            Duration::from_secs(15),
            self.pool.get_sender(
                &self.proxy,
                "127.0.0.1",
                APP_PORT,
                APP_PORT,
                self.peer.addr.port(),
                Some(&self.peer_id),
                None,
                None,
            ),
        )
        .await
        .expect("timely checkout")
        .expect("mesh-mTLS sender")
    }
}

fn request() -> Request<MeshMtlsRequestBody> {
    request_for("/width")
}

fn request_for(path: &str) -> Request<MeshMtlsRequestBody> {
    Request::builder()
        .method("GET")
        .uri(format!("https://orders.example.com{path}"))
        .body(MeshMtlsRequestBody::Grpc(GrpcBody::Buffered(Full::new(
            Bytes::new(),
        ))))
        .expect("request")
}

type ResponseFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
            > + Send,
    >,
>;

/// Check out a sender and dispatch one request on it, returning the sender
/// (for `pending_requests`) and the still-unanswered response future.
async fn dispatch(fixture: &Fixture) -> (MeshMtlsSender, ResponseFuture) {
    let mut sender = fixture.checkout().await;
    let future = sender.send_request(request()).expect("send");
    (sender, Box::pin(future))
}

async fn expect_ok(future: ResponseFuture) {
    let response = tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("timely response")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await;
}

/// Park `count` requests on the peer, each dispatched through a fresh checkout,
/// so every one of them is a pending response head on some pooled connection.
async fn park(fixture: &Fixture, count: usize) -> Vec<(MeshMtlsSender, ResponseFuture)> {
    fixture.peer.hold();
    let mut parked = Vec::with_capacity(count);
    for _ in 0..count {
        parked.push(dispatch(fixture).await);
    }
    parked
}

// ===== tests =====

#[tokio::test(flavor = "multi_thread")]
async fn sequential_traffic_stays_on_one_connection() {
    let fixture = fixture(8, None).await;

    for _ in 0..(MESH_MTLS_GROWTH_PENDING_PER_CONNECTION * 4) {
        let (_sender, future) = dispatch(&fixture).await;
        expect_ok(future).await;
    }

    assert_eq!(fixture.pool.pool_size(), 1);
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "requests that never overlap must not widen the pool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_requests_follow_response_heads_and_dropped_futures() {
    let fixture = fixture(1, None).await;

    let parked = park(&fixture, 3).await;
    let sender = parked[0].0.clone();
    assert_eq!(
        sender.pending_requests(),
        3,
        "every unanswered request on the connection is pending, across clones"
    );

    // Abandoning a request (deadline, client went away) releases its slot even
    // though the peer never answered it.
    let mut parked = parked;
    drop(parked.pop());
    assert_eq!(sender.pending_requests(), 2);

    fixture.peer.release_all();
    for (_, future) in parked {
        expect_ok(future).await;
    }
    assert_eq!(
        sender.pending_requests(),
        0,
        "an answered request is no longer pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_pressure_widens_only_up_to_the_configured_bound() {
    let fixture = fixture(2, None).await;
    let threshold = MESH_MTLS_GROWTH_PENDING_PER_CONNECTION;

    // Below the threshold: no growth however many checkouts happen.
    let mut parked = park(&fixture, threshold - 1).await;
    let _ = fixture.checkout().await;
    assert_eq!(fixture.pool.pool_size(), 1);
    assert_eq!(fixture.peer.accepted(), 1);

    // Reaching the threshold on the only connection: the next checkout dials a
    // second connection and returns it.
    parked.push(dispatch(&fixture).await);
    assert_eq!(parked[0].0.pending_requests(), threshold);
    let grown = fixture.checkout().await;
    assert_eq!(fixture.pool.pool_size(), 2, "pressure adds a connection");
    assert_eq!(
        fixture.peer.accepted(),
        2,
        "the new connection is a real dial"
    );
    assert_eq!(
        grown.pending_requests(),
        0,
        "the checkout that grew the pool is served on the new connection"
    );

    // Both connections at the threshold, bound reached: no third connection.
    for _ in 0..threshold {
        parked.push(dispatch(&fixture).await);
    }
    let _ = fixture.checkout().await;
    assert_eq!(
        fixture.pool.pool_size(),
        2,
        "never beyond http2_connections_per_host"
    );
    assert_eq!(fixture.peer.accepted(), 2);

    fixture.peer.release_all();
    for (_, future) in parked {
        expect_ok(future).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn checkouts_go_to_the_least_loaded_connection() {
    let fixture = fixture(2, None).await;
    let threshold = MESH_MTLS_GROWTH_PENDING_PER_CONNECTION;

    // Grow to two connections: `threshold` parked on the first, then one
    // checkout that lands on the fresh second connection.
    let mut parked = park(&fixture, threshold).await;
    let first = parked[0].0.clone();
    let second = fixture.checkout().await;
    assert_eq!(fixture.pool.pool_size(), 2);
    assert_eq!(first.pending_requests(), threshold);
    assert_eq!(second.pending_requests(), 0);

    // While the first connection is the busier one, every further request is
    // dispatched on the second until the two are level.
    for expected_on_second in 1..=threshold {
        let (sender, future) = dispatch(&fixture).await;
        parked.push((sender.clone(), future));
        assert_eq!(first.pending_requests(), threshold);
        assert_eq!(sender.pending_requests(), expected_on_second);
    }
    assert_eq!(second.pending_requests(), threshold);

    fixture.peer.release_all();
    for (_, future) in parked {
        expect_ok(future).await;
    }
    assert_eq!(first.pending_requests(), 0);
    assert_eq!(second.pending_requests(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn growth_never_bypasses_destination_rule_max_connections() {
    // `maxConnections = 1` for the destination's app port: the pool may want a
    // second physical connection, but policy says no.
    let fixture = fixture(4, Some(1)).await;
    let threshold = MESH_MTLS_GROWTH_PENDING_PER_CONNECTION;

    let parked = park(&fixture, threshold).await;
    let served = fixture.checkout().await;
    assert_eq!(
        fixture.pool.pool_size(),
        1,
        "a refused growth dial must not add a connection"
    );
    assert_eq!(
        served.pending_requests(),
        threshold,
        "the request is served on the existing, admitted connection"
    );
    // Later pressured checkouts stay on the existing connection too (backoff
    // after the refusal), and the requests themselves keep working.
    let _ = fixture.checkout().await;
    assert_eq!(fixture.pool.pool_size(), 1);
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "exactly one physical connection was ever admitted"
    );

    fixture.peer.release_all();
    for (_, future) in parked {
        expect_ok(future).await;
    }
    let (_, future) = dispatch(&fixture).await;
    expect_ok(future).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_growth_dial_keeps_serving_on_the_existing_connection() {
    let fixture = fixture(4, None).await;
    let threshold = MESH_MTLS_GROWTH_PENDING_PER_CONNECTION;

    // The established connection keeps serving, but no new connection can be
    // dialed: growth must fail quietly and the request must still go out.
    let parked = park(&fixture, threshold).await;
    fixture.peer.stop_accepting();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (sender, future) = dispatch(&fixture).await;
    assert_eq!(
        fixture.pool.pool_size(),
        1,
        "a failed growth dial adds nothing"
    );
    assert_eq!(
        sender.pending_requests(),
        threshold + 1,
        "the pressured request rides the connection that already exists"
    );

    fixture.peer.release_all();
    expect_ok(future).await;
    for (_, future) in parked {
        expect_ok(future).await;
    }
}

/// Issue #5464: one connection under the shipped `PoolConfig` must carry
/// hundreds of concurrent small responses without either side closing it.
///
/// With hyper's adaptive window on (the old default) the connection window
/// starts at 65,535 bytes; 512 streams sharing it force the peer into
/// sub-256-byte DATA frames, and h2's small-frame flood budget then answers
/// with `GOAWAY ENHANCE_YOUR_CALM too_many_data_frames`. Fixed 8 MiB / 32 MiB
/// windows keep frames whole and size that budget to 16 MiB.
#[tokio::test(flavor = "multi_thread")]
async fn one_connection_carries_hundreds_of_concurrent_small_responses() {
    // The fixture builds its pool from `PoolConfig::default()`.
    assert!(
        !PoolConfig::default().http2_adaptive_window,
        "the shipped default is fixed windows"
    );
    let fixture = fixture(1, None).await;
    const CONCURRENCY: usize = 512;

    for path in [KIB_PATH, "/width", KIB_PATH, "/width"] {
        let mut in_flight: Vec<ResponseFuture> = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let mut sender = fixture.checkout().await;
            in_flight.push(Box::pin(
                sender.send_request(request_for(path)).expect("send"),
            ));
        }
        for future in in_flight {
            expect_ok(future).await;
        }
    }

    assert_eq!(fixture.pool.pool_size(), 1);
    assert_eq!(
        fixture.peer.accepted(),
        1,
        "every round rode the single bounded connection; nothing was torn down"
    );
}

//! Source-side reuse of the APPLICATION connection inside a fenced HBONE
//! tunnel (issue #5042 step 2).
//!
//! The receiver half of the contract — that the admission fence re-evaluates
//! live tunnels, and that `handle_hbone_request` advertises it on the CONNECT
//! `200` only while the fence really holds the tunnel — lives in
//! `hbone_admission_fence_tests.rs`. These tests are the SOURCE half: what a
//! gateway does with that advertisement, and what it must never do without it.
//!
//! The fixture is a real SPIFFE-mTLS HTTP/2 CONNECT terminator that relays each
//! admitted tunnel to a real loopback application over a FRESH TCP connection,
//! exactly as a destination relay does. That is what makes the two counters the
//! issue's own measurement table is written in observable here: `connects` (one
//! per CONNECT the peer admitted) and `app_accepts` (one per `accept(2)` the
//! application saw). Pre-#5042 both equal the request count; with reuse both
//! equal the pool size.
//!
//! The peer can also be told to REFUSE new CONNECTs and to REVOKE live ones —
//! the two things a receiver-side policy tightening does — so the source's
//! reaction is pinned without re-testing the sweep itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::_test_support::hbone_inner_h1_request_body_for_test;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, ResponseBodyMode,
    default_namespace,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::modes::mesh::hbone::{TUNNEL_REUSE_FENCED, TUNNEL_REUSE_HEADER};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::grpc_proxy::GrpcBody;
use ferrum_edge::proxy::hbone_inner_pool::{
    HboneInnerConnectionPool, HboneInnerH1Checkout, HboneInnerH1RequestBody, HboneInnerH2Load,
    HboneInnerH2Publication, HboneInnerH2StreamLease, HboneInnerKeyParts, HboneInnerProtocol,
    HboneSourceCredential, MAX_IDLE_H1_PER_KEY,
};
use ferrum_edge::proxy::hbone_pool::HboneConnectionPool;
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest as H2SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::scaffolding::port_registry::TestSocket;

const TRUST_DOMAIN: &str = "cluster.local";
const GATEWAY_SPIFFE: &str = "ns/edge/sa/gateway";
const PEER_SPIFFE: &str = "ns/default/sa/orders";
const CALLER_A: &str = "spiffe://cluster.local/ns/default/sa/caller-a";
const CALLER_B: &str = "spiffe://cluster.local/ns/default/sa/caller-b";
/// The namespace `source_proxy` declares, so the hand-built key identity and
/// the proxy the dial runs under agree.
const NAMESPACE: &str = ferrum_edge::config::types::DEFAULT_NAMESPACE;
const PROXY_ID: &str = "hbone-inner-pool";
const UPSTREAM_ID: &str = "orders";
const DEADLINE: Duration = Duration::from_secs(10);
/// hyper's `DEFAULT_INITIAL_MAX_SEND_STREAMS` (`hyper-1.9.0`
/// `src/proto/h2/client.rs`), the value a nested HTTP/2 client reports for
/// `current_max_send_streams()` until `h2` has APPLIED the peer's SETTINGS —
/// which it defers until it writes the SETTINGS ACK, strictly later than the
/// peer's SETTINGS bytes arriving. `h2` then overwrites it with the advertised
/// MAX_CONCURRENT_STREAMS, or with `usize::MAX` when the peer advertises none,
/// so "no longer this value" is exactly "the peer's SETTINGS are in force".
const HYPER_PRE_SETTINGS_MAX_SEND_STREAMS: usize = 100;

// ---------------------------------------------------------------------------
// Synthetic SPIFFE identity material
// ---------------------------------------------------------------------------

fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!("{}-inner-pool-root", td.as_str()),
    );
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
    // An explicit, parseable validity window: the source credential deadline is
    // read out of this leaf's `notAfter`, so a lease's bound and the
    // certificate the tunnel actually presents describe the same instant.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::hours(1);

    let leaf = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (leaf.der().to_vec(), leaf_key.serialize_der())
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

/// Gateway + peer identities issued from one synthetic root, so the peer
/// verifies the gateway's client SVID and the gateway pins the peer's.
struct Identities {
    gateway: SvidBundle,
    peer: SvidBundle,
    peer_id: SpiffeId,
}

fn identities() -> Identities {
    let td = TrustDomain::new(TRUST_DOMAIN).expect("trust domain");
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, GATEWAY_SPIFFE).expect("gateway id");
    let peer_id = SpiffeId::from_parts(&td, PEER_SPIFFE).expect("peer id");
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);
    Identities {
        gateway: bundle_for(gateway_id, gateway_leaf, gateway_key, root_der.clone()),
        peer: bundle_for(peer_id.clone(), peer_leaf, peer_key, root_der),
        peer_id,
    }
}

// ---------------------------------------------------------------------------
// The application behind the peer's relay
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppBehaviour {
    /// One `200` with a 2-byte `Content-Length` body per request, keep-alive.
    /// The shape the issue's own measurement used.
    Ok,
    /// Declares 16 bytes, writes 5, and closes. The response is TRUNCATED, so
    /// the exchange never completes cleanly and the lease must not come back.
    Truncate,
    /// One `200` carrying `Connection: close`, then the socket is closed. The
    /// carrier is unusable afterwards and must never re-enter the idle set.
    ConnectionClose,
    /// `204 No Content` per request, keep-alive. hyper reports the response
    /// body as already ended, which is the dispatch's `is_end_stream` arm:
    /// the lease is checked in immediately rather than travelling with a body.
    NoContent,
    /// Declares four body bytes, writes two, waits for
    /// [`App::release_split_body`], then writes the rest. What the CLIENT sees
    /// before the release is what distinguishes an eagerly buffered response
    /// (nothing, not even the headers) from a streamed one (headers and the
    /// first two bytes).
    SplitBody,
    /// An h2c server: one `200` per request, and after `goaway_after` requests
    /// it gracefully shuts the connection down (GOAWAY).
    H2c { goaway_after: usize },
    /// An h2c server advertising `SETTINGS_MAX_CONCURRENT_STREAMS`, so the
    /// source pool learns a real per-carrier stream cap.
    H2cCapped { max_concurrent_streams: u32 },
}

struct App {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
    handle: JoinHandle<()>,
}

impl App {
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Requests the application actually SERVED. The reuse contract is that
    /// this never exceeds the number of client requests: the at-most-once
    /// pre-wire replay may only resend a request nothing wrote to the wire.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Let an [`AppBehaviour::SplitBody`] response finish. `notify_one` stores
    /// a permit, so the test may release before or after the app parks.
    fn release_split_body(&self) {
        self.release.notify_one();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Read one complete HTTP/1.1 request — head plus any declared body — off
/// `stream`, returning `false` at EOF.
///
/// Draining the declared body matters: these tests keep the application
/// connection alive across requests, so leaving upload bytes in the socket
/// would make the NEXT request's head unparseable and turn a reuse assertion
/// into a framing accident.
async fn read_h1_request(stream: &mut TcpStream) -> bool {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => head.push(byte[0]),
        }
    }
    let declared = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if declared > 0 {
        let mut body = vec![0_u8; declared];
        if stream.read_exact(&mut body).await.is_err() {
            return false;
        }
    }
    true
}

async fn start_app(behaviour: AppBehaviour) -> App {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind application");
    let addr = listener.local_addr().expect("application addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let accepts_for_task = Arc::clone(&accepts);
    let requests_for_task = Arc::clone(&requests);
    let release_for_task = Arc::clone(&release);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            accepts_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_app_connection(
                stream,
                behaviour,
                Arc::clone(&requests_for_task),
                Arc::clone(&release_for_task),
            ));
        }
    });
    App {
        addr,
        accepts,
        requests,
        release,
        handle,
    }
}

async fn serve_app_connection(
    mut stream: TcpStream,
    behaviour: AppBehaviour,
    requests: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
) {
    match behaviour {
        AppBehaviour::Ok => {
            while read_h1_request(&mut stream).await {
                requests.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        AppBehaviour::Truncate => {
            if read_h1_request(&mut stream).await {
                requests.fetch_add(1, Ordering::SeqCst);
                // Declares sixteen body bytes and writes five, then hangs up.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\n\r\nshort")
                    .await;
                let _ = stream.shutdown().await;
            }
        }
        AppBehaviour::ConnectionClose => {
            if read_h1_request(&mut stream).await {
                requests.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            }
        }
        AppBehaviour::NoContent => {
            while read_h1_request(&mut stream).await {
                requests.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        AppBehaviour::SplitBody => {
            while read_h1_request(&mut stream).await {
                requests.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nab")
                    .await
                    .is_err()
                {
                    return;
                }
                // The tail is withheld until the test says so, which is what
                // makes "did the client see the headers yet?" a decisive
                // question rather than a timing guess.
                release.notified().await;
                if stream.write_all(b"cd").await.is_err() {
                    return;
                }
            }
        }
        AppBehaviour::H2cCapped {
            max_concurrent_streams,
        } => {
            let Ok(mut server) = h2::server::Builder::new()
                .max_concurrent_streams(max_concurrent_streams)
                .handshake(stream)
                .await
            else {
                return;
            };
            while let Some(next) = server.accept().await {
                let Ok((_request, mut respond)) = next else {
                    return;
                };
                requests.fetch_add(1, Ordering::SeqCst);
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("h2c response");
                let Ok(mut send) = respond.send_response(response, false) else {
                    return;
                };
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
            }
        }
        AppBehaviour::H2c { goaway_after } => {
            let Ok(mut server) = h2::server::handshake(stream).await else {
                return;
            };
            let mut served = 0_usize;
            while let Some(next) = server.accept().await {
                let Ok((_request, mut respond)) = next else {
                    return;
                };
                requests.fetch_add(1, Ordering::SeqCst);
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("h2c response");
                let Ok(mut send) = respond.send_response(response, false) else {
                    return;
                };
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
                served += 1;
                if goaway_after > 0 && served >= goaway_after {
                    server.graceful_shutdown();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The peer: a SPIFFE-mTLS HTTP/2 CONNECT terminator that relays to the app
// ---------------------------------------------------------------------------

struct Peer {
    addr: SocketAddr,
    /// CONNECTs the peer ADMITTED (a refused CONNECT is not counted).
    connects: Arc<AtomicUsize>,
    /// Whether new CONNECTs are refused — a receiver-side policy tightening.
    refuse: Arc<AtomicBool>,
    /// Live relay tasks, so a test can cut every tunnel the way a fence sweep
    /// does: the relay ends, its `SendStream` drops, and the peer resets the
    /// CONNECT stream.
    live: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Accepted mTLS connection tasks, so a test can take the whole session
    /// away — what a destination that restarts, or reaps its idle
    /// connections, really does to a source that still has one pooled.
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    handle: JoinHandle<()>,
}

impl Peer {
    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    fn set_refuse(&self, on: bool) {
        self.refuse.store(on, Ordering::SeqCst);
    }

    /// Cut every live tunnel, as a fence sweep's revocation does.
    async fn revoke_all(&self) {
        let mut live = self.live.lock().await;
        for task in live.drain(..) {
            task.abort();
        }
    }

    /// Take every accepted session away and WAIT for it to be gone.
    ///
    /// Aborting the relay tasks alone is not a reap: the tunnel's receive half
    /// lives in a child task, so the CONNECT stream can stay half-open and a
    /// source that writes into it is answered by nobody. Dropping the accepted
    /// connection task drops the TLS stream and its socket, so the source gets
    /// a real EOF on the transport under its pooled inner connection. Each
    /// handle is AWAITED after the abort, so when this returns the sockets are
    /// closed rather than merely scheduled to be.
    async fn reap_sessions(&self) {
        let relays: Vec<JoinHandle<()>> = self.live.lock().await.drain(..).collect();
        let sessions: Vec<JoinHandle<()>> = self.connections.lock().await.drain(..).collect();
        for task in relays.into_iter().chain(sessions) {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start_peer(peer_slot: SharedSvidBundle, app_addr: SocketAddr, advertise: bool) -> Peer {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind hbone peer");
    let addr = listener.local_addr().expect("peer addr");
    let connects = Arc::new(AtomicUsize::new(0));
    let advertise = Arc::new(AtomicBool::new(advertise));
    let refuse = Arc::new(AtomicBool::new(false));
    let live: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let connections: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

    let connects_for_task = Arc::clone(&connects);
    let advertise_for_task = Arc::clone(&advertise);
    let refuse_for_task = Arc::clone(&refuse);
    let live_for_task = Arc::clone(&live);
    let connections_for_task = Arc::clone(&connections);

    let handle = tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(peer_slot, true, Arc::new(Vec::new()))
            .expect("peer server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let connects = Arc::clone(&connects_for_task);
            let advertise = Arc::clone(&advertise_for_task);
            let refuse = Arc::clone(&refuse_for_task);
            let live = Arc::clone(&live_for_task);
            let session = tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut server) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(next) = server.accept().await {
                    let Ok((request, mut respond)) = next else {
                        return;
                    };
                    if request.method() != http::Method::CONNECT {
                        continue;
                    }
                    if refuse.load(Ordering::SeqCst) {
                        let refusal = Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(())
                            .expect("refusal");
                        let _ = respond.send_response(refusal, true);
                        continue;
                    }
                    connects.fetch_add(1, Ordering::SeqCst);
                    let mut builder = Response::builder().status(StatusCode::OK);
                    if advertise.load(Ordering::SeqCst) {
                        builder = builder.header(TUNNEL_REUSE_HEADER, TUNNEL_REUSE_FENCED);
                    }
                    let Ok(accepted) =
                        respond.send_response(builder.body(()).expect("connect response"), false)
                    else {
                        return;
                    };
                    let recv = request.into_body();
                    let task = tokio::spawn(relay_tunnel(recv, accepted, app_addr));
                    live.lock().await.push(task);
                }
            });
            connections_for_task.lock().await.push(session);
        }
    });

    Peer {
        addr,
        connects,
        refuse,
        live,
        connections,
        handle,
    }
}

/// Byte-relay one admitted tunnel to a FRESH application connection, which is
/// what makes `app_accepts` count exactly what a destination relay costs.
async fn relay_tunnel(
    mut recv: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    app_addr: SocketAddr,
) {
    let Ok(app) = TcpStream::connect(app_addr).await else {
        send.send_reset(h2::Reason::CONNECT_ERROR);
        return;
    };
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let upstream = tokio::spawn(async move {
        while let Some(chunk) = recv.data().await {
            let Ok(chunk) = chunk else { return };
            let _ = recv.flow_control().release_capacity(chunk.len());
            if app_write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = app_write.shutdown().await;
    });
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        match app_read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = send.send_data(Bytes::new(), true);
    upstream.abort();
}

// ---------------------------------------------------------------------------
// Source-side gateway
// ---------------------------------------------------------------------------

fn source_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        labels: Default::default(),
        id: PROXY_ID.to_string(),
        namespace: default_namespace(),
        name: Some("HBONE inner pool".to_string()),
        hosts: vec!["orders.local".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 8080,
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
        upstream_id: Some(UPSTREAM_ID.to_string()),
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

fn source_pool(gateway: SvidBundle) -> Arc<HboneConnectionPool> {
    Arc::new(HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        svid_slot(gateway),
        8,
    ))
}

/// The dispatch-side key identity, built exactly the way
/// `proxy_to_backend_hbone` builds it: everything that decides who is talking
/// to whom, under what credential, over what wire settings.
struct KeyIdentity {
    credential: HboneSourceCredential,
    pool_config: PoolConfig,
    namespace: String,
    proxy_id: String,
    upstream_id: Option<String>,
    /// The admitting proxy's lifecycle generation. `None` is the shape a
    /// synthesized relay proxy produces — absent from every published
    /// generation by design.
    proxy_lifecycle_generation: Option<u64>,
    peer_id: SpiffeId,
    /// The PINNED peer identity, when one is pinned. `None` is the
    /// trust-domain-scoped cross-cluster shape.
    expected_peer: Option<SpiffeId>,
    /// The remote trust domain a cross-cluster session is verified against.
    expected_trust_domain: Option<TrustDomain>,
    /// The ClientHello SNI override a cross-cluster east-west dial carries.
    sni_override: Option<String>,
    app_host: String,
    app_port: u16,
    /// The host the OUTER session is dialled to. Differs from `app_host` on
    /// NodeWaypoint secured egress and cross-cluster east-west.
    dial_host: String,
    hbone_port: u16,
    asserted_principal: Option<SpiffeId>,
}

impl KeyIdentity {
    fn parts(&self, protocol: HboneInnerProtocol) -> HboneInnerKeyParts<'_> {
        HboneInnerKeyParts {
            protocol,
            namespace: self.namespace.as_str(),
            proxy_id: self.proxy_id.as_str(),
            upstream_id: self.upstream_id.as_deref(),
            proxy_lifecycle_generation: self.proxy_lifecycle_generation,
            app_host: self.app_host.as_str(),
            app_port: self.app_port,
            dial_host: self.dial_host.as_str(),
            hbone_port: self.hbone_port,
            expected_peer: self.expected_peer.as_ref(),
            expected_trust_domain: self.expected_trust_domain.as_ref(),
            sni_override: self.sni_override.as_deref(),
            source_principal: self
                .asserted_principal
                .as_ref()
                .unwrap_or(&self.credential.identity),
            source_principal_asserted: self.asserted_principal.is_some(),
            credential: &self.credential,
            pool_config: &self.pool_config,
        }
    }
}

/// The base identity every focused test starts from: in-cluster, pinned peer,
/// gateway acting as itself, `dial_host == app_host`.
fn base_identity(
    credential: HboneSourceCredential,
    peer_id: SpiffeId,
    app_host: &str,
    app_port: u16,
    hbone_port: u16,
) -> KeyIdentity {
    KeyIdentity {
        credential,
        pool_config: PoolConfig::default(),
        namespace: NAMESPACE.to_string(),
        proxy_id: PROXY_ID.to_string(),
        upstream_id: Some(UPSTREAM_ID.to_string()),
        proxy_lifecycle_generation: None,
        expected_peer: Some(peer_id.clone()),
        peer_id,
        expected_trust_domain: None,
        sni_override: None,
        app_host: app_host.to_string(),
        app_port,
        dial_host: app_host.to_string(),
        hbone_port,
        asserted_principal: None,
    }
}

/// Everything one test drives: a real source pool, a real peer, a real app.
struct Fixture {
    pool: Arc<HboneConnectionPool>,
    peer: Peer,
    app: App,
    identity: KeyIdentity,
}

async fn fixture(behaviour: AppBehaviour, advertise: bool) -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let app = start_app(behaviour).await;
    let peer = start_peer(svid_slot(ids.peer), app.addr, advertise).await;
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("the gateway SVID resolves a source credential identity");
    let identity = base_identity(credential, ids.peer_id, "127.0.0.1", 8080, peer.addr.port());
    Fixture {
        pool,
        peer,
        app,
        identity,
    }
}

impl Fixture {
    /// Open ONE new CONNECT and run a fresh inner HTTP/1.1 client over it —
    /// the dispatch's cold-miss path, including reading the peer's capability
    /// advertisement off the `200` before the tunnel is consumed.
    async fn try_open_fresh_h1(&self) -> Result<HboneInnerH1Checkout, String> {
        let proxy = source_proxy();
        // The dispatch snapshots the retirement generation BEFORE the dial;
        // mirror that here so the fixture's cold-miss path is fenced exactly
        // as `open_hbone_inner_h1` is.
        let generation = self.pool.inner_pool().drain_generation();
        let tunnel = tokio::time::timeout(
            DEADLINE,
            self.pool.get_tunnel_via(
                &proxy,
                &self.identity.dial_host,
                &self.identity.app_host,
                self.identity.app_port,
                self.identity.app_port,
                self.identity.hbone_port,
                self.identity.expected_peer.as_ref(),
                None,
                None,
                self.identity.asserted_principal.as_ref(),
            ),
        )
        .await
        .map_err(|_| "CONNECT timed out".to_string())?
        .map_err(|err| format!("the peer refused the CONNECT: {err}"))?;
        let advertised = tunnel.peer_advertises_inner_reuse();
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, HboneInnerH1RequestBody>(TokioIo::new(tunnel))
            .await
            .map_err(|err| format!("inner HTTP/1.1 handshake failed: {err}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(self.pool.inner_pool().fresh_h1(
            &self.identity.parts(HboneInnerProtocol::Http1),
            sender,
            advertised,
            true,
            self.identity.credential.leaf_deadline,
            generation,
        ))
    }

    async fn open_fresh_h1(&self) -> HboneInnerH1Checkout {
        self.try_open_fresh_h1()
            .await
            .expect("the peer admits the CONNECT")
    }

    /// One inner request, exactly as the dispatch does it: check out a lease if
    /// one is pooled, otherwise open a fresh CONNECT; send; and return the
    /// lease ONLY after the whole response body has been read.
    async fn request(&self) -> Result<(StatusCode, Bytes), String> {
        let mut checkout = match self.pool.inner_pool().checkout_h1(
            &self.identity.parts(HboneInnerProtocol::Http1),
            true,
            self.identity.credential.leaf_deadline,
        ) {
            Some(pooled) => pooled,
            None => self.try_open_fresh_h1().await?,
        };
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .header("host", "orders.local")
            .body(hbone_inner_h1_request_body_for_test(Bytes::new()))
            .expect("inner request");
        let response = tokio::time::timeout(DEADLINE, checkout.sender.send_request(request))
            .await
            .map_err(|_| "inner request timed out".to_string())?
            .map_err(|err| format!("inner send failed: {err}"))?;
        let status = response.status();
        // Every error arm below returns WITHOUT checking in, which is the whole
        // contract: a lease comes back only after a clean, fully consumed
        // response.
        let collected = tokio::time::timeout(DEADLINE, response.into_body().collect())
            .await
            .map_err(|_| "inner response body timed out".to_string())?
            .map_err(|err| format!("inner response body failed: {err}"))?;
        HboneInnerConnectionPool::checkin_h1_when_idle(self.pool.inner_pool(), checkout);
        Ok((status, collected.to_bytes()))
    }
}

/// `checkin_h1_when_idle` may defer onto a spawned task when hyper's
/// dispatcher has not re-armed yet, so residency is asserted by polling rather
/// than by reading the counter once.
async fn wait_for_pooled(pool: &HboneInnerConnectionPool, expected: usize) {
    tokio::time::timeout(DEADLINE, async {
        while pool.pooled_connections() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {expected} pooled inner connections, found {}",
            pool.pooled_connections()
        )
    });
}

// ---------------------------------------------------------------------------
// The reuse claim, in the issue's own two counters
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_fenced_peer_reuses_the_inner_connection_and_the_app_accepts_once() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    for _ in 0..3 {
        let (status, body) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"ok");
        wait_for_pooled(fx.pool.inner_pool(), 1).await;
    }

    assert_eq!(
        fx.peer.connects(),
        1,
        "three requests over a fenced tunnel must cost ONE CONNECT"
    );
    assert_eq!(
        fx.app.accepts(),
        1,
        "the destination application must see ONE accept(2), not one per request"
    );
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_misses, 1, "only the first request is a cold miss");
    assert_eq!(stats.h1_hits, 2, "the other two are pool hits");
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.discards, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_does_not_advertise_the_fence_keeps_per_request_behaviour() {
    let fx = fixture(AppBehaviour::Ok, false).await;

    for _ in 0..3 {
        let (status, body) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"ok");
    }

    assert_eq!(
        fx.peer.connects(),
        3,
        "without the capability the source must open one CONNECT per request"
    );
    assert_eq!(
        fx.app.accepts(),
        3,
        "and the application must see one accept(2) per request, exactly as before"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "nothing may be pooled for a peer that does not fence its live tunnels"
    );
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_hits, 0);
    assert_eq!(stats.h1_misses, 3);
    assert_eq!(
        stats.discards, 3,
        "each healthy-but-unpoolable connection is accounted as a discard"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alternating_source_principals_never_share_an_inner_connection() {
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    let caller_a = SpiffeId::new(CALLER_A).expect("caller a");
    let caller_b = SpiffeId::new(CALLER_B).expect("caller b");

    for round in 0..4 {
        fx.identity.asserted_principal = Some(if round % 2 == 0 {
            caller_a.clone()
        } else {
            caller_b.clone()
        });
        let (status, _) = fx.request().await.expect("request succeeds");
        assert_eq!(status, StatusCode::OK);
        wait_for_pooled(fx.pool.inner_pool(), if round == 0 { 1 } else { 2 }).await;
    }

    assert_eq!(
        fx.peer.connects(),
        2,
        "two principals must open two tunnels — and only two, because each \
         principal reuses its own"
    );
    assert_eq!(fx.app.accepts(), 2);
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h1_misses, 2, "one cold miss per principal");
    assert_eq!(stats.h1_hits, 2, "and one hit per principal after that");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_own_svid_is_a_different_key_from_asserting_that_identity() {
    // "The gateway acting as itself" and "the gateway asserting an identity on
    // behalf of a peer" are different admission facts at the destination even
    // when the SPIFFE string is identical, so they must not share a connection.
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    let own = fx.identity.credential.identity.clone();

    fx.request().await.expect("gateway-as-itself request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.identity.asserted_principal = Some(own);
    fx.request().await.expect("asserted-identity request");
    wait_for_pooled(fx.pool.inner_pool(), 2).await;

    assert_eq!(
        fx.peer.connects(),
        2,
        "the asserted form must not inherit the unasserted form's connection"
    );
    assert_eq!(fx.app.accepts(), 2);
}

// ---------------------------------------------------------------------------
// Revocation, refusal, and credential bounds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_tunnel_is_discarded_and_the_next_request_faces_the_new_policy() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;
    assert_eq!(fx.peer.connects(), 1);

    // The receiver tightens: every live tunnel is cut (what a fence sweep's
    // revocation does to the wire) and the same principal's next CONNECT is
    // refused. Both halves matter — cutting alone would only cost a redial.
    fx.peer.revoke_all().await;
    fx.peer.set_refuse(true);

    // The next request must face the CURRENT policy rather than ride the
    // revoked tunnel. Either the pooled lease is already observably closed and
    // the fresh CONNECT is refused, or the close has not propagated yet and the
    // send fails pre-wire — which is exactly the case the dispatch replays onto
    // a fresh CONNECT that this peer now refuses. Both are failures here, and
    // neither is a served request.
    let refused = fx.request().await;
    assert!(
        refused.is_err(),
        "a reused tunnel must never survive its revocation, got {refused:?}"
    );

    // And the revoked connection is gone from the pool either way: a checkout
    // that found it took it out, and a checkout that found it closed evicted it.
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 0);
    assert!(
        fx.pool
            .inner_pool()
            .checkout_h1(
                &fx.identity.parts(HboneInnerProtocol::Http1),
                true,
                fx.identity.credential.leaf_deadline,
            )
            .is_none(),
        "nothing reusable may remain for a principal the receiver now refuses"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_elapsed_source_credential_is_never_handed_out() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    // A lease whose admitting credential has ALREADY elapsed. `checkin_h1` is
    // the direct entry point (`checkin_h1_when_idle` would refuse to pool it,
    // which is the production guard), so the pool is deliberately put into the
    // state time would otherwise produce: a resident connection past its bound.
    let elapsed = tokio::time::Instant::now();
    let expired = fx.pool.inner_pool().fresh_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        fx.open_fresh_h1().await.sender,
        true,
        true,
        Some(elapsed),
        fx.pool.inner_pool().drain_generation(),
    );
    fx.pool.inner_pool().checkin_h1(expired);
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    let checkout = fx.pool.inner_pool().checkout_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        true,
        fx.identity.credential.leaf_deadline,
    );
    assert!(
        checkout.is_none(),
        "reuse must never outlive the source credential that admitted it"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an expired entry is EVICTED, not merely skipped: it must not stay \
         reachable for the next caller either"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_bound_only_ever_tightens_across_the_requests_that_use_it() {
    // The current request's credential bound is folded INTO the lease that
    // comes back, so a connection pooled under a long-lived credential cannot
    // be handed on with a longer bound than the request that last used it.
    // It deliberately does NOT decide whether the pooled entry may exist: a
    // caller arriving with a short-lived credential must not evict a healthy
    // connection out from under everyone else.
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    let short_lived = tokio::time::Instant::now() + Duration::from_millis(50);
    let leased = fx
        .pool
        .inner_pool()
        .checkout_h1(
            &fx.identity.parts(HboneInnerProtocol::Http1),
            true,
            Some(short_lived),
        )
        .expect("a healthy connection is still reusable");
    assert!(leased.reused());

    // Once that short bound has passed, the lease may not re-enter the idle
    // set — even though the connection itself is perfectly healthy.
    tokio::time::sleep(Duration::from_millis(80)).await;
    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), leased);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a lease past the earliest credential that ever used it is discarded"
    );
    assert!(fx.pool.inner_pool().stats().discards >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_alive_off_never_consults_or_fills_the_idle_set() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    let checkout = fx.pool.inner_pool().checkout_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        false,
        fx.identity.credential.leaf_deadline,
    );
    assert!(checkout.is_none(), "keep-alive off never reuses");

    let lease = fx.pool.inner_pool().fresh_h1(
        &fx.identity.parts(HboneInnerProtocol::Http1),
        fx.open_fresh_h1().await.sender,
        true,
        false,
        fx.identity.credential.leaf_deadline,
        fx.pool.inner_pool().drain_generation(),
    );
    assert!(
        !lease.poolable(),
        "a lease taken under keep-alive off may never re-enter the idle set"
    );
    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), lease);
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_response_never_returns_the_lease() {
    let fx = fixture(AppBehaviour::Truncate, true).await;

    let first = fx.request().await;
    assert!(
        first.is_err(),
        "a response that declares sixteen bytes and delivers five is truncated"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a truncated exchange leaves the framing state unknown, so the lease is \
         dropped and the tunnel retired — never pooled"
    );

    // The next request therefore pays a fresh CONNECT and a fresh app accept,
    // which is the point: a poisoned connection must not be handed to anyone.
    let _ = fx.request().await;
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

// ---------------------------------------------------------------------------
// Trust drains reach the inner connections
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_svid_rotation_retires_inner_connections_built_under_the_retired_leaf() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    // The rotation drain resolves the retired leaf fingerprint out of the key,
    // exactly as it does for the outer transports.
    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::clone(&fx.identity.credential.fingerprint)]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an inner connection must stop being reachable when the leaf that \
         authenticated its tunnel rotates out"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unrelated_fingerprint_retirement_leaves_the_pool_alone() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::from("some-other-leaf-fingerprint")]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "the retain pass matches on the key's own leaf fingerprint, so a drain \
         for a leaf this connection was never built under does not REMOVE it"
    );
    // It is nonetheless SUPERSEDED: a rotation advances the entry fence for the
    // whole pool, deliberately, because the pass walks the map shard by shard
    // and a concurrent checkout can win a shard it has not reached. The cost is
    // one extra CONNECT on the next checkout under an unrelated fingerprint.
    // See `an_entry_a_retirement_superseded_is_evicted_at_checkout_not_served`.
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_pool_retirement_reaches_the_inner_connections_through_the_outer_pool() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    // A committed gateway trust withdrawal clears the mesh pools WHOLE. Because
    // the inner pool is OWNED by the outer one, that reaches the inner
    // connections without a second call site anybody has to remember.
    fx.pool.force_drain_all();
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an inner connection is only ever as trustworthy as the tunnel it rides"
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_per_key_idle_bound_is_enforced() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    // One more exclusive lease than the per-key bound admits.
    let mut leases = Vec::new();
    for _ in 0..(MAX_IDLE_H1_PER_KEY + 1) {
        leases.push(fx.open_fresh_h1().await);
    }
    assert_eq!(fx.peer.connects(), MAX_IDLE_H1_PER_KEY + 1);
    for lease in leases {
        fx.pool.inner_pool().checkin_h1(lease);
    }

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        MAX_IDLE_H1_PER_KEY,
        "one key may never retain more than its bound"
    );
    assert_eq!(
        fx.pool.inner_pool().stats().discards,
        1,
        "the over-cap connection is discarded, which is the pre-reuse cost — \
         never an error"
    );
}

// ---------------------------------------------------------------------------
// Nested HTTP/2 (native gRPC inside the tunnel)
// ---------------------------------------------------------------------------

/// Open a CONNECT and run a nested HTTP/2 client over it, the way
/// `open_hbone_grpc_sender` does.
async fn open_fresh_h2(fx: &Fixture) -> NestedH2 {
    let proxy = source_proxy();
    let tunnel = tokio::time::timeout(
        DEADLINE,
        fx.pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            &fx.identity.app_host,
            fx.identity.app_port,
            fx.identity.app_port,
            fx.identity.hbone_port,
            Some(&fx.identity.peer_id),
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely CONNECT")
    .expect("the peer admits the CONNECT");
    let advertised = tunnel.peer_advertises_inner_reuse();
    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, GrpcBody>(TokioIo::new(tunnel))
        .await
        .expect("nested HTTP/2 handshake");
    // EXACTLY the production sampling path (`open_hbone_grpc_sender`): the load
    // is created before the driver is spawned and the driver stores
    // `Connection::current_max_send_streams()` after every poll. The cap lives
    // on hyper's `Connection`, never on the `SendRequest` the pool holds, and
    // reading it once would record hyper's pre-settings default of 100 for
    // every peer — `h2` does not apply the peer's SETTINGS until it writes the
    // ACK, which is later than their bytes arriving.
    let load = HboneInnerH2Load::default();
    // Production does not hand the connection straight to its driver either: it
    // first polls it through `h2c_preface::await_peer_settings`, and it is that
    // PRE-SPAWN driving that makes the cap the first checkout reads the peer's
    // real one. That helper is crate-private, so drive the same way here, until
    // `h2` has APPLIED the peer's SETTINGS. "Applied" is observable without
    // knowing what the app advertises: `h2` overwrites hyper's
    // `initial_max_send_streams` with the advertised value, or with
    // `usize::MAX` when the peer advertises none, so the cap simply stops being
    // hyper's default. Skipping this left a carrier that completed a whole RPC
    // still reporting 100 — a parked driver is not polled again, so an idle
    // connection never converges on its own.
    let mut connection = Box::pin(connection);
    // A connection that ENDS during the pre-drive must not be handed on: a
    // completed future may not be polled again.
    let ended = AtomicBool::new(false);
    // Scoped so the drive's borrow of `connection` has certainly ended before
    // the connection is moved into its driver task below.
    let applied = {
        let drive = std::future::poll_fn(|cx| {
            let polled = std::future::Future::poll(connection.as_mut(), cx);
            load.set_peer_max_streams(connection.current_max_send_streams());
            if polled.is_ready() {
                ended.store(true, Ordering::SeqCst);
                return std::task::Poll::Ready(());
            }
            if load.peer_max_streams() == HYPER_PRE_SETTINGS_MAX_SEND_STREAMS {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(())
        });
        tokio::time::timeout(DEADLINE, drive).await
    };
    assert!(
        applied.is_ok(),
        "the destination app never applied its own HTTP/2 SETTINGS; the nested \
         carrier would report hyper's pre-settings default forever"
    );
    // Hand it to the long-lived driver, which keeps the cap current for the
    // rest of the carrier's life exactly as production's does — including a
    // peer that lowers it mid-connection.
    if !ended.load(Ordering::SeqCst) {
        let published_cap = load.clone();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| {
                let polled = std::future::Future::poll(connection.as_mut(), cx);
                published_cap.set_peer_max_streams(connection.current_max_send_streams());
                polled
            })
            .await;
        });
    }
    NestedH2 {
        sender,
        advertised,
        load,
    }
}

/// One nested HTTP/2 carrier the fixture opened, with the peer's advertised
/// stream cap kept current by its driver task.
struct NestedH2 {
    sender: H2SendRequest<GrpcBody>,
    advertised: bool,
    load: HboneInnerH2Load,
}

impl NestedH2 {
    fn peer_max_streams(&self) -> usize {
        self.load.peer_max_streams()
    }

    /// Block until the recorded cap is `expected`.
    ///
    /// `open_fresh_h2` already drove the connection until the peer's SETTINGS
    /// were applied, so this normally returns on its first read; it stays as
    /// the assertion that the value the POOL will act on is the value the peer
    /// advertised, rather than hyper's pre-settings default.
    async fn await_peer_max_streams(&self, expected: usize) {
        let settled = tokio::time::timeout(DEADLINE, async {
            while self.peer_max_streams() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            settled.is_ok(),
            "the nested peer's SETTINGS_MAX_CONCURRENT_STREAMS never settled at \
             {expected}; last observed {}",
            self.peer_max_streams()
        );
    }
}

/// Publish a freshly established nested carrier exactly as
/// `open_hbone_grpc_sender` does: source material unchanged, the carrier's own
/// driver-maintained load, and the retirement generation read before the dial.
fn publish_fresh_h2(
    fx: &Fixture,
    parts: &HboneInnerKeyParts<'_>,
    nested: &NestedH2,
) -> HboneInnerH2StreamLease {
    fx.pool.inner_pool().publish_h2(
        parts,
        &nested.sender,
        HboneInnerH2Publication {
            peer_advertises_fence: nested.advertised,
            source_material_unchanged: true,
            load: nested.load.clone(),
            credential_deadline: fx.identity.credential.leaf_deadline,
            generation: fx.pool.inner_pool().drain_generation(),
        },
    )
}

fn empty_grpc_body() -> GrpcBody {
    GrpcBody::Buffered(http_body_util::Full::new(Bytes::new()))
}

async fn send_rpc(sender: &mut H2SendRequest<GrpcBody>) -> Result<StatusCode, String> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://orders.local/svc/Method")
        .header("content-type", "application/grpc")
        .body(empty_grpc_body())
        .expect("rpc request");
    tokio::time::timeout(DEADLINE, sender.ready())
        .await
        .map_err(|_| "rpc carrier never became ready".to_string())?
        .map_err(|err| format!("rpc carrier unusable: {err}"))?;
    let response = tokio::time::timeout(DEADLINE, sender.send_request(request))
        .await
        .map_err(|_| "rpc timed out".to_string())?
        .map_err(|err| format!("rpc failed: {err}"))?;
    let status = response.status();
    let _ = tokio::time::timeout(DEADLINE, response.into_body().collect()).await;
    Ok(status)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_is_shared_across_rpcs_on_one_connect() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    assert!(
        fx.pool.inner_pool().checkout_h2(&parts).is_none(),
        "the first RPC cannot be a pool hit"
    );
    let mut nested = open_fresh_h2(&fx).await;
    assert!(nested.advertised, "the fixture peer advertises the fence");
    let first_lease = publish_fresh_h2(&fx, &parts, &nested);
    assert_eq!(
        send_rpc(&mut nested.sender).await.expect("first rpc"),
        StatusCode::OK
    );
    drop(first_lease);

    // Every later RPC clones the published carrier: no CONNECT, no nested
    // preface/SETTINGS exchange, no second app accept.
    for _ in 0..2 {
        let mut shared = fx
            .pool
            .inner_pool()
            .checkout_h2(&parts)
            .expect("the shared nested HTTP/2 sender is reused");
        assert_eq!(
            send_rpc(&mut shared.sender).await.expect("shared rpc"),
            StatusCode::OK
        );
    }

    assert_eq!(fx.peer.connects(), 1, "three RPCs must cost ONE CONNECT");
    assert_eq!(fx.app.accepts(), 1);
    let stats = fx.pool.inner_pool().stats();
    assert_eq!(stats.h2_hits, 2);
    assert_eq!(stats.h2_misses, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_that_received_goaway_is_retired_and_never_reissued() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 1 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let mut nested = open_fresh_h2(&fx).await;
    let first_lease = publish_fresh_h2(&fx, &parts, &nested);
    assert_eq!(
        send_rpc(&mut nested.sender).await.expect("first rpc"),
        StatusCode::OK
    );
    drop(first_lease);
    drop(nested);

    // The application answered one RPC and then went away. Once the connection
    // has drained, the carrier reports closed and the pool must retire it
    // rather than hand it out again.
    tokio::time::timeout(DEADLINE, async {
        while let Some(reused) = fx.pool.inner_pool().checkout_h2(&parts) {
            // The driver can close this clone after checkout checked
            // liveness. Only a subsequent miss proves checkout has
            // observed closure and removed the resident carrier.
            drop(reused);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a drained carrier must stop being reissued");

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a retired carrier leaves the pool rather than staying reachable"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);

    // The next RPC opens a fresh CONNECT and a fresh nested connection.
    let mut fresh = open_fresh_h2(&fx).await;
    assert_eq!(
        send_rpc(&mut fresh.sender).await.expect("rpc after goaway"),
        StatusCode::OK
    );
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_h2_sender_is_never_published_for_a_peer_without_the_capability() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, false).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let mut nested = open_fresh_h2(&fx).await;
    assert!(
        !nested.advertised,
        "this peer does not advertise the admission fence"
    );
    let lease = publish_fresh_h2(&fx, &parts, &nested);
    assert_eq!(
        send_rpc(&mut nested.sender).await.expect("rpc"),
        StatusCode::OK
    );
    drop(lease);

    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an unfenced peer's nested connection must never be retained"
    );
    assert!(fx.pool.inner_pool().checkout_h2(&parts).is_none());
    assert_eq!(fx.pool.inner_pool().stats().discards, 1);
}

// ---------------------------------------------------------------------------
// Key partitioning, proven on the key text itself
// ---------------------------------------------------------------------------

/// Render the key for `parts` so a test can compare two identities directly.
fn key_of(parts: &HboneInnerKeyParts<'_>) -> String {
    let mut buf = String::new();
    let _ = ferrum_edge::proxy::hbone_inner_pool::write_hbone_inner_pool_key(&mut buf, parts);
    buf
}

/// The route-generation run the publication retention pass compares, resolved
/// through the span the key writer recorded rather than by splitting the key.
fn route_of(parts: &HboneInnerKeyParts<'_>) -> String {
    let mut buf = String::new();
    let spans = ferrum_edge::proxy::hbone_inner_pool::write_hbone_inner_pool_key(&mut buf, parts);
    spans
        .route(&buf)
        .expect("the writer's own span addresses its own key")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_admission_component_partitions_the_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("source credential identity");
    let base = base_identity(credential, ids.peer_id.clone(), "10.0.0.7", 8080, 15008);
    let baseline = key_of(&base.parts(HboneInnerProtocol::Http1));

    // The inner wire protocol.
    assert_ne!(baseline, key_of(&base.parts(HboneInnerProtocol::H2)));

    let mut variant = base_identity(
        base.credential.clone(),
        ids.peer_id.clone(),
        &base.app_host,
        base.app_port,
        base.hbone_port,
    );

    variant.app_host = "10.0.0.8".to_string();
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a different application endpoint is a different connection"
    );
    variant.app_host = base.app_host.clone();

    variant.app_port = 9090;
    assert_ne!(baseline, key_of(&variant.parts(HboneInnerProtocol::Http1)));
    variant.app_port = base.app_port;

    // The DIAL host, independently of the application endpoint: NodeWaypoint
    // secured egress and cross-cluster east-west both dial a host that is not
    // the CONNECT `:authority`, and the two must never share a connection.
    variant.dial_host = "10.0.0.9".to_string();
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "the outer dial peer partitions independently of the app endpoint"
    );
    variant.dial_host = base.dial_host.clone();

    variant.hbone_port = 15009;
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a different peer HBONE listener is a different dial"
    );
    variant.hbone_port = base.hbone_port;

    // The cross-cluster verification scope. These are the fields the outer
    // pool documents as security-critical: a session verified against TD-B for
    // service-X must never be reused for a different trust domain or SNI.
    variant.expected_trust_domain = Some(TrustDomain::new("remote.example").expect("remote td"));
    let scoped_to_remote = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(
        baseline, scoped_to_remote,
        "a remote-trust-domain-scoped session never shares an in-cluster one"
    );
    variant.expected_trust_domain = Some(TrustDomain::new("other.example").expect("other td"));
    assert_ne!(
        scoped_to_remote,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "two remote trust domains never share an inner connection"
    );
    variant.expected_trust_domain = None;

    variant.sni_override = Some("reviews.default.svc.cluster.local".to_string());
    let sni_a = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(
        baseline, sni_a,
        "an east-west SNI override partitions the pool"
    );
    variant.sni_override = Some("ratings.default.svc.cluster.local".to_string());
    assert_ne!(
        sni_a,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "two destination-FQDN SNI overrides never share an inner connection"
    );
    variant.sni_override = None;

    // A PINNED peer identity versus none at all. The absent form is the
    // trust-domain-scoped cross-cluster shape, which authorizes strictly less
    // than a pin and must not inherit a pinned session.
    variant.expected_peer = None;
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "an unpinned dial must not reuse a session verified against a pinned peer"
    );
    variant.expected_peer = Some(SpiffeId::new(CALLER_A).expect("caller a"));
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a different pinned peer is a different destination"
    );
    variant.expected_peer = base.expected_peer.clone();

    // The route generation: namespace, proxy id, upstream id, and the
    // admitting proxy's lifecycle generation.
    variant.namespace = "other-namespace".to_string();
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a proxy in another namespace inherits nothing"
    );
    variant.namespace = base.namespace.clone();

    variant.proxy_id = "another-proxy".to_string();
    assert_ne!(baseline, key_of(&variant.parts(HboneInnerProtocol::Http1)));
    variant.proxy_id = base.proxy_id.clone();

    variant.upstream_id = Some("another-upstream".to_string());
    assert_ne!(baseline, key_of(&variant.parts(HboneInnerProtocol::Http1)));
    variant.upstream_id = None;
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "an absent upstream id is its own identity, not a wildcard"
    );
    variant.upstream_id = base.upstream_id.clone();

    variant.proxy_lifecycle_generation = Some(7);
    let generation_seven = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(
        baseline, generation_seven,
        "a proxy resolvable in a published generation is not the synthesized shape"
    );
    variant.proxy_lifecycle_generation = Some(8);
    assert_ne!(
        generation_seven,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a republished or re-bound proxy is a new incarnation that inherits nothing"
    );
    variant.proxy_lifecycle_generation = None;

    variant.asserted_principal = Some(SpiffeId::new(CALLER_A).expect("caller a"));
    let asserted_a = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(baseline, asserted_a, "an asserted principal partitions");
    variant.asserted_principal = Some(SpiffeId::new(CALLER_B).expect("caller b"));
    assert_ne!(
        asserted_a,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "two asserted principals never share an inner connection"
    );
    variant.asserted_principal = None;

    // The source credential generation.
    variant.credential = HboneSourceCredential {
        generation: base.credential.generation + 1,
        ..base.credential.clone()
    };
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "a rotation partitions the pool rather than laundering a connection"
    );

    // The leaf fingerprint, at the fixed index the rotation drain resolves.
    variant.credential = HboneSourceCredential {
        fingerprint: Arc::from("a-different-leaf"),
        ..base.credential.clone()
    };
    let rotated = key_of(&variant.parts(HboneInnerProtocol::Http1));
    assert_ne!(baseline, rotated);
    assert_eq!(
        rotated.split('|').nth(2),
        Some("a-different-leaf"),
        "the rotation drain resolves the fingerprint positionally, so its index \
         is part of the contract"
    );

    // The effective connection policy.
    variant.credential = base.credential.clone();
    variant.pool_config = PoolConfig {
        http2_max_frame_size: PoolConfig::default().http2_max_frame_size + 1024,
        ..PoolConfig::default()
    };
    assert_ne!(
        baseline,
        key_of(&variant.parts(HboneInnerProtocol::Http1)),
        "wire settings that configure the constructed client are part of the key"
    );
}

/// The per-request policy fields the sibling pools also exclude. They are
/// applied per dispatch on every request, reused connection or not, so keying
/// on them would fragment the pool without bounding anything.
#[tokio::test(flavor = "multi_thread")]
async fn per_request_policy_is_not_part_of_the_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = identities();
    let pool = source_pool(ids.gateway);
    let credential = pool
        .source_credential_identity()
        .expect("source credential identity");

    let mut proxy = source_proxy();
    let baseline = PoolConfig::default().for_proxy(&proxy);
    proxy.backend_connect_timeout_ms = 1;
    proxy.backend_read_timeout_ms = 2;
    proxy.backend_write_timeout_ms = 3;
    let retimed = PoolConfig::default().for_proxy(&proxy);

    let identity_for = |pool_config: PoolConfig| {
        let mut identity = base_identity(
            credential.clone(),
            ids.peer_id.clone(),
            "10.0.0.7",
            8080,
            15008,
        );
        identity.pool_config = pool_config;
        identity
    };

    assert_eq!(
        key_of(&identity_for(baseline).parts(HboneInnerProtocol::Http1)),
        key_of(&identity_for(retimed).parts(HboneInnerProtocol::Http1)),
        "connect/read/write timeouts are applied per dispatch and must not \
         partition a pooled connection"
    );
}

// ---------------------------------------------------------------------------
// The PRODUCTION dispatch: a real frontend through `proxy_to_backend_hbone`
// ---------------------------------------------------------------------------
//
// Everything above drives the pool directly. These drive the GATEWAY: a real
// `ProxyState` whose upstream target is `mesh.hbone`-tagged, a real HTTP/1.1
// frontend served by `handle_proxy_request`, and the same real peer + real
// application as the focused tests. That is what exercises the parts of the
// change that live in the dispatch rather than in the pool — the at-most-once
// pre-wire replay, the `poolable()`-gated eager buffer, the
// `is_end_stream` / `PooledBackendLeaseSlot` split, `Connection: close`,
// HEAD/204/304, and a client that walks away mid-body.

/// The gateway SVID on disk, which is how `ProxyState::new` loads it.
struct SvidFiles {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
    trust_bundle_path: String,
}

fn issue_svid_pem(spiffe_id: &SpiffeId, root_pem: &str, root_key_pem: &str) -> (String, String) {
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
    let leaf = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (leaf.pem(), leaf_key.serialize_pem())
}

/// Gateway + peer identities, with the gateway's half also written to disk.
struct GatewayIdentities {
    peer_slot: SharedSvidBundle,
    peer_id: SpiffeId,
    files: SvidFiles,
}

fn gateway_identities() -> GatewayIdentities {
    let td = TrustDomain::new(TRUST_DOMAIN).expect("trust domain");
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, GATEWAY_SPIFFE).expect("gateway id");
    let peer_id = SpiffeId::from_parts(&td, PEER_SPIFFE).expect("peer id");
    let (gateway_leaf_pem, gateway_key_pem) = issue_svid_pem(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);

    let dir = tempfile::tempdir().expect("svid dir");
    let cert_path = dir.path().join("gateway-svid.pem");
    let key_path = dir.path().join("gateway-svid.key");
    let trust_bundle_path = dir.path().join("trust-bundle.pem");
    std::fs::write(&cert_path, gateway_leaf_pem).expect("write gateway leaf");
    std::fs::write(&key_path, gateway_key_pem).expect("write gateway key");
    std::fs::write(&trust_bundle_path, &root_pem).expect("write trust bundle");

    GatewayIdentities {
        peer_slot: svid_slot(bundle_for(peer_id.clone(), peer_leaf, peer_key, root_der)),
        peer_id,
        files: SvidFiles {
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            trust_bundle_path: trust_bundle_path.to_string_lossy().into_owned(),
            _dir: dir,
        },
    }
}

/// A real gateway in front of the real peer and the real application.
struct GatewayFixture {
    state: ProxyState,
    frontend: SocketAddr,
    peer: Peer,
    app: App,
    /// The gateway SVID on disk, held for the fixture's whole life so the
    /// temporary directory outlives anything that may re-read it.
    _svid_files: SvidFiles,
    _config_handles: Vec<tokio::task::JoinHandle<()>>,
    frontend_task: JoinHandle<()>,
}

impl Drop for GatewayFixture {
    fn drop(&mut self) {
        self.frontend_task.abort();
        for handle in &self._config_handles {
            handle.abort();
        }
    }
}

impl GatewayFixture {
    fn inner_pool(&self) -> &Arc<HboneInnerConnectionPool> {
        self.state.hbone_pool.inner_pool()
    }

    /// Open one frontend HTTP/1.1 connection to the gateway.
    async fn connect(&self) -> FrontendClient {
        let stream = TcpStream::connect(self.frontend)
            .await
            .expect("connect to the gateway frontend");
        let _ = stream.set_nodelay(true);
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("frontend h1 handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        FrontendClient { sender, driver }
    }

    /// One complete client request through the gateway, body fully read.
    async fn get(&self, path: &str) -> (StatusCode, Bytes) {
        let mut client = self.connect().await;
        let response = client.send(http::Method::GET, path).await;
        let status = response.status();
        let body = tokio::time::timeout(DEADLINE, response.into_body().collect())
            .await
            .expect("frontend body in time")
            .expect("frontend body")
            .to_bytes();
        (status, body)
    }
}

struct FrontendClient {
    sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>,
    driver: JoinHandle<()>,
}

impl Drop for FrontendClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl FrontendClient {
    async fn send(
        &mut self,
        method: http::Method,
        path: &str,
    ) -> hyper::Response<hyper::body::Incoming> {
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "orders.local")
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("frontend request");
        tokio::time::timeout(DEADLINE, self.sender.send_request(request))
            .await
            .expect("frontend response in time")
            .expect("frontend response")
    }
}

/// Build a gateway whose single route dispatches over Ambient HBONE to `peer`,
/// with the destination application behind the peer's relay.
async fn gateway_fixture(behaviour: AppBehaviour, advertise: bool) -> GatewayFixture {
    gateway_fixture_with_cutoff(behaviour, advertise, 65_536).await
}

async fn gateway_fixture_with_cutoff(
    behaviour: AppBehaviour,
    advertise: bool,
    response_buffer_cutoff_bytes: usize,
) -> GatewayFixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = gateway_identities();
    let app = start_app(behaviour).await;
    let peer = start_peer(ids.peer_slot, app.addr, advertise).await;

    let mut config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "consumers": [],
        "plugin_configs": [],
        "proxies": [{
            "id": PROXY_ID,
            "hosts": ["orders.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": app.addr.port(),
            "upstream_id": UPSTREAM_ID,
            "preserve_host_header": false,
            "backend_read_timeout_ms": 5000,
            "backend_connect_timeout_ms": 5000
        }],
        "upstreams": [{
            "id": UPSTREAM_ID,
            "targets": [{
                "host": "127.0.0.1",
                "port": app.addr.port(),
                "tags": {
                    "mesh.hbone": "true",
                    "mesh.hbone_port": peer.addr.port().to_string(),
                    "mesh.spiffe_id": ids.peer_id.as_str()
                }
            }]
        }]
    }))
    .expect("gateway config deserializes");
    config.normalize_fields();

    let env_config = ferrum_edge::config::EnvConfig {
        gateway_svid_cert_path: Some(ids.files.cert_path.clone()),
        gateway_svid_key_path: Some(ids.files.key_path.clone()),
        gateway_svid_trust_bundle_path: Some(ids.files.trust_bundle_path.clone()),
        response_buffer_cutoff_bytes,
        ..Default::default()
    };
    let (state, config_handles) = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state");
    assert!(
        state.admits_gateway_mesh_identity(),
        "the file-loaded gateway SVID must admit Ambient HBONE dispatch"
    );

    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind gateway frontend");
    let frontend = listener.local_addr().expect("frontend addr");
    let frontend_state = state.clone();
    let frontend_task = tokio::spawn(async move {
        loop {
            let Ok((stream, remote)) = listener.accept().await else {
                return;
            };
            let state = frontend_state.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            ferrum_edge::proxy::handle_proxy_request(
                                req, state, remote, false, None, None,
                            )
                            .await
                        }
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    GatewayFixture {
        state,
        frontend,
        peer,
        app,
        _svid_files: ids.files,
        _config_handles: config_handles,
        frontend_task,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_production_dispatch_reuses_one_inner_connection_across_requests() {
    let fx = gateway_fixture(AppBehaviour::Ok, true).await;

    for _ in 0..3 {
        let (status, body) = fx.get("/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"ok");
        wait_for_pooled(fx.inner_pool(), 1).await;
    }

    assert_eq!(
        fx.peer.connects(),
        1,
        "three gateway requests over a fenced tunnel must cost ONE CONNECT"
    );
    assert_eq!(fx.app.accepts(), 1);
    assert_eq!(fx.app.requests(), 3);
    let stats = fx.inner_pool().stats();
    assert_eq!(stats.h1_misses, 1);
    assert_eq!(stats.h1_hits, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_silently_reaps_a_pooled_tunnel_costs_one_extra_connect_and_no_duplicate() {
    // The reuse race the at-most-once PRE-WIRE `try_send_request` handback
    // exists for: the destination's side of a POOLED tunnel is gone, and the
    // source has not necessarily learned it yet. Whether a given run takes the
    // handback arm (the close has not propagated, so the lease IS handed out
    // and the unsent request comes back) or the eviction arm (it has, so
    // `take_idle_h1` drops it) is a genuine scheduler race, and the contract is
    // that BOTH produce the same observable outcome.
    //
    // So the cycle is run REPEATEDLY with no sleep between the reap and the
    // next request, and the contract is asserted after every iteration. A sleep
    // here would settle the race in the eviction arm's favour every time and
    // leave the replay arm — the highest-risk new code on this path —
    // unexecuted; over this many iterations the scheduler takes both.
    const CYCLES: usize = 24;

    let fx = gateway_fixture(AppBehaviour::Ok, true).await;

    let (status, _) = fx.get("/").await;
    assert_eq!(status, StatusCode::OK);
    wait_for_pooled(fx.inner_pool(), 1).await;
    assert_eq!(fx.peer.connects(), 1);
    assert_eq!(fx.app.requests(), 1);

    for cycle in 1..=CYCLES {
        let connects_before = fx.peer.connects();
        // The destination takes the whole session away — and this returns only
        // once its sockets are actually closed, so the source's pooled inner
        // connection is riding a transport that has really ended rather than
        // one whose stream is half-open and swallows writes.
        fx.peer.reap_sessions().await;

        let (status, body) = fx.get("/").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "cycle {cycle}: a reaped pooled tunnel must not be visible to the client"
        );
        assert_eq!(body.as_ref(), b"ok");
        assert_eq!(
            fx.peer.connects(),
            connects_before + 1,
            "cycle {cycle}: recovering from the reap must cost EXACTLY one \
             extra CONNECT — the replay is at most once"
        );
        assert_eq!(
            fx.app.requests(),
            cycle + 1,
            "cycle {cycle}: a pre-wire handback replays a request nothing wrote \
             to the wire, so the application must never see it twice"
        );
        assert_eq!(
            fx.app.accepts(),
            cycle + 1,
            "cycle {cycle}: one reaped tunnel is one new application connection"
        );
        // The replacement is pooled again, so the next cycle starts from the
        // same state this one did.
        wait_for_pooled(fx.inner_pool(), 1).await;
    }

    assert_eq!(fx.peer.connects(), CYCLES + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_close_response_discards_the_lease_instead_of_pooling_it() {
    let fx = gateway_fixture(AppBehaviour::ConnectionClose, true).await;

    let (status, body) = fx.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ok");

    let (status, _) = fx.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        fx.peer.connects(),
        2,
        "a `Connection: close` response leaves nothing reusable, so the next \
         request must pay a fresh CONNECT"
    );
    assert_eq!(fx.app.accepts(), 2);
    assert_eq!(
        fx.inner_pool().pooled_connections(),
        0,
        "a carrier the peer closed must never re-enter the idle set"
    );
    // The refusal may land from the deferred readiness waiter, so poll for the
    // accounting rather than sampling it once.
    tokio::time::timeout(DEADLINE, async {
        while fx.inner_pool().stats().discards == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a closed carrier is accounted as a discard, not silently dropped");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bodyless_response_checks_the_lease_in_immediately_and_is_reused() {
    // A 204 has no body for hyper to read, so `is_end_stream` is already true
    // at the dispatch and the lease is checked in right there rather than
    // travelling with a `PooledBackendLeaseSlot`.
    let fx = gateway_fixture(AppBehaviour::NoContent, true).await;

    for _ in 0..3 {
        let (status, body) = fx.get("/").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        wait_for_pooled(fx.inner_pool(), 1).await;
    }

    assert_eq!(
        fx.peer.connects(),
        1,
        "a bodyless response is a complete exchange, so its carrier is reusable"
    );
    assert_eq!(fx.app.accepts(), 1);
    assert_eq!(fx.app.requests(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_walks_away_mid_body_retires_the_inner_connection() {
    // A response larger than the eager-buffer cutoff keeps the STREAMING shape,
    // so the lease rides the `ProxyBody`. The client takes the headers and the
    // first two bytes and then drops the connection, which is one of the
    // abnormal terminals: the lease must be dropped, never checked in.
    let fx = gateway_fixture_with_cutoff(AppBehaviour::SplitBody, true, 2).await;

    {
        // The application is still withholding the tail, so the response is
        // provably incomplete when the frontend connection — and with it the
        // streaming `ProxyBody` that owns the lease — goes away.
        let mut client = fx.connect().await;
        let response = client.send(http::Method::GET, "/").await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(fx.peer.connects(), 1);

    // Only now may the application finish; a background releaser keeps handing
    // out permits so the follow-up request never has to time its release
    // against a response it is also awaiting.
    let releaser_handle = Arc::clone(&fx.app.release);
    let releaser = tokio::spawn(async move {
        loop {
            releaser_handle.notify_one();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    tokio::time::timeout(DEADLINE, async {
        while fx.inner_pool().pooled_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("an abandoned streaming body must never pool its lease");

    let (status, body) = fx.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"abcd");
    assert_eq!(
        fx.peer.connects(),
        2,
        "the abandoned exchange retired its tunnel, so the next request redials"
    );
    assert_eq!(fx.app.accepts(), 2);
    releaser.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fenced_peer_eagerly_buffers_a_small_declared_response() {
    // `poolable()` is what admits the eager buffer. With it on, the dispatch
    // reads the whole declared body before the client sees anything — which is
    // exactly what keeps the exclusive H1 carrier alive across a frontend that
    // would otherwise drop the body without the terminal poll.
    let fx = gateway_fixture(AppBehaviour::SplitBody, true).await;
    let mut client = fx.connect().await;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "orders.local")
        .body(http_body_util::Full::new(Bytes::new()))
        .expect("frontend request");
    let mut pending = Box::pin(client.sender.send_request(request));

    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut pending)
            .await
            .is_err(),
        "an eagerly buffered response cannot reach the client before the \
         application has written its whole declared body"
    );

    fx.app.release_split_body();
    let response = tokio::time::timeout(DEADLINE, pending)
        .await
        .expect("buffered response in time")
        .expect("buffered response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("buffered body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"abcd");
    wait_for_pooled(fx.inner_pool(), 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_without_the_capability_keeps_streaming_the_same_response() {
    // The SAME response shape on a peer that does NOT advertise the fence.
    // `poolable()` is false, so the eager buffer is not applied and the client
    // sees the response headers while the application is still writing —
    // byte-for-byte the pre-#5042 behaviour.
    let fx = gateway_fixture(AppBehaviour::SplitBody, false).await;
    let mut client = fx.connect().await;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "orders.local")
        .body(http_body_util::Full::new(Bytes::new()))
        .expect("frontend request");
    let pending = Box::pin(client.sender.send_request(request));

    let response = tokio::time::timeout(DEADLINE, pending)
        .await
        .expect("streamed response headers arrive before the body completes")
        .expect("streamed response");
    assert_eq!(response.status(), StatusCode::OK);

    fx.app.release_split_body();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("streamed body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"abcd");
    assert_eq!(
        fx.inner_pool().pooled_connections(),
        0,
        "an unfenced peer's connection is never retained"
    );
}

// ---------------------------------------------------------------------------
// The retirement fence: a lease that was CHECKED OUT across a drain
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_pool_drain_discards_a_lease_that_was_checked_out_across_it() {
    // The shape a CRL reload produces: `reload_backend_tls_material` calls
    // `force_drain_all` and does NOT retire the tunnel gates, so the in-flight
    // inner connection stays perfectly healthy and its key's fingerprint is
    // unchanged. Clearing the maps cannot reach a checked-out lease — it is not
    // in them — so without the generation fence the check-in would re-insert it
    // under the very same key and the drain would be a fail-open.
    let fx = fixture(AppBehaviour::Ok, true).await;

    let before = fx.pool.inner_pool().drain_generation();
    let lease = fx.open_fresh_h1().await;
    assert_eq!(
        lease.drain_generation(),
        before,
        "a lease records the generation current when its CONNECT was dialled"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "an exclusive lease is deliberately NOT in the pool's maps"
    );
    assert_eq!(fx.peer.connects(), 1);

    fx.pool.force_drain_all();
    assert_ne!(
        fx.pool.inner_pool().drain_generation(),
        before,
        "a whole-pool retirement must advance the generation FIRST"
    );

    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), lease);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a lease that straddled a drain must never be resurrected under its key"
    );
    assert!(
        fx.pool.inner_pool().fenced_checkins() >= 1,
        "and the refusal must be attributable to the fence, not to liveness"
    );

    // Nothing reusable is left, so the next request faces a fresh CONNECT the
    // destination judges under the CURRENT policy.
    fx.request().await.expect("request after the drain");
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_svid_rotation_drain_also_fences_a_lease_that_was_checked_out_across_it() {
    let fx = fixture(AppBehaviour::Ok, true).await;

    let lease = fx.open_fresh_h1().await;
    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::clone(&fx.identity.credential.fingerprint)]);

    HboneInnerConnectionPool::checkin_h1_when_idle(fx.pool.inner_pool(), lease);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a rotation drain must reach an outstanding lease too"
    );
    assert!(fx.pool.inner_pool().fenced_checkins() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entry_a_retirement_superseded_is_evicted_at_checkout_not_served() {
    // The ENTRY half of the drain fence (the lease half is the two tests
    // above). A whole-pool retirement advances the generation FIRST and then
    // walks the map shard by shard, so a checkout that reads the LEASE
    // generation after the bump can still win a shard the walk has not reached
    // and find the entry sitting there. Without a per-entry stamp it would be
    // handed out, serve a request on material the drain retired, and be filed
    // straight back under the same key with the CURRENT generation — which both
    // check-in fence reads then accept, and every later hit refreshes its idle
    // clock. Nothing else catches it: a CRL reload changes neither the key's
    // leaf fingerprint nor its recorded credential deadline.
    //
    // `retire_svid_fingerprints` with a fingerprint this key does NOT carry
    // reproduces exactly that state through the production API: the fence is
    // advanced for the whole pool, and the retain pass leaves this entry
    // resident because its key names another leaf.
    let fx = fixture(AppBehaviour::Ok, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::Http1);

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::from("some-other-leaf-fingerprint")]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "the entry is still resident — which is precisely the state the entry \
         stamp has to catch"
    );

    let evictions_before = fx.pool.inner_pool().stats().evictions;
    assert!(
        fx.pool
            .inner_pool()
            .checkout_h1(&parts, true, fx.identity.credential.leaf_deadline)
            .is_none(),
        "an entry a retirement superseded must be EVICTED at checkout — never \
         handed out, and never laundered by adopting the caller's generation"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "and it must leave the pool rather than stay reachable"
    );
    assert!(
        fx.pool.inner_pool().stats().evictions > evictions_before,
        "the refusal is an eviction, not a silent skip"
    );

    // The next request therefore pays a fresh CONNECT the destination judges
    // under the CURRENT policy, which is the whole point of the fence.
    fx.request().await.expect("request after the retirement");
    assert_eq!(fx.peer.connects(), 2);
    assert_eq!(fx.app.accepts(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_carrier_a_retirement_superseded_is_evicted_at_checkout() {
    // The nested-HTTP/2 half of the same fence. Milder than H1 — a checkout
    // clones and leaves the carrier resident, so a drain's own clear still
    // removes it — but a carrier taken out of a shard the walk has not reached
    // would still carry RPCs under retired material for as long as it lived.
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let nested = open_fresh_h2(&fx).await;
    drop(publish_fresh_h2(&fx, &parts, &nested));
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    fx.pool
        .inner_pool()
        .retire_svid_fingerprints(&[Arc::from("some-other-leaf-fingerprint")]);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "the retain pass leaves a carrier filed under another leaf resident"
    );

    assert!(
        fx.pool.inner_pool().checkout_h2(&parts).is_none(),
        "a nested carrier a retirement superseded must be evicted, not cloned"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "and it must leave the pool rather than stay reachable"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drain_between_the_outer_dial_and_publication_never_pools_the_nested_sender() {
    // `open_hbone_grpc_sender` snapshots the retirement generation BEFORE
    // `get_tunnel_via`, so a drain that lands while the CONNECT and the nested
    // handshake are in flight refuses the publication instead of resurrecting a
    // carrier the drain already cleared.
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);

    let generation = fx.pool.inner_pool().drain_generation();
    let mut nested = open_fresh_h2(&fx).await;
    assert!(nested.advertised);

    fx.pool.force_drain_all();

    let lease = fx.pool.inner_pool().publish_h2(
        &parts,
        &nested.sender,
        HboneInnerH2Publication {
            peer_advertises_fence: nested.advertised,
            source_material_unchanged: true,
            load: nested.load.clone(),
            credential_deadline: fx.identity.credential.leaf_deadline,
            generation,
        },
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a nested sender dialled before a drain must not be published after it"
    );
    assert!(fx.pool.inner_pool().fenced_checkins() >= 1);
    assert!(fx.pool.inner_pool().checkout_h2(&parts).is_none());

    // The RPC the caller already owns is still served on it, which is the whole
    // point of the publication being a hint rather than a gate.
    assert_eq!(
        send_rpc(&mut nested.sender).await.expect("rpc"),
        StatusCode::OK
    );
    drop(lease);
}

#[tokio::test(flavor = "multi_thread")]
async fn source_material_that_moved_during_the_dial_refuses_the_nested_publication() {
    // The mirror of the outer pool's own insert refusal: an SVID slot, CRL
    // slot, or leaf fingerprint that moved mid-dial means `get_tunnel_via`
    // declined to pool the transport, and the nested sender rides that very
    // transport.
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let parts = fx.identity.parts(HboneInnerProtocol::H2);
    let mut nested = open_fresh_h2(&fx).await;

    let lease = fx.pool.inner_pool().publish_h2(
        &parts,
        &nested.sender,
        HboneInnerH2Publication {
            peer_advertises_fence: nested.advertised,
            // The gateway's SVID, CRL slot, or leaf fingerprint moved while
            // this dial was in flight.
            source_material_unchanged: false,
            load: nested.load.clone(),
            credential_deadline: fx.identity.credential.leaf_deadline,
            generation: fx.pool.inner_pool().drain_generation(),
        },
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a sender whose source material rotated mid-dial is never pooled"
    );
    assert!(fx.pool.inner_pool().stats().discards >= 1);
    assert_eq!(
        send_rpc(&mut nested.sender).await.expect("rpc"),
        StatusCode::OK
    );
    drop(lease);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_source_dial_fence_notices_a_gateway_svid_rotation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let first = identities();
    let second = identities();
    let slot = svid_slot(first.gateway);
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        Arc::clone(&slot),
        8,
    );

    let fence = pool
        .source_dial_fence()
        .expect("a loaded gateway SVID snapshots a dial fence");
    assert!(
        pool.source_dial_fence_intact(&fence),
        "unchanged material must not refuse a publication"
    );

    slot.store(Arc::new(Some(second.gateway)));
    assert!(
        !pool.source_dial_fence_intact(&fence),
        "a rotation between the snapshot and the publication must be visible"
    );
}

// ---------------------------------------------------------------------------
// Nested HTTP/2 width
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn nested_h2_carriers_widen_when_every_incumbent_is_at_the_peers_stream_cap() {
    let fx = fixture(
        AppBehaviour::H2cCapped {
            max_concurrent_streams: 1,
        },
        true,
    )
    .await;
    let mut identity = base_identity(
        fx.identity.credential.clone(),
        fx.identity.peer_id.clone(),
        &fx.identity.app_host,
        fx.identity.app_port,
        fx.identity.hbone_port,
    );
    // The operator's own per-destination HTTP/2 width. It is deliberately NOT
    // part of the pool key, so pinning it here does not change the identity.
    identity.pool_config = PoolConfig {
        http2_connections_per_host: 2,
        ..PoolConfig::default()
    };
    let parts = identity.parts(HboneInnerProtocol::H2);

    let mut first = open_fresh_h2(&fx).await;
    // One RPC first, so the nested peer's SETTINGS have certainly arrived
    // before the carrier is published and its cap is read — production gets
    // that from `h2c_preface::await_peer_settings`.
    assert_eq!(
        send_rpc(&mut first.sender).await.expect("first rpc"),
        StatusCode::OK
    );
    // The fixture application advertises `SETTINGS_MAX_CONCURRENT_STREAMS: 1`,
    // and the pool must see exactly that — not hyper's pre-settings default of
    // 100, which a one-shot sample taken at spawn time records for every peer
    // and which silently disables the widen decision this test is about.
    first.await_peer_max_streams(1).await;
    let cap = first.peer_max_streams();
    assert_eq!(
        cap, 1,
        "the carrier must record the cap the nested peer really advertised"
    );
    let publish_lease = publish_fresh_h2(&fx, &parts, &first);
    drop(publish_lease);
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    // Fill the only carrier to the peer's cap.
    let mut held = Vec::with_capacity(cap);
    for _ in 0..cap {
        held.push(
            fx.pool
                .inner_pool()
                .checkout_h2(&parts)
                .expect("a carrier with room under its peer's cap is reusable"),
        );
    }

    assert!(
        fx.pool.inner_pool().checkout_h2(&parts).is_none(),
        "a carrier at its nested peer's SETTINGS_MAX_CONCURRENT_STREAMS must \
         report a MISS so the caller opens a sibling, not queue every RPC \
         behind one connection"
    );

    // The caller does exactly that, and the key now holds two carriers.
    let mut second = open_fresh_h2(&fx).await;
    assert_eq!(
        send_rpc(&mut second.sender).await.expect("second rpc"),
        StatusCode::OK
    );
    second.await_peer_max_streams(cap).await;
    // The publication itself is this dispatch's first hold on the sibling.
    let second_lease = publish_fresh_h2(&fx, &parts, &second);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        2,
        "the key widened to the configured `http2_connections_per_host`"
    );
    assert_eq!(fx.peer.connects(), 2);

    // Fill the sibling too. Every checkout must land on it, since the first
    // carrier is already at its cap.
    for _ in 1..cap {
        held.push(
            fx.pool
                .inner_pool()
                .checkout_h2(&parts)
                .expect("the freshly widened carrier has room"),
        );
    }

    // Both carriers are now at their cap and the key is at its width, so the
    // next checkout QUEUES on the least loaded rather than growing further —
    // the outer pool's saturated branch, restated.
    let queued = fx
        .pool
        .inner_pool()
        .checkout_h2(&parts)
        .expect("a key at its width queues on the least-loaded carrier");
    drop(queued);
    drop(second_lease);
    drop(held);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        2,
        "queueing must not retire either carrier"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_publication_that_loses_the_width_race_is_accounted_as_a_discard() {
    let fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    let mut identity = base_identity(
        fx.identity.credential.clone(),
        fx.identity.peer_id.clone(),
        &fx.identity.app_host,
        fx.identity.app_port,
        fx.identity.hbone_port,
    );
    identity.pool_config = PoolConfig {
        http2_connections_per_host: 1,
        ..PoolConfig::default()
    };
    let parts = identity.parts(HboneInnerProtocol::H2);

    let first = open_fresh_h2(&fx).await;
    drop(publish_fresh_h2(&fx, &parts, &first));
    let discards_after_first = fx.pool.inner_pool().stats().discards;
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    let second = open_fresh_h2(&fx).await;
    drop(publish_fresh_h2(&fx, &parts, &second));
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "a live incumbent set already at its width wins the race"
    );
    assert_eq!(
        fx.pool.inner_pool().stats().discards,
        discards_after_first + 1,
        "and the losing sender is accounted as a healthy-but-unpooled discard"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_alive_off_never_publishes_a_nested_carrier_and_fences_no_lease() {
    // The nested-HTTP/2 half of `keep_alive_off_never_consults_or_fills_the_idle_set`.
    //
    // The asymmetry would be worse than an inconsistency. A keep-alive-off
    // proxy is SKIPPED by `collect_live_hbone_inner_routes`, so its key is
    // never in the live set any publication is compared against; a carrier
    // resident under it would therefore be retired on EVERY publication, and
    // every retirement advances the drain generation, which fences every
    // outstanding lease POOL-WIDE. One route with keep-alive off would cost one
    // extra CONNECT per in-flight plain-HTTP HBONE request on every other key,
    // once per config publication.
    let mut fx = fixture(AppBehaviour::H2c { goaway_after: 0 }, true).await;
    // A route the published generation CAN name, so the retention pass below is
    // allowed to speak about it at all.
    fx.identity.proxy_lifecycle_generation = Some(5);

    let mut off = base_identity(
        fx.identity.credential.clone(),
        fx.identity.peer_id.clone(),
        &fx.identity.app_host,
        fx.identity.app_port,
        fx.identity.hbone_port,
    );
    off.proxy_id = "hbone-inner-pool-no-keep-alive".to_string();
    off.proxy_lifecycle_generation = Some(6);
    off.pool_config = PoolConfig {
        enable_http_keep_alive: false,
        ..PoolConfig::default()
    };
    let off_parts = off.parts(HboneInnerProtocol::H2);

    assert!(
        fx.pool.inner_pool().checkout_h2(&off_parts).is_none(),
        "keep-alive off never reuses a nested carrier"
    );

    let nested = open_fresh_h2(&fx).await;
    let discards_before = fx.pool.inner_pool().stats().discards;
    drop(publish_fresh_h2(&fx, &off_parts, &nested));
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a nested carrier under a route with keep-alive off is never published"
    );
    assert_eq!(
        fx.pool.inner_pool().stats().discards,
        discards_before + 1,
        "and the unpooled sender is accounted as a discard, which is the \
         pre-reuse cost — never an error"
    );

    // A carrier under an ordinary keep-alive-ON route IS pooled, so the pool is
    // not empty for the publication below to walk.
    let on_parts = fx.identity.parts(HboneInnerProtocol::H2);
    let live_carrier = open_fresh_h2(&fx).await;
    drop(publish_fresh_h2(&fx, &on_parts, &live_carrier));
    assert_eq!(fx.pool.inner_pool().pooled_connections(), 1);

    // Because nothing is resident under the keep-alive-off route, a publication
    // that omits it — as EVERY publication does, since
    // `collect_live_hbone_inner_routes` skips a keep-alive-off proxy — retires
    // nothing, and therefore does not advance the drain generation that fences
    // every outstanding lease pool-wide.
    let mut live = std::collections::HashSet::new();
    live.insert(route_of(&on_parts));
    assert!(
        !live.contains(&route_of(&off.parts(HboneInnerProtocol::H2))),
        "the keep-alive-off route is deliberately absent from the live set"
    );
    let before = fx.pool.inner_pool().drain_generation();
    fx.pool.inner_pool().retain_live_routes(&live);
    assert_eq!(
        fx.pool.inner_pool().drain_generation(),
        before,
        "a keep-alive-off route must not make every publication fence every \
         outstanding lease pool-wide"
    );
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "and the live route's own carrier must survive the publication"
    );
}

// ---------------------------------------------------------------------------
// Publication-time retirement
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_retires_inner_connections_the_new_config_no_longer_declares() {
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    // A proxy the published generation CAN name: this is the shape the
    // retention pass is allowed to speak about.
    fx.identity.proxy_lifecycle_generation = Some(5);

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;
    let live_route = route_of(&fx.identity.parts(HboneInnerProtocol::Http1));

    // A publication that still declares this exact route changes nothing.
    let mut live = std::collections::HashSet::new();
    live.insert(live_route.clone());
    fx.pool.inner_pool().retain_live_routes(&live);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "a route the published configuration still declares must be kept"
    );

    // A publication that re-binds the proxy (a new lifecycle generation) makes
    // the resident entry unreachable, and must retire it rather than leave it
    // holding an outer stream until the amortised idle sweep.
    let mut rebound = fx.identity.parts(HboneInnerProtocol::Http1);
    rebound.proxy_lifecycle_generation = Some(6);
    let mut live = std::collections::HashSet::new();
    live.insert(route_of(&rebound));
    fx.pool.inner_pool().retain_live_routes(&live);
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        0,
        "a re-bound proxy is a new incarnation and inherits nothing"
    );
    assert!(fx.pool.inner_pool().stats().evictions >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_leaves_a_lease_with_no_lifecycle_generation_alone() {
    // A synthesized relay proxy is absent from every published generation by
    // design, so its route carries no lifecycle generation and the published
    // configuration cannot speak about it. Retiring it on every publication
    // would be wrong; it stays bounded by the idle timeout.
    let fx = fixture(AppBehaviour::Ok, true).await;
    assert!(fx.identity.proxy_lifecycle_generation.is_none());

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    fx.pool
        .inner_pool()
        .retain_live_routes(&std::collections::HashSet::new());
    assert_eq!(
        fx.pool.inner_pool().pooled_connections(),
        1,
        "an entry the published configuration cannot name must not be retired \
         by its absence"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_that_retires_nothing_does_not_fence_outstanding_leases() {
    let mut fx = fixture(AppBehaviour::Ok, true).await;
    fx.identity.proxy_lifecycle_generation = Some(5);

    fx.request().await.expect("first request");
    wait_for_pooled(fx.pool.inner_pool(), 1).await;

    let mut live = std::collections::HashSet::new();
    live.insert(route_of(&fx.identity.parts(HboneInnerProtocol::Http1)));
    let before = fx.pool.inner_pool().drain_generation();
    fx.pool.inner_pool().retain_live_routes(&live);
    assert_eq!(
        fx.pool.inner_pool().drain_generation(),
        before,
        "a publication that withdraws nothing must not fence every outstanding \
         lease and force a reconnect storm"
    );
}

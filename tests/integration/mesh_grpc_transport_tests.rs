//! Live data-path regression for gRPC dispatched over BOTH mesh transports —
//! Sidecar SVID-mTLS and Ambient HBONE — same-cluster and cross-cluster
//! (issue #3284).
//!
//! Before #3284 every gRPC dispatch surface that could not reach
//! `proxy_to_backend_mesh_mtls` — notably the HTTP/3 cross-protocol bridge —
//! refused a `mesh.mtls`-tagged target pre-dial with UNAVAILABLE, and native
//! gRPC over Ambient HBONE was refused on EVERY frontend. The fix routes those
//! dispatches through `GrpcDispatchTransport`, which hands the SHARED
//! `GrpcBody` either to the SVID-mTLS HTTP/2 pool or to a NESTED hyper HTTP/2
//! connection run over the authenticated HBONE CONNECT byte tunnel.
//!
//! These tests drive those exact transports against REAL peers:
//!
//! * Sidecar: a rustls SVID-mTLS listener speaking real HTTP/2, answering with
//!   response headers, a DATA frame, and a terminal TRAILERS frame.
//! * Ambient: a rustls SVID-mTLS listener speaking real HTTP/2 that accepts an
//!   HBONE CONNECT and byte-copies the stream to a local h2c gRPC server —
//!   exactly what a destination HBONE relay does — so the nested HTTP/2 client
//!   really has to negotiate and frame end to end.
//!
//! They assert the authenticated hop is taken (the peer observes this gateway's
//! client SVID), that the request is addressed with the mesh `:authority`
//! rather than the transport dial port, that `te: trailers` survives, that
//! `grpc-status` relays back, that a client-streaming upload commits
//! incrementally (bidi), that a client `grpc-timeout` is honored, and that a
//! target whose pinned peer identity does not match FAILS CLOSED rather than
//! falling back to an unauthenticated direct dial.

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::grpc_proxy::{
    GrpcConnectionPool, GrpcDispatchTransport, GrpcProxyError, GrpcResponseKind, GrpcTimeoutKind,
    proxy_grpc_request_from_bytes, proxy_grpc_request_streaming_channel,
};
use ferrum_edge::proxy::hbone_pool::{
    HBONE_AUTHORITY_HOST_TAG, HBONE_DIAL_HOST_TAG, HBONE_PORT_TAG, HBONE_TARGET_TAG,
    HboneConnectionPool, MESH_SPIFFE_ID_TAG,
};
use ferrum_edge::proxy::mesh_mtls_pool::{
    MESH_CROSS_CLUSTER_TAG, MESH_EASTWEST_SNI_TAG, MESH_MTLS_PORT_TAG, MESH_MTLS_TARGET_TAG,
    MESH_TRUST_DOMAIN_TAG, MeshMtlsConnectionPool,
};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// The destination's declared APPLICATION port. Deliberately different from the
/// port the transport actually dials (the peer sidecar's inbound mTLS listener),
/// so the test proves the authority/dial-port split rather than a coincidence.
const APP_PORT: u16 = 9080;

fn init_crypto_provider() {
    // Installing twice across tests in one binary is expected; ignore the error.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

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

fn grpc_proxy_for_test() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "mesh-mtls-grpc".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh mTLS gRPC".to_string()),
        hosts: vec!["reviews.default.svc.cluster.local".to_string()],
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

/// The mesh-tagged target: `host:APP_PORT` is the destination workload, while
/// `mesh.mtls_port` is the peer sidecar's inbound mTLS listener that is actually
/// dialed.
fn mesh_mtls_target(mtls_port: u16, pinned_peer: &str) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(MESH_MTLS_TARGET_TAG.to_string(), "true".to_string());
    tags.insert(MESH_MTLS_PORT_TAG.to_string(), mtls_port.to_string());
    tags.insert(MESH_SPIFFE_ID_TAG.to_string(), pinned_peer.to_string());
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: APP_PORT,
        service_port_policy_key: None,
        weight: 1,
        tags,
        locality: None,
        path: None,
    }
}

/// What the destination observed on the accepted gRPC stream.
struct ObservedRequest {
    scheme: String,
    authority: String,
    path: String,
    te: Option<String>,
    content_type: Option<String>,
    grpc_timeout: Option<String>,
    /// Only meaningful for a peer that terminated TLS itself (Sidecar mesh-mTLS);
    /// the HBONE app server sits behind the relay and sees plaintext h2c.
    peer_presented_client_cert: bool,
}

/// How the destination gRPC server answers the one RPC it serves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GrpcPeerBehavior {
    /// Drain the whole request body, THEN answer headers + DATA + trailers.
    /// The ordinary unary shape.
    RespondAfterUpload,
    /// Answer headers + DATA as soon as the FIRST request DATA frame arrives —
    /// i.e. while the client is still uploading — then drain the rest and send
    /// the terminal trailers. This is the bidirectional-streaming shape that
    /// deadlocks if the gateway buffers the upload.
    RespondOnFirstRequestFrame,
    /// Observe the request and never answer. Used to prove the client
    /// `grpc-timeout` deadline is honored over the mesh transport.
    NeverRespond,
    /// Drain the upload, then answer with an APPLICATION-LEVEL failure: HTTP 200
    /// plus a terminal `grpc-status: 9` (FAILED_PRECONDITION), a `grpc-message`,
    /// and a custom non-hop-by-hop trailer. A mesh transport must relay this
    /// verbatim rather than collapsing it into a gateway-authored UNAVAILABLE
    /// (issue #3728 acceptance: "non-zero upstream `grpc-status` and trailers are
    /// returned unchanged").
    RespondWithNonZeroStatus,
}

/// The application-level failure `RespondWithNonZeroStatus` answers with.
const PEER_FAILED_PRECONDITION: &str = "9";
const PEER_FAILURE_MESSAGE: &str = "upstream refused the RPC";
const PEER_CUSTOM_TRAILER: &str = "real-http2-trailer";

/// Serve exactly ONE gRPC RPC over an already-established byte stream: observe
/// the request, then answer per `behavior`.
///
/// Generic over the transport so the Sidecar test drives it over a terminated
/// SVID-mTLS socket and the Ambient test drives it over a plain h2c socket
/// behind the HBONE relay — the same server code, so a difference in the
/// assertions can only come from the transport under test.
///
/// The accepted stream is handled on a SPAWNED task while this task keeps
/// polling `h2::server::Connection::accept`: that call is the connection's ONLY
/// I/O driver, so queued response HEADERS/DATA flush — and further request DATA
/// is read — only while it runs. Handling the stream inline deadlocks the
/// bidirectional shape: `RespondOnFirstRequestFrame` answers and then waits for
/// the rest of the client's upload, but the client deliberately withholds it
/// until it has seen the response, which can never flush while the connection's
/// only driver is parked on that wait. (Same invariant as
/// `start_hbone_grpc_relay` below.)
async fn serve_one_grpc_rpc<T>(
    io: T,
    response_body: Bytes,
    behavior: GrpcPeerBehavior,
    peer_presented_client_cert: bool,
    observed_tx: oneshot::Sender<ObservedRequest>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut h2 = h2::server::handshake(io).await.expect("h2 server");
    let (request, respond) = h2.accept().await.expect("gRPC stream").expect("stream ok");

    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let _ = observed_tx.send(ObservedRequest {
        scheme: request.uri().scheme_str().unwrap_or_default().to_string(),
        authority: request
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default(),
        path: request.uri().path().to_string(),
        te: header("te"),
        content_type: header("content-type"),
        grpc_timeout: header("grpc-timeout"),
        peer_presented_client_cert,
    });

    let recv = request.into_body();
    let handler = tokio::spawn(serve_grpc_stream(recv, respond, response_body, behavior));

    // Drive the connection for its whole lifetime: this flushes the handler's
    // response frames and feeds it the client's continuing upload, and it also
    // keeps the connection alive until the client is done reading.
    while let Some(next) = h2.accept().await {
        if next.is_err() {
            break;
        }
    }

    // Explicit completion coordination, so a handler assertion failure surfaces
    // instead of vanishing with the task. A `NeverRespond` peer parks forever by
    // design, so the join is bounded.
    match tokio::time::timeout(std::time::Duration::from_secs(5), handler).await {
        // Handler finished, or is still deliberately parked.
        Ok(Ok(())) | Err(_) => {}
        Ok(Err(join_error)) => std::panic::resume_unwind(join_error.into_panic()),
    }
}

/// The accepted stream's half of `serve_one_grpc_rpc`, run on its own task so
/// the owning `h2::server::Connection` keeps being driven while this awaits the
/// client. Every await here is on the peer's next request frame, which only
/// arrives — and whose response only leaves — because that driver is running.
async fn serve_grpc_stream(
    mut recv: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    response_body: Bytes,
    behavior: GrpcPeerBehavior,
) {
    if behavior == GrpcPeerBehavior::NeverRespond {
        // Hold the stream open without answering; the client deadline must fire.
        while let Some(chunk) = recv.data().await {
            let Ok(chunk) = chunk else { return };
            let _ = recv.flow_control().release_capacity(chunk.len());
        }
        std::future::pending::<()>().await;
        return;
    }

    let respond_now = |respond: &mut h2::server::SendResponse<Bytes>| {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .expect("grpc response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response headers");
        send.send_data(response_body.clone(), false)
            .expect("send response data");
        send
    };

    let mut send = if behavior == GrpcPeerBehavior::RespondOnFirstRequestFrame {
        // Wait for exactly one request DATA frame — proof that the gateway
        // committed the upload incrementally rather than buffering it — then
        // answer while the client is still sending.
        let first = recv.data().await.expect("a request DATA frame");
        let first = first.expect("request data");
        let _ = recv.flow_control().release_capacity(first.len());
        respond_now(&mut respond)
    } else {
        // Drain the request body so the client's upload completes before the
        // terminal trailers are written.
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.expect("request data");
            let _ = recv.flow_control().release_capacity(chunk.len());
        }
        respond_now(&mut respond)
    };

    if behavior == GrpcPeerBehavior::RespondOnFirstRequestFrame {
        while let Some(chunk) = recv.data().await {
            let Ok(chunk) = chunk else { break };
            let _ = recv.flow_control().release_capacity(chunk.len());
        }
    }

    let mut trailers = HeaderMap::new();
    if behavior == GrpcPeerBehavior::RespondWithNonZeroStatus {
        trailers.insert(
            "grpc-status",
            PEER_FAILED_PRECONDITION.parse().expect("status"),
        );
        trailers.insert(
            "grpc-message",
            PEER_FAILURE_MESSAGE.parse().expect("message"),
        );
        trailers.insert(
            "x-mesh-peer-trailer",
            PEER_CUSTOM_TRAILER.parse().expect("trailer"),
        );
    } else {
        trailers.insert("grpc-status", "0".parse().expect("status value"));
        trailers.insert("grpc-message", "ok".parse().expect("message value"));
    }
    send.send_trailers(trailers).expect("send trailers");
}

/// A real SVID-mTLS HTTP/2 listener that serves ONE gRPC RPC — the Sidecar peer.
async fn start_mesh_mtls_grpc_server(
    server_slot: SharedSvidBundle,
    response_body: Bytes,
    behavior: GrpcPeerBehavior,
) -> (std::net::SocketAddr, oneshot::Receiver<ObservedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mesh mtls server");
    let addr = listener.local_addr().expect("listener addr");
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let (tcp, _) = listener.accept().await.expect("accept mesh mtls tcp");
        let tls = acceptor.accept(tcp).await.expect("accept spiffe tls");
        let peer_presented_client_cert = tls.get_ref().1.peer_certificates().is_some();
        serve_one_grpc_rpc(
            tls,
            response_body,
            behavior,
            peer_presented_client_cert,
            observed_tx,
        )
        .await;
    });

    (addr, observed_rx)
}

/// A plaintext h2c gRPC server — the destination APP behind an Ambient HBONE
/// relay. The relay byte-copies the tunnel into this socket, so the nested
/// HTTP/2 client really has to negotiate and frame end to end.
async fn start_h2c_grpc_app(
    response_body: Bytes,
    behavior: GrpcPeerBehavior,
) -> (std::net::SocketAddr, oneshot::Receiver<ObservedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind h2c app");
    let addr = listener.local_addr().expect("listener addr");
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept app tcp");
        let _ = tcp.set_nodelay(true);
        serve_one_grpc_rpc(tcp, response_body, behavior, false, observed_tx).await;
    });

    (addr, observed_rx)
}

/// What the Ambient destination's HBONE listener observed on the CONNECT.
struct ObservedConnect {
    authority: String,
    peer_presented_client_cert: bool,
}

/// A real Ambient HBONE listener: SVID-mTLS + HTTP/2, accepting ONE bare
/// CONNECT and byte-copying it to the CONNECT `:authority` — exactly what the
/// destination-side transparent relay does. The inner HTTP/2 gRPC connection is
/// therefore genuinely tunnelled.
///
/// The byte-copy loops are SPAWNED and the accepting task then keeps polling
/// `h2::server::Connection::accept`: that call is the connection's ONLY I/O
/// driver, so the CONNECT response, the tunnelled DATA in both directions, and
/// flow control move only while it runs. Copying inline instead would freeze the
/// connection the moment the first copy await parked — the relay would never
/// even flush its `200`. (Same shape as `gateway_hbone_pool_tests`' echo relay.)
async fn start_hbone_grpc_relay(
    server_slot: SharedSvidBundle,
) -> (std::net::SocketAddr, oneshot::Receiver<ObservedConnect>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone relay");
    let addr = listener.local_addr().expect("listener addr");
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let (tcp, _) = listener.accept().await.expect("accept hbone tcp");
        let tls = acceptor.accept(tcp).await.expect("accept spiffe tls");
        let peer_presented_client_cert = tls.get_ref().1.peer_certificates().is_some();
        let mut h2 = h2::server::handshake(tls).await.expect("h2 server");
        let (request, mut respond) = h2
            .accept()
            .await
            .expect("CONNECT stream")
            .expect("stream ok");
        assert_eq!(request.method(), http::Method::CONNECT);
        let authority = request.uri().to_string();
        let _ = observed_tx.send(ObservedConnect {
            authority: authority.clone(),
            peer_presented_client_cert,
        });
        // A real relay only dials targets the open-relay guard admits; this
        // fixture stays on loopback for the same reason.
        assert!(
            authority.starts_with("127.0.0.1:"),
            "the CONNECT authority must name the loopback destination, got {authority}"
        );

        let mut recv = request.into_body();
        tokio::spawn(async move {
            let mut send = respond
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("connect response"),
                    false,
                )
                .expect("send connect response");

            let app = TcpStream::connect(authority)
                .await
                .expect("relay dials the destination app");
            let _ = app.set_nodelay(true);
            let (mut app_read, mut app_write) = tokio::io::split(app);

            // tunnel → app
            tokio::spawn(async move {
                while let Some(chunk) = recv.data().await {
                    let Ok(chunk) = chunk else { break };
                    let _ = recv.flow_control().release_capacity(chunk.len());
                    if app_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = app_write.shutdown().await;
            });

            // app → tunnel. The fixture's frames are small (gRPC control frames
            // and a few-byte message), so they always fit the default HTTP/2
            // window and no explicit capacity reservation is needed — the same
            // simplification `gateway_hbone_pool_tests`' echo relay makes.
            let mut buf = vec![0u8; 16 * 1024];
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
        });

        // Keep driving the connection for the tunnel's lifetime (see above).
        while let Some(next) = h2.accept().await {
            if next.is_err() {
                break;
            }
        }
    });

    (addr, observed_rx)
}

fn mesh_mtls_pool(gateway_slot: SharedSvidBundle) -> MeshMtlsConnectionPool {
    MeshMtlsConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        8,
        Arc::new(AtomicU64::new(0)),
    )
}

fn hbone_pool(gateway_slot: SharedSvidBundle) -> HboneConnectionPool {
    HboneConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        8,
        Arc::new(AtomicU64::new(0)),
    )
}

/// The gateway + peer identity material every test in this module shares.
struct MeshIdentities {
    gateway_slot: SharedSvidBundle,
    server_slot: SharedSvidBundle,
    peer_id: SpiffeId,
}

fn mesh_identities() -> MeshIdentities {
    init_crypto_provider();
    let td = TrustDomain::new("cluster.local").expect("trust domain");
    let (root, root_pem, root_key_pem) = synthetic_root(&td);

    let gateway_id =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/gateway").expect("gateway id");
    let peer_id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/reviews").expect("peer id");
    let (gw_leaf, gw_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (peer_leaf, peer_key) = issue_svid(&peer_id, &root_pem, &root_key_pem);
    let gateway = bundle_for(gateway_id, gw_leaf, gw_key, root.clone());
    let server = bundle_for(peer_id.clone(), peer_leaf, peer_key, root);

    MeshIdentities {
        gateway_slot: svid_slot(gateway),
        server_slot: svid_slot(server),
        peer_id,
    }
}

/// The Ambient target: `host:app_port` is the destination workload, while
/// `mesh.hbone_port` is the peer's HBONE listener that is actually dialed.
fn hbone_target(app_port: u16, relay_port: u16, pinned_peer: &str) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(HBONE_TARGET_TAG.to_string(), "true".to_string());
    tags.insert(HBONE_PORT_TAG.to_string(), relay_port.to_string());
    tags.insert(MESH_SPIFFE_ID_TAG.to_string(), pinned_peer.to_string());
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: app_port,
        service_port_policy_key: None,
        weight: 1,
        tags,
        locality: None,
        path: None,
    }
}

/// The CROSS-CLUSTER Ambient target: `target.host` is a scoped SYNTHETIC
/// identity (never dialable), the east-west gateway rides `mesh.hbone_dial_host`
/// / `mesh.hbone_port`, the real destination rides `mesh.hbone_authority_host`,
/// and verification is trust-domain-scoped with a destination-FQDN SNI override
/// instead of a pinned pod SPIFFE.
fn cross_cluster_hbone_target(app_port: u16, gateway_port: u16) -> UpstreamTarget {
    let mut tags = HashMap::new();
    tags.insert(HBONE_TARGET_TAG.to_string(), "true".to_string());
    tags.insert(MESH_CROSS_CLUSTER_TAG.to_string(), "true".to_string());
    tags.insert(HBONE_DIAL_HOST_TAG.to_string(), "127.0.0.1".to_string());
    tags.insert(HBONE_PORT_TAG.to_string(), gateway_port.to_string());
    tags.insert(
        HBONE_AUTHORITY_HOST_TAG.to_string(),
        "127.0.0.1".to_string(),
    );
    tags.insert(
        MESH_EASTWEST_SNI_TAG.to_string(),
        "reviews.default.svc.cluster.local".to_string(),
    );
    tags.insert(
        MESH_TRUST_DOMAIN_TAG.to_string(),
        "cluster.local".to_string(),
    );
    UpstreamTarget {
        // Scoped synthetic identity, exactly as the cross-cluster materializer
        // stamps it — it must never be dialed or used as an authority.
        host: "remote|reviews.default.svc.cluster.local".to_string(),
        port: app_port,
        service_port_policy_key: None,
        weight: 1,
        tags,
        locality: None,
        path: None,
    }
}

/// The materialized header view every dispatch surface passes down.
/// `proxy_headers` is AUTHORITATIVE: a name absent from it is treated as a
/// plugin removal, so the content type has to be present exactly as the real
/// request path supplies it.
fn grpc_request_headers() -> (hyper::HeaderMap, HashMap<String, String>) {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("content-type".to_string(), "application/grpc".to_string());
    (headers, proxy_headers)
}

/// Await one fixture observation under a bound.
///
/// An unbounded await on a channel that a broken datapath never fills turns a
/// single failing assertion into a test that hangs until the CI job's own
/// timeout kills the whole shard, so every observation in this module goes
/// through here and fails as itself instead.
async fn await_observation<T>(rx: oneshot::Receiver<T>, what: &str) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), rx)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|_| panic!("{what} was never observed; the fixture task ended first"))
}

/// A length-prefixed gRPC message (5-byte prefix + payload), the wire shape both
/// directions carry.
fn grpc_message(payload: &[u8]) -> Bytes {
    let mut framed = Vec::with_capacity(5 + payload.len());
    framed.push(0);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    Bytes::from(framed)
}

// ── Sidecar SVID-mTLS ───────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_dispatches_over_sidecar_mesh_mtls_and_relays_status_trailers() {
    let ids = mesh_identities();
    let expected_body = grpc_message(b"pong");
    let (addr, observed_rx) = start_mesh_mtls_grpc_server(
        ids.server_slot,
        expected_body.clone(),
        GrpcPeerBehavior::RespondAfterUpload,
    )
    .await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = mesh_mtls_target(addr.port(), ids.peer_id.as_str());

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.mtls target must resolve the sidecar mTLS transport");
    assert_eq!(
        transport.label(),
        "mesh_mtls",
        "a mesh.mtls target must NOT resolve to the direct-dial gRPC pool"
    );

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{APP_PORT}/reviews.Reviews/Get"),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await
    .expect("gRPC over the sidecar mesh mTLS transport must succeed");

    let response = match result {
        GrpcResponseKind::Buffered(response) => response,
        GrpcResponseKind::Streaming(_) => panic!("buffered dispatch returned a streaming response"),
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body, expected_body,
        "the backend's gRPC message must relay byte-for-byte"
    );
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "HTTP/2 trailers must survive the mesh hop; trailers were {:?}",
        response.trailers
    );
    assert_eq!(
        response.trailers.get("grpc-message").map(String::as_str),
        Some("ok")
    );

    let observed = await_observation(observed_rx, "the sidecar peer's request").await;
    assert_eq!(
        observed.scheme, "https",
        "the SVID-mTLS hop must preserve HTTPS request semantics"
    );
    assert!(
        observed.peer_presented_client_cert,
        "the mesh hop must present this gateway's client SVID, never an unauthenticated dial"
    );
    assert_eq!(
        observed.authority,
        format!("127.0.0.1:{APP_PORT}"),
        "the request must be addressed to the destination APP port, not the :15006-style dial port"
    );
    assert_eq!(observed.path, "/reviews.Reviews/Get");
    assert_eq!(
        observed.te.as_deref(),
        Some("trailers"),
        "the gRPC HTTP/2 mapping mandates `te: trailers` on the mesh transport too"
    );
    assert_eq!(observed.content_type.as_deref(), Some("application/grpc"));
}

#[tokio::test]
async fn grpc_over_mesh_mtls_fails_closed_when_the_pinned_peer_does_not_match() {
    let ids = mesh_identities();
    let (addr, _observed_rx) = start_mesh_mtls_grpc_server(
        ids.server_slot,
        grpc_message(b"pong"),
        GrpcPeerBehavior::RespondAfterUpload,
    )
    .await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    // Same reachable peer, but the target pins a DIFFERENT workload identity.
    let target = mesh_mtls_target(addr.port(), "spiffe://cluster.local/ns/default/sa/ratings");

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("a well-formed mesh.mtls target still resolves the transport");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{APP_PORT}/reviews.Reviews/Get"),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "a peer whose SVID does not match the pinned mesh.spiffe_id must fail closed, \
         never fall back to an unauthenticated direct dial"
    );
}

// ── Ambient HBONE ───────────────────────────────────────────────────────────
//
// The nested HTTP/2 gRPC connection runs INSIDE the authenticated HBONE CONNECT
// byte tunnel. Every assertion below therefore exercises three hops at once:
// the outer SVID-mTLS dial, the CONNECT the destination relay byte-copies, and
// the inner h2c connection the gRPC server actually speaks.

#[tokio::test]
async fn grpc_dispatches_over_same_cluster_ambient_hbone_and_relays_status_trailers() {
    let ids = mesh_identities();
    let expected_body = grpc_message(b"pong");
    let (app_addr, app_observed_rx) =
        start_h2c_grpc_app(expected_body.clone(), GrpcPeerBehavior::RespondAfterUpload).await;
    let (relay_addr, connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");
    assert_eq!(
        transport.label(),
        "hbone",
        "a mesh.hbone target must NOT resolve to the direct-dial gRPC pool"
    );

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await
    .expect("gRPC over the Ambient HBONE transport must succeed");

    let response = match result {
        GrpcResponseKind::Buffered(response) => response,
        GrpcResponseKind::Streaming(_) => panic!("buffered dispatch returned a streaming response"),
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.body, expected_body);
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "HTTP/2 trailers must survive the HBONE tunnel; trailers were {:?}",
        response.trailers
    );
    assert_eq!(
        response.trailers.get("grpc-message").map(String::as_str),
        Some("ok")
    );

    let connect = await_observation(connect_observed_rx, "the relay's CONNECT").await;
    assert!(
        connect.peer_presented_client_cert,
        "the outer HBONE hop must present this gateway's client SVID"
    );
    assert_eq!(
        connect.authority,
        format!("127.0.0.1:{}", app_addr.port()),
        "the CONNECT must pin the destination workload's app address:port"
    );

    let observed = await_observation(app_observed_rx, "the app's request").await;
    assert_eq!(
        observed.scheme, "http",
        "the authenticated outer HBONE hop must not mislabel the inner h2c app request as HTTPS"
    );
    assert_eq!(
        observed.authority,
        format!("127.0.0.1:{}", app_addr.port()),
        "the inner request must be addressed to the destination app, not the :15008 dial port"
    );
    assert_eq!(observed.path, "/reviews.Reviews/Get");
    assert_eq!(
        observed.te.as_deref(),
        Some("trailers"),
        "the gRPC HTTP/2 mapping mandates `te: trailers` inside the tunnel too"
    );
    assert_eq!(observed.content_type.as_deref(), Some("application/grpc"));
}

#[tokio::test]
async fn grpc_over_ambient_hbone_fails_closed_when_the_pinned_peer_does_not_match() {
    let ids = mesh_identities();
    let (app_addr, _app_observed_rx) =
        start_h2c_grpc_app(grpc_message(b"pong"), GrpcPeerBehavior::RespondAfterUpload).await;
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    // Same reachable relay, but the target pins a DIFFERENT workload identity.
    let target = hbone_target(
        app_addr.port(),
        relay_addr.port(),
        "spiffe://cluster.local/ns/default/sa/ratings",
    );

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("a well-formed mesh.hbone target still resolves the transport");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "an HBONE peer whose SVID does not match the pinned mesh.spiffe_id must fail closed, \
         never fall back to an unauthenticated direct dial"
    );
}

#[tokio::test]
async fn grpc_over_ambient_hbone_bounds_the_nested_h2_handshake_by_connect_timeout() {
    let ids = mesh_identities();
    // Accept the relayed application TCP connection but never speak HTTP/2.
    // Before the regression fix this left the nested hyper handshake waiting
    // forever whenever the client supplied no grpc-timeout.
    let app_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled app");
    let app_addr = app_listener.local_addr().expect("stalled app addr");
    let (accepted_tx, accepted_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (_tcp, _) = app_listener.accept().await.expect("accept stalled app");
        let _ = accepted_tx.send(());
        std::future::pending::<()>().await;
    });
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let mut proxy = grpc_proxy_for_test();
    proxy.backend_connect_timeout_ms = 250;
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());
    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let started = tokio::time::Instant::now();
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;

    tokio::time::timeout(std::time::Duration::from_secs(1), accepted_rx)
        .await
        .expect("the relay reached the stalled app before the timeout")
        .expect("stalled app acceptance signal");
    assert!(
        matches!(
            result,
            Err(GrpcProxyError::BackendTimeout {
                kind: GrpcTimeoutKind::Connect,
                ..
            })
        ),
        "a stalled nested HTTP/2 handshake must be a connect timeout"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "the nested HTTP/2 handshake must not outlive the configured connect timeout"
    );
}

#[tokio::test]
async fn grpc_over_ambient_hbone_classifies_a_rejected_inner_handshake_as_h2c() {
    let ids = mesh_identities();
    // The outer SVID-mTLS/HBONE handshake succeeds, but the destination app
    // rejects the nested cleartext HTTP/2 preface. That is an h2c protocol
    // failure, not evidence of a TLS failure on the already-established outer
    // mesh hop.
    let app_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rejecting app");
    let app_addr = app_listener.local_addr().expect("rejecting app addr");
    tokio::spawn(async move {
        let (mut tcp, _) = app_listener.accept().await.expect("accept rejecting app");
        tcp.write_all(b"not-an-http2-server")
            .await
            .expect("write rejecting preface");
        let _ = tcp.shutdown().await;
    });
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());
    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(GrpcProxyError::BackendUnavailable {
                kind: ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::H2cHandshake,
                ..
            })
        ),
        "a rejected nested cleartext handshake must classify as H2cHandshake"
    );
}

#[tokio::test]
async fn grpc_dispatches_over_cross_cluster_ambient_hbone_through_the_east_west_gateway() {
    let ids = mesh_identities();
    let expected_body = grpc_message(b"pong");
    let (app_addr, app_observed_rx) =
        start_h2c_grpc_app(expected_body.clone(), GrpcPeerBehavior::RespondAfterUpload).await;
    // The "remote east-west gateway": dialed with a destination-FQDN SNI
    // override and trust-domain-scoped verification (NO pinned pod SPIFFE).
    let (gateway_addr, connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = cross_cluster_hbone_target(app_addr.port(), gateway_addr.port());

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("well-formed cross-cluster mesh.hbone must resolve the east-west transport");
    assert_eq!(transport.label(), "hbone");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    // The gateway builds this URL from the target, whose host is a SCOPED
    // SYNTHETIC identity with `|` separators — not a parseable URI authority.
    // The transport must still recover the path and rebuild the request line.
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!(
            "http://remote|reviews.default.svc.cluster.local:{}/reviews.Reviews/Get",
            app_addr.port()
        ),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await
    .expect("gRPC over the cross-cluster Ambient HBONE transport must succeed");

    let response = match result {
        GrpcResponseKind::Buffered(response) => response,
        GrpcResponseKind::Streaming(_) => panic!("buffered dispatch returned a streaming response"),
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.body, expected_body);
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "`grpc-status` must relay across the east-west hop; trailers were {:?}",
        response.trailers
    );

    let connect = await_observation(connect_observed_rx, "the east-west gateway's CONNECT").await;
    assert_eq!(
        connect.authority,
        format!("127.0.0.1:{}", app_addr.port()),
        "the CONNECT authority must be the REAL remote pod address from \
         mesh.hbone_authority_host, never the scoped synthetic target host"
    );

    let observed = await_observation(app_observed_rx, "the app's request").await;
    assert_eq!(
        observed.scheme, "http",
        "cross-cluster HBONE still terminates in a plaintext h2c app request"
    );
    assert_eq!(
        observed.path, "/reviews.Reviews/Get",
        "the request path must survive a target host that is not a URI authority"
    );
    assert_eq!(
        observed.authority,
        format!("127.0.0.1:{}", app_addr.port()),
        "the inner `:authority` must never carry the scoped synthetic identity"
    );
    assert_eq!(observed.te.as_deref(), Some("trailers"));
}

#[tokio::test]
async fn grpc_streams_request_data_incrementally_over_ambient_hbone() {
    let ids = mesh_identities();
    let expected_body = grpc_message(b"pong");
    // The app answers on the FIRST request DATA frame — before the client has
    // half-closed. A gateway that buffered the upload would deadlock here.
    let (app_addr, app_observed_rx) = start_h2c_grpc_app(
        expected_body.clone(),
        GrpcPeerBehavior::RespondOnFirstRequestFrame,
    )
    .await;
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());
    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");

    let (headers, proxy_headers) = grpc_request_headers();
    let (body_tx, body_rx) = tokio::sync::mpsc::channel(8);
    body_tx
        .send(Ok(http_body::Frame::data(grpc_message(b"ping"))))
        .await
        .expect("queue the first request message");

    let mut held_upload = None;
    let result = proxy_grpc_request_streaming_channel(
        hyper::Method::POST,
        headers,
        body_rx,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Chat", app_addr.port()),
        &transport,
        &proxy_headers,
        4 * 1024 * 1024,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU64::new(0)),
        None,
        None,
        &mut held_upload,
        None,
    )
    .await
    .expect("bidirectional gRPC over the Ambient HBONE transport must succeed");

    // The response headers arrived while `body_tx` is still OPEN — the upload
    // was committed frame by frame, not buffered until half-close.
    let mut streaming = match result {
        GrpcResponseKind::Streaming(streaming) => streaming,
        GrpcResponseKind::Buffered(_) => {
            panic!("the streaming channel path must not buffer the response")
        }
    };
    assert_eq!(streaming.status, 200);

    let first = streaming
        .body
        .frame()
        .await
        .expect("a response DATA frame")
        .expect("response frame ok");
    assert_eq!(
        first.data_ref().expect("DATA frame"),
        &expected_body,
        "the peer's message must relay byte-for-byte before the client half-closes"
    );

    // Now half-close and drain to the terminal trailers.
    drop(body_tx);
    let mut trailers = None;
    while let Some(frame) = streaming.body.frame().await {
        let frame = frame.expect("response frame ok");
        if let Ok(map) = frame.into_trailers() {
            trailers = Some(map);
            break;
        }
    }
    let trailers = trailers.expect("the terminal TRAILERS frame must survive the HBONE tunnel");
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0")
    );

    let observed = await_observation(app_observed_rx, "the app's request").await;
    assert_eq!(observed.path, "/reviews.Reviews/Chat");
    assert_eq!(observed.te.as_deref(), Some("trailers"));
}

#[tokio::test]
async fn grpc_over_ambient_hbone_honors_the_client_deadline() {
    let ids = mesh_identities();
    // The peer accepts the RPC and never answers; only the client deadline can
    // end it.
    let (app_addr, app_observed_rx) =
        start_h2c_grpc_app(grpc_message(b"pong"), GrpcPeerBehavior::NeverRespond).await;
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());
    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");

    let (mut headers, mut proxy_headers) = grpc_request_headers();
    headers.insert("grpc-timeout", "2S".parse().unwrap());
    proxy_headers.insert("grpc-timeout".to_string(), "2S".to_string());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1_500);

    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        Some(deadline),
    )
    .await;

    assert!(
        result.is_err(),
        "a peer that never answers must trip the client gRPC deadline over the mesh transport"
    );

    // The deadline is also PROPAGATED: the destination saw a `grpc-timeout`
    // rewritten to the remaining budget, not the client's original value.
    let observed = await_observation(app_observed_rx, "the app's request").await;
    assert!(
        observed.grpc_timeout.is_some(),
        "the client deadline must be propagated to the destination as `grpc-timeout`"
    );
}

/// A NON-ZERO upstream `grpc-status`, its `grpc-message`, and a custom
/// non-hop-by-hop trailer must relay over the Ambient HBONE tunnel unchanged
/// (issue #3728 acceptance). Collapsing an application-level failure into a
/// gateway-authored UNAVAILABLE would make an Ambient destination's errors
/// indistinguishable from a transport failure, on the very frontend whose
/// pre-dial refusal this work removed.
#[tokio::test]
async fn grpc_over_ambient_hbone_relays_a_non_zero_status_and_custom_trailers() {
    let ids = mesh_identities();
    let expected_body = grpc_message(b"detail");
    let behavior = GrpcPeerBehavior::RespondWithNonZeroStatus;
    let (app_addr, _app_observed_rx) = start_h2c_grpc_app(expected_body.clone(), behavior).await;
    let (relay_addr, _connect_observed_rx) = start_hbone_grpc_relay(ids.server_slot).await;

    let grpc_pool = GrpcConnectionPool::default();
    let mesh_pool = mesh_mtls_pool(Arc::clone(&ids.gateway_slot));
    let ambient_pool = hbone_pool(ids.gateway_slot);
    let proxy = grpc_proxy_for_test();
    let target = hbone_target(app_addr.port(), relay_addr.port(), ids.peer_id.as_str());

    let transport =
        GrpcDispatchTransport::for_target(&grpc_pool, &mesh_pool, &ambient_pool, Some(&target))
            .expect("mesh.hbone target must resolve the Ambient HBONE transport");
    assert_eq!(transport.label(), "hbone");

    let (headers, proxy_headers) = grpc_request_headers();
    let dns = DnsCache::new(DnsConfig::default());
    let result = proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        grpc_message(b"ping"),
        None,
        &proxy,
        &format!("http://127.0.0.1:{}/reviews.Reviews/Get", app_addr.port()),
        &transport,
        &dns,
        &proxy_headers,
        false,
        0,
        None,
    )
    .await
    .expect("an application-level gRPC failure is a SUCCESSFUL dispatch, not a transport error");

    let response = match result {
        GrpcResponseKind::Buffered(response) => response,
        GrpcResponseKind::Streaming(_) => panic!("buffered dispatch returned a streaming response"),
    };
    assert_eq!(
        response.status, 200,
        "gRPC application errors ride HTTP 200 + trailers"
    );
    assert_eq!(
        response.body, expected_body,
        "the peer's DATA must relay even when the terminal status is non-zero"
    );
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some(PEER_FAILED_PRECONDITION),
        "the upstream grpc-status must relay UNCHANGED; trailers were {:?}",
        response.trailers
    );
    assert_eq!(
        response.trailers.get("grpc-message").map(String::as_str),
        Some(PEER_FAILURE_MESSAGE)
    );
    assert_eq!(
        response
            .trailers
            .get("x-mesh-peer-trailer")
            .map(String::as_str),
        Some(PEER_CUSTOM_TRAILER),
        "custom (non-hop-by-hop) trailers must survive the HBONE tunnel"
    );
}

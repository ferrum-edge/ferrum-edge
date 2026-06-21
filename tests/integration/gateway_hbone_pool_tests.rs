use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::modes::mesh::hbone::HboneIdentity;
use ferrum_edge::proxy::hbone_pool::{HBONE_TARGET_TAG, HboneConnectionPool, HbonePoolError};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

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
        id: "gateway-hbone".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Gateway HBONE".to_string()),
        hosts: vec!["orders.example.com".to_string()],
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
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: now,
        updated_at: now,
    }
}

async fn start_hbone_echo_server(
    server_slot: SharedSvidBundle,
) -> (std::net::SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone server");
    let addr = listener.local_addr().expect("listener addr");
    let (baggage_tx, baggage_rx) = oneshot::channel();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let (tcp, _) = listener.accept().await.expect("accept hbone tcp");
        let tls = acceptor.accept(tcp).await.expect("accept spiffe tls");
        let mut h2 = h2::server::handshake(tls).await.expect("h2 server");
        let accepted = h2
            .accept()
            .await
            .expect("connect stream")
            .expect("stream ok");
        tokio::spawn(async move {
            let (request, mut respond) = accepted;
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.uri().to_string(), "127.0.0.1:8080");
            let identity = HboneIdentity::from_headers(request.headers());
            let source = identity
                .source_principal
                .as_ref()
                .map(SpiffeId::as_str)
                .unwrap_or_default()
                .to_string();
            let _ = baggage_tx.send(source);

            let mut recv = request.into_body();
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("connect response");
            let mut send = respond
                .send_response(response, false)
                .expect("send response");
            while let Some(chunk) = recv.data().await {
                let chunk = chunk.expect("request data");
                let _ = recv.flow_control().release_capacity(chunk.len());
                if send.send_data(chunk, false).is_err() {
                    return;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });

        while let Some(next) = h2.accept().await {
            if next.is_err() {
                break;
            }
        }
    });

    (addr, baggage_rx)
}

/// HBONE echo server that survives across many CONNECT streams and counts every
/// distinct TCP connection it accepts. Each accepted TCP connection is one full
/// TLS+h2 handshake, so the returned counter is the number of times the gateway
/// pool (re)dialed the sidecar. The regression test for PR #1400 asserts this
/// stays at 1 while a busy connection is repeatedly served by the shared-lock
/// fast path: if the fast path stops refreshing recency, the connection is
/// pruned as idle and redialed, bumping this counter past 1.
///
/// Unlike `start_hbone_echo_server`, every CONNECT stream on every connection is
/// answered with an echo, so the pool can keep driving `get_tunnel` in a loop.
async fn start_hbone_counting_echo_server(
    server_slot: SharedSvidBundle,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone counting server");
    let addr = listener.local_addr().expect("listener addr");
    let connection_count = Arc::new(AtomicUsize::new(0));
    let count_for_task = connection_count.clone();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            count_for_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let mut h2 = match h2::server::handshake(tls).await {
                    Ok(h2) => h2,
                    Err(_) => return,
                };
                while let Some(next) = h2.accept().await {
                    let (request, mut respond) = match next {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    if request.method() != http::Method::CONNECT {
                        continue;
                    }
                    tokio::spawn(async move {
                        let mut recv = request.into_body();
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .expect("connect response");
                        let mut send = match respond.send_response(response, false) {
                            Ok(send) => send,
                            Err(_) => return,
                        };
                        while let Some(chunk) = recv.data().await {
                            let chunk = match chunk {
                                Ok(chunk) => chunk,
                                Err(_) => return,
                            };
                            let _ = recv.flow_control().release_capacity(chunk.len());
                            if send.send_data(chunk, false).is_err() {
                                return;
                            }
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            });
        }
    });

    (addr, connection_count)
}

async fn start_hbone_reject_server(
    server_slot: SharedSvidBundle,
    status: StatusCode,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone reject server");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let (tcp, _) = listener.accept().await.expect("accept hbone tcp");
        let tls = acceptor.accept(tcp).await.expect("accept spiffe tls");
        let mut h2 = h2::server::handshake(tls).await.expect("h2 server");
        let accepted = h2
            .accept()
            .await
            .expect("connect stream")
            .expect("stream ok");
        let (request, mut respond) = accepted;
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().to_string(), "127.0.0.1:8080");
        let response = Response::builder()
            .status(status)
            .body(())
            .expect("connect reject response");
        respond
            .send_response(response, true)
            .expect("send reject response");

        while let Some(next) = h2.accept().await {
            if next.is_err() {
                break;
            }
        }
    });

    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_pool_opens_spiffe_mtls_connect_and_injects_source_baggage() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let gateway_slot = svid_slot(bundle_for(
        gateway_id.clone(),
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let server_slot = svid_slot(bundle_for(server_id, server_leaf, server_key, root_der));
    let (server_addr, baggage_rx) = start_hbone_echo_server(server_slot).await;

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    let proxy = proxy_for_test();
    let mut tunnel = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        pool.get_tunnel(&proxy, "127.0.0.1", 8080, 8080, server_addr.port(), None),
    )
    .await
    .expect("timely hbone tunnel open")
    .expect("open hbone tunnel");

    tunnel.write_all(b"mesh-hello").await.expect("write tunnel");
    let mut echoed = [0_u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tunnel.read_exact(&mut echoed),
    )
    .await
    .expect("timely echo through hbone tunnel")
    .expect("read echoed tunnel bytes");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), tunnel.shutdown()).await;

    assert_eq!(&echoed, b"mesh-hello");
    assert_eq!(baggage_rx.await.expect("baggage"), gateway_id.as_str());
}

/// Regression for PR #1400: a connection that is only ever served by the
/// shared-lock fast path (`try_cached_sender_read`) must not be pruned as idle.
///
/// The fast path returns a cached, ready sender without taking the exclusive
/// shard write lock. Before the fix it returned that sender WITHOUT advancing
/// `last_used_at`, so on a busy pool a heavily-used connection's recency never
/// moved: once `idle_timeout_seconds` elapsed it was pruned and the next request
/// paid a full TCP+mTLS+h2 redial. The fix bumps `last_used_at` with a relaxed
/// atomic store on the fast path.
///
/// `entries`/`last_used_at` are private, so this asserts behaviorally: the echo
/// server counts every TCP connection it accepts (one per handshake/redial).
/// With the fix the gateway dials exactly once and reuses it across a busy loop
/// that spans several idle windows; without the fix the connection is recycled
/// and the counter climbs past 1. `pool_size()` is also pinned at 1 throughout.
#[tokio::test(flavor = "multi_thread")]
async fn hbone_fast_path_hit_refreshes_recency_and_keeps_busy_connection_alive() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let gateway_slot = svid_slot(bundle_for(
        gateway_id,
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let server_slot = svid_slot(bundle_for(server_id, server_leaf, server_key, root_der));
    let (server_addr, connection_count) = start_hbone_counting_echo_server(server_slot).await;

    // Small idle window with a single connection per backend so a missed recency
    // refresh would prune-and-redial within the busy loop below.
    let pool_config = PoolConfig {
        idle_timeout_seconds: 1,
        http2_connections_per_host: 1,
        ..PoolConfig::default()
    };
    let pool = HboneConnectionPool::new(
        pool_config,
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    let proxy = proxy_for_test();

    // One round-trip over a freshly checked-out tunnel; drives a CONNECT stream
    // and proves the underlying connection is live without leaving it pending.
    async fn drive_busy_round_trip(pool: &HboneConnectionPool, proxy: &Proxy, server_port: u16) {
        let mut tunnel = tokio::time::timeout(
            Duration::from_secs(10),
            pool.get_tunnel(proxy, "127.0.0.1", 8080, 8080, server_port, None),
        )
        .await
        .expect("timely hbone tunnel open")
        .expect("open hbone tunnel");
        tunnel.write_all(b"ping").await.expect("write busy tunnel");
        let mut echoed = [0_u8; 4];
        tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
            .await
            .expect("timely echo through busy tunnel")
            .expect("read echoed busy bytes");
        assert_eq!(&echoed, b"ping");
        let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.shutdown()).await;
    }

    // Warm exactly one connection. This goes through the create path.
    drive_busy_round_trip(&pool, &proxy, server_addr.port()).await;
    assert_eq!(
        pool.pool_size(),
        1,
        "warmup should leave exactly one pooled HBONE connection"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "warmup should open exactly one TCP connection"
    );

    // Drive the fast path every ~250ms for ~3s. The idle window is 1s, so the
    // total span comfortably exceeds several idle timeouts. Every checkout after
    // warmup is served by `try_cached_sender_read`; if it stopped refreshing
    // recency, the entry would expire and the next checkout would redial.
    let loop_started = std::time::Instant::now();
    let mut iterations = 0_u32;
    while loop_started.elapsed() < Duration::from_secs(3) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        drive_busy_round_trip(&pool, &proxy, server_addr.port()).await;
        iterations += 1;
        assert_eq!(
            pool.pool_size(),
            1,
            "fast-path reuse must keep exactly one pooled connection (iteration {iterations})"
        );
        assert_eq!(
            connection_count.load(Ordering::SeqCst),
            1,
            "busy fast-path reuse must not redial the sidecar (iteration {iterations})"
        );
    }

    assert!(
        iterations >= 8,
        "expected the busy loop to span several idle windows, only ran {iterations} iterations"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "the busy connection must be reused, not recycled, across the whole idle-spanning loop"
    );
    assert_eq!(
        pool.pool_size(),
        1,
        "exactly one HBONE connection should remain pooled at the end"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_warmup_requires_connect_acceptance() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let gateway_slot = svid_slot(bundle_for(
        gateway_id,
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let server_slot = svid_slot(bundle_for(server_id, server_leaf, server_key, root_der));
    let server_addr = start_hbone_reject_server(server_slot, StatusCode::FORBIDDEN).await;

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    let proxy = proxy_for_test();
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        pool.warmup_connection(&proxy, "127.0.0.1", 8080, 8080, server_addr.port(), None),
    )
    .await
    .expect("timely hbone warmup")
    .expect_err("warmup must reject sidecars that refuse CONNECT");

    match err {
        HbonePoolError::ConnectRejected { status, .. } => {
            assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
        }
        other => panic!("expected CONNECT rejection, got {other:?}"),
    }
}

#[test]
fn mesh_hbone_tag_constant_matches_documented_target_tag() {
    let mut tags = HashMap::new();
    tags.insert(HBONE_TARGET_TAG.to_string(), "true".to_string());
    assert_eq!(tags.get("mesh.hbone").map(String::as_str), Some("true"));
}

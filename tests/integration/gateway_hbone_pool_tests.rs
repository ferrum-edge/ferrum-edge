use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::env_config::{EnvConfig, OperatingMode};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy, ResponseBodyMode,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet};
use ferrum_edge::modes::mesh::hbone::HboneIdentity;
use ferrum_edge::proxy::hbone_pool::{
    H2ConnectTunnel, HBONE_DEFAULT_MAX_HEADER_LIST_SIZE, HBONE_TARGET_TAG, HboneConnectionPool,
    HbonePoolError,
};
use ferrum_edge::proxy::mesh_mtls_pool::{MeshMtlsConnectionPool, MeshMtlsSender};
use ferrum_edge::proxy::mesh_trust_registry::{
    MESH_KEEPALIVE_FAILED_MESSAGE, MESH_TRUST_WITHDRAWN_MESSAGE, MeshTransportGate,
};
use ferrum_edge::proxy::{GatewayTrustCommit, ProxyState};
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Response, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::CertificateRevocationListDer;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
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
    issue_svid_with_serial(spiffe_id, root_pem, root_key_pem, None)
}

fn issue_svid_with_serial(
    spiffe_id: &SpiffeId,
    root_pem: &str,
    root_key_pem: &str,
    serial: Option<SerialNumber>,
) -> (Vec<u8>, Vec<u8>) {
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(spiffe_id_to_san(spiffe_id).expect("spiffe san"));
    params.serial_number = serial;
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

fn crl_revoking(
    root_pem: &str,
    root_key_pem: &str,
    serial_number: SerialNumber,
) -> ferrum_edge::tls::CrlList {
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let now = time::OffsetDateTime::now_utc();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number,
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let pem = params
        .signed_by(&issuer)
        .expect("sign crl")
        .pem()
        .expect("crl pem");
    let crls: Vec<CertificateRevocationListDer<'static>> =
        rustls_pemfile::crls(&mut pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("parse crl");
    Arc::new(crls)
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
async fn hbone_pool_opens_spiffe_mtls_connect_and_injects_asserted_source_baggage() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let workload_id = SpiffeId::from_parts(&td, "ns/default/sa/workload").unwrap();
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
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            // In-cluster: no cross-cluster trust-domain scope / SNI override.
            None,
            None,
            Some(&workload_id),
        ),
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
    assert_eq!(baggage_rx.await.expect("baggage"), workload_id.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_outbound_spiffe_dial_enforces_crl_revocation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let accepted_id = SpiffeId::from_parts(&td, "ns/default/sa/accepted").unwrap();
    let revoked_id = SpiffeId::from_parts(&td, "ns/default/sa/revoked").unwrap();
    let revoked_serial = SerialNumber::from(42_u64);
    let accepted_serial = SerialNumber::from(43_u64);

    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (accepted_leaf, accepted_key) = issue_svid_with_serial(
        &accepted_id,
        &root_pem,
        &root_key_pem,
        Some(accepted_serial),
    );
    let (revoked_leaf, revoked_key) = issue_svid_with_serial(
        &revoked_id,
        &root_pem,
        &root_key_pem,
        Some(revoked_serial.clone()),
    );
    let gateway_slot = svid_slot(bundle_for(
        gateway_id,
        gateway_leaf,
        gateway_key,
        root_der.clone(),
    ));
    let accepted_slot = svid_slot(bundle_for(
        accepted_id.clone(),
        accepted_leaf,
        accepted_key,
        root_der.clone(),
    ));
    let revoked_slot = svid_slot(bundle_for(
        revoked_id.clone(),
        revoked_leaf,
        revoked_key,
        root_der,
    ));
    let crls = crl_revoking(&root_pem, &root_key_pem, revoked_serial);
    let (accepted_addr, _accepted_baggage) = start_hbone_echo_server(accepted_slot).await;
    let (revoked_addr, _revoked_baggage) = start_hbone_echo_server(revoked_slot).await;
    let proxy = proxy_for_test();

    let accepted_pool = HboneConnectionPool::new_with_svid_generation_and_crls(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot.clone(),
        crls.clone(),
        4,
        Arc::new(AtomicU64::new(0)),
    );
    tokio::time::timeout(
        Duration::from_secs(15),
        accepted_pool.warmup_connection_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            accepted_addr.port(),
            Some(&accepted_id),
        ),
    )
    .await
    .expect("unrevoked outbound dial should complete promptly")
    .expect("unrevoked outbound peer SVID should be accepted");

    let revoked_pool = HboneConnectionPool::new_with_svid_generation_and_crls(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        crls,
        4,
        Arc::new(AtomicU64::new(0)),
    );
    tokio::time::timeout(
        Duration::from_secs(15),
        revoked_pool.warmup_connection_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            revoked_addr.port(),
            Some(&revoked_id),
        ),
    )
    .await
    .expect("revoked outbound dial should fail promptly")
    .expect_err("revoked-but-unexpired outbound peer SVID must be rejected");
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
            pool.get_tunnel_via(
                proxy,
                "127.0.0.1",
                "127.0.0.1",
                8080,
                8080,
                server_port,
                None,
                // In-cluster: no cross-cluster trust-domain scope / SNI override.
                None,
                None,
                None,
            ),
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
        pool.warmup_connection_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
        ),
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

// ─── A committed gateway trust change must clear pooled entries it withdrew ──
//
// The mesh pools key on the leaf SVID *fingerprint*, not on the backend security
// generation. A gateway trust `Replace`/`Clear` leaves the leaf alone, so every
// pooled key is byte-identical across the commit and an HBONE / mesh-mTLS
// pooled entry authenticated under a root the accepted generation WITHDREW keeps
// matching for pool lookup. The only thing that used to remove it was the rotation
// consumer's force-drain, which `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` skips entirely at
// its documented default of `0` — so the withdrawal was unbounded (issue #3727).
//
// These tests drive the REAL pools owned by a real `ProxyState`: genuine
// SPIFFE-mTLS HTTP/2 connections are established through `state.hbone_pool` and
// `state.mesh_mtls_pool`, then the production publication seam commits the trust
// decision. The drain window is the default `0`, so the rotation consumer cannot
// force-drain anything at all; and the assertions run with NO `.await` after the
// synchronous publishing call, so nothing they observe could have come from
// another task. Whatever the pools report is what the publication itself did to
// pool discoverability. `gateway_mesh_trust_retirement_tests` owns the separate
// assertions that already-issued handles are signalled and terminate.

/// A `ProxyState` in the DOCUMENTED DEFAULT drain configuration whose mesh pools
/// share `gateway_svid_bundle` and `backend_svid_generation` with the state.
async fn dp_state_with_gateway_svid(gateway: SvidBundle) -> (ProxyState, Vec<JoinHandle<()>>) {
    let env_config = EnvConfig {
        mode: OperatingMode::DataPlane,
        ..Default::default()
    };
    assert_eq!(
        env_config.mesh_svid_rotation_drain_seconds, 0,
        "these tests exist for the DEFAULT drain window; a non-zero default would \
         let the rotation consumer's delayed force-drain do the work instead"
    );
    let dns_cache = DnsCache::new(DnsConfig::default());
    let built = ProxyState::new(GatewayConfig::default(), dns_cache, env_config, None, None);
    let (state, tasks) = built.expect("test proxy state should build");
    // Exactly how the SVID source watcher installs an identity: the live slot AND
    // the published request epoch adopt it together.
    state.install_gateway_runtime_svid_bundle(gateway);
    (state, tasks)
}

/// Establish one real pooled HBONE tunnel and one real pooled mesh-mTLS
/// connection through the state's own pools, leaving one discoverable entry in
/// each pool map.
async fn pool_one_mesh_pooled_entry_each(
    state: &ProxyState,
    server_addr: std::net::SocketAddr,
    server_id: &SpiffeId,
) -> (H2ConnectTunnel, MeshMtlsSender) {
    let proxy = proxy_for_test();
    let tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        state.hbone_pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            Some(server_id),
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely hbone dial")
    .expect("hbone tunnel opens");
    let sender = tokio::time::timeout(
        Duration::from_secs(15),
        state.mesh_mtls_pool.get_sender(
            &proxy,
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            Some(server_id),
            None,
            None,
        ),
    )
    .await
    .expect("timely mesh-mTLS dial")
    .expect("mesh-mTLS connection opens");

    assert_eq!(
        state.hbone_pool.pool_size(),
        1,
        "the HBONE dial must have left exactly one discoverable pooled entry"
    );
    assert_eq!(
        state.mesh_mtls_pool.pool_size(),
        1,
        "the mesh-mTLS dial must have left exactly one discoverable pooled entry"
    );
    (tunnel, sender)
}

fn local_only_trust(td: &TrustDomain, authority: Vec<u8>) -> TrustBundleSet {
    TrustBundleSet::local_only(TrustBundle {
        trust_domain: td.clone(),
        x509_authorities: vec![authority],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    })
}

fn dp_snapshot(version: &str) -> GatewayConfig {
    GatewayConfig {
        version: version.to_string(),
        ..Default::default()
    }
}

fn backend_security_generation(state: &ProxyState) -> u64 {
    state.backend_svid_generation.load(Ordering::Acquire)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_committed_trust_replace_clears_pooled_mesh_entries_at_the_default_zero_drain() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let root = root_der.clone();
    let server_bundle = bundle_for(server_id.clone(), server_leaf, server_key, root);
    let server_slot = svid_slot(server_bundle);
    let (server_addr, _connections) = start_hbone_counting_echo_server(server_slot).await;

    let gateway_bundle = bundle_for(gateway_id, gateway_leaf, gateway_key, root_der);
    let (state, _tasks) = dp_state_with_gateway_svid(gateway_bundle).await;
    let (_tunnel, _sender) = pool_one_mesh_pooled_entry_each(&state, server_addr, &server_id).await;
    let before = backend_security_generation(&state);

    // ── The production publication seam. No `.await` past this point. ────────
    // A CP-delivered Replace that withdraws the root must clear both pooled
    // entries that were authenticated under it from the pool maps. The rotation
    // consumer cannot help here: at `drain_seconds == 0` it never calls
    // `force_drain` at all.
    let rotated_td = TrustDomain::new("rotated.local").unwrap();
    state.update_config_with_gateway_trust(
        dp_snapshot("trust-replace"),
        GatewayTrustCommit::Replace(local_only_trust(&rotated_td, vec![4, 2])),
    );

    assert_eq!(
        state.hbone_pool.pool_size(),
        0,
        "an HBONE pooled entry authenticated under the withdrawn root must not \
         remain discoverable in the pool map — its key embeds the leaf fingerprint, \
         which the trust change did not touch, so only an explicit pool clear can remove it"
    );
    assert_eq!(
        state.mesh_mtls_pool.pool_size(),
        0,
        "the mesh-mTLS pool keys on the same unchanged fingerprint and must be \
         cleared from the pool map by the same publication"
    );
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "the generation-keyed HTTP/H2/gRPC/H3 pools must be re-partitioned by the \
         same publication"
    );
    assert!(
        state.admits_gateway_mesh_identity(),
        "the accepted generation must be authenticating once the call returns, so \
         the pool clear provably ran while admission was still fenced"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clear_that_restores_the_same_authority_keeps_pooled_mesh_entries() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let root = root_der.clone();
    let server_bundle = bundle_for(server_id.clone(), server_leaf, server_key, root);
    let server_slot = svid_slot(server_bundle);
    let (server_addr, _connections) = start_hbone_counting_echo_server(server_slot).await;

    let root = root_der.clone();
    let gateway_bundle = bundle_for(gateway_id, gateway_leaf, gateway_key, root);
    let (state, _tasks) = dp_state_with_gateway_svid(gateway_bundle).await;

    // Install a real CP override whose effective authority is byte-identical to
    // the source-loaded bundle. Clearing it restores the same verifier: no root
    // is withdrawn, so #3859's no-churn contract must preserve live transports.
    state.update_config_with_gateway_trust(
        dp_snapshot("trust-install"),
        GatewayTrustCommit::Replace(local_only_trust(&td, root_der)),
    );
    let (_tunnel, _sender) = pool_one_mesh_pooled_entry_each(&state, server_addr, &server_id).await;
    let before = backend_security_generation(&state);

    // ── Overlap-only Clear. No `.await` past this point. ─────────────────────
    state.update_config_with_gateway_trust(dp_snapshot("trust-clear"), GatewayTrustCommit::Clear);

    assert_eq!(
        state.hbone_pool.pool_size(),
        1,
        "restoring the same authority must not churn the HBONE pooled entry"
    );
    assert_eq!(
        state.mesh_mtls_pool.pool_size(),
        1,
        "restoring the same authority must not churn the mesh-mTLS pooled entry"
    );
    assert_eq!(
        backend_security_generation(&state),
        before,
        "an overlap-only Clear must not advance the backend security generation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_commit_that_withdraws_no_root_never_clears_a_pooled_mesh_entry() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let server_id = SpiffeId::from_parts(&td, "ns/default/sa/orders").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let (server_leaf, server_key) = issue_svid(&server_id, &root_pem, &root_key_pem);

    let root = root_der.clone();
    let server_bundle = bundle_for(server_id.clone(), server_leaf, server_key, root);
    let server_slot = svid_slot(server_bundle);
    let (server_addr, _connections) = start_hbone_counting_echo_server(server_slot).await;

    let gateway_bundle = bundle_for(gateway_id, gateway_leaf, gateway_key, root_der);
    let (state, _tasks) = dp_state_with_gateway_svid(gateway_bundle).await;
    let (_tunnel, _sender) = pool_one_mesh_pooled_entry_each(&state, server_addr, &server_id).await;
    let before = backend_security_generation(&state);

    // An ordinary resource reload: the side channel says nothing about trust, so
    // no root is withdrawn. Clearing pool entries here would be a self-inflicted reconnect
    // storm on every CP delta.
    state.update_config_with_gateway_trust(
        dp_snapshot("ordinary-reload"),
        GatewayTrustCommit::Unchanged,
    );

    assert_eq!(
        state.hbone_pool.pool_size(),
        1,
        "an Unchanged commit changes no trust material and must not churn a pool"
    );
    assert_eq!(state.mesh_mtls_pool.pool_size(), 1);
    assert_eq!(
        backend_security_generation(&state),
        before,
        "an Unchanged commit must not advance the backend security generation"
    );

    // A `Clear` with no override installed is what the CP sends on EVERY full
    // snapshot of a deployment that uses no gateway trust bundles. It removes no
    // root, so it must not clear anything either — otherwise a DP reconnect
    // would drop every pooled mesh entry on the node.
    state.update_config_with_gateway_trust(
        dp_snapshot("redundant-clear"),
        GatewayTrustCommit::Clear,
    );

    assert_eq!(
        state.hbone_pool.pool_size(),
        1,
        "a Clear that withdraws nothing must not clear a pooled mesh entry"
    );
    assert_eq!(state.mesh_mtls_pool.pool_size(), 1);
    assert_eq!(backend_security_generation(&state), before);
}

/// First accepted TCP is held open after the TLS+H2 handshake without reading
/// or writing, so client PINGs time out instead of seeing FIN/RST. Later
/// accepts are a normal CONNECT echo so a redial can succeed (issue #4162).
async fn start_hbone_blackhole_then_echo_server(
    server_slot: SharedSvidBundle,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone blackhole server");
    let addr = listener.local_addr().expect("listener addr");
    let connection_count = Arc::new(AtomicUsize::new(0));
    let count_for_task = connection_count.clone();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        let mut first = true;
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            count_for_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let blackhole = first;
            first = false;
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let h2 = match h2::server::handshake(tls).await {
                    Ok(h2) => h2,
                    Err(_) => return,
                };
                if blackhole {
                    // Hold the accepted socket open without reading or writing
                    // so client PINGs time out rather than seeing FIN/RST.
                    std::future::pending::<()>().await;
                }
                let mut h2 = h2;
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

fn keepalive_proxy() -> Proxy {
    let mut proxy = proxy_for_test();
    proxy.pool_enable_http2 = Some(true);
    proxy.pool_http2_keep_alive_interval_seconds = Some(1);
    proxy.pool_http2_keep_alive_timeout_seconds = Some(1);
    proxy.backend_connect_timeout_ms = 8_000;
    proxy
}

async fn wait_for_hbone_pool_size(pool: &HboneConnectionPool, expected: usize, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if pool.pool_size() == expected {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "HBONE pool_size stayed at {} (wanted {expected}) after {timeout:?}",
                pool.pool_size()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_keepalive_timeout_evicts_dead_pooled_transport_and_redials() {
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
    let (server_addr, connection_count) = start_hbone_blackhole_then_echo_server(server_slot).await;

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    let proxy = keepalive_proxy();

    let first = tokio::time::timeout(
        Duration::from_secs(12),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely first hbone attempt");
    match first {
        Ok(_) => {}
        Err(HbonePoolError::ConnectStream { message, .. }) => {
            assert!(
                !message.contains("timed out after"),
                "keepalive must tear the dead transport down instead of leaving \
                 CONNECT hung until connect_timeout: {message}"
            );
        }
        Err(other) => panic!("unexpected first-dial error: {other:?}"),
    }

    wait_for_hbone_pool_size(&pool, 0, Duration::from_secs(8)).await;
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "the black-holed peer must still be the only dial before redial"
    );

    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely redial")
    .expect("redial must open a fresh HBONE tunnel instead of reusing the dead pooled transport");

    tunnel.write_all(b"keepalive-redial").await.expect("write");
    let mut echoed = [0_u8; 16];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(&echoed, b"keepalive-redial");
    assert!(
        connection_count.load(Ordering::SeqCst) >= 2,
        "next checkout after keepalive eviction must redial, not reuse the dead peer"
    );
    assert_eq!(
        pool.pool_size(),
        1,
        "the replacement transport must stay pooled and not be evicted as if it were the dead one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_keepalive_does_not_tear_down_a_healthy_pooled_transport() {
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

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    let proxy = keepalive_proxy();

    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .expect("timely hbone tunnel open")
    .expect("open hbone tunnel");
    tunnel.write_all(b"still-alive").await.expect("write");
    let mut echoed = [0_u8; 11];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(&echoed, b"still-alive");
    drop(tunnel);

    assert_eq!(pool.pool_size(), 1);
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(
        pool.pool_size(),
        1,
        "a healthy peer that answers PINGs must not be torn down by keepalive"
    );
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "keepalive must not force a redial against a live peer"
    );
}

#[test]
fn hbone_keepalive_abort_is_distinct_from_trust_withdrawal() {
    let trust = MeshTransportGate::new();
    assert!(trust.retire());
    assert!(trust.is_retired());
    assert!(!trust.keepalive_failed());
    assert!(
        trust
            .retired_io_error()
            .to_string()
            .contains(MESH_TRUST_WITHDRAWN_MESSAGE)
    );

    let keepalive = MeshTransportGate::new();
    assert!(keepalive.abort_keepalive());
    assert!(keepalive.keepalive_failed());
    assert!(
        !keepalive.is_retired(),
        "keepalive failure must not set the trust-withdrawal flag"
    );
    assert!(
        keepalive
            .keepalive_io_error()
            .to_string()
            .contains(MESH_KEEPALIVE_FAILED_MESSAGE)
    );
    assert_ne!(MESH_KEEPALIVE_FAILED_MESSAGE, MESH_TRUST_WITHDRAWN_MESSAGE);
    assert!(!keepalive.abort_keepalive(), "abort is one-shot");
    assert!(!trust.retire(), "retire is one-shot");
}

/// HBONE peer that answers the FIRST CONNECT stream with a response header block
/// deliberately larger than the pool's receive-side
/// `SETTINGS_MAX_HEADER_LIST_SIZE`, then serves the SECOND CONNECT stream on the
/// SAME h2 connection as a normal echo.
///
/// The block is sized between the cap (16 KiB) and `h2`'s 4x "abuse" multiplier
/// (64 KiB) on purpose: inside that band `h2` refuses the oversized STREAM and
/// keeps the connection, which is exactly the behaviour the regression asserts.
/// The returned counter is the number of TCP connections accepted, so a value of
/// 1 after both streams proves the transport survived the refusal instead of
/// being torn down and redialed.
async fn start_hbone_oversize_response_header_server(
    server_slot: SharedSvidBundle,
    pad_headers: usize,
    pad_value_len: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hbone oversize header server");
    let addr = listener.local_addr().expect("listener addr");
    let connection_count = Arc::new(AtomicUsize::new(0));
    let count_for_task = connection_count.clone();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            count_for_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut h2) = h2::server::handshake(tls).await else {
                    return;
                };
                let mut stream_index = 0_usize;
                while let Some(next) = h2.accept().await {
                    let Ok((request, mut respond)) = next else {
                        return;
                    };
                    let oversized = stream_index == 0;
                    stream_index += 1;
                    tokio::spawn(async move {
                        let mut builder = Response::builder().status(StatusCode::OK);
                        if oversized {
                            let padding = "p".repeat(pad_value_len);
                            for i in 0..pad_headers {
                                builder = builder
                                    .header(format!("x-ferrum-pad-{i:04}"), padding.as_str());
                            }
                        }
                        let response = builder.body(()).expect("connect response");
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        if oversized {
                            // The client refuses this stream; nothing to echo.
                            return;
                        }
                        let mut recv = request.into_body();
                        while let Some(chunk) = recv.data().await {
                            let Ok(chunk) = chunk else {
                                return;
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

/// Issue #4541: the outbound HBONE h2 client must bound the response header block
/// an SVID-holding peer can push at it. Without a `max_header_list_size` the raw
/// `h2` client keeps its 16 MiB default and decodes/buffers the whole thing.
///
/// The cap is a STREAM-level refusal, so the CONNECT fails while the transport
/// stays usable: the follow-up CONNECT is served on the same pooled connection.
#[tokio::test(flavor = "multi_thread")]
async fn hbone_refuses_an_oversized_peer_response_header_block_without_killing_the_connection() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let workload_id = SpiffeId::from_parts(&td, "ns/default/sa/workload").unwrap();
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

    // 24 x (name 16 + value 1000 + 32 HPACK overhead) ~= 25 KiB decoded: over the
    // 16 KiB cap, comfortably under the 64 KiB abuse ceiling that would make this
    // a CONNECTION error instead of a stream refusal.
    let (server_addr, connection_count) =
        start_hbone_oversize_response_header_server(server_slot, 24, 1000).await;

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    assert_eq!(
        pool.effective_max_header_list_size(),
        HBONE_DEFAULT_MAX_HEADER_LIST_SIZE,
        "an unattached pool must still bound the peer's header block"
    );
    let proxy = proxy_for_test();

    let refused = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            None,
            None,
            Some(&workload_id),
        ),
    )
    .await
    .expect("timely hbone tunnel attempt")
    .err()
    .expect("oversized response header block must refuse the CONNECT stream");
    assert!(
        matches!(refused, HbonePoolError::ConnectStream { .. }),
        "expected a stream-level CONNECT failure, got {refused:?}"
    );

    // The connection survived the refusal: this CONNECT rides the SAME pooled
    // transport, so no second TCP dial is made.
    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            server_addr.port(),
            None,
            None,
            None,
            Some(&workload_id),
        ),
    )
    .await
    .expect("timely hbone tunnel open after refusal")
    .expect("connection must survive a stream-level header-size refusal");

    tunnel.write_all(b"mesh-hello").await.expect("write tunnel");
    let mut echoed = [0_u8; 10];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo through surviving hbone tunnel")
        .expect("read echoed tunnel bytes");
    let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.shutdown()).await;
    assert_eq!(&echoed, b"mesh-hello");

    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "the header-size cap must refuse the stream, not tear down the connection"
    );
}

/// Issue #4541: a pool built without an operator policy must not silently inherit
/// `h2`'s 16 MiB `SETTINGS_MAX_HEADER_LIST_SIZE`. The unset default is hyper's
/// own 16 KiB, which is what every sibling backend transport rides.
#[test]
fn hbone_pool_default_max_header_list_size_is_hyper_parity_not_h2s_16_mib() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    const H2_CRATE_DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 16 << 20;
    assert_eq!(HBONE_DEFAULT_MAX_HEADER_LIST_SIZE, 16 * 1024);
    assert_ne!(
        HBONE_DEFAULT_MAX_HEADER_LIST_SIZE,
        H2_CRATE_DEFAULT_MAX_HEADER_LIST_SIZE
    );

    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    let gateway_slot = svid_slot(bundle_for(gateway_id, gateway_leaf, gateway_key, root_der));

    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_slot,
        4,
    );
    assert_eq!(
        pool.effective_max_header_list_size(),
        HBONE_DEFAULT_MAX_HEADER_LIST_SIZE
    );

    // Attaching the operator policy replaces the default, and is idempotent.
    pool.attach_max_header_list_size(64 * 1024);
    assert_eq!(pool.effective_max_header_list_size(), 64 * 1024);
    pool.attach_max_header_list_size(1024 * 1024);
    assert_eq!(
        pool.effective_max_header_list_size(),
        64 * 1024,
        "attach must be one-shot (OnceLock::set)"
    );
}

/// Number of simultaneous cold-pool checkouts driven at one hard-down peer.
const COALESCED_COHORT: usize = 6;
/// How long the black-hole listener holds an accepted socket before dropping
/// it. Long enough that every cohort member is provably inside the pool (and
/// has therefore joined the in-flight creation) before the creator's dial
/// fails.
const BLACK_HOLE_HOLD: Duration = Duration::from_millis(750);

/// A listener that ACCEPTS every dial, counts it, holds the socket for `hold`
/// and then drops it without ever answering the ClientHello, so the client's
/// TLS handshake fails.
///
/// Nothing is ever established, so the accept count IS the physical dial count
/// for the cohort — the deterministic evidence issue #5046 asks for in place of
/// a benchmark.
async fn start_counting_black_hole(hold: Duration) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind black-hole listener");
    let port = listener.local_addr().expect("black-hole addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                tokio::time::sleep(hold).await;
                drop(socket);
            });
        }
    });
    (port, accepts)
}

fn gateway_svid_slot_for_test() -> SharedSvidBundle {
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let (gateway_leaf, gateway_key) = issue_svid(&gateway_id, &root_pem, &root_key_pem);
    svid_slot(bundle_for(gateway_id, gateway_leaf, gateway_key, root_der))
}

async fn dial_black_holed_hbone(
    pool: &HboneConnectionPool,
    proxy: &Proxy,
    port: u16,
) -> HbonePoolError {
    let dial = pool.get_tunnel_via(
        proxy,
        "127.0.0.1",
        "127.0.0.1",
        8080,
        8080,
        port,
        None,
        None,
        None,
        None,
    );
    match dial.await {
        Ok(_) => panic!("a black-holed peer can never complete an HBONE dial"),
        Err(err) => err,
    }
}

async fn dial_black_holed_mesh_mtls(
    pool: &MeshMtlsConnectionPool,
    proxy: &Proxy,
    port: u16,
) -> HbonePoolError {
    let dial = pool.get_sender(proxy, "127.0.0.1", 8080, 8080, port, None, None, None);
    match dial.await {
        Ok(_) => panic!("a black-holed peer can never complete a mesh-mTLS dial"),
        Err(err) => err,
    }
}

/// One physical dial for the whole cohort, and the SAME typed outcome for
/// every member of it.
fn assert_shared_dial_failure(outcomes: &[HbonePoolError], accepts: &AtomicUsize) {
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "a simultaneous cohort against one hard-down peer must run ONE physical dial"
    );
    assert_eq!(outcomes.len(), COALESCED_COHORT);
    for outcome in outcomes {
        assert!(
            matches!(outcome, HbonePoolError::TlsHandshake { .. }),
            "every waiter must receive the creator's typed failure"
        );
        assert_eq!(outcome.error_class(), ErrorClass::TlsError);
        assert_eq!(outcome.public_reason(), "TLS handshake failed");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hbone_cohort_pays_for_one_failed_dial_not_one_per_waiter() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (server_port, accepts) = start_counting_black_hole(BLACK_HOLE_HOLD).await;
    let pool = Arc::new(HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_svid_slot_for_test(),
        4,
    ));
    let proxy = Arc::new(proxy_for_test());
    let ready = Arc::new(tokio::sync::Barrier::new(COALESCED_COHORT));

    let mut tasks = Vec::with_capacity(COALESCED_COHORT);
    for _ in 0..COALESCED_COHORT {
        let pool = pool.clone();
        let proxy = proxy.clone();
        let ready = ready.clone();
        let task = tokio::spawn(async move {
            ready.wait().await;
            dial_black_holed_hbone(&pool, &proxy, server_port).await
        });
        tasks.push(task);
    }

    let mut outcomes = Vec::with_capacity(COALESCED_COHORT);
    for task in tasks {
        outcomes.push(task.await.expect("checkout task should not panic"));
    }

    assert_shared_dial_failure(&outcomes, &accepts);
    assert_eq!(
        pool.pool_size(),
        0,
        "a failed creation must never leave a pooled entry behind"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_mtls_cohort_pays_for_one_failed_dial_not_one_per_waiter() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (server_port, accepts) = start_counting_black_hole(BLACK_HOLE_HOLD).await;
    let pool = Arc::new(MeshMtlsConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_svid_slot_for_test(),
        4,
    ));
    let proxy = Arc::new(proxy_for_test());
    let ready = Arc::new(tokio::sync::Barrier::new(COALESCED_COHORT));

    let mut tasks = Vec::with_capacity(COALESCED_COHORT);
    for _ in 0..COALESCED_COHORT {
        let pool = pool.clone();
        let proxy = proxy.clone();
        let ready = ready.clone();
        let task = tokio::spawn(async move {
            ready.wait().await;
            dial_black_holed_mesh_mtls(&pool, &proxy, server_port).await
        });
        tasks.push(task);
    }

    let mut outcomes = Vec::with_capacity(COALESCED_COHORT);
    for task in tasks {
        outcomes.push(task.await.expect("checkout task should not panic"));
    }

    assert_shared_dial_failure(&outcomes, &accepts);
    assert_eq!(
        pool.pool_size(),
        0,
        "a failed creation must never leave a pooled entry behind"
    );
}

/// Recovery: the request immediately after a broadcast failure must dial the
/// peer again. The broadcast releases one cohort; it is not a negative cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_after_a_broadcast_failure_dials_the_peer_again() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (server_port, accepts) = start_counting_black_hole(Duration::from_millis(50)).await;
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        gateway_svid_slot_for_test(),
        4,
    );
    let proxy = proxy_for_test();

    for attempt in 1..=3 {
        let err = dial_black_holed_hbone(&pool, &proxy, server_port).await;
        assert!(matches!(err, HbonePoolError::TlsHandshake { .. }));
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            attempt,
            "each independent request must be free to re-dial the peer"
        );
    }
}

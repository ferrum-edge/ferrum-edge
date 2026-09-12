//! Live gateway-to-mesh trust withdrawal: transports authenticated under a
//! withdrawn authority must STOP CARRYING TRAFFIC, not merely disappear from the
//! pool map (issue #3859).
//!
//! `pool_size() == 0` proves only that a future lookup cannot discover a
//! connection. Every assertion here is made on a handle that has ALREADY left
//! the pool — a retained `H2ConnectTunnel`, a retained `MeshMtlsSender`, a
//! cloned HTTP/2 sender — because those are the handles that kept forwarding
//! before this change.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::{
    JwtAuthority, SharedSvidBundle, SvidBundle, TrustBundle, TrustBundleSet,
};
use ferrum_edge::proxy::grpc_proxy::GrpcBody;
use ferrum_edge::proxy::hbone_pool::{HboneConnectionPool, HbonePoolError};
use ferrum_edge::proxy::mesh_mtls_pool::{
    MeshMtlsConnectionPool, MeshMtlsRequestBody, MeshMtlsSenderError,
};
use ferrum_edge::proxy::mesh_trust_registry::{
    MeshTransportGate, MeshTransportKind, MeshTrustRegistry, TrustWithdrawalReason,
    trust_withdrawal_reason,
};
use ferrum_edge::tls::spiffe::build_spiffe_inbound_config;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

/// Trust view carrying the given synthetic X.509 authorities. The bytes are
/// opaque to the comparison under test; only set membership matters.
fn trust_view(td: &str, authorities: Vec<Vec<u8>>) -> TrustBundleSet {
    TrustBundleSet::local_only(TrustBundle {
        trust_domain: TrustDomain::new(td).expect("trust domain"),
        x509_authorities: authorities,
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    })
}

fn trust_view_with_jwt(td: &str, key_id: &str, public_key_pem: &str) -> TrustBundleSet {
    TrustBundleSet::local_only(TrustBundle {
        trust_domain: TrustDomain::new(td).expect("trust domain"),
        x509_authorities: vec![vec![1, 2, 3]],
        jwt_authorities: vec![JwtAuthority {
            key_id: key_id.to_string(),
            public_key_pem: public_key_pem.to_string(),
        }],
        refresh_hint_seconds: None,
    })
}

fn proxy_for_test() -> Proxy {
    let now = Utc::now();
    Proxy {
        labels: Default::default(),
        id: "gateway-mesh-trust".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Gateway mesh trust".to_string()),
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

/// Long-lived SPIFFE-mTLS h2 server that echoes every CONNECT stream's body.
/// Serves the HBONE tunnel tests and, unchanged, the mesh-mTLS sender test
/// (hyper's HTTP/2 client speaks ordinary h2 to it).
///
/// The returned counter is the number of accepted TCP connections, i.e. the
/// number of times the gateway pool (re)dialed. It is what proves a RETIRED
/// transport was not silently reused: a post-withdrawal lookup must show a
/// FRESH dial, not the old socket.
async fn start_mesh_echo_server(
    server_slot: SharedSvidBundle,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind mesh echo server");
    let addr = listener.local_addr().expect("listener addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_for_task = connections.clone();

    tokio::spawn(async move {
        let inbound = build_spiffe_inbound_config(server_slot, true, Arc::new(Vec::new()))
            .expect("server config");
        let acceptor = TlsAcceptor::from(inbound);
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            connections_for_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut h2) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(next) = h2.accept().await {
                    let (request, mut respond) = match next {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    tokio::spawn(async move {
                        let mut recv = request.into_body();
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .expect("response");
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        while let Some(chunk) = recv.data().await {
                            let Ok(chunk) = chunk else { return };
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

    (addr, connections)
}

struct MeshFixture {
    gateway_slot: SharedSvidBundle,
    server_addr: std::net::SocketAddr,
    server_connections: Arc<AtomicUsize>,
    workload_id: SpiffeId,
}

async fn mesh_fixture() -> MeshFixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let td = TrustDomain::new("cluster.local").unwrap();
    let (root_der, root_pem, root_key_pem) = synthetic_root(&td);
    let gateway_id = SpiffeId::from_parts(&td, "ns/edge/sa/gateway").unwrap();
    let workload_id = SpiffeId::from_parts(&td, "ns/default/sa/workload").unwrap();
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
    let (server_addr, server_connections) = start_mesh_echo_server(server_slot).await;

    MeshFixture {
        gateway_slot,
        server_addr,
        server_connections,
        workload_id,
    }
}

// ===== withdrawal decision: the no-churn matrix =====

#[test]
fn identical_replace_and_additive_overlap_are_not_withdrawals() {
    let before = trust_view("cluster.local", vec![vec![1], vec![2]]);
    let identical = trust_view("cluster.local", vec![vec![1], vec![2]]);
    let additive = trust_view("cluster.local", vec![vec![1], vec![2], vec![3]]);
    // Order must not matter: an authority set is a set.
    let reordered = trust_view("cluster.local", vec![vec![2], vec![1]]);

    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&identical), false),
        None,
        "an identical Replace must not retire any transport"
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&additive), false),
        None,
        "an additive overlap must not retire any transport"
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&reordered), false),
        None,
        "authority ORDER is not authority membership"
    );
}

#[test]
fn removing_any_authority_is_a_withdrawal() {
    let before = trust_view("cluster.local", vec![vec![1], vec![2]]);
    let narrowed = trust_view("cluster.local", vec![vec![1]]);
    let replaced = trust_view("cluster.local", vec![vec![9]]);
    let other_domain = trust_view("other.local", vec![vec![1], vec![2]]);

    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&narrowed), false),
        Some(TrustWithdrawalReason::ReplaceRemovedAuthority)
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&replaced), false),
        Some(TrustWithdrawalReason::ReplaceRemovedAuthority)
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&other_domain), false),
        Some(TrustWithdrawalReason::ReplaceRemovedAuthority),
        "the same bytes under a DIFFERENT trust domain are a different authority"
    );
}

#[test]
fn jwt_authority_rotation_under_one_key_id_is_a_withdrawal() {
    let before = trust_view_with_jwt("cluster.local", "kid-1", "-----BEGIN PUBLIC KEY-----a");
    let same = trust_view_with_jwt("cluster.local", "kid-1", "-----BEGIN PUBLIC KEY-----a");
    let swapped = trust_view_with_jwt("cluster.local", "kid-1", "-----BEGIN PUBLIC KEY-----b");

    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&same), false),
        None
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&before), Some(&swapped), false),
        Some(TrustWithdrawalReason::ReplaceRemovedAuthority),
        "a same-kid key swap withdraws the old key, so live sessions must be retired"
    );
}

#[test]
fn clear_semantics_distinguish_a_redundant_clear_from_a_real_withdrawal() {
    let installed = trust_view("cluster.local", vec![vec![1], vec![2]]);
    let startup_superset = trust_view("cluster.local", vec![vec![1], vec![2], vec![3]]);
    let startup_narrower = trust_view("cluster.local", vec![vec![1]]);

    assert_eq!(
        trust_withdrawal_reason(None, None, true),
        None,
        "a Clear with no installed override is a no-op"
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&installed), Some(&startup_superset), true),
        None,
        "a Clear whose restored startup material still carries every authority is a no-op"
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&installed), Some(&startup_narrower), true),
        Some(TrustWithdrawalReason::ClearedOverride),
        "a Clear that leaves an authority behind is a real withdrawal"
    );
    assert_eq!(
        trust_withdrawal_reason(Some(&installed), None, true),
        Some(TrustWithdrawalReason::ClearedOverride),
        "a Clear with no restored material withdraws everything"
    );
}

// ===== registry: fence, publish, retire, reopen =====

#[test]
fn withdrawal_publishes_a_new_generation_and_retires_the_outgoing_one() {
    let registry = MeshTrustRegistry::new();
    let generation = registry.accepted_generation();

    let ticket = registry.admission_ticket();
    let gate = MeshTransportGate::new();
    let registration = registry
        .register(ticket, MeshTransportKind::Hbone, gate.clone())
        .expect("first transport is admitted");
    assert_eq!(registry.registered_len(), 1);
    assert!(!gate.is_retired());

    let outcome =
        registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);

    assert_eq!(outcome.retired_generation, generation);
    assert_eq!(outcome.published_generation, generation + 1);
    assert_eq!(outcome.retired_hbone, 1);
    assert_eq!(outcome.retired_mesh_mtls, 0);
    assert!(
        gate.is_retired(),
        "the gate must be signalled synchronously, before admission reopens"
    );
    assert_eq!(registry.registered_len(), 0);
    assert_eq!(registry.accepted_generation(), generation + 1);
    assert_eq!(registry.retired_through(), generation);

    // Admission is reopened for the NEW generation.
    let fresh = registry.admission_ticket();
    let fresh_gate = MeshTransportGate::new();
    registry
        .register(fresh, MeshTransportKind::MeshMtls, fresh_gate.clone())
        .expect("a transport dialled under the published generation is admitted");
    assert!(!fresh_gate.is_retired());

    drop(registration);
}

#[test]
fn a_transport_dialled_before_publication_cannot_be_admitted_afterwards() {
    // This is the creation race: the dial started under generation N, the
    // withdrawal published N+1 while it was in flight, and the connection
    // completed afterwards. It must not be pooled OR returned.
    let registry = MeshTrustRegistry::new();
    let in_flight_ticket = registry.admission_ticket();

    let _ = registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);

    let escaped_gate = MeshTransportGate::new();
    let refused = registry.register(
        in_flight_ticket,
        MeshTransportKind::Hbone,
        escaped_gate.clone(),
    );
    assert!(
        refused.is_err(),
        "an old-generation transport must be refused, not inserted"
    );
    assert_eq!(
        registry.registered_len(),
        0,
        "a refused transport must not repopulate the registry"
    );
}

#[test]
fn retirement_is_exact_once_per_transport() {
    let registry = MeshTrustRegistry::new();
    let gate = MeshTransportGate::new();
    let _registration = registry
        .register(
            registry.admission_ticket(),
            MeshTransportKind::MeshMtls,
            gate.clone(),
        )
        .expect("admitted");

    let first = registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ClearedOverride);
    let second = registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ClearedOverride);

    assert_eq!(first.retired_mesh_mtls, 1);
    assert_eq!(
        second.retired_total(),
        0,
        "a second withdrawal must not re-count an already-retired transport"
    );
    assert!(
        !gate.retire(),
        "the gate transition is exact-once, so relay/permit release cannot double-complete"
    );
}

#[test]
fn an_ordinary_connection_close_deregisters_without_retiring() {
    let registry = MeshTrustRegistry::new();
    let gate = MeshTransportGate::new();
    let registration = registry
        .register(
            registry.admission_ticket(),
            MeshTransportKind::Hbone,
            gate.clone(),
        )
        .expect("admitted");
    assert_eq!(registry.registered_len(), 1);

    drop(registration);

    assert_eq!(
        registry.registered_len(),
        0,
        "the driver's registration is the connection's lifetime"
    );
    assert!(
        !gate.is_retired(),
        "an ordinary close is not a trust event and must not be reported as a retirement"
    );
}

// ===== live HBONE: the retained handle is the assertion surface =====

#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_makes_a_retained_hbone_tunnel_unusable_and_stops_traffic() {
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();

    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            None,
            None,
            None,
            Some(&fixture.workload_id),
        ),
    )
    .await
    .expect("timely hbone tunnel open")
    .expect("open hbone tunnel");

    // Traffic flows before the withdrawal.
    tunnel.write_all(b"before").await.expect("write tunnel");
    let mut echoed = [0_u8; 6];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("echo bytes");
    assert_eq!(&echoed, b"before");
    assert_eq!(pool.pool_size(), 1);
    assert_eq!(registry.registered_len(), 1);

    // The operator withdraws an authority.
    let outcome =
        registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);
    assert_eq!(outcome.retired_hbone, 1);
    pool.force_drain_all();

    // `pool_size() == 0` is necessary but NOT what this test is about.
    assert_eq!(pool.pool_size(), 0);

    // The RETAINED tunnel is now unusable in both directions.
    let write = tunnel.write_all(b"after").await;
    assert!(
        write.is_err(),
        "a retired tunnel must refuse to forward client bytes"
    );
    let mut leaked = [0_u8; 5];
    let read = tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut leaked))
        .await
        .expect("a retired tunnel must resolve rather than hang");
    assert!(
        read.is_err(),
        "a retired tunnel must refuse to deliver backend bytes"
    );

    // And the withdrawal message discloses nothing about the trust material.
    let message = write.expect_err("write error").to_string();
    assert!(
        message.contains("gateway trust authority withdrawn"),
        "unexpected retirement error: {message}"
    );
    for leak in ["cluster.local", "spiffe://", "BEGIN", "sa/gateway"] {
        assert!(
            !message.contains(leak),
            "the retirement error must not disclose trust material: {message}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_stops_an_actively_streaming_hbone_tunnel() {
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();

    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            None,
            None,
            None,
            Some(&fixture.workload_id),
        ),
    )
    .await
    .expect("timely hbone tunnel open")
    .expect("open hbone tunnel");

    tunnel.write_all(b"warm").await.expect("write tunnel");
    let mut echoed = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("echo bytes");

    // A relay parked on a read is the realistic shape of a live session: no
    // traffic is in flight when the operator revokes the root.
    let relay = tokio::spawn(async move {
        let mut buf = [0_u8; 32];
        tunnel.read(&mut buf).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);

    let parked = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("a parked relay must be released, not left hanging")
        .expect("relay task");
    match parked {
        Err(_) => {}
        Ok(0) => {}
        Ok(n) => panic!("a retired tunnel delivered {n} bytes after withdrawal"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retired_hbone_transport_is_never_reused_for_a_later_stream() {
    // The pooled HTTP/2 sender is multiplexed: several CONNECT tunnels ride one
    // socket. After a withdrawal, no later caller may be served on that socket —
    // the server-side connection count is what proves it, because an empty pool
    // map alone would look identical whether the old sender was reused or not.
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();

    let open_tunnel = || {
        tokio::time::timeout(
            Duration::from_secs(15),
            pool.get_tunnel_via(
                &proxy,
                "127.0.0.1",
                "127.0.0.1",
                8080,
                8080,
                fixture.server_addr.port(),
                None,
                None,
                None,
                Some(&fixture.workload_id),
            ),
        )
    };

    let mut first = open_tunnel()
        .await
        .expect("timely open")
        .expect("open first tunnel");
    let mut second = open_tunnel()
        .await
        .expect("timely open")
        .expect("open second tunnel");
    assert_eq!(pool.pool_size(), 1, "both tunnels ride one pooled sender");
    assert_eq!(
        fixture.server_connections.load(Ordering::SeqCst),
        1,
        "multiplexed tunnels must share one socket before the withdrawal"
    );

    registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ClearedOverride);
    pool.force_drain_all();

    // BOTH already-issued tunnels are dead, including the one the pool never
    // saw again.
    assert!(first.write_all(b"x").await.is_err());
    assert!(second.write_all(b"x").await.is_err());

    // A later caller is served, but only over a FRESH transport under the newly
    // published generation — never the retired socket.
    let mut replacement = open_tunnel()
        .await
        .expect("timely open")
        .expect("a withdrawal must not permanently break egress");
    replacement.write_all(b"fresh").await.expect("write");
    let mut echoed = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(5), replacement.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("echo bytes");
    assert_eq!(&echoed, b"fresh");
    assert_eq!(
        fixture.server_connections.load(Ordering::SeqCst),
        2,
        "the replacement must be a fresh dial, not the retired transport"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_additive_overlap_keeps_a_live_tunnel_usable_until_the_old_root_is_removed() {
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = HboneConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();

    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_tunnel_via(
            &proxy,
            "127.0.0.1",
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            None,
            None,
            None,
            Some(&fixture.workload_id),
        ),
    )
    .await
    .expect("timely hbone tunnel open")
    .expect("open hbone tunnel");

    // Phase 1: publish an ADDITIVE overlap. The publication path consults
    // `trust_withdrawal_reason`, which reports no withdrawal, so nothing is
    // retired and the live session keeps working.
    let old_root = trust_view("cluster.local", vec![vec![1]]);
    let overlap = trust_view("cluster.local", vec![vec![1], vec![2]]);
    assert_eq!(
        trust_withdrawal_reason(Some(&old_root), Some(&overlap), false),
        None
    );
    assert_eq!(registry.registered_len(), 1);

    tunnel.write_all(b"still-live").await.expect("write tunnel");
    let mut echoed = [0_u8; 10];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut echoed))
        .await
        .expect("timely echo across an additive rotation")
        .expect("echo bytes");
    assert_eq!(&echoed, b"still-live");

    // Phase 2: the operator now removes the OLD root. That is a withdrawal, and
    // the same live session must terminate.
    let new_root_only = trust_view("cluster.local", vec![vec![2]]);
    let reason = trust_withdrawal_reason(Some(&overlap), Some(&new_root_only), false)
        .expect("removing the old root is a withdrawal");
    registry.retire_for_trust_withdrawal(reason);

    assert!(
        tunnel.write_all(b"after").await.is_err(),
        "removing the old root must terminate the session it authenticated"
    );
}

// ===== live mesh-mTLS: the retained sender is the assertion surface =====

#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_makes_a_retained_mesh_mtls_sender_fail_readiness() {
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = MeshMtlsConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();
    let peer = SpiffeId::from_parts(
        &TrustDomain::new("cluster.local").unwrap(),
        "ns/default/sa/orders",
    )
    .unwrap();

    let mut sender = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_sender(
            &proxy,
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            Some(&peer),
            None,
            None,
        ),
    )
    .await
    .expect("timely mesh-mTLS connection")
    .expect("mesh-mTLS sender");

    assert_eq!(pool.pool_size(), 1);
    assert_eq!(registry.registered_len(), 1);
    // The retained sender is usable before the withdrawal.
    tokio::time::timeout(Duration::from_secs(5), sender.ready())
        .await
        .expect("timely readiness")
        .expect("a live sender is ready");

    registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);
    pool.force_drain_all();
    assert_eq!(pool.pool_size(), 0);

    // A successful readiness here would be the regression: the caller already
    // holds this sender, so a pool that only forgot the connection would still
    // let it open new streams on the withdrawn-trust TLS session.
    let readiness = tokio::time::timeout(Duration::from_secs(10), sender.ready())
        .await
        .expect("a retired sender must resolve rather than hang");
    assert!(
        matches!(readiness, Err(MeshMtlsSenderError::TrustWithdrawn)),
        "a retained mesh-mTLS sender must fail readiness after its trust is withdrawn \
         as TrustWithdrawn, not wait for the H2 driver to close: {readiness:?}"
    );

    // A later caller is served again, but never on the retired transport: the
    // server-side connection count proves the pool dialed afresh under the
    // newly published generation.
    let mut replacement = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_sender(
            &proxy,
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            Some(&peer),
            None,
            None,
        ),
    )
    .await
    .expect("timely re-lookup")
    .expect("a withdrawal must not permanently break mesh-mTLS egress");
    tokio::time::timeout(Duration::from_secs(5), replacement.ready())
        .await
        .expect("timely readiness")
        .expect("the replacement transport is usable");
    assert_eq!(
        fixture.server_connections.load(Ordering::SeqCst),
        2,
        "the replacement must be a fresh dial, not the retired transport"
    );
}

// ===== metrics: fixed cardinality, no trust material =====

#[test]
fn retirement_metrics_are_fixed_cardinality_and_material_free() {
    let registry = MeshTrustRegistry::new();
    let _registration = registry
        .register(
            registry.admission_ticket(),
            MeshTransportKind::Hbone,
            MeshTransportGate::new(),
        )
        .expect("admitted");
    registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);

    let mut rendered = String::new();
    ferrum_edge::plugins::prometheus_metrics::render_gateway_trust_retirement_prometheus(
        &mut rendered,
        ",namespace=\"ferrum\"",
        &ferrum_edge::proxy::mesh_trust_registry::metrics_snapshot(),
    );

    for family in [
        "ferrum_gateway_trust_accepted_generation",
        "ferrum_gateway_trust_withdrawals_total",
        "ferrum_gateway_trust_retired_transports_total",
        "ferrum_gateway_trust_admission_refusals_total",
    ] {
        assert!(rendered.contains(family), "missing family {family}");
    }
    // Closed label sets only.
    assert!(rendered.contains("reason=\"replace_removed_authority\""));
    assert!(rendered.contains("reason=\"cleared_override\""));
    assert!(rendered.contains("transport=\"hbone\""));
    assert!(rendered.contains("transport=\"mesh_mtls\""));
    for leak in ["spiffe://", "cluster.local", "BEGIN", "sha256", "kid"] {
        assert!(
            !rendered.contains(leak),
            "gateway trust metrics must not disclose trust material: {rendered}"
        );
    }
}

fn empty_mesh_mtls_request() -> http::Request<MeshMtlsRequestBody> {
    Request::builder()
        .uri("http://orders.example.com/")
        .body(MeshMtlsRequestBody::Grpc(GrpcBody::Buffered(Full::new(
            Bytes::new(),
        ))))
        .expect("empty mesh-mTLS request")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cloned_mesh_mtls_sender_refuses_the_next_stream_synchronously_after_gate_retirement() {
    // The pooled checkout used to map away `MeshMtlsTransport.gate` and return
    // a bare hyper sender. After checkout, a clone could race a withdrawal:
    // the driver is only notified asynchronously, so the H2 sender can still
    // be ready and open a stream before socket-close propagates. The gate must
    // travel with every clone and be consulted in `send_request` before hyper
    // queues the stream.
    let fixture = mesh_fixture().await;
    let registry = MeshTrustRegistry::new();
    let pool = MeshMtlsConnectionPool::new(
        PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        fixture.gateway_slot.clone(),
        4,
    );
    pool.attach_mesh_trust_registry(registry.clone());
    let proxy = proxy_for_test();
    let peer = SpiffeId::from_parts(
        &TrustDomain::new("cluster.local").unwrap(),
        "ns/default/sa/orders",
    )
    .unwrap();

    let mut sender = tokio::time::timeout(
        Duration::from_secs(15),
        pool.get_sender(
            &proxy,
            "127.0.0.1",
            8080,
            8080,
            fixture.server_addr.port(),
            Some(&peer),
            None,
            None,
        ),
    )
    .await
    .expect("timely mesh-mTLS connection")
    .expect("mesh-mTLS sender");
    tokio::time::timeout(Duration::from_secs(5), sender.ready())
        .await
        .expect("timely readiness")
        .expect("a live sender is ready");

    let mut cloned = sender.clone();
    registry.retire_for_trust_withdrawal(TrustWithdrawalReason::ReplaceRemovedAuthority);
    // No await: the connection driver has not been scheduled to drop the H2
    // session. `send_request` must still refuse synchronously via the gate.
    match cloned.send_request(empty_mesh_mtls_request()) {
        Err(HbonePoolError::TrustWithdrawn) => {}
        Ok(_) => panic!(
            "a cloned mesh-mTLS sender must not open a stream after gate retirement \
             while the underlying H2 sender is still open"
        ),
        Err(other) => panic!("cloned send after retirement must be TrustWithdrawn, not {other:?}"),
    }
    match sender.send_request(empty_mesh_mtls_request()) {
        Err(HbonePoolError::TrustWithdrawn) => {}
        Ok(_) => panic!("the original checkout must share the clone's gate"),
        Err(other) => {
            panic!("original send after retirement must be TrustWithdrawn, not {other:?}")
        }
    }
}

#[test]
fn commit_installs_accepted_material_before_advancing_the_ownership_generation() {
    // Pin the fail-closed publication order in source: a dial that takes a
    // ticket at the material-publication boundary must not be able to load old
    // trust under the new generation.
    let source = include_str!("../../src/proxy/mod.rs");
    let start = source
        .find("fn commit_gateway_trust_generation_locked(")
        .expect("commit_gateway_trust_generation_locked must exist");
    let body = &source[start..];
    let end = body
        .find("\n    fn publish_request_epoch_with_gateway_trust(")
        .expect("publish_request_epoch_with_gateway_trust follows the locked commit");
    let func = &body[..end];

    let fence = func
        .find("self.fence_gateway_trust_generation()")
        .expect("fence first");
    let store = func
        .find("self.store_gateway_trust_material(")
        .expect("store accepted material");
    let store_last = func
        .rfind("self.store_gateway_trust_material(")
        .expect("both Replace and Clear store before retire");
    let retire = func
        .find("self.mesh_trust_registry.retire_for_trust_withdrawal(")
        .expect("then advance ownership generation and retire outgoing transports");
    let advance = func
        .find("self.advance_backend_security_generation()")
        .expect("then retire cache/pool discoverability");
    let publish = func
        .find("self.publish_live_gateway_trust()")
        .expect("then reopen live admission");

    assert!(
        fence < store,
        "admission must be fenced before accepted material is installed"
    );
    assert!(
        store_last < retire,
        "every store_gateway_trust_material arm must run before retire_for_trust_withdrawal \
         so a new-generation ticket cannot load old verifier material"
    );
    assert!(
        retire < advance,
        "ownership generation must advance before backend-security/pool retirement"
    );
    assert!(
        advance < publish,
        "live admission must reopen only after material, ownership, and pools agree"
    );
}

#[test]
fn mesh_mtls_get_sender_returns_the_gated_handle_not_a_bare_hyper_sender() {
    let source = include_str!("../../src/proxy/mesh_mtls_pool.rs");
    let start = source
        .find("pub async fn get_sender(")
        .expect("get_sender must exist");
    let body = &source[start..];
    let end = body
        .find("\n    /// Open a raw-TCP egress CONNECT tunnel")
        .expect("open_connect_tunnel follows get_sender");
    let func = &body[..end];
    assert!(
        !func.contains("transport.sender"),
        "get_sender must not strip MeshMtlsTransport.gate; the public handle is the gated sender"
    );
    assert!(
        !func.contains(".map(|transport| transport.sender)"),
        "get_sender must not map away the retirement gate"
    );
}

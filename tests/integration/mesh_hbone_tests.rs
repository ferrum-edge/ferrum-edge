use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};

use crate::common::{empty_digest_header, generate_hmac_signature};

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, DEFAULT_TRUST_DOMAIN, default_mesh_runtime, service_for, workload_for,
};

use ferrum_edge::config::types::{
    AuthMode, BackendScheme, CircuitBreakerConfig, Consumer, DispatchKind, GatewayConfig,
    PluginAssociation, PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, InboundRelayDenial, MeshConfig, MeshEgressUdpDestination,
    MeshEgressUdpDialEndpoint, MeshInboundRelayDestination, MeshInboundRelayHost,
    MeshWaypointBinding, MeshWaypointServiceRef, MultiClusterConfig, ResolvedIngressListener,
    Workload, WorkloadPort, WorkloadSelector, inbound_relay_destinations_from_workloads,
    inbound_relay_resolved_ip_is_loopback_namespace, own_address_port_bounds_from_workloads,
};
use ferrum_edge::modes::mesh::enrolled_destinations::{
    EnrolledPodEntry, NodeLocalEnrolledDestinations, NodeLocalEnrolledDestinationsHandle,
    NodeLocalEnrolledDestinationsManager,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, MeshTrafficDirection, prepare_gateway_config_from_mesh_slice,
};
use ferrum_edge::proxy::netns_capture::{
    DirectoryCaptureSource, PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget,
};
use ferrum_edge::proxy::{
    ProxyState, start_proxy_listener_with_bound_listener,
    start_proxy_listener_with_bound_listener_and_mesh_direction,
};

fn create_mesh_proxy(backend_port: u16) -> Proxy {
    Proxy {
        id: "mesh-hbone".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh HBONE".to_string()),
        api_spec_id: None,
        hosts: vec!["orders.default.svc.cluster.local".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn create_mesh_proxy_state(proxy: Proxy) -> ProxyState {
    create_mesh_proxy_state_with_config(proxy, Vec::new(), Vec::new())
}

fn create_mesh_proxy_state_with_config(
    proxy: Proxy,
    consumers: Vec<Consumer>,
    plugin_configs: Vec<PluginConfig>,
) -> ProxyState {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers,
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
    };
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        ..EnvConfig::default()
    };
    ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

fn create_hmac_consumer(secret: &str) -> Consumer {
    let mut hmac_creds = Map::new();
    hmac_creds.insert("secret".to_string(), Value::String(secret.to_string()));
    let credentials = HashMap::from([(
        "hmac_auth".to_string(),
        Value::Array(vec![Value::Object(hmac_creds)]),
    )]);

    Consumer {
        id: "hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "hmacuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn hmac_auth_plugin_config() -> PluginConfig {
    PluginConfig {
        id: "hmac-auth".to_string(),
        plugin_name: "hmac_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "signing_profile": "ferrum-hmac-v1",
            "allow_unsafe_replayable_v1": true
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Proxy-scoped `spiffe_identity` plugin. The real Ambient/HBONE listener
/// auto-injects `__mesh_spiffe_identity`; these `RequestContext`-level tests
/// build the proxy directly, so they add it explicitly to populate
/// `ctx.peer_spiffe_id` from the verified mTLS peer cert.
fn spiffe_identity_plugin_config(proxy_id: &str) -> PluginConfig {
    PluginConfig {
        id: "spiffe-identity".to_string(),
        plugin_name: "spiffe_identity".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// SPIFFE-shaped cert material for the inbound HBONE mTLS handshake: a CA, a
/// server leaf SVID (with a `127.0.0.1` SAN so rustls accepts the listener),
/// and a client leaf SVID whose URI SAN is the source workload identity that
/// `spiffe_identity` extracts into `ctx.peer_spiffe_id`.
struct HboneMtlsCerts {
    ca_der: rustls::pki_types::CertificateDer<'static>,
    server_cert_der: rustls::pki_types::CertificateDer<'static>,
    server_key_der: rustls::pki_types::PrivateKeyDer<'static>,
    client_cert_der: rustls::pki_types::CertificateDer<'static>,
    client_key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

fn generate_hbone_mtls_certs(client_spiffe: &str) -> HboneMtlsCerts {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
    };

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "hbone-test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let ca_der = ca_cert.der().clone();
    // `Issuer::new` consumes the params + key, so capture the CA DER first.
    let issuer = Issuer::new(ca_params, ca_key);

    // Server leaf: 127.0.0.1 SAN so the test client's rustls IP check passes.
    let server_key = KeyPair::generate().expect("server key");
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).expect("server");
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .expect("server leaf");

    // Client leaf: carries the SPIFFE URI SAN as its identity.
    let client_key = KeyPair::generate().expect("client key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client");
    client_params.subject_alt_names.push(SanType::URI(
        Ia5String::try_from(client_spiffe.to_string()).expect("spiffe uri san"),
    ));
    client_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client leaf");

    HboneMtlsCerts {
        ca_der,
        server_cert_der: server_cert.der().clone(),
        server_key_der: rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der())
            .expect("server key der"),
        client_cert_der: client_cert.der().clone(),
        client_key_der: rustls::pki_types::PrivateKeyDer::try_from(client_key.serialize_der())
            .expect("client key der"),
    }
}

/// Server-side `ServerConfig` for the inbound HBONE listener: requires and
/// verifies a client cert against the test CA and negotiates `h2` via ALPN so
/// the HBONE CONNECT arrives as HTTP/2.
fn hbone_server_config(certs: &HboneMtlsCerts) -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_der.clone()).expect("add ca");
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let mut cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![certs.server_cert_der.clone()],
            certs.server_key_der.clone_key(),
        )
        .expect("server config");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// Client-side `ClientConfig` presenting the SPIFFE client cert. ALPN `h2`.
fn hbone_client_config(certs: &HboneMtlsCerts) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_der.clone()).expect("add ca");
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![certs.client_cert_der.clone()],
            certs.client_key_der.clone_key(),
        )
        .expect("client config");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

async fn start_gateway_mtls(
    state: ProxyState,
    server_config: Arc<rustls::ServerConfig>,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

/// Open an mTLS HTTP/2 connection to the gateway and return the h2 request
/// sender plus the driver task handle.
async fn connect_hbone_h2_mtls(
    gateway_addr: std::net::SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let tcp = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let server_name = rustls::pki_types::ServerName::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
    );
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client tls handshake");
    let (sender, conn) = h2::client::handshake(tls).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);
    (sender, conn_task)
}

async fn start_gateway(state: ProxyState) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

async fn start_echo_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let mut received = Vec::new();
        if stream.read_to_end(&mut received).await.is_ok() {
            let _ = stream.write_all(b"echo:").await;
            let _ = stream.write_all(&received).await;
            let _ = stream.shutdown().await;
        }
    });
    (addr, handle)
}

async fn start_idle_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle backend");
    let addr = listener.local_addr().expect("idle backend local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let mut buf = [0_u8; 16];
        let _ = stream.read(&mut buf).await;
    });
    (addr, handle)
}

/// Accepts a connection, drains anything the client sends, but never writes
/// back. Used to exercise the relay's `backend_read_timeout` (backend→client
/// inactivity). The backend stays alive for the full test, so a stream close
/// observed by the client is from the relay watchdog, not a backend hang-up.
async fn start_quiet_backend() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind quiet backend");
    let addr = listener.local_addr().expect("quiet backend local addr");
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0_u8; 4096];
        tokio::select! {
            _ = stop_rx => {}
            _ = async {
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            } => {}
        }
    });
    (addr, handle, stop_tx)
}

fn mesh_route_dispatch_connect_timeout_plugin(
    proxy_id: &str,
    backend_host: &str,
    backend_port: u16,
    timeout_ms: u64,
) -> PluginConfig {
    PluginConfig {
        id: "mesh-route-dispatch-cfg".to_string(),
        plugin_name: "mesh_route_dispatch".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "rules": [{
                "match": { "methods": ["CONNECT"] },
                "destination": {
                    "backend_host": backend_host,
                    "backend_port": backend_port,
                },
                "timeout_ms": timeout_ms,
            }]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_relays_data_frames_to_tcp_backend() {
    // A real HBONE peer terminates mTLS and presents a SPIFFE client cert, so
    // `spiffe_identity` populates `ctx.peer_spiffe_id` and the relay trust
    // gate admits the tunnel.
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (backend_addr, backend_handle) = start_echo_backend().await;
    let mut proxy = create_mesh_proxy(backend_addr.port());
    let spiffe_plugin = spiffe_identity_plugin_config(&proxy.id);
    proxy.plugins.push(PluginAssociation {
        plugin_config_id: spiffe_plugin.id.clone(),
    });
    let state = create_mesh_proxy_state_with_config(proxy, vec![], vec![spiffe_plugin]);
    let (gateway_addr, shutdown_tx) = start_gateway_mtls(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, mut request_body) = sender.send_request(req, false).expect("send CONNECT");
    request_body
        .send_data(Bytes::from_static(b"mesh-bytes"), true)
        .expect("send CONNECT data");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut response_body = resp.into_body();
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut body = Vec::new();
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk.expect("CONNECT response chunk");
            let _ = response_body.flow_control().release_capacity(chunk.len());
            body.extend_from_slice(&chunk);
        }
        body
    })
    .await
    .expect("collect CONNECT response");
    assert_eq!(&body[..], b"echo:mesh-bytes");

    shutdown_tx.send(true).expect("shutdown gateway");
    backend_handle.await.expect("backend task");
    conn_task.abort();
}

/// Security regression (mesh audit finding #2): a bare HTTP/2 CONNECT with no
/// authenticated mesh peer must NOT be relayed as a transparent HBONE tunnel.
/// Here the gateway listens in plaintext (no mTLS), so `ctx.peer_spiffe_id` is
/// never populated; the relay trust gate rejects the CONNECT with 403 and
/// never dials the backend.
#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_without_authenticated_peer_is_rejected() {
    let (backend_addr, backend_handle) = start_echo_backend().await;
    let state = create_mesh_proxy_state(create_mesh_proxy(backend_addr.port()));
    let (gateway_addr, shutdown_tx) = start_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = h2::client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, _request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "bare CONNECT with no authenticated peer must be rejected, not relayed"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
    // The relay never dials the backend on the rejection path, so the echo
    // backend's `accept()` would hang forever — abort it rather than await.
    backend_handle.abort();
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_with_body_auth_plugin_is_rejected() {
    const HMAC_SECRET: &str = "mesh-hbone-secret-at-least-32-bytes";

    let (backend_addr, backend_handle) = start_echo_backend().await;
    let state = create_mesh_proxy_state_with_config(
        create_mesh_proxy(backend_addr.port()),
        vec![create_hmac_consumer(HMAC_SECRET)],
        vec![hmac_auth_plugin_config()],
    );
    let (gateway_addr, shutdown_tx) = start_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = h2::client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);

    let method = "CONNECT";
    let path = "/";
    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let signature = generate_hmac_signature(
        method,
        path,
        &date,
        "hmacuser",
        "orders.default.svc.cluster.local:8080",
        HMAC_SECRET,
    );
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .header(
            "authorization",
            format!(
                r#"hmac username="hmacuser", algorithm="hmac-sha256", signature="{signature}""#
            ),
        )
        .header("date", date)
        .header("digest", empty_digest_header())
        .body(())
        .expect("connect request");
    let (response_fut, mut request_body) = sender.send_request(req, false).expect("send CONNECT");
    request_body
        .send_data(Bytes::from_static(b"mesh-bytes"), true)
        .expect("send CONNECT data");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    shutdown_tx.send(true).expect("shutdown gateway");
    // PR #1052 changed this test from "auth allows tunnel" to "auth rejects
    // tunnel" → the gateway never dials the backend, so `start_echo_backend`'s
    // `listener.accept()` hangs forever. The previous `backend_handle.await`
    // therefore blocked the test indefinitely (the mesh-platform shard hit
    // the 30-minute GHA job timeout on this exact test). Abort instead —
    // the rejection path is what's under test; the backend's accept loop
    // never running is the *expected* state.
    backend_handle.abort();
    conn_task.abort();
}

/// Regression test for GAP-3H: the standard `before_proxy` chain must run on
/// the outer HBONE CONNECT request so `mesh_route_dispatch` can set route
/// overrides (timeout / retry / backend selection) that flow into the HBONE
/// relay via `apply_route_overrides_with_upstreams` inside
/// `handle_hbone_request`.
///
/// Setup:
/// * Proxy default `backend_read_timeout_ms = 30000` (30s, won't fire in test).
/// * Proxy default `tcp_idle_timeout_seconds = 300` (huge — won't fire).
/// * `mesh_route_dispatch` rule matches `method=CONNECT` and sets
///   `timeout_ms: 500` for the same backend.
/// * Backend accepts the relay and never writes back.
///
/// With the fix, the override lands on `proxy.backend_read_timeout_ms = 500`
/// inside `handle_hbone_request`, the relay's backend→client watchdog fires
/// within ~1.5s, and the H2 stream closes. Without the fix the override is
/// dropped on the HBONE path and the relay stays open until the test bails.
#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_mesh_route_dispatch_override_drives_relay_timeout() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (backend_addr, backend_handle, backend_stop) = start_quiet_backend().await;
    let mut proxy = create_mesh_proxy(backend_addr.port());
    // Defaults that would keep the relay open well past the assertion window
    // — only the route override should be able to trip the watchdog.
    proxy.backend_read_timeout_ms = 30_000;
    proxy.backend_write_timeout_ms = 30_000;
    proxy.tcp_idle_timeout_seconds = Some(300);
    let proxy_id = proxy.id.clone();
    let plugin = mesh_route_dispatch_connect_timeout_plugin(
        &proxy_id,
        "127.0.0.1",
        backend_addr.port(),
        500,
    );
    let spiffe_plugin = spiffe_identity_plugin_config(&proxy_id);
    // Proxy-scoped plugins are wired into the proxy's plugin chain via the
    // association list (see `PluginCache::build_cache`); without this, the
    // route-dispatch plugin would never run.
    proxy.plugins.push(PluginAssociation {
        plugin_config_id: plugin.id.clone(),
    });
    proxy.plugins.push(PluginAssociation {
        plugin_config_id: spiffe_plugin.id.clone(),
    });
    let state = create_mesh_proxy_state_with_config(proxy, vec![], vec![plugin, spiffe_plugin]);
    let (gateway_addr, shutdown_tx) = start_gateway_mtls(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, mut request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);
    // Push at least one byte so the relay is fully wired up; the quiet
    // backend will drain it without responding, exercising the
    // backend→client watchdog rather than the c2b idle path.
    request_body
        .send_data(Bytes::from_static(b"ping"), false)
        .expect("send CONNECT data");

    let mut response_body = resp.into_body();
    // 500ms override + ~1s watchdog tick → close should land well under 4s.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(4), response_body.data())
        .await
        .expect("relay should close once route override timeout fires");
    match closed {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(chunk)) if chunk.is_empty() => {}
        Some(Ok(chunk)) => panic!("unexpected relay data: {chunk:?}"),
    }

    shutdown_tx.send(true).expect("shutdown gateway");
    let _ = backend_stop.send(());
    let _ = backend_handle.await;
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_closes_idle_tunnel() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (backend_addr, backend_handle) = start_idle_backend().await;
    let mut proxy = create_mesh_proxy(backend_addr.port());
    proxy.tcp_idle_timeout_seconds = Some(1);
    proxy.backend_read_timeout_ms = 0;
    proxy.backend_write_timeout_ms = 0;
    let spiffe_plugin = spiffe_identity_plugin_config(&proxy.id);
    proxy.plugins.push(PluginAssociation {
        plugin_config_id: spiffe_plugin.id.clone(),
    });
    let state = create_mesh_proxy_state_with_config(proxy, vec![], vec![spiffe_plugin]);
    let (gateway_addr, shutdown_tx) = start_gateway_mtls(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, _request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut response_body = resp.into_body();
    let idle_close = tokio::time::timeout(std::time::Duration::from_secs(4), response_body.data())
        .await
        .expect("idle tunnel should close");
    match idle_close {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(chunk)) if chunk.is_empty() => {}
        Some(Ok(chunk)) => panic!("idle tunnel returned unexpected data: {chunk:?}"),
    }

    shutdown_tx.send(true).expect("shutdown gateway");
    backend_handle.await.expect("backend task");
    conn_task.abort();
}

// ── EgressGateway external UDP ServiceEntry egress (issue #3263) ──────────

/// Mesh config for an EgressGateway that admits exactly one external UDP
/// destination.
///
/// `workloads` is deliberately EMPTY and the terminator-ownership markers are
/// unset, so the byte-stream open-relay guard
/// (`inbound_hbone_relay_destination_decision`) denies every authority — an
/// EgressGateway terminates for no in-mesh workload (issue #4150). Whatever the
/// relay admits here therefore came from the external UDP allowlist and nothing
/// else.
fn egress_udp_mesh_config(host: &str, port: u16, dial_port: u16) -> MeshConfig {
    egress_udp_mesh_config_with_endpoints(host, port, &[("127.0.0.1", dial_port)])
}

/// Same, but with an explicit dial-endpoint set, so a test can separate the
/// admitted AUTHORITY from the destination the relay actually dials.
fn egress_udp_mesh_config_with_endpoints(
    host: &str,
    port: u16,
    dial_endpoints: &[(&str, u16)],
) -> MeshConfig {
    MeshConfig {
        egress_udp_destinations: vec![MeshEgressUdpDestination {
            host: host.to_string(),
            port,
            dial_endpoints: dial_endpoints
                .iter()
                .map(|(host, port)| MeshEgressUdpDialEndpoint {
                    host: (*host).to_string(),
                    port: *port,
                })
                .collect(),
            service_entry: "external-udp".to_string(),
            namespace: "default".to_string(),
        }],
        ..MeshConfig::default()
    }
}

fn spiffe_identity_global_plugin_config() -> PluginConfig {
    PluginConfig {
        id: "spiffe-identity-global".to_string(),
        plugin_name: "spiffe_identity".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Build an inbound-direction mesh gateway with a static mTLS `ServerConfig`
/// and the supplied mesh block, so `udp`-marked CONNECTs reach the relay
/// synthesis path.
fn create_egress_udp_gateway_state(mesh: MeshConfig) -> ProxyState {
    let spiffe_plugin = spiffe_identity_global_plugin_config();
    let config = GatewayConfig {
        version: "1".to_string(),
        // One unrelated HTTP route keeps the config shaped like a real gateway.
        // It can never serve these CONNECTs: a `udp`-marked CONNECT is forced to
        // a route miss so it always takes the guarded relay-synthesis path.
        proxies: vec![create_mesh_proxy(1)],
        consumers: vec![],
        plugin_configs: vec![spiffe_plugin],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
    };
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        ..EnvConfig::default()
    };
    ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

async fn start_egress_udp_gateway(
    state: ProxyState,
    server_config: Arc<rustls::ServerConfig>,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

/// A stand-in "external" UDP service: echoes `pong:<payload>` back to whoever
/// sent the datagram.
async fn start_external_udp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind external udp echo");
    let addr = socket.local_addr().expect("external udp echo addr");
    let handle = tokio::spawn(async move {
        let mut buf = vec![0_u8; 2048];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let mut reply = b"pong:".to_vec();
            reply.extend_from_slice(&buf[..read]);
            if socket.send_to(&reply, peer).await.is_err() {
                return;
            }
        }
    });
    (addr, handle)
}

/// `[u16 big-endian length][payload]` — the datagram-over-mesh wire framing.
fn frame_datagram(payload: &[u8]) -> Bytes {
    let mut framed = Vec::with_capacity(2 + payload.len());
    framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(payload);
    Bytes::from(framed)
}

/// Read framed bytes off the tunnel until one whole datagram is decoded.
async fn read_framed_datagram(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut buffered: Vec<u8> = Vec::new();
    loop {
        if buffered.len() >= 2 {
            let len = u16::from_be_bytes([buffered[0], buffered[1]]) as usize;
            if buffered.len() >= 2 + len {
                return buffered[2..2 + len].to_vec();
            }
        }
        let chunk = body
            .data()
            .await
            .expect("tunnel closed before a full datagram")
            .expect("tunnel datagram chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        buffered.extend_from_slice(&chunk);
    }
}

fn udp_connect_request(authority: &str) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(authority)
        .header("x-ferrum-mesh-protocol", "udp")
        .body(())
        .expect("udp connect request")
}

/// Live request AND response over an EgressGateway external UDP destination:
/// an authenticated `udp`-marked mesh CONNECT naming an admitted external
/// `host:port` relays the framed datagram to that destination and frames the
/// reply back over the same tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_service_entry_destination_relays_request_and_response() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let (gateway_addr, shutdown_tx) =
        start_egress_udp_gateway(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, mut request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("udp CONNECT response")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    request_body
        .send_data(frame_datagram(b"ping"), false)
        .expect("send framed datagram");

    let mut response_body = resp.into_body();
    let echoed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_framed_datagram(&mut response_body),
    )
    .await
    .expect("external udp reply");
    assert_eq!(echoed, b"pong:ping".to_vec());

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
    conn_task.abort();
}

/// Fail-closed: a `udp`-marked CONNECT naming a destination the ServiceEntry
/// allowlist does not admit is refused before any socket is opened. The
/// admitted destination in this config is a DIFFERENT port on the same host, so
/// nothing but the exact `(host, port)` match can be what admits traffic.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_unadmitted_destination_is_refused() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let admitted_port = external_addr.port().wrapping_add(1).max(1);
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        admitted_port,
        admitted_port,
    ));
    let (gateway_addr, shutdown_tx) =
        start_egress_udp_gateway(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, _request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("udp CONNECT response")
        .expect("udp CONNECT response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "an unadmitted external UDP destination must never open a relay socket"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
    conn_task.abort();
}

/// Fail-closed: an EMPTY allowlist — what every non-EgressGateway topology and
/// every reload that withdrew the ServiceEntry produces — admits nothing, even
/// for a destination that was previously reachable.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_empty_allowlist_admits_nothing() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(MeshConfig::default());
    let (gateway_addr, shutdown_tx) =
        start_egress_udp_gateway(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, _request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("udp CONNECT response")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
    conn_task.abort();
}

/// The relay is authenticated: a `udp`-marked CONNECT to an ADMITTED external
/// destination over a plaintext (non-mTLS) listener carries no peer SPIFFE
/// identity and is rejected 403 before any socket is opened. Admission by the
/// ServiceEntry allowlist never substitutes for peer authentication.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_admitted_destination_still_requires_authenticated_peer() {
    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let gateway_addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            None,
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = h2::client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);

    let (response_fut, _request_body) = sender
        .send_request(
            udp_connect_request(&format!("127.0.0.1:{}", external_addr.port())),
            false,
        )
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("udp CONNECT response")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
    conn_task.abort();
}

// ── SOURCE-side external UDP egress → EgressGateway (issue #3263) ──────────
//
// These drive the ORIGINATOR half: the mesh materializer builds the source's
// captured-UDP route and its identity-pinned gateway upstream, and the very tag
// helpers `mesh_udp_capture`'s session task uses resolve that target into a
// mesh-mTLS datagram tunnel. Only the TPROXY capture socket (which needs root +
// a netns) is stood in for; everything from route materialization through the
// authenticated tunnel, the gateway's allowlist admission, the external
// datagram and the framed reply is real.

fn spiffe_root() -> (Vec<u8>, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "egress-udp-test-root");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let cert = params.self_signed(&key).expect("root cert");
    (cert.der().to_vec(), cert.pem(), key.serialize_pem())
}

fn issue_spiffe_svid(
    spiffe_id: &ferrum_edge::identity::SpiffeId,
    root_pem: &str,
    root_key_pem: &str,
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{
        CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    let issuer_key = KeyPair::from_pem(root_key_pem).expect("issuer key");
    let issuer = Issuer::from_ca_cert_pem(root_pem, issuer_key).expect("issuer");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(ferrum_edge::identity::spiffe::spiffe_id_to_san(spiffe_id).expect("spiffe san"));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = params.signed_by(&leaf_key, &issuer).expect("leaf cert");
    (cert.der().to_vec(), leaf_key.serialize_der())
}

fn spiffe_svid_slot(
    id: &ferrum_edge::identity::SpiffeId,
    root_der: &[u8],
    root_pem: &str,
    root_key_pem: &str,
) -> ferrum_edge::identity::SharedSvidBundle {
    let (leaf, key) = issue_spiffe_svid(id, root_pem, root_key_pem);
    let bundle = ferrum_edge::identity::SvidBundle {
        spiffe_id: id.clone(),
        cert_chain_der: vec![leaf],
        private_key_pkcs8_der: key.into(),
        trust_bundles: ferrum_edge::identity::TrustBundleSet::local_only(
            ferrum_edge::identity::TrustBundle {
                trust_domain: id.trust_domain().clone(),
                x509_authorities: vec![root_der.to_vec()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        ),
    };
    Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(bundle))))
}

/// Materialized source-side view: the captured-datagram route plus the
/// identity-pinned gateway upstream target the datapath dials.
struct SourceSideEgress {
    dest_ip: String,
    port: u16,
    target: ferrum_edge::config::types::UpstreamTarget,
}

/// Run the real mesh materializer for a `Sidecar` source with a configured
/// EgressGateway and return its single external UDP egress route.
fn materialize_source_side_external_udp(
    gateway_addr: std::net::SocketAddr,
    gateway_spiffe: &str,
    service_entry_host: &str,
    endpoint_ip: &str,
    service_port: u16,
) -> Option<SourceSideEgress> {
    use ferrum_edge::modes::mesh::config::{
        AppProtocol, MeshEndpoint, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
    };

    let mesh = MeshConfig {
        service_entries: vec![ServiceEntry {
            name: "external-udp".to_string(),
            namespace: "default".to_string(),
            hosts: vec![service_entry_host.to_string()],
            endpoints: vec![MeshEndpoint {
                address: endpoint_ip.to_string(),
                ports: HashMap::new(),
                labels: HashMap::new(),
                network: None,
            }],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: service_port,
                protocol: AppProtocol::Udp,
                name: Some("udp".to_string()),
                target_port: None,
            }],
            export_to: vec!["*".to_string()],
            workload_selector: None,
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
    };

    let mut runtime = source_sidecar_runtime();
    runtime.egress_gateway = gateway_spiffe.parse().ok().map(|spiffe_id| {
        ferrum_edge::modes::mesh::MeshEgressGatewayEndpoint {
            host: gateway_addr.ip().to_string(),
            port: gateway_addr.port(),
            spiffe_id,
        }
    });

    let prepared = ferrum_edge::modes::mesh::prepare_gateway_config_for_mesh(config, &runtime)
        .expect("source mesh apply");
    let mesh = prepared.mesh.as_deref().expect("prepared mesh block");
    let route = mesh.external_udp_egress_routes.first()?;
    let target = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == route.upstream_id)
        .expect("route upstream materialized")
        .targets
        .first()
        .expect("one gateway target")
        .clone();
    Some(SourceSideEgress {
        dest_ip: route.dest_ip.clone(),
        port: route.port,
        target,
    })
}

fn source_sidecar_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    use ferrum_edge::modes::mesh::{MeshConfigProtocol, MeshRuntimeConfig, MeshTopology};
    MeshRuntimeConfig {
        node_id: "egress-udp-source".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_credential_policy: Default::default(),
        stock_xds_allow_plaintext: false,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
        outbound_listen_addr: "127.0.0.1:15001".parse().unwrap(),
        hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "127.0.0.1:15090".parse().unwrap(),
        egress_gateway: None,
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().unwrap(),
        dns_upstream_addr: "127.0.0.53:53".parse().unwrap(),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: true,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
        locality_lb_strict: false,
    }
}

/// Open the datagram tunnel exactly as `mesh_udp_capture`'s session task does:
/// resolve the mesh-mTLS dial plan off the materialized target's tags, then dial
/// through the shared `MeshMtlsConnectionPool`.
async fn open_source_side_datagram_tunnel(
    pool: &ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool,
    proxy: &Proxy,
    target: &ferrum_edge::config::types::UpstreamTarget,
) -> Result<ferrum_edge::proxy::hbone_pool::H2ConnectTunnel, String> {
    use ferrum_edge::proxy::mesh_mtls_pool::{
        MeshMtlsDialPlan, target_mesh_mtls_authority_host, target_mesh_mtls_dial_host,
        target_mesh_mtls_port,
    };
    let dial_plan = MeshMtlsDialPlan::resolve(target).map_err(|e| e.to_string())?;
    let dial_host = target_mesh_mtls_dial_host(target).map_err(|e| e.to_string())?;
    let authority_host = target_mesh_mtls_authority_host(target).unwrap_or(target.host.as_str());
    pool.open_datagram_tunnel(
        proxy,
        dial_host,
        authority_host,
        target.port,
        target.dispatch_policy_port(),
        target_mesh_mtls_port(target),
        dial_plan.expected_peer.as_ref(),
        dial_plan.expected_trust_domain.as_ref(),
        dial_plan.sni_override,
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Read one framed datagram off a byte-stream tunnel.
async fn read_framed_datagram_from_tunnel<T>(tunnel: &mut T) -> Vec<u8>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    tunnel
        .read_exact(&mut header)
        .await
        .expect("framed datagram header");
    let len = u16::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; len];
    tunnel
        .read_exact(&mut payload)
        .await
        .expect("framed datagram payload");
    payload
}

/// FULL source→gateway→external round trip (issue #3263): the source-side
/// materialized route dials the CONFIGURED EgressGateway over SVID-mTLS pinned
/// to the gateway identity, the gateway admits the CONNECT authority from its
/// ServiceEntry allowlist, relays the framed datagram to the external endpoint,
/// and frames the reply back.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_source_side_route_relays_through_gateway_to_external_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (root_der, root_pem, root_key_pem) = spiffe_root();
    let gateway_id: ferrum_edge::identity::SpiffeId =
        "spiffe://cluster.local/ns/istio-system/sa/ferrum-egress"
            .parse()
            .expect("gateway id");
    let source_id: ferrum_edge::identity::SpiffeId = "spiffe://cluster.local/ns/default/sa/app"
        .parse()
        .expect("source id");
    let gateway_slot = spiffe_svid_slot(&gateway_id, &root_der, &root_pem, &root_key_pem);
    let source_slot = spiffe_svid_slot(&source_id, &root_der, &root_pem, &root_key_pem);

    let (external_addr, external_handle) = start_external_udp_echo().await;
    // The gateway admits the external endpoint IP as an authority derived from
    // that endpoint — exactly what the source names in its CONNECT.
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let server_config = ferrum_edge::tls::spiffe::build_spiffe_inbound_config(
        gateway_slot,
        true,
        Arc::new(Vec::new()),
    )
    .expect("gateway spiffe server config");
    let (gateway_addr, shutdown_tx) = start_egress_udp_gateway(state, server_config).await;

    let source = materialize_source_side_external_udp(
        gateway_addr,
        gateway_id.as_str(),
        "udp-echo.external.test",
        "127.0.0.1",
        external_addr.port(),
    )
    .expect("source-side route materializes");
    assert_eq!(source.dest_ip, "127.0.0.1");
    assert_eq!(source.port, external_addr.port());

    let pool = ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool::new(
        ferrum_edge::config::PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        source_slot,
        4,
    );
    let proxy = create_mesh_proxy(1);
    let mut tunnel = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        open_source_side_datagram_tunnel(&pool, &proxy, &source.target),
    )
    .await
    .expect("datagram tunnel dial")
    .expect("datagram tunnel opens");

    tunnel
        .write_all(&frame_datagram(b"ping"))
        .await
        .expect("write framed datagram");
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_framed_datagram_from_tunnel(&mut tunnel),
    )
    .await
    .expect("framed reply");
    assert_eq!(reply, b"pong:ping".to_vec());

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
}

/// Fail closed: a source whose pinned gateway identity does NOT match the
/// gateway's SVID refuses the dial. Identity is verified, not assumed, and there
/// is no plaintext or direct-dial fallback.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_source_side_refuses_a_gateway_with_the_wrong_identity() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (root_der, root_pem, root_key_pem) = spiffe_root();
    let gateway_id: ferrum_edge::identity::SpiffeId =
        "spiffe://cluster.local/ns/istio-system/sa/ferrum-egress"
            .parse()
            .expect("gateway id");
    let source_id: ferrum_edge::identity::SpiffeId = "spiffe://cluster.local/ns/default/sa/app"
        .parse()
        .expect("source id");
    let gateway_slot = spiffe_svid_slot(&gateway_id, &root_der, &root_pem, &root_key_pem);
    let source_slot = spiffe_svid_slot(&source_id, &root_der, &root_pem, &root_key_pem);

    let (external_addr, external_handle) = start_external_udp_echo().await;
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config(
        "127.0.0.1",
        external_addr.port(),
        external_addr.port(),
    ));
    let server_config = ferrum_edge::tls::spiffe::build_spiffe_inbound_config(
        gateway_slot,
        true,
        Arc::new(Vec::new()),
    )
    .expect("gateway spiffe server config");
    let (gateway_addr, shutdown_tx) = start_egress_udp_gateway(state, server_config).await;

    // Same reachable address, DIFFERENT pinned identity.
    let source = materialize_source_side_external_udp(
        gateway_addr,
        "spiffe://cluster.local/ns/istio-system/sa/impostor",
        "udp-echo.external.test",
        "127.0.0.1",
        external_addr.port(),
    )
    .expect("source-side route materializes");

    let pool = ferrum_edge::proxy::mesh_mtls_pool::MeshMtlsConnectionPool::new(
        ferrum_edge::config::PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        source_slot,
        4,
    );
    let proxy = create_mesh_proxy(1);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        open_source_side_datagram_tunnel(&pool, &proxy, &source.target),
    )
    .await
    .expect("dial completes");
    assert!(
        result.is_err(),
        "a gateway whose SVID does not match the pinned identity must not terminate egress"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
}

/// STATIC endpoint semantics: a CONNECT naming the ServiceEntry HOST relays to
/// the declared endpoint and NEVER DNS-resolves the authority. The host used
/// here does not resolve at all, so any resolution attempt fails the relay.
#[tokio::test(flavor = "multi_thread")]
async fn egress_udp_static_authority_relays_to_endpoint_without_resolving_the_host() {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let (external_addr, external_handle) = start_external_udp_echo().await;
    // Authority = an unresolvable STATIC host; dial endpoint = the echo server.
    let state = create_egress_udp_gateway_state(egress_udp_mesh_config_with_endpoints(
        "static.invalid.test",
        9999,
        &[("127.0.0.1", external_addr.port())],
    ));
    let (gateway_addr, shutdown_tx) =
        start_egress_udp_gateway(state, hbone_server_config(&certs)).await;

    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let (response_fut, mut request_body) = sender
        .send_request(udp_connect_request("static.invalid.test:9999"), false)
        .expect("send udp CONNECT");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("udp CONNECT response")
        .expect("udp CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    request_body
        .send_data(frame_datagram(b"ping"), false)
        .expect("send framed datagram");

    let mut response_body = resp.into_body();
    let echoed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_framed_datagram(&mut response_body),
    )
    .await
    .expect("external udp reply");
    assert_eq!(
        echoed,
        b"pong:ping".to_vec(),
        "a STATIC authority must relay to its declared endpoint, not to a resolved host"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
    external_handle.abort();
    conn_task.abort();
}

// ── Inbound CONNECT terminator ownership guard (issue #4150) ──────────────

/// Workload record for the terminator-ownership tests.
fn relay_guard_workload(service: &str, addresses: &[&str], ports: &[u16]) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{service}"))
            .expect("test SPIFFE id"),
        selector: WorkloadSelector::default(),
        service_name: service.to_string(),
        service_namespace: None,
        addresses: addresses.iter().map(|addr| addr.to_string()).collect(),
        ports: ports
            .iter()
            .map(|port| WorkloadPort {
                port: *port,
                protocol: AppProtocol::Http,
                name: None,
            })
            .collect(),
        trust_domain: TrustDomain::new("cluster.local").expect("test trust domain"),
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// Slice shaped like a Sidecar terminator that runs at `10.244.1.7` in a
/// namespace where `10.244.9.9` is another pod entirely. Sidecar shares the
/// application pod's network namespace, so loopback is an own-namespace shortcut.
fn sidecar_terminator_mesh() -> MeshConfig {
    MeshConfig {
        workloads: vec![
            relay_guard_workload("app", &["10.244.1.7", "fd00:10:244:1::7"], &[8080]),
            relay_guard_workload("neighbour", &["10.244.9.9"], &[8080]),
        ],
        inbound_relay_admits_accepted_local_address: true,
        inbound_relay_admits_loopback_namespace: true,
        // What the apply path projects for an own-pod terminator: the
        // per-address port bound of the record it owns (issue #4249). The
        // own-address / loopback arms read only this.
        inbound_relay_own_address_ports: own_address_port_bounds_from_workloads(&[
            relay_guard_workload("app", &["10.244.1.7", "fd00:10:244:1::7"], &[8080]),
        ]),
        ..MeshConfig::default()
    }
}

/// Ambient terminator at a non-loopback pod IP, with loopback/DNS-localhost
/// also present in inventory. Ambient is node-shared and must not inherit
/// Sidecar's loopback-namespace shortcut.
fn ambient_terminator_mesh() -> MeshConfig {
    MeshConfig {
        workloads: vec![relay_guard_workload(
            "app",
            &["10.244.1.7", "127.0.0.1"],
            &[8080],
        )],
        inbound_relay_destinations: vec![
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Ip(ip("10.244.1.7")),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Ip(ip("127.0.0.1")),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Name("localhost".to_string()),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Name("app.localhost".to_string()),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
        ],
        inbound_relay_admits_accepted_local_address: true,
        // What the apply path projects for an own-pod terminator: the
        // per-address port bound of the record it owns (issue #4249).
        inbound_relay_own_address_ports: own_address_port_bounds_from_workloads(&[
            relay_guard_workload("app", &["10.244.1.7", "127.0.0.1"], &[8080]),
        ]),
        ..MeshConfig::default()
    }
}

fn ip(literal: &str) -> std::net::IpAddr {
    literal.parse().expect("test IP literal")
}

/// A CONNECT naming the address the peer actually reached on this socket is the
/// terminator's own workload, so the transparent relay serves it.
#[test]
fn inbound_relay_admits_the_terminators_own_address() {
    let mesh = sidecar_terminator_mesh();
    let own = Some(ip("10.244.1.7"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, own),
        Ok(())
    );
    // Loopback resolves inside this pod's own network namespace, bounded to the
    // ports this pod declares.
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 8080, own),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 8080, own),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost.", 8080, own),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("app.localhost", 8080, own),
        Ok(())
    );
    // IPv4-mapped loopback is the same namespace: Sidecar admits it only on
    // an owned declared port, never as a stray local listener.
    for host in ["::ffff:127.0.0.1", "[::ffff:127.0.0.1]"] {
        assert_eq!(
            mesh.inbound_relay_destination_decision(host, 8080, own),
            Ok(()),
            "Sidecar must admit mapped-loopback authority {host} on a declared port"
        );
        assert_eq!(
            mesh.inbound_relay_destination_decision(host, 15021, own),
            Err(InboundRelayDenial::PortNotDeclared),
            "Sidecar must still bound mapped-loopback authority {host} to declared ports"
        );
    }
    // A port this pod does not declare is still refused, so a stray local
    // listener is not reachable just because it shares the netns.
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 15021, own),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 15021, own),
        Err(InboundRelayDenial::PortNotDeclared)
    );
}

/// Ambient may admit the accepted socket's non-loopback local destination, but
/// must not inherit Sidecar's own-network-namespace loopback shortcut.
#[test]
fn inbound_relay_ambient_refuses_loopback_namespace() {
    let mesh = ambient_terminator_mesh();
    let own = Some(ip("10.244.1.7"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, own),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 15021, own),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    for host in [
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]",
        "localhost",
        "localhost.",
        "app.localhost",
    ] {
        assert_eq!(
            mesh.inbound_relay_destination_decision(host, 8080, own),
            Err(InboundRelayDenial::AddressNotTerminated),
            "Ambient must refuse loopback-namespace authority {host} even when inventory-listed"
        );
    }
}

/// IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) must be classified as the
/// loopback namespace before accepted-local-address or inventory matching.
/// `IpAddr::is_loopback()` is false for that form; later `to_canonical()`
/// would otherwise match a `127.0.0.1` inventory entry and bypass the
/// Sidecar-only loopback refusal.
#[test]
fn inbound_relay_mapped_ipv4_loopback_does_not_fall_through_to_inventory() {
    let mapped = ["::ffff:127.0.0.1", "[::ffff:127.0.0.1]"];
    let own = Some(ip("10.244.1.7"));

    let ambient = ambient_terminator_mesh();
    for host in mapped {
        assert_eq!(
            ambient.inbound_relay_destination_decision(host, 8080, own),
            Err(InboundRelayDenial::AddressNotTerminated),
            "Ambient must refuse mapped-loopback {host} even when inventory lists 127.0.0.1"
        );
    }

    // Waypoint / gateway topologies leave both privilege flags false (the
    // MeshConfig default). Inventory listing canonical loopback still cannot
    // admit the mapped spelling.
    let gateway = MeshConfig {
        inbound_relay_destinations: inbound_relay_destinations_from_workloads(&[
            relay_guard_workload("loopback-app", &["127.0.0.1"], &[8080]),
        ]),
        ..MeshConfig::default()
    };
    assert!(!gateway.inbound_relay_admits_accepted_local_address);
    assert!(!gateway.inbound_relay_admits_loopback_namespace);
    for host in mapped {
        assert_eq!(
            gateway.inbound_relay_destination_decision(host, 8080, own),
            Err(InboundRelayDenial::AddressNotTerminated),
            "waypoint/gateway default-false must refuse mapped-loopback authority {host}"
        );
    }
}

/// The issue #4150 fix: another workload the SLICE declares is not a
/// destination this proxy terminates for. Relaying there would dial that pod in
/// plaintext from this pod's IP and skip its own AuthorizationPolicy set.
#[test]
fn inbound_relay_refuses_a_different_slice_declared_workload() {
    let mesh = sidecar_terminator_mesh();
    let own = Some(ip("10.244.1.7"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, own),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    // Not even when the peer omits/loses the socket proof entirely.
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, None),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    // And an address nothing declares stays refused, as before.
    assert_eq!(
        mesh.inbound_relay_destination_decision("203.0.113.10", 8080, own),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
}

/// IPv4 / IPv6 equivalence is decided on the CANONICAL address, so the two
/// spellings of one address never disagree — an IPv4-mapped authority is the
/// same destination as its IPv4 form, while a genuinely different IPv6 address
/// is a different destination.
#[test]
fn inbound_relay_folds_ipv4_mapped_ipv6_to_one_decision() {
    let mesh = sidecar_terminator_mesh();
    let own_v4 = Some(ip("10.244.1.7"));
    let own_mapped = Some(ip("::ffff:10.244.1.7"));
    let own_v6 = Some(ip("fd00:10:244:1::7"));

    let mapped_authority =
        mesh.inbound_relay_destination_decision("[::ffff:10.244.1.7]", 8080, own_v4);
    assert_eq!(mapped_authority, Ok(()));
    let mapped_socket = mesh.inbound_relay_destination_decision("10.244.1.7", 8080, own_mapped);
    assert_eq!(mapped_socket, Ok(()));
    // The pod's IPv6 address is admitted on an IPv6 socket, in any spelling.
    let expanded = mesh.inbound_relay_destination_decision("[fd00:10:244:1:0:0:0:7]", 8080, own_v6);
    assert_eq!(expanded, Ok(()));
    // A distinct IPv6 address is a distinct destination, not an alias.
    assert_eq!(
        mesh.inbound_relay_destination_decision("[fd00:10:244:1::99]", 8080, own_v6),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    // A bracketed IPv4 literal is not a valid authority host at all.
    assert_eq!(
        mesh.inbound_relay_destination_decision("[10.244.1.7]", 8080, own_v4),
        Err(InboundRelayDenial::UnresolvableHost)
    );
}

/// NodeWaypoint / ServiceWaypoint terminate for OTHER workloads by design, and
/// only for the ones in their narrow inventory. They run outside those pods'
/// network namespaces, so they get no own-namespace loopback shortcut and
/// their own address is never a relay destination.
#[test]
fn inbound_relay_admits_only_the_waypoint_termination_inventory() {
    let mesh = MeshConfig {
        // A workload the slice knows but this waypoint does NOT terminate for.
        workloads: vec![relay_guard_workload("elsewhere", &["10.244.9.9"], &[8080])],
        inbound_relay_destinations: inbound_relay_destinations_from_workloads(&[
            relay_guard_workload("enrolled", &["10.244.2.9"], &[8080]),
            relay_guard_workload("portless", &["10.244.2.10"], &[]),
        ]),
        ..MeshConfig::default()
    };
    let waypoint = Some(ip("10.244.4.4"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 8080, waypoint),
        Ok(())
    );
    // A record declaring no ports does not constrain its address.
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.10", 6379, waypoint),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 9999, waypoint),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.4.4", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );

    // Inventory data cannot make the waypoint/host network namespace's
    // loopback address into a workload termination target.
    let loopback_mesh = MeshConfig {
        inbound_relay_destinations: inbound_relay_destinations_from_workloads(&[
            relay_guard_workload("loopback-app", &["127.0.0.1"], &[8080]),
        ]),
        ..MeshConfig::default()
    };
    for host in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]"] {
        assert_eq!(
            loopback_mesh.inbound_relay_destination_decision(host, 8080, waypoint),
            Err(InboundRelayDenial::AddressNotTerminated),
            "waypoint must refuse loopback-namespace authority {host} even when inventory-listed"
        );
    }

    let localhost_namespace_mesh = MeshConfig {
        inbound_relay_destinations: vec![
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Name("localhost.".to_string()),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
            MeshInboundRelayDestination {
                host: MeshInboundRelayHost::Name("app.localhost".to_string()),
                ports: vec![8080],
                enrollment: Default::default(),
                registry_uncontested: true,
            },
        ],
        ..MeshConfig::default()
    };
    for host in ["localhost.", "LocalHost", "app.localhost", "APP.Localhost"] {
        assert_eq!(
            localhost_namespace_mesh.inbound_relay_destination_decision(host, 8080, waypoint),
            Err(InboundRelayDenial::AddressNotTerminated),
            "waypoint must refuse loopback-namespace authority {host} even when inventory-listed"
        );
    }
}

fn screen_resolved(
    mesh: &MeshConfig,
    ips: &[&str],
) -> Result<Option<Vec<std::net::IpAddr>>, InboundRelayDenial> {
    mesh.screen_inbound_relay_resolved_ips(ips.iter().copied().map(ip))
}

#[test]
fn inbound_relay_resolved_ip_loopback_namespace_uses_canonical_semantics() {
    for loopback in [
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:127.255.255.255",
    ] {
        assert!(
            inbound_relay_resolved_ip_is_loopback_namespace(ip(loopback)),
            "{loopback} is in the loopback namespace after canonicalization"
        );
    }
    for safe in [
        "10.244.2.9",
        "::ffff:10.244.2.9",
        "192.0.2.10",
        "2001:db8::9",
    ] {
        assert!(
            !inbound_relay_resolved_ip_is_loopback_namespace(ip(safe)),
            "{safe} must remain eligible"
        );
    }
}

/// After a declared hostname is admitted by name, DNS answers that land in the
/// loopback namespace must still be refused on topologies that do not share the
/// destination pod's network namespace.
#[test]
fn inbound_relay_resolved_candidates_refuse_loopback_outside_sidecar() {
    let ambient = ambient_terminator_mesh();
    let node_waypoint = MeshConfig {
        inbound_relay_destinations: inbound_relay_destinations_from_workloads(&[
            relay_guard_workload("enrolled-host", &["workload.internal.example"], &[8080]),
        ]),
        ..MeshConfig::default()
    };
    let service_waypoint = MeshConfig {
        inbound_relay_destinations: inbound_relay_destinations_from_workloads(&[
            relay_guard_workload("bound-host", &["reviews.default.svc"], &[9080]),
        ]),
        ..MeshConfig::default()
    };
    assert!(!ambient.inbound_relay_admits_loopback_namespace);
    assert!(!node_waypoint.inbound_relay_admits_loopback_namespace);
    assert!(!service_waypoint.inbound_relay_admits_loopback_namespace);

    for (label, mesh) in [
        ("Ambient", &ambient),
        ("NodeWaypoint", &node_waypoint),
        ("ServiceWaypoint", &service_waypoint),
    ] {
        for loopback in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:127.255.255.255",
        ] {
            assert_eq!(
                screen_resolved(mesh, &[loopback]),
                Err(InboundRelayDenial::AddressNotTerminated),
                "{label} must refuse resolved loopback {loopback} before dial"
            );
        }
        assert_eq!(
            screen_resolved(mesh, &["10.244.2.9", "2001:db8::9"]),
            Ok(None),
            "{label} must leave an all-safe answer set unchanged"
        );
        assert_eq!(
            screen_resolved(
                mesh,
                &[
                    "127.0.0.1",
                    "10.244.2.9",
                    "::1",
                    "::ffff:127.0.0.1",
                    "192.0.2.10",
                ],
            ),
            Ok(Some(vec![ip("10.244.2.9"), ip("192.0.2.10")])),
            "{label} mixed DNS answers must retain only non-loopback candidates, in order"
        );
        assert_eq!(
            screen_resolved(mesh, &["127.0.0.1", "::1", "::ffff:127.0.0.1"]),
            Err(InboundRelayDenial::AddressNotTerminated),
            "{label} all-loopback DNS answers must fail closed before dial"
        );
    }
}

/// Sidecar shares the pod network namespace, so ordinary relay may still dial
/// resolved loopback on a declared application port.
#[test]
fn inbound_relay_resolved_candidates_sidecar_retains_loopback() {
    let mesh = sidecar_terminator_mesh();
    assert!(mesh.inbound_relay_admits_loopback_namespace);
    assert_eq!(
        screen_resolved(
            &mesh,
            &["127.0.0.1", "::1", "::ffff:127.0.0.1", "10.244.1.7"],
        ),
        Ok(None),
        "Sidecar ordinary relay must not drop resolved loopback"
    );
}

/// Sidecar `ingress[]` remaps to a validated loopback defaultEndpoint remain a
/// distinct path from ordinary-relay candidate screening.
#[test]
fn inbound_relay_ingress_remap_loopback_endpoint_is_still_the_declared_mapping() {
    let mesh = MeshConfig {
        local_ingress_listeners: vec![ResolvedIngressListener {
            port: 16379,
            endpoint_host: "127.0.0.1".to_string(),
            endpoint_port: 6379,
            protocol: AppProtocol::Redis,
            endpoint_unix_path: None,
            endpoint_unix_h2c: false,
            owner_namespace: "default".to_string(),
            owner_service: "redis".to_string(),
            bind: None,
        }],
        sidecar_ingress_declared: true,
        local_workload_addresses: vec![ip("10.244.1.7")],
        inbound_relay_admits_loopback_namespace: true,
        ..MeshConfig::default()
    };
    assert!(mesh.sidecar_ingress_connect_relay_endpoint_matches(16379, "127.0.0.1", 6379));
    assert!(!mesh.sidecar_ingress_connect_relay_endpoint_matches(16379, "127.0.0.1", 8080));
    assert_eq!(
        screen_resolved(&mesh, &["127.0.0.1"]),
        Ok(None),
        "ingress remap topologies keep Sidecar loopback privilege on ordinary answers"
    );
}

/// Brace-match one item from `src` starting at `signature`. Strings are skipped
/// so a `{` inside a format/error body cannot close the function early.
fn rust_fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("missing `{signature}`"));
    let after_sig = &src[start..];
    let brace_off = after_sig
        .find('{')
        .unwrap_or_else(|| panic!("`{signature}` has no opening brace"));
    let body = &after_sig[brace_off..];
    let mut depth = 0i32;
    let mut in_string = false;
    let mut prev = '\0';
    for (i, ch) in body.char_indices() {
        if in_string {
            if ch == '"' && prev != '\\' {
                in_string = false;
            }
            prev = ch;
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[..=i];
                }
            }
            _ => {}
        }
        prev = ch;
    }
    panic!("unclosed `{signature}`");
}

fn collapsed_tokens(src: &str) -> String {
    src.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Match `callee(arg, …)` after whitespace collapsing, with or without a
/// rustfmt trailing comma. Do not require a particular line break shape.
fn contains_call(collapsed: &str, callee: &str, args: &[&str]) -> bool {
    let joined = args.join(", ");
    [
        format!("{callee}( {joined} )"),
        format!("{callee}( {joined}, )"),
        format!("{callee}({joined})"),
        format!("{callee}({joined},)"),
    ]
    .into_iter()
    .any(|pattern| collapsed.contains(&pattern))
}

/// TCP (`connect_backend`) and UDP (`handle_hbone_udp_request`) must both
/// invoke the shared candidate screen; the EgressGateway external-UDP path
/// must skip it. Live DNS is nondeterministic, so this is a source contract
/// over the concrete helper rather than a live resolver.
#[test]
fn inbound_relay_resolved_loopback_screen_is_wired_on_tcp_and_udp_dial_paths() {
    let src = include_str!("../../src/proxy/hbone_proxy.rs");
    let helper = "screen_ordinary_inbound_hbone_relay_dns_candidates";
    let file = collapsed_tokens(src);
    assert_eq!(
        file.matches(helper).count(),
        3,
        "helper definition plus TCP and UDP call sites"
    );

    let tcp = collapsed_tokens(rust_fn_body(src, "async fn connect_backend("));
    assert!(
        contains_call(&tcp, helper, &["proxy", "mesh", "candidates"]),
        "byte-stream connect_backend must screen resolved candidates before dial"
    );
    let tcp_screen = tcp
        .find(helper)
        .expect("connect_backend must name the shared screen");
    let tcp_dial = tcp
        .find("connect_candidates")
        .expect("connect_backend must still dial screened candidates");
    assert!(
        tcp_screen < tcp_dial,
        "loopback screening must run before the TCP candidate dial"
    );

    let udp = collapsed_tokens(rust_fn_body(
        src,
        "pub(super) async fn handle_hbone_udp_request(",
    ));
    assert!(
        udp.contains("if external_egress_allowed { dest_candidates } else { match"),
        "local UDP relay must screen resolved candidates; external UDP egress must not"
    );
    assert!(
        contains_call(&udp, helper, &["proxy", "mesh_config", "dest_candidates"],),
        "datagram CONNECT must screen dest_candidates on the ordinary local-relay path"
    );

    let helper_body = collapsed_tokens(rust_fn_body(
        src,
        "fn screen_ordinary_inbound_hbone_relay_dns_candidates(",
    ));
    assert!(
        helper_body.contains(
            "if proxy.id != MESH_INBOUND_HBONE_RELAY_PROXY_ID { return Ok(candidates); }"
        ),
        "screening must stay on the ordinary inbound relay, not ingress remap or other HBONE backends"
    );
}

/// A gateway-side HBONE DNS-screen 403 after `check_circuit_breaker` admitted a
/// HALF_OPEN probe must release that slot without changing backend health.
/// Real connection failures still trip the breaker.
#[test]
fn inbound_hbone_dns_screen_denial_releases_half_open_probe_without_tripping() {
    use ferrum_edge::_test_support::settle_hbone_backend_connect_circuit_breaker_outcome_for_test;
    use ferrum_edge::circuit_breaker::CircuitBreaker;

    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500, 502, 503],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    cb.record_failure(503, true, false);
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);

    settle_hbone_backend_connect_circuit_breaker_outcome_for_test(&cb, StatusCode::FORBIDDEN, true);
    assert_eq!(
        cb.state_name(),
        "half_open",
        "DNS-screen 403 must not reopen the breaker"
    );
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "DNS-screen 403 must release the HALF_OPEN probe slot"
    );
    assert!(
        cb.can_execute().is_ok(),
        "after a health-neutral denial the next probe must still be admissible"
    );
    assert_eq!(cb.half_open_in_flight(), 1);

    settle_hbone_backend_connect_circuit_breaker_outcome_for_test(
        &cb,
        StatusCode::BAD_GATEWAY,
        true,
    );
    assert_eq!(
        cb.state_name(),
        "open",
        "a real HBONE connect failure must still trip the breaker"
    );
    assert_eq!(cb.half_open_in_flight(), 0);
}

/// The byte-stream CONNECT error arm must settle the selected-target breaker
/// through the production helper: FORBIDDEN (DNS-screen policy) is neutral,
/// every other connect failure is a failure. Double-settlement is forbidden.
#[test]
fn inbound_hbone_dns_screen_denial_settles_half_open_via_production_helper() {
    let src = include_str!("../../src/proxy/hbone_proxy.rs");
    let collapsed: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains(
            "settle_hbone_backend_connect_circuit_breaker_outcome( &cb, err.status, cb_is_half_open_probe, );"
        ),
        "connect_backend error arm must settle the same selected-target breaker"
    );
    assert_eq!(
        collapsed
            .matches("settle_hbone_backend_connect_circuit_breaker_outcome")
            .count(),
        2,
        "helper definition plus the one connect_backend error-arm call site"
    );
    assert!(
        collapsed.contains(
            "if status == StatusCode::FORBIDDEN { cb.record_neutral(is_half_open_probe); } else { cb.record_failure(status.as_u16(), true, is_half_open_probe); }"
        ),
        "FORBIDDEN DNS-screen denials must record_neutral; other connect failures record_failure"
    );
    let connect_err_arm = collapsed
        .split("\"HBONE backend connection failed\"")
        .nth(1)
        .expect("connect_backend error logging")
        .split("ctx.metadata.insert( \"error_class\"")
        .next()
        .expect("error_class metadata after breaker settlement");
    assert!(
        !connect_err_arm.contains("record_failure") && !connect_err_arm.contains("record_neutral"),
        "the connect error arm must not double-settle beside the helper"
    );
}

/// Mixed-answer filtering must keep the iterator's rotated dial order; an
/// all-safe set must return `Ok(None)` so the caller dials the original
/// answer set without allocating a filtered Vec.
#[test]
fn inbound_relay_resolved_candidates_all_safe_returns_none_without_filtering() {
    let mesh = ambient_terminator_mesh();
    assert_eq!(
        screen_resolved(&mesh, &["10.244.2.9"]),
        Ok(None),
        "a single safe answer must be allocation-free Ok(None)"
    );
    assert_eq!(
        screen_resolved(&mesh, &["::ffff:10.244.2.9", "192.0.2.10", "2001:db8::9"]),
        Ok(None),
        "canonical IPv4-mapped non-loopback answers are safe and must not allocate"
    );
    assert_eq!(
        screen_resolved(
            &mesh,
            &[
                "10.244.2.9",
                "::ffff:127.0.0.1",
                "192.0.2.10",
                "127.1.2.3",
                "2001:db8::9",
            ],
        ),
        Ok(Some(vec![
            ip("10.244.2.9"),
            ip("192.0.2.10"),
            ip("2001:db8::9"),
        ])),
        "mixed answers must retain only safe candidates in original dial order"
    );
}

// ── Termination inventory is per-OWNER, not per-identity (issues #4249/#4251) ─

/// Prepare a serving snapshot from `slice` and hand back its mesh block.
fn prepared_mesh(slice: &MeshSlice, runtime: &MeshRuntimeConfig) -> Box<MeshConfig> {
    prepare_gateway_config_from_mesh_slice(slice, runtime)
        .expect("slice → config")
        .mesh
        .expect("prepared mesh")
}

/// Issue #4249: a shared SPIFFE id is a service-account identity, not
/// ownership. The `Sidecar` / `Ambient` termination inventory is built with the
/// same LOCAL-workload predicate the slice builder uses, so a same-identity
/// record the slice places in another CLUSTER — or one carrying labels this
/// workload does not have, i.e. a sibling replica on another node — is not a
/// destination this proxy terminates for.
#[test]
fn inbound_relay_own_identity_inventory_requires_cluster_and_label_locality() {
    let own_spiffe = format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{DEFAULT_NAMESPACE}/sa/reviews");

    let mut own = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.5.5"],
    );
    own.cluster = Some("cluster-a".to_string());
    // Same SPIFFE, remote cluster: `tag_remote_workloads` preserves a remote
    // endpoint's identity, so an identity-only filter admits it and would dial
    // it in plaintext, bypassing the east-west gateway's inner mTLS.
    let mut remote_replica = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.7.7"],
    );
    remote_replica.cluster = Some("cluster-b".to_string());
    // Same SPIFFE and cluster, labels this workload does not carry.
    let mut label_mismatch = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews"), ("version", "canary")],
        ["10.244.8.8"],
    );
    label_mismatch.cluster = Some("cluster-a".to_string());

    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        version: "test".to_string(),
        workloads: vec![own, remote_replica, label_mismatch],
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            ..MultiClusterConfig::default()
        }),
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::Ambient,
        workload_spiffe_id: Some(own_spiffe),
        workload_labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        ..default_mesh_runtime()
    };

    let mesh = prepared_mesh(&slice, &runtime);
    // A ztunnel-style proxy's socket address is the node, not a workload, so
    // nothing below rides in on the own-address arm.
    let node = Some(ip("10.244.0.1"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "this proxy's own local workload record stays a termination destination"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.7.7", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a same-identity record in another cluster must not be an own-pod destination"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.8.8", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a same-identity sibling whose labels this workload does not carry must be refused"
    );
}

/// Issue #4249: several workload records can legitimately declare ONE address —
/// `hostNetwork` pods all declare the node IP — so the own-address arm and the
/// own-namespace loopback shortcut take their port bound from the records this
/// terminator OWNS. A co-located pod's app port must not become reachable
/// through this proxy just because it shares the address.
#[test]
fn inbound_relay_own_address_port_bound_excludes_co_located_workloads() {
    let own_spiffe = format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{DEFAULT_NAMESPACE}/sa/reviews");

    // Both records declare the shared (host-network) address; only the first is
    // this terminator's own, and it serves 8080 only.
    let own = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.5.5"],
    );
    let mut co_located = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings")],
        ["10.244.5.5"],
    );
    co_located.ports = vec![WorkloadPort {
        port: 9443,
        protocol: AppProtocol::Http,
        name: Some("admin".to_string()),
    }];

    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        version: "test".to_string(),
        workloads: vec![own, co_located],
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::Sidecar,
        workload_spiffe_id: Some(own_spiffe),
        ..default_mesh_runtime()
    };

    let mesh = prepared_mesh(&slice, &runtime);
    // The peer reached this pod at the shared address on this socket.
    let own_ip = Some(ip("10.244.5.5"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, own_ip),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "a co-located workload's port must not widen the own-address bound"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 8080, own_ip),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "the own-namespace loopback shortcut is bounded by the same owned records"
    );
}

/// The pod UIDs the node-agent registry keys these fixtures by. Real registry
/// keys are Kubernetes `metadata.uid` values; the guard only compares them.
const LOCAL_POD_UID: &str = "5a3c2f4e-0c11-4b2c-9c3a-000000000001";
const OTHER_POD_UID: &str = "5a3c2f4e-0c11-4b2c-9c3a-000000000002";

/// Publish `entries` into a fresh node-local enrolled-pod index and bind it to
/// `mesh` exactly as the mesh serving runtime's registry poller does, returning
/// the index so a test can re-publish (pod churn) or retract it.
fn bind_enrolled_registry(
    mesh: &mut MeshConfig,
    entries: &[EnrolledPodEntry],
) -> Arc<NodeLocalEnrolledDestinations> {
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    index.publish(entries);
    let handle = NodeLocalEnrolledDestinationsHandle::new(index.clone());
    mesh.inbound_relay_node_local_registry = handle;
    index
}

fn enrolled(pod_uid: &str, identity: &str, address: &str) -> EnrolledPodEntry {
    EnrolledPodEntry {
        pod_uid: pod_uid.to_string(),
        identity: Some(identity.to_string()),
        addresses: vec![ip(address)],
    }
}

fn write_strict_registry_entry(dir: &std::path::Path, pod_uid: &str, ipv4: &str, spiffe: &str) {
    std::fs::write(
        dir.join(pod_uid),
        format!("/sys/fs/cgroup/kubepods/{pod_uid}\nspiffe_id={spiffe}\nipv4={ipv4}\n"),
    )
    .expect("strict registry entry");
}

fn strict_registry_manager(
    source: Arc<dyn PodCaptureSource>,
    index: Arc<NodeLocalEnrolledDestinations>,
) -> NodeLocalEnrolledDestinationsManager {
    NodeLocalEnrolledDestinationsManager::new(source, index, std::time::Duration::from_secs(2))
}

fn reviews_spiffe() -> String {
    format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{DEFAULT_NAMESPACE}/sa/reviews")
}

/// One Ambient slice carrying `workloads`, all in the local cluster.
fn ambient_relay_fixture(workloads: Vec<Workload>) -> (MeshSlice, MeshRuntimeConfig) {
    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        version: "test".to_string(),
        workloads,
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            ..MultiClusterConfig::default()
        }),
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::Ambient,
        workload_spiffe_id: Some(reviews_spiffe()),
        workload_labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        ..default_mesh_runtime()
    };
    (slice, runtime)
}

/// A `reviews` replica in the local cluster carrying the shared pod-template
/// labels — the shape `workload_is_local` cannot tell apart.
fn reviews_replica(pod_address: &'static str, pod_uid: &str) -> Workload {
    let mut workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        [pod_address],
    );
    workload.cluster = Some("cluster-a".to_string());
    workload.pod_uid = Some(pod_uid.to_string());
    workload
}

/// Issue #4249, the residual this closes: two replicas of ONE Deployment share
/// a service-account SPIFFE id, a cluster, AND their pod-template labels while
/// running on different nodes. `workload_is_local` compares exactly those three
/// facts, so it admits the off-node sibling — the assertion below states that
/// explicitly rather than assuming it.
///
/// The node bound is the node-agent's enrolled-pod registry. Once it is
/// authoritative only the replica this node actually enrols is a destination;
/// the identical sibling is refused `AddressNotTerminated`, with no per-entry
/// fallback to identity matching.
#[test]
fn inbound_relay_ambient_registry_refuses_same_identity_sibling_on_another_node() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    // Byte-for-byte the same identity, cluster and labels. Only the pod — and
    // the node whose agent enrols it — differs.
    let off_node_sibling = reviews_replica("10.244.9.9", OTHER_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local, off_node_sibling]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    // A ztunnel-style proxy's socket address is the node, not a workload, so
    // nothing below rides in on the own-address arm.
    let node = Some(ip("10.244.0.1"));

    // With no registry configured the identity/cluster/label predicate is the
    // only bound, and it admits BOTH replicas. That is the documented
    // no-registry fallback AND the exact gap #4249 tracks.
    assert!(
        !mesh.inbound_relay_node_local_registry.is_authoritative(),
        "a config prepared outside a serving mesh runtime carries no registry"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, node),
        Ok(()),
        "identity + cluster + labels alone do NOT exclude a same-workload replica \
         on another node; the node bound has to come from somewhere else"
    );

    // Bind the node-agent's registry: this node enrols the local replica only.
    let enrollment = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &enrollment);

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "the replica this node's agent actually enrols stays a termination destination"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a same-cluster, same-SPIFFE, same-label sibling this node does not enrol \
         must be refused, not fall back to identity matching"
    );
}

/// Issue #4249: an ENROLLED address is not enough on its own — the enrolled pod
/// must be the one the slice record names. A pod address recycled onto another
/// pod (the ABA case the registry key exists to catch), or enrolled under
/// another attested identity, is refused.
#[test]
fn inbound_relay_ambient_registry_binds_admission_to_the_enrolled_pod() {
    let own_spiffe = reviews_spiffe();
    let ratings_spiffe =
        format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{DEFAULT_NAMESPACE}/sa/ratings");
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    // The address is enrolled, but by a DIFFERENT pod than the slice names.
    let recycled = [enrolled(OTHER_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &recycled);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an enrolled address owned by another pod UID is not this record's destination"
    );

    // Same pod UID, attested by the node-agent under another workload identity.
    let misattested = [enrolled(LOCAL_POD_UID, &ratings_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &misattested);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an enrolled pod attested under another identity is not this record's destination"
    );

    // The matching enrollment admits.
    let matching = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &matching);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
}

/// Issue #4249: registry churn must remove admission within the poller's own
/// bounded lifecycle, never leave a stale fail-open entry. A withdrawn pod
/// stops being a destination on the next published generation, and a retracted
/// index (shutdown, aborted poller) vouches for nothing at all. The mesh slice
/// is unchanged throughout.
#[test]
fn inbound_relay_ambient_registry_withdrawal_removes_admission() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    let enrollment = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    let index = bind_enrolled_registry(&mut mesh, &enrollment);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    // The node-agent withdrew the pod; the next published generation stops
    // admitting it.
    index.publish(&[]);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a withdrawn pod must leave the admitted set with the registry generation, \
         not at the next mesh apply"
    );

    // A re-enrolled pod is admitted again; a retracted index refuses.
    index.publish(&enrollment);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    index.clear();
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a retracted index vouches for nothing; it must not fall back to the slice view"
    );
}

/// Issue #4249: an address two DIFFERENT enrolled pods claim is ambiguous and
/// is refused for both, mirroring the contested-interface rule the host-UDP
/// planner already applies. The registry cannot say which pod owns it, and
/// guessing would relay to one pod under the other's enrollment.
#[test]
fn inbound_relay_ambient_registry_refuses_a_contested_enrolled_address() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    let contested = [
        enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5"),
        enrolled(OTHER_POD_UID, &own_spiffe, "10.244.5.5"),
    ];
    bind_enrolled_registry(&mut mesh, &contested);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an address claimed by two enrolled pods must be refused for both"
    );
}

/// Issue #4249: while the registry is authoritative a DECLARED NAME is refused
/// outright. The guard never resolves a name, and whatever address a dial would
/// resolve it to is selected AFTER this decision — DNS may answer with an
/// off-node sibling, or with anything else — so no evidence checked here would
/// still bind the socket. Admitting a name because some record sharing it
/// declares an enrolled address is exactly the union this must not perform.
#[test]
fn inbound_relay_ambient_registry_refuses_declared_name_destinations() {
    let own_spiffe = reviews_spiffe();

    // A workload declared ONLY by DNS name — the `ServiceEntry`/`WorkloadEntry`
    // /VM shape node-local enrollment cannot express.
    let named_only = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["enrolled-echo.live.ferrum.test"],
    );
    // A record sharing that same name while ALSO declaring the enrolled pod
    // address. Merging the two and admitting the name because this one is
    // enrolled would make the name relayable even though DNS may resolve it to
    // the other record's (unenrolled, possibly off-node) pod.
    let mut named_and_enrolled = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["enrolled-echo.live.ferrum.test", "10.244.5.5"],
    );
    named_and_enrolled.pod_uid = Some(LOCAL_POD_UID.to_string());
    named_and_enrolled.cluster = Some("cluster-a".to_string());
    let (slice, runtime) = ambient_relay_fixture(vec![named_only, named_and_enrolled]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    let named = "enrolled-echo.live.ferrum.test";
    // Before the registry is bound the name is admitted on the identity /
    // locality bound alone — the documented no-registry fallback.
    assert!(!mesh.inbound_relay_node_local_registry.is_authoritative());
    assert_eq!(
        mesh.inbound_relay_destination_decision(named, 8080, node),
        Ok(())
    );

    let enrollment = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &enrollment);

    assert_eq!(
        mesh.inbound_relay_destination_decision(named, 8080, node),
        Err(InboundRelayDenial::UnresolvableHost),
        "an authoritative registry must refuse a declared name outright, even when a \
         record sharing that name declares an address this node does enrol"
    );
    // The enrolled ADDRESS itself stays relayable: refusing the name is not a
    // refusal of the pod.
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
}

/// Issue #4249: several workload records can declare ONE address while
/// belonging to DIFFERENT pods (`hostNetwork` pods all declare the node IP).
/// While the registry is authoritative each record is judged on its OWN pod
/// UID against the enrolled owner, so the sibling's ports are refused without
/// also refusing the enrolled pod. Absent pod-UID evidence is the case the
/// registry cannot separate; that is covered by
/// `inbound_relay_ambient_registry_refuses_uidless_record_contesting_enrolled_address`.
#[test]
fn inbound_relay_ambient_registry_separates_shared_address_claimed_by_different_pods() {
    let own_spiffe = reviews_spiffe();

    let mut enrolled_pod = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    enrolled_pod.ports = vec![WorkloadPort {
        port: 8080,
        protocol: AppProtocol::Http,
        name: Some("http".to_string()),
    }];
    // Same declared address, same SPIFFE / cluster / labels, DIFFERENT pod —
    // and a port the enrolled pod does not serve.
    let mut unenrolled_sibling = reviews_replica("10.244.5.5", OTHER_POD_UID);
    unenrolled_sibling.ports = vec![WorkloadPort {
        port: 9443,
        protocol: AppProtocol::Http,
        name: Some("admin".to_string()),
    }];
    let (slice, runtime) = ambient_relay_fixture(vec![enrolled_pod, unenrolled_sibling]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    assert!(!mesh.inbound_relay_node_local_registry.is_authoritative());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, node),
        Ok(()),
        "without a registry, the documented identity/locality fallback still admits both records"
    );

    let enrollment = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &enrollment);

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "both records carry a pod UID, so the registry separates them: the \
         enrolled pod is admitted on the port its OWN record declares"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, node),
        Err(InboundRelayDenial::PortNotDeclared),
        "the unenrolled sibling's pod UID does not match the registry owner, so \
         its port is never admitted — that is the issue #4249 property, and it \
         does not require refusing the enrolled pod as well"
    );
}

/// Issue #4249: `WorkloadEntry` records carry no pod UID. If one declares an
/// enrolled pod's IP under the same service-account identity, identity-only
/// enrollment comparison would otherwise let it widen the admitted port set.
/// A lone UID-less record remains valid; only the shared-address contest is
/// refused once the registry is authoritative.
#[test]
fn inbound_relay_ambient_registry_refuses_uidless_record_contesting_enrolled_address() {
    let own_spiffe = reviews_spiffe();

    let mut enrolled_pod = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    enrolled_pod.ports = vec![WorkloadPort {
        port: 8080,
        protocol: AppProtocol::Http,
        name: Some("http".to_string()),
    }];
    let mut uidless_record = reviews_replica("10.244.5.5", OTHER_POD_UID);
    uidless_record.pod_uid = None;
    uidless_record.ports = vec![WorkloadPort {
        port: 9443,
        protocol: AppProtocol::Http,
        name: Some("operator-admin".to_string()),
    }];
    let mut lone_uidless_record = reviews_replica("10.244.5.6", OTHER_POD_UID);
    lone_uidless_record.pod_uid = None;
    lone_uidless_record.ports = vec![WorkloadPort {
        port: 7070,
        protocol: AppProtocol::Http,
        name: Some("vm-http".to_string()),
    }];
    let (slice, runtime) =
        ambient_relay_fixture(vec![enrolled_pod, uidless_record, lone_uidless_record]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));

    // First pin the old/no-registry behavior: both records pass the shared
    // identity, cluster, and labels bound. The later refusal is therefore the
    // registry-bounded contested-address rule, not a fixture mismatch.
    assert!(!mesh.inbound_relay_node_local_registry.is_authoritative());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, node),
        Ok(()),
        "a UID-less same-identity record widens the no-registry fallback"
    );

    let enrollment = [
        enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5"),
        enrolled(OTHER_POD_UID, &own_spiffe, "10.244.5.6"),
    ];
    bind_enrolled_registry(&mut mesh, &enrollment);

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a UID-less sibling makes the address contested for every claimant"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "the UID-less record must not widen the enrolled pod's admitted ports"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7070, node),
        Ok(()),
        "a lone UID-less WorkloadEntry / VM record at an enrolled IP stays admissible"
    );
}

struct StaticCaptureSource(Vec<PodCaptureTarget>);

impl PodCaptureSource for StaticCaptureSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.0.clone()
    }
}

struct IncompleteCaptureSource;

impl PodCaptureSource for IncompleteCaptureSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        panic!("the relay-guard manager must not use the permissive list_targets scan");
    }

    fn list_complete_targets(&self) -> Result<Vec<PodCaptureTarget>, String> {
        Err("registry snapshot was not complete".to_string())
    }
}

fn capture_target(pod_uid: &str, ipv4: &str) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: pod_uid.to_string(),
        cgroup_path: format!("/sys/fs/cgroup/kubepods/{pod_uid}"),
        source_identity: None,
        source_ips: PodCaptureSourceIps {
            ipv4: Some(ipv4.parse().expect("fixture ipv4")),
            ipv6: None,
        },
    }
}

/// In-memory sources stay testable through the default complete-snapshot
/// implementation (`Ok(list_targets())`). An `Err` from that method must
/// retract last-good immediately rather than retain or partially publish.
#[test]
fn inbound_relay_registry_manager_publishes_complete_snapshots_and_retracts_on_error() {
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);
    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    mesh.inbound_relay_node_local_registry =
        NodeLocalEnrolledDestinationsHandle::new(index.clone());

    let publisher = strict_registry_manager(
        Arc::new(StaticCaptureSource(vec![capture_target(
            LOCAL_POD_UID,
            "10.244.5.5",
        )])),
        index.clone(),
    );
    let published = publisher.reconcile_once();
    assert_eq!(published.len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "a complete in-memory snapshot must publish"
    );

    let retractor = strict_registry_manager(Arc::new(IncompleteCaptureSource), index);
    assert!(retractor.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an incomplete snapshot must retract last-good rather than retain it"
    );
}

/// Production `DirectoryCaptureSource` is the strict reader the relay guard
/// must consume. A valid snapshot publishes; a malformed sibling entry is not
/// skipped — the whole index retracts, including previously admitted pods —
/// and a later complete snapshot recovers.
#[test]
fn inbound_relay_registry_malformed_production_entry_retracts_then_recovers() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let other = reviews_replica("10.244.5.6", OTHER_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local, other]);
    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    mesh.inbound_relay_node_local_registry =
        NodeLocalEnrolledDestinationsHandle::new(index.clone());

    let dir = tempfile::tempdir().expect("registry");
    write_strict_registry_entry(dir.path(), LOCAL_POD_UID, "10.244.5.5", &own_spiffe);
    write_strict_registry_entry(dir.path(), OTHER_POD_UID, "10.244.5.6", &own_spiffe);
    let manager = strict_registry_manager(Arc::new(DirectoryCaptureSource::new(dir.path())), index);

    assert_eq!(manager.reconcile_once().len(), 2);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Ok(())
    );

    std::fs::write(dir.path().join(OTHER_POD_UID), b"").expect("malformed registry entry");
    assert!(manager.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a malformed sibling must retract the whole index, not skip the bad file \
         and keep last-good or the remaining valid entry"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated)
    );

    write_strict_registry_entry(dir.path(), OTHER_POD_UID, "10.244.5.6", &own_spiffe);
    assert_eq!(manager.reconcile_once().len(), 2);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "a later complete snapshot must be allowed to republish"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Ok(())
    );
}

/// Strict `list_complete_targets` distinguishes an omitted optional field from a
/// present malformed one. A valid complete registry publishes; a present invalid
/// `spiffe_id=` retracts instead of becoming missing evidence (so the address
/// cannot still admit on address/pod-UID alone); invalid IPv4/IPv6, duplicate
/// recognized keys, unknown content, and an unsafe pod-UID filename each retract
/// the whole last-good index; repairing the entry republishes. Hidden
/// dot-prefixed registry control entries are skipped rather than parsed as pods.
/// `list_targets` remains the best-effort scan and is not what the manager uses.
#[test]
fn inbound_relay_registry_strict_parse_retracts_malformed_evidence_then_recovers() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let other = reviews_replica("10.244.5.6", OTHER_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local, other]);
    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    mesh.inbound_relay_node_local_registry =
        NodeLocalEnrolledDestinationsHandle::new(index.clone());

    let dir = tempfile::tempdir().expect("registry");
    write_strict_registry_entry(dir.path(), LOCAL_POD_UID, "10.244.5.5", &own_spiffe);
    write_strict_registry_entry(dir.path(), OTHER_POD_UID, "10.244.5.6", &own_spiffe);
    std::fs::create_dir_all(dir.path().join(".ready")).expect("ready control dir");
    std::fs::write(dir.path().join(".ready").join("marker"), b"").expect("ready marker");
    std::fs::create_dir_all(dir.path().join(".udp-ready")).expect("udp-ready control dir");
    std::fs::write(dir.path().join(".udp-ready").join(LOCAL_POD_UID), b"")
        .expect("udp-ready marker");
    let source = DirectoryCaptureSource::new(dir.path());
    let manager = strict_registry_manager(
        Arc::new(DirectoryCaptureSource::new(dir.path())),
        index.clone(),
    );

    assert_eq!(
        manager.reconcile_once().len(),
        2,
        "a valid complete registry must publish, skipping hidden control entries"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Ok(())
    );

    let local_body = |spiffe: &str, ipv4: &str, extra: &str| {
        format!("/sys/fs/cgroup/kubepods/{LOCAL_POD_UID}\nspiffe_id={spiffe}\nipv4={ipv4}\n{extra}")
    };
    let other_body = |spiffe: &str, ipv4: &str, extra: &str| {
        format!("/sys/fs/cgroup/kubepods/{OTHER_POD_UID}\nspiffe_id={spiffe}\nipv4={ipv4}\n{extra}")
    };

    std::fs::write(
        dir.path().join(LOCAL_POD_UID),
        local_body("not-a-spiffe", "10.244.5.5", ""),
    )
    .expect("invalid spiffe_id");
    let permissive = source.list_targets();
    assert!(
        permissive
            .iter()
            .any(|target| { target.pod_uid == LOCAL_POD_UID && target.source_identity.is_none() }),
        "the best-effort scan must keep the pod and treat a present malformed \
         spiffe_id= as absent identity"
    );
    assert!(
        source.list_complete_targets().is_err(),
        "the complete snapshot must refuse a present malformed spiffe_id="
    );
    assert!(manager.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a present invalid spiffe_id= must retract rather than publish missing evidence"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a malformed sibling must retract the whole last-good index"
    );
    assert!(
        !index.terminates_for(ip("10.244.5.5"), None, Some(LOCAL_POD_UID)),
        "malformed identity must not still admit the address on address/pod-UID alone"
    );
    assert!(
        !index.terminates_for(
            ip("10.244.5.5"),
            Some(own_spiffe.as_str()),
            Some(LOCAL_POD_UID),
        ),
        "malformed identity must not skip the identity comparison by becoming None"
    );

    write_strict_registry_entry(dir.path(), LOCAL_POD_UID, "10.244.5.5", &own_spiffe);
    assert_eq!(manager.reconcile_once().len(), 2);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    let poisons = [
        (
            "invalid ipv4",
            OTHER_POD_UID,
            other_body(&own_spiffe, "not-an-ipv4", ""),
        ),
        (
            "invalid ipv6",
            OTHER_POD_UID,
            other_body(&own_spiffe, "10.244.5.6", "ipv6=not-an-ipv6\n"),
        ),
        (
            "duplicate recognized key",
            OTHER_POD_UID,
            other_body(&own_spiffe, "10.244.5.6", "ipv4=10.244.5.7\n"),
        ),
        (
            "unknown content",
            OTHER_POD_UID,
            other_body(&own_spiffe, "10.244.5.6", "hostname=evil.example\n"),
        ),
        (
            "empty spiffe_id",
            OTHER_POD_UID,
            format!("/sys/fs/cgroup/kubepods/{OTHER_POD_UID}\nspiffe_id=\nipv4=10.244.5.6\n"),
        ),
    ];
    for (reason, uid, body) in poisons {
        std::fs::write(dir.path().join(uid), body).expect("poison registry entry");
        assert!(
            manager.reconcile_once().is_empty(),
            "{reason}: complete snapshot must retract"
        );
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
            Err(InboundRelayDenial::AddressNotTerminated),
            "{reason}: last-good must not be retained"
        );
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
            Err(InboundRelayDenial::AddressNotTerminated),
            "{reason}: partial publish of the remaining valid file is forbidden"
        );
        write_strict_registry_entry(dir.path(), OTHER_POD_UID, "10.244.5.6", &own_spiffe);
        assert_eq!(
            manager.reconcile_once().len(),
            2,
            "{reason}: repairing the entry must allow republish"
        );
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
            Ok(()),
            "{reason}: repaired snapshot must recover the sibling"
        );
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
            Ok(())
        );
    }

    let unsafe_name = "uid with space";
    std::fs::write(
        dir.path().join(unsafe_name),
        b"/sys/fs/cgroup/x\nipv4=10.0.0.9\n",
    )
    .expect("unsafe pod-UID filename");
    assert!(
        manager.reconcile_once().is_empty(),
        "an unsafe pod-UID filename must retract the last-good index"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    std::fs::remove_file(dir.path().join(unsafe_name)).expect("remove unsafe name");
    assert_eq!(
        manager.reconcile_once().len(),
        2,
        "removing the unsafe leaf must allow republish"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 8080, node),
        Ok(())
    );
}

/// A path-safe alphanumeric registry leaf is a valid filename, but pairing it
/// with `spiffe_id=` does not produce a `UdpSourceIdentity`: production
/// identity binding requires a Kubernetes UUID. The strict complete snapshot
/// must retract rather than publish missing evidence (the live #4258 timeout
/// was this fixture shape). Permissive `list_targets` may keep the pod with
/// `source_identity=None`; that scan is not what the inbound relay uses.
#[test]
fn inbound_relay_registry_strict_parse_retracts_spiffe_on_non_uuid_leaf() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);
    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    mesh.inbound_relay_node_local_registry =
        NodeLocalEnrolledDestinationsHandle::new(index.clone());

    let dir = tempfile::tempdir().expect("registry");
    write_strict_registry_entry(dir.path(), LOCAL_POD_UID, "10.244.5.5", &own_spiffe);
    let source = DirectoryCaptureSource::new(dir.path());
    let manager = strict_registry_manager(
        Arc::new(DirectoryCaptureSource::new(dir.path())),
        index.clone(),
    );
    assert_eq!(manager.reconcile_once().len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    let safe_non_uuid = "functional-udp-enrolled-destination-pod";
    std::fs::write(
        dir.path().join(safe_non_uuid),
        format!(
            "/sys/fs/cgroup/kubepods/{safe_non_uuid}\nspiffe_id={own_spiffe}\nipv4=10.244.5.7\n"
        ),
    )
    .expect("path-safe non-UUID leaf with identity");

    let permissive = source.list_targets();
    assert!(
        permissive
            .iter()
            .any(|target| { target.pod_uid == safe_non_uuid && target.source_identity.is_none() }),
        "the best-effort scan must keep the path-safe leaf and treat the unbound \
         identity as absent"
    );
    assert!(
        source.list_complete_targets().is_err(),
        "the complete snapshot must refuse spiffe_id= bound to a non-UUID pod UID"
    );
    assert!(manager.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a sibling with spiffe_id= on a non-UUID leaf must retract the whole last-good index"
    );
    assert!(
        !index.terminates_for(
            ip("10.244.5.7"),
            Some(own_spiffe.as_str()),
            Some(safe_non_uuid),
        ),
        "the non-UUID identity binding must not still admit on address/pod-UID alone"
    );

    std::fs::remove_file(dir.path().join(safe_non_uuid)).expect("remove non-UUID leaf");
    assert_eq!(manager.reconcile_once().len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(()),
        "removing the non-UUID identity-bound leaf must allow republish"
    );
}

/// Unsafe names, oversized files, and Unix symlinks are the production
/// filesystem shapes the strict reader refuses. Each must retract a
/// previously valid publish; repairing the directory recovers.
#[test]
fn inbound_relay_registry_unsafe_oversized_or_symlinked_entry_retracts_then_recovers() {
    let own_spiffe = reviews_spiffe();
    let local = reviews_replica("10.244.5.5", LOCAL_POD_UID);
    let (slice, runtime) = ambient_relay_fixture(vec![local]);
    let mut mesh = prepared_mesh(&slice, &runtime);
    let node = Some(ip("10.244.0.1"));
    let index = Arc::new(NodeLocalEnrolledDestinations::new());
    mesh.inbound_relay_node_local_registry =
        NodeLocalEnrolledDestinationsHandle::new(index.clone());

    let dir = tempfile::tempdir().expect("registry");
    write_strict_registry_entry(dir.path(), LOCAL_POD_UID, "10.244.5.5", &own_spiffe);
    let manager = strict_registry_manager(
        Arc::new(DirectoryCaptureSource::new(dir.path())),
        index.clone(),
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "the index admits nothing before the first complete publish"
    );
    assert_eq!(manager.reconcile_once().len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    std::fs::write(
        dir.path().join("pod..unsafe"),
        b"/sys/fs/cgroup/x\nipv4=10.0.0.9\n",
    )
    .expect("unsafe name");
    assert!(manager.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an unsafe registry name must retract the previously valid publish"
    );
    std::fs::remove_file(dir.path().join("pod..unsafe")).expect("remove unsafe name");
    assert_eq!(manager.reconcile_once().len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    std::fs::write(dir.path().join("oversized"), vec![b'x'; 16 * 1024 + 1])
        .expect("oversized entry");
    assert!(manager.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "an oversized registry entry must retract the previously valid publish"
    );
    std::fs::remove_file(dir.path().join("oversized")).expect("remove oversized");
    assert_eq!(manager.reconcile_once().len(), 1);
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("symlink-pod"))
            .expect("symlink entry");
        assert!(manager.reconcile_once().is_empty());
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
            Err(InboundRelayDenial::AddressNotTerminated),
            "a symlinked registry entry must retract the previously valid publish"
        );
        std::fs::remove_file(dir.path().join("symlink-pod")).expect("remove symlink");
        assert_eq!(manager.reconcile_once().len(), 1);
        assert_eq!(
            mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
            Ok(())
        );
    }

    let missing = strict_registry_manager(
        Arc::new(DirectoryCaptureSource::new("/definitely/not-a-registry")),
        index,
    );
    assert!(missing.reconcile_once().is_empty());
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a missing registry directory must retract rather than retain last-good"
    );
}

/// Issue #4249, the `Sidecar` half. A Sidecar shares the application pod's
/// network namespace, so the accepted socket's local address is a pod-unique
/// transport proof of every destination it may relay to — it needs no
/// multi-destination inventory, and carrying one admitted a same-SPIFFE,
/// same-cluster, same-label sibling replica it has no node-agent registry to
/// exclude. The general inventory is now EMPTY; the owned workload view
/// survives only as the own-address / loopback port bound.
#[test]
fn inbound_relay_sidecar_admits_only_its_own_accepted_local_address() {
    let own_spiffe = format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{DEFAULT_NAMESPACE}/sa/reviews");

    let mut own = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.5.5"],
    );
    own.cluster = Some("cluster-a".to_string());
    // Byte-for-byte the same identity, cluster and labels; another pod, on
    // another node. `workload_is_local` cannot tell it apart.
    let mut sibling = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.9.9"],
    );
    sibling.cluster = Some("cluster-a".to_string());
    // A co-located pod declaring the SAME address on a port this workload does
    // not serve — the `hostNetwork` shape.
    let mut co_located = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings")],
        ["10.244.5.5"],
    );
    co_located.cluster = Some("cluster-a".to_string());
    co_located.ports = vec![WorkloadPort {
        port: 9443,
        protocol: AppProtocol::Http,
        name: Some("admin".to_string()),
    }];

    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        version: "test".to_string(),
        workloads: vec![own, sibling, co_located],
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            ..MultiClusterConfig::default()
        }),
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::Sidecar,
        workload_spiffe_id: Some(own_spiffe),
        workload_labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        ..default_mesh_runtime()
    };

    let mesh = prepared_mesh(&slice, &runtime);
    assert!(
        mesh.inbound_relay_destinations.is_empty(),
        "a Sidecar terminates only for the pod whose netns it shares, so it carries \
         no multi-destination inventory"
    );
    assert!(mesh.inbound_relay_admits_accepted_local_address);

    // The peer reached this pod at its own address, on this socket.
    let own_ip = Some(ip("10.244.5.5"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, own_ip),
        Ok(()),
        "the accepted local address stays admissible on a port this pod declares"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 8080, own_ip),
        Ok(()),
        "the own-namespace loopback shortcut is bounded by the same owned records"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "a co-located hostNetwork sibling's port must not widen the own-address bound"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "nor the loopback shortcut"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.9.9", 8080, own_ip),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a same-SPIFFE, same-cluster, same-label sibling replica is not this \
         Sidecar's destination"
    );
    // ...and a Sidecar never installs a node-local registry, because it has no
    // inventory for one to bound.
    assert!(!mesh.inbound_relay_node_local_registry.is_authoritative());
}

// ── Own-address port bound: address-level pod ambiguity (issue #4249) ────────

/// Declared application ports for a relay fixture workload.
fn declared_ports(ports: &[u16]) -> Vec<WorkloadPort> {
    ports
        .iter()
        .map(|port| WorkloadPort {
            port: *port,
            protocol: AppProtocol::Http,
            name: None,
        })
        .collect()
}

/// A `reviews` replica declaring `address` on `ports`, carrying `pod_uid` when
/// one is given. Same SPIFFE, same cluster and same pod-template labels as
/// every other replica — the shape the owned-workload filter cannot separate.
fn reviews_replica_declaring(
    address: &'static str,
    pod_uid: Option<&str>,
    ports: &[u16],
) -> Workload {
    let mut workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        [address],
    );
    workload.cluster = Some("cluster-a".to_string());
    workload.pod_uid = pod_uid.map(str::to_string);
    workload.ports = declared_ports(ports);
    workload
}

/// One own-pod terminator slice on `topology`, carrying `workloads` in the
/// local cluster under this proxy's own `reviews` identity.
fn own_pod_relay_fixture(
    topology: MeshTopology,
    workloads: Vec<Workload>,
) -> (MeshSlice, MeshRuntimeConfig) {
    let (slice, mut runtime) = ambient_relay_fixture(workloads);
    runtime.topology = topology;
    (slice, runtime)
}

/// Issue #4249, the own-ADDRESS half. Two replicas of one Deployment share a
/// service-account SPIFFE id, a cluster and their pod-template labels, so both
/// enter the owned workload view; under `hostNetwork` they also share the node
/// IP while carrying different pod UIDs. The own-address and loopback arms must
/// not admit the UNION of the two pods' ports on that address — a co-located
/// pod's application port would become reachable through this terminator — and
/// nothing at guard time can pick between them, so the address fails closed for
/// BOTH.
#[test]
fn inbound_relay_sidecar_own_address_fails_closed_on_two_pods_sharing_an_address() {
    let shared = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[8080]);
    let co_located = reviews_replica_declaring("10.244.5.5", Some(OTHER_POD_UID), &[9443]);
    let (slice, runtime) = own_pod_relay_fixture(MeshTopology::Sidecar, vec![shared, co_located]);

    let mesh = prepared_mesh(&slice, &runtime);
    // The peer reached the shared (host-network) address on this socket.
    let own_ip = Some(ip("10.244.5.5"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "an address two different pods declare cannot be attributed to either, so \
         neither record's ports may be admitted through it"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "the co-located pod's port must not ride in on the shared address either"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("127.0.0.1", 8080, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "the own-namespace loopback shortcut stands in for the same ambiguous \
         address and fails closed with it"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared)
    );
}

/// The `Ambient` half of the same defect. `Ambient` sets the own-address marker
/// too, and that arm returns BEFORE the registry-bounded inventory is consulted
/// — so a shared address the node-agent registry would have disambiguated must
/// still fail closed on the port bound itself.
#[test]
fn inbound_relay_ambient_own_address_fails_closed_on_two_pods_sharing_an_address() {
    let own_spiffe = reviews_spiffe();
    let shared = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[8080]);
    let co_located = reviews_replica_declaring("10.244.5.5", Some(OTHER_POD_UID), &[9443]);
    let (slice, runtime) = own_pod_relay_fixture(MeshTopology::Ambient, vec![shared, co_located]);

    let mut mesh = prepared_mesh(&slice, &runtime);
    let enrollment = [enrolled(LOCAL_POD_UID, &own_spiffe, "10.244.5.5")];
    bind_enrolled_registry(&mut mesh, &enrollment);
    let own_ip = Some(ip("10.244.5.5"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "the unenrolled co-located pod's port must not be admitted by the \
         own-address arm, which never reaches the registry"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "and the address stays ambiguous for the enrolled pod too — the arm has \
         no evidence to pick between two records declaring it"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 8080, own_ip),
        Err(InboundRelayDenial::AddressNotTerminated),
        "Ambient refuses the loopback namespace categorically, so the ambiguous \
         own-address port bound never becomes the reported reason — declaring \
         the port could not admit it either"
    );

    // The registry-bounded general inventory is unchanged and still admits the
    // enrolled pod when the socket's own address is NOT the destination.
    let node = Some(ip("10.244.0.1"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, node),
        Ok(())
    );
}

/// The legitimate multi-record shape stays admitted: several Service records
/// for ONE pod agree on a non-empty pod UID, which is positive proof they are
/// the same pod, so their declared ports are unioned exactly as one record's
/// would be. A lone record with no pod UID at all — a `WorkloadEntry` / VM
/// record, or an ordinary pod whose carrier does not stamp one — is
/// unambiguous for its address and keeps working.
#[test]
fn inbound_relay_own_address_unions_ports_only_across_one_proven_pod() {
    let http = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[8080]);
    let grpc = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[9090]);
    // A second address, declared by a single record carrying no pod UID.
    let uidless = reviews_replica_declaring("10.244.5.6", None, &[7070]);
    let (slice, runtime) = own_pod_relay_fixture(MeshTopology::Sidecar, vec![http, grpc, uidless]);

    let mesh = prepared_mesh(&slice, &runtime);
    let own_ip = Some(ip("10.244.5.5"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, own_ip),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9090, own_ip),
        Ok(()),
        "two Service records for one proven pod legitimately union their ports"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 9090, own_ip),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, own_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "the union is still bounded by what that pod declares"
    );

    // The single uidless record is the only one on its address, so it is
    // unambiguous and keeps the pre-#4249 behaviour.
    let other_ip = Some(ip("10.244.5.6"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7070, other_ip),
        Ok(())
    );
}

/// A pod UID is only proof when EVERY record on the address carries it and they
/// agree. A mix of present and missing UIDs, or several records none of which
/// carries one, is ambiguous — the records may be one pod or several, and the
/// guard cannot tell — so the address is refused rather than unioned.
#[test]
fn inbound_relay_own_address_fails_closed_on_missing_and_mixed_pod_uids() {
    let with_uid = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[8080]);
    let without_uid = reviews_replica_declaring("10.244.5.5", None, &[9443]);
    // A second shared address where NEITHER record publishes a UID.
    let anonymous_a = reviews_replica_declaring("10.244.5.6", None, &[7070]);
    let anonymous_b = reviews_replica_declaring("10.244.5.6", None, &[7071]);
    let (slice, runtime) = own_pod_relay_fixture(
        MeshTopology::Sidecar,
        vec![with_uid, without_uid, anonymous_a, anonymous_b],
    );

    let mesh = prepared_mesh(&slice, &runtime);

    let mixed = Some(ip("10.244.5.5"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, mixed),
        Err(InboundRelayDenial::PortNotDeclared),
        "a record without a pod UID cannot be proven to be the same pod as one \
         that has it"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, mixed),
        Err(InboundRelayDenial::PortNotDeclared)
    );

    let anonymous = Some(ip("10.244.5.6"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7070, anonymous),
        Err(InboundRelayDenial::PortNotDeclared),
        "two records with no pod UID at all may be two pods; fail closed"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7071, anonymous),
        Err(InboundRelayDenial::PortNotDeclared)
    );
}

/// With NO workload identity configured nothing can be attributed to this
/// terminator, so there is no owned view to project. That must not become a
/// permissive fallback to the whole declared workload view: the same ambiguity
/// rule is applied to that view instead, so a shared address still fails closed
/// while an unambiguous one still serves. Remote-provenance records are not
/// candidates: an overlapping remote pod CIDR must not manufacture ambiguity
/// at the local pod's address.
#[test]
fn inbound_relay_own_address_without_identity_does_not_union_a_shared_address() {
    let shared_a = reviews_replica_declaring("10.244.5.5", Some(LOCAL_POD_UID), &[8080]);
    let shared_b = reviews_replica_declaring("10.244.5.5", Some(OTHER_POD_UID), &[9443]);
    let lone = reviews_replica_declaring("10.244.5.6", Some(LOCAL_POD_UID), &[7070]);
    let mut remote_overlap = reviews_replica_declaring("10.244.5.6", Some(OTHER_POD_UID), &[7443]);
    remote_overlap.remote_provenance = true;
    let (slice, mut runtime) = own_pod_relay_fixture(
        MeshTopology::Sidecar,
        vec![shared_a, shared_b, lone, remote_overlap],
    );
    // No `FERRUM_MESH_WORKLOAD_SPIFFE_ID`.
    runtime.workload_spiffe_id = None;

    let mesh = prepared_mesh(&slice, &runtime);
    assert!(
        mesh.inbound_relay_destinations.is_empty(),
        "no identity still means no general relay inventory"
    );

    let shared_ip = Some(ip("10.244.5.5"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 8080, shared_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "an absent identity must not license the pre-#4249 whole-view union"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.5", 9443, shared_ip),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("localhost", 9443, shared_ip),
        Err(InboundRelayDenial::PortNotDeclared)
    );

    // ...while an address exactly one record declares is still served, so this
    // is a narrowing rather than an inbound outage.
    let lone_ip = Some(ip("10.244.5.6"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7070, lone_ip),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 9443, lone_ip),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.5.6", 7443, lone_ip),
        Err(InboundRelayDenial::PortNotDeclared),
        "an overlapping remote-provenance record must not widen or contest the local bound"
    );
}

/// Issue #4251: a `ServiceWaypoint` is the L7 terminator for the services bound
/// to it. The slice's own workload narrowing is only NAMESPACE-level (the
/// waypoint's namespace plus its bound services' namespaces), so a workload
/// sitting in a bound service's namespace that backs NO bound service must be
/// refused `AddressNotTerminated` rather than relayed to in plaintext.
#[test]
fn inbound_relay_service_waypoint_admits_only_bound_service_backends() {
    let backing = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.1.7"],
    );
    let unbound = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings")],
        ["10.244.2.9"],
    );
    // Only `reviews` is bound to this waypoint, so only its Service survives
    // the slice's service narrowing; `ratings` is namespace-visible only.
    let bound_service = service_for("reviews", DEFAULT_NAMESPACE, &[&backing]);

    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        waypoint_name: Some("reviews-waypoint".to_string()),
        version: "test".to_string(),
        workloads: vec![backing, unbound],
        services: vec![bound_service],
        service_waypoint_bound_services: vec![MeshWaypointServiceRef {
            namespace: DEFAULT_NAMESPACE.to_string(),
            name: "reviews".to_string(),
        }],
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::ServiceWaypoint,
        waypoint_name: Some("reviews-waypoint".to_string()),
        ..default_mesh_runtime()
    };

    let mesh = prepared_mesh(&slice, &runtime);
    // A waypoint runs outside the destination pods' netns; its own address is
    // never a relay destination.
    let waypoint = Some(ip("10.244.4.4"));

    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, waypoint),
        Ok(()),
        "a bound service's backing workload is a destination this waypoint terminates for"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a workload visible in the bound service's namespace that backs no bound \
         service is not a destination this waypoint terminates for"
    );
}

/// Issue #4251, fail-closed side: bound services that list no backing workload
/// leave the inventory EMPTY rather than falling back to the namespace-visible
/// workload view.
#[test]
fn inbound_relay_service_waypoint_without_backing_refs_terminates_for_nothing() {
    let visible = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.1.7"],
    );
    // A Service shell with no `workloads[]` authorization list.
    let bound_service = service_for("reviews", DEFAULT_NAMESPACE, &[]);

    let slice = MeshSlice {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        waypoint_name: Some("reviews-waypoint".to_string()),
        version: "test".to_string(),
        workloads: vec![visible],
        services: vec![bound_service],
        service_waypoint_bound_services: vec![MeshWaypointServiceRef {
            namespace: DEFAULT_NAMESPACE.to_string(),
            name: "reviews".to_string(),
        }],
        ..MeshSlice::default()
    };
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::ServiceWaypoint,
        waypoint_name: Some("reviews-waypoint".to_string()),
        ..default_mesh_runtime()
    };

    let mesh = prepared_mesh(&slice, &runtime);

    assert!(
        mesh.inbound_relay_destinations.is_empty(),
        "no authorized backing workload must leave the inventory empty"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, Some(ip("10.244.4.4"))),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
}

fn prepared_service_waypoint_from_gateway_config(
    mesh: MeshConfig,
    waypoint_name: &str,
) -> (MeshSlice, Box<MeshConfig>) {
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..MeshSliceRequest::default()
    }
    .with_waypoint_name(Some(waypoint_name.to_string()));
    let slice = MeshSlice::from_gateway_config(&config, request);
    let runtime = MeshRuntimeConfig {
        topology: MeshTopology::ServiceWaypoint,
        waypoint_name: Some(waypoint_name.to_string()),
        ..default_mesh_runtime()
    };
    let prepared = prepared_mesh(&slice, &runtime);
    (slice, prepared)
}

fn reviews_and_ratings_mesh(bindings: Vec<MeshWaypointBinding>) -> MeshConfig {
    let reviews = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.244.1.7"],
    );
    let ratings = workload_for(
        "ratings",
        DEFAULT_NAMESPACE,
        [("app", "ratings")],
        ["10.244.2.9"],
    );
    MeshConfig {
        services: vec![
            service_for("reviews", DEFAULT_NAMESPACE, &[&reviews]),
            service_for("ratings", DEFAULT_NAMESPACE, &[&ratings]),
        ],
        workloads: vec![reviews, ratings],
        waypoint_bindings: bindings,
        ..MeshConfig::default()
    }
}

// ── Issue #4252 — post-plugin effective-destination handler re-check ────────
//
// Mesh-mode has no deployed source that puts `mesh_route_dispatch` on the
// synthesized inbound HBONE relay (`MeshSlice::from_gateway_config` does not
// project `GatewayConfig.plugin_configs`; file source accepts only MeshConfig;
// xDS reverse translation does not carry operator plugins). The functional
// cases therefore prove synthesis-time 404. These in-process tests invoke the
// real dispatcher → `handle_hbone_request` / `handle_hbone_udp_request` path
// with a normal GatewayConfig plugin cache: CONNECT names a dest B terminates
// for, a global `mesh_route_dispatch` rewrites onto C, and each handler must
// 403 with zero backend hits. Deleting either re-check fails these tests;
// a synthesis 404 would mean this setup never reached the handlers.

fn is_usable_non_loopback_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_unspecified()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

async fn probe_udp_egress_local_ip(dest: SocketAddr) -> Result<IpAddr, String> {
    let bind = if dest.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("probe bind {bind}: {e}"))?;
    socket
        .connect(dest)
        .await
        .map_err(|e| format!("probe connect {dest}: {e}"))?;
    socket
        .local_addr()
        .map(|addr| addr.ip())
        .map_err(|e| format!("probe local_addr: {e}"))
}

/// Fail closed when the runner has only loopback: a 127.0.0.2 C can be
/// refused by PR #4315's loopback-namespace guard instead of ownership.
async fn discover_bindable_non_loopback_local_ip() -> IpAddr {
    let probes = [
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
        SocketAddr::from((
            std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            53,
        )),
    ];
    let mut evidence = Vec::new();
    let mut seen = HashSet::new();
    for dest in probes {
        match probe_udp_egress_local_ip(dest).await {
            Ok(ip) => {
                if !seen.insert(ip) {
                    continue;
                }
                if !is_usable_non_loopback_unicast(ip) {
                    evidence.push(format!(
                        "probe {dest} → {ip}: rejected (loopback/unspecified/link-local/multicast/broadcast)"
                    ));
                    continue;
                }
                match TcpListener::bind(SocketAddr::new(ip, 0)).await {
                    Ok(listener) => {
                        drop(listener);
                        return ip;
                    }
                    Err(e) => evidence.push(format!("probe {dest} → {ip}: TCP bind failed: {e}")),
                }
            }
            Err(e) => evidence.push(format!("probe {dest}: {e}")),
        }
    }
    panic!(
        "no usable non-loopback local interface address for workload C. Evidence:\n{}",
        evidence.join("\n")
    );
}

fn global_mesh_route_dispatch_to(host: &str, port: u16) -> PluginConfig {
    PluginConfig {
        id: "third-workload-route-override".to_string(),
        plugin_name: "mesh_route_dispatch".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "rules": [{
                "match": { "methods": ["CONNECT"] },
                "destination": {
                    "backend_host": host,
                    "backend_port": port
                }
            }],
            "reject_unmatched": false
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Sidecar-shaped: CONNECT names loopback B, which #4315 admits only when this
/// terminator shares the destination pod netns. C is a non-loopback third
/// workload this terminator does not own, so the handler re-check refuses it
/// for ownership rather than the loopback-namespace guard.
fn post_plugin_refusal_mesh(b_port: u16, c_ip: IpAddr, c_port: u16) -> MeshConfig {
    let c_addr = c_ip.to_string();
    MeshConfig {
        workloads: vec![
            relay_guard_workload("svc-b", &["127.0.0.1"], &[b_port]),
            relay_guard_workload("svc-c", &[&c_addr], &[c_port]),
        ],
        inbound_relay_admits_accepted_local_address: true,
        inbound_relay_admits_loopback_namespace: true,
        // Issue #4249 bound the loopback arm to the per-address port the
        // terminator actually owns, so the Sidecar-shaped fixture must project
        // B's own-address ports the way the apply path does. Without this the
        // control CONNECT to 127.0.0.1 is refused `PortNotDeclared` and the
        // test sees a 404 instead of C's ownership 403.
        inbound_relay_own_address_ports: own_address_port_bounds_from_workloads(&[
            relay_guard_workload("svc-b", &["127.0.0.1"], &[b_port]),
        ]),
        ..MeshConfig::default()
    }
}

fn reviews_only_waypoint_binding(waypoint_for: &str) -> MeshWaypointBinding {
    MeshWaypointBinding {
        name: "reviews-waypoint".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        waypoint_for: waypoint_for.to_string(),
        gateway_class_name: None,
        services: vec![MeshWaypointServiceRef {
            namespace: DEFAULT_NAMESPACE.to_string(),
            name: "reviews".to_string(),
        }],
    }
}

fn reviews_bound_service_ref() -> MeshWaypointServiceRef {
    MeshWaypointServiceRef {
        namespace: DEFAULT_NAMESPACE.to_string(),
        name: "reviews".to_string(),
    }
}

/// Issue #4251, production path: `narrow_for_service_waypoint` still fail-opens
/// the routing view when the named binding is absent, so `MeshSlice.services`
/// carries every namespace-visible Service. That view must NOT license the
/// inbound HBONE relay — missing binding evidence yields an empty inventory.
#[test]
fn inbound_relay_service_waypoint_missing_binding_from_gateway_config_terminates_for_nothing() {
    let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
        reviews_and_ratings_mesh(Vec::new()),
        "reviews-waypoint",
    );

    assert_eq!(
        slice.services.len(),
        2,
        "routing still fail-opens when the named Gateway has not landed"
    );
    assert!(
        slice.service_waypoint_bound_services.is_empty(),
        "a missing binding must not stamp relay evidence from namespace-visible Services"
    );
    assert!(
        mesh.inbound_relay_destinations.is_empty(),
        "no matching binding must leave the relay inventory empty"
    );

    let waypoint = Some(ip("10.244.4.4"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
}

fn assert_reviews_service_relay_from_gateway_config(slice: &MeshSlice, mesh: &MeshConfig) {
    assert_eq!(
        slice.service_waypoint_bound_services,
        vec![reviews_bound_service_ref()],
        "service-terminating waypoint_for must stamp exact bound-service refs"
    );
    assert_eq!(
        slice
            .services
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["reviews"],
        "the matching binding must narrow the routing view to the bound Service"
    );

    let waypoint = Some(ip("10.244.4.4"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, waypoint),
        Ok(()),
        "a bound service's backing workload is a destination this waypoint terminates for"
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated),
        "a namespace-visible workload that backs no bound service is not terminated here"
    );
}

fn assert_no_service_relay_from_gateway_config(slice: &MeshSlice, mesh: &MeshConfig) {
    assert!(
        slice.service_waypoint_bound_services.is_empty(),
        "non-service-terminating waypoint_for must not stamp inbound-relay binding evidence"
    );
    assert!(
        mesh.inbound_relay_destinations.is_empty(),
        "no service-terminating binding evidence must leave the relay inventory empty"
    );

    let waypoint = Some(ip("10.244.4.4"));
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.1.7", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
    assert_eq!(
        mesh.inbound_relay_destination_decision("10.244.2.9", 8080, waypoint),
        Err(InboundRelayDenial::AddressNotTerminated)
    );
}

/// Issue #4251, production path: `waypoint_for=service` (and mixed-case) retains
/// exact service binding evidence and admits only those bound backends.
#[test]
fn inbound_relay_service_waypoint_exact_binding_from_gateway_config_admits_only_bound_backends() {
    for waypoint_for in ["service", "SERVICE"] {
        let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
            reviews_and_ratings_mesh(vec![reviews_only_waypoint_binding(waypoint_for)]),
            "reviews-waypoint",
        );
        assert_reviews_service_relay_from_gateway_config(&slice, &mesh);
    }
}

/// Issue #4251, production path: `waypoint_for=all` is also service-terminating
/// and must stamp the same exact bound-service refs as `service`.
#[test]
fn inbound_relay_service_waypoint_waypoint_for_all_from_gateway_config_admits_only_bound_backends()
{
    for waypoint_for in ["all", "All"] {
        let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
            reviews_and_ratings_mesh(vec![reviews_only_waypoint_binding(waypoint_for)]),
            "reviews-waypoint",
        );
        assert_reviews_service_relay_from_gateway_config(&slice, &mesh);
    }
}

/// Issue #4251, production path: `waypoint_for=none` is an explicit opt-out and
/// must produce an empty relay inventory even when the binding lists services.
#[test]
fn inbound_relay_service_waypoint_waypoint_for_none_from_gateway_config_terminates_for_nothing() {
    let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
        reviews_and_ratings_mesh(vec![reviews_only_waypoint_binding("none")]),
        "reviews-waypoint",
    );

    assert!(
        slice.services.is_empty() && slice.workloads.is_empty(),
        "waypoint_for=none must produce an empty admitted routing set"
    );
    assert_no_service_relay_from_gateway_config(&slice, &mesh);
}

/// Issue #4251, production path: `waypoint_for=workload` still lists Service
/// refs on the routing view (the K8s translator appends them) but does not
/// claim service traffic, so inbound service relay must terminate for nothing.
#[test]
fn inbound_relay_service_waypoint_waypoint_for_workload_from_gateway_config_terminates_for_nothing()
{
    let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
        reviews_and_ratings_mesh(vec![reviews_only_waypoint_binding("workload")]),
        "reviews-waypoint",
    );

    assert_eq!(
        slice
            .services
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["reviews"],
        "waypoint_for=workload must keep the existing routing-view narrowing"
    );
    assert_no_service_relay_from_gateway_config(&slice, &mesh);
}

/// Issue #4251, production path: blank and unknown/forward `waypoint_for`
/// values fail closed for inbound service-relay evidence.
#[test]
fn inbound_relay_service_waypoint_unknown_waypoint_for_from_gateway_config_terminates_for_nothing()
{
    for waypoint_for in ["", "direct"] {
        let (slice, mesh) = prepared_service_waypoint_from_gateway_config(
            reviews_and_ratings_mesh(vec![reviews_only_waypoint_binding(waypoint_for)]),
            "reviews-waypoint",
        );
        assert_no_service_relay_from_gateway_config(&slice, &mesh);
    }
}

fn create_post_plugin_third_workload_state(
    mesh: MeshConfig,
    route_override: PluginConfig,
) -> ProxyState {
    let spiffe_plugin = spiffe_identity_global_plugin_config();
    let config = GatewayConfig {
        version: "1".to_string(),
        // Unrelated HTTP route: CONNECT to 127.0.0.1:b_port misses it, so
        // synthesis builds `__mesh-inbound-hbone-relay` and the global plugin
        // chain (including mesh_route_dispatch) runs on that unknown proxy id.
        proxies: vec![create_mesh_proxy(1)],
        consumers: vec![],
        plugin_configs: vec![spiffe_plugin, route_override],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
    };
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        ..EnvConfig::default()
    };
    ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

#[derive(Clone, Copy)]
enum PostPluginConnectFlavor {
    ByteStream,
    Datagram,
}

async fn start_counting_tcp_backend(
    ip: IpAddr,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .unwrap_or_else(|e| panic!("bind post-plugin TCP backend on {ip}: {e}"));
    let addr = listener.local_addr().expect("post-plugin TCP backend addr");
    let (hit_tx, hit_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = ready_tx.send(());
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            drop(stream);
            if hit_tx.send(()).is_err() {
                return;
            }
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
        .await
        .expect("post-plugin TCP backend became ready")
        .expect("post-plugin TCP backend task dropped ready");
    (addr, hit_rx, task)
}

async fn start_counting_udp_backend(
    ip: IpAddr,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(ip, 0))
        .await
        .unwrap_or_else(|e| panic!("bind post-plugin UDP backend on {ip}: {e}"));
    let addr = socket.local_addr().expect("post-plugin UDP backend addr");
    let (hit_tx, hit_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let mut buf = vec![0u8; 65535];
        while socket.recv_from(&mut buf).await.is_ok() {
            if hit_tx.send(()).is_err() {
                return;
            }
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
        .await
        .expect("post-plugin UDP backend became ready")
        .expect("post-plugin UDP backend task dropped ready");
    (addr, hit_rx, task)
}

/// `None` means the channel CLOSED — C's backend task exited, so it could not
/// have recorded a dial and "zero hits" is not evidence. Only a timeout with
/// the backend still listening is a genuine zero.
async fn observe_backend_hits(
    hit_rx: &mut mpsc::UnboundedReceiver<()>,
    window: std::time::Duration,
) -> Option<usize> {
    match tokio::time::timeout(window, hit_rx.recv()).await {
        Ok(Some(())) => {
            let mut hits = 1;
            while hit_rx.try_recv().is_ok() {
                hits += 1;
            }
            Some(hits)
        }
        Err(_) => Some(0),
        Ok(None) => None,
    }
}

/// Collect a refusal body, stopping at the first stream error instead of
/// panicking. The CONNECT request stream is deliberately left OPEN with
/// unread payload on it, so a peer that completes its response may RST the
/// stream afterwards; that must not turn a correct 403 into a panic. Whatever
/// was received still has to satisfy the body assertion.
async fn collect_h2_body(mut body: h2::RecvStream) -> Bytes {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            break;
        };
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Bytes::from(out)
}

async fn drive_post_plugin_third_workload_refusal(flavor: PostPluginConnectFlavor) {
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let c_ip = discover_bindable_non_loopback_local_ip().await;
    let (c_addr, mut hit_rx, echo) = match flavor {
        PostPluginConnectFlavor::ByteStream => start_counting_tcp_backend(c_ip).await,
        PostPluginConnectFlavor::Datagram => start_counting_udp_backend(c_ip).await,
    };
    let c_port = c_addr.port();
    let b_port = if c_port == 18080 { 18081 } else { 18080 };
    let state = create_post_plugin_third_workload_state(
        post_plugin_refusal_mesh(b_port, c_ip, c_port),
        global_mesh_route_dispatch_to(&c_ip.to_string(), c_port),
    );
    let (gateway_addr, shutdown_tx) =
        start_egress_udp_gateway(state, hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let authority = format!("127.0.0.1:{b_port}");
    let req = match flavor {
        PostPluginConnectFlavor::ByteStream => Request::builder()
            .method(Method::CONNECT)
            .uri(&authority)
            .body(())
            .expect("byte-stream CONNECT"),
        PostPluginConnectFlavor::Datagram => udp_connect_request(&authority),
    };
    let (response_fut, mut request_body) = sender.send_request(req, false).expect("send CONNECT");
    // Put real bytes on the CONNECT stream. Without them the datagram flavor
    // would never forward anything even if the re-check were deleted, so its
    // zero-hit assertion would be vacuous rather than evidence. The stream is
    // left OPEN (`end_stream = false`) so a relay that WAS established would
    // stay alive long enough to deliver them.
    match flavor {
        PostPluginConnectFlavor::ByteStream => {
            let payload = Bytes::from_static(b"third-workload-must-not-be-dialed");
            let _ = request_body.send_data(payload, false);
        }
        PostPluginConnectFlavor::Datagram => {
            let mut framed = bytes::BytesMut::new();
            ferrum_edge::proxy::mesh_udp_frame::encode_datagram(&mut framed, b"ping")
                .expect("encode datagram");
            let _ = request_body.send_data(framed.freeze(), false);
        }
    }
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), response_fut)
        .await
        .expect("CONNECT response")
        .expect("CONNECT response");
    let status = resp.status();
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        collect_h2_body(resp.into_body()),
    )
    .await
    .unwrap_or_else(|_| Bytes::new());
    let observed = observe_backend_hits(&mut hit_rx, std::time::Duration::from_secs(2)).await;

    shutdown_tx.send(true).expect("shutdown gateway");
    echo.abort();
    conn_task.abort();

    let body_text = String::from_utf8_lossy(&body);
    let Some(hits) = observed else {
        panic!(
            "workload C's backend task exited before the observation window, so zero hits \
             proves nothing. body={body_text}"
        )
    };
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "post-plugin re-check must return 404-distinct 403; 404 means synthesis \
         never reached the handler, 200/502 means the override or guard did not \
         fire. body={body_text}"
    );
    assert!(
        body_text.contains("relay destination not allowed"),
        "403 must be the destination re-check, not the unauthenticated-peer \
         gate. body={body_text}"
    );
    assert_eq!(
        hits, 0,
        "workload C's backend must see zero accepts/datagrams. body={body_text}"
    );
}

/// Byte-stream: CONNECT names B so synthesis admits, global mesh_route_dispatch
/// rewrites onto C, `handle_hbone_request` must 403 before `connect_backend`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_hbone_relay_refuses_post_plugin_third_workload_byte_stream() {
    drive_post_plugin_third_workload_refusal(PostPluginConnectFlavor::ByteStream).await;
}

/// Datagram-over-CONNECT: the independently placed re-check in
/// `handle_hbone_udp_request` must 403 before `resolve_local_udp_dest`.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_hbone_relay_refuses_post_plugin_third_workload_datagram() {
    drive_post_plugin_third_workload_refusal(PostPluginConnectFlavor::Datagram).await;
}

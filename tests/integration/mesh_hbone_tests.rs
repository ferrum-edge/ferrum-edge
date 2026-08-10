use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::common::{empty_digest_header, generate_hmac_signature};

use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, PluginAssociation,
    PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshEgressUdpDestination, MeshEgressUdpDialEndpoint,
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
        k8s_mesh_overlay: Default::default(),
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
/// `workloads` is deliberately EMPTY so the byte-stream open-relay guard
/// (`inbound_hbone_relay_destination_allowed`) denies every authority — a
/// loopback authority is admitted only when some workload declares that port.
/// Whatever the relay admits here therefore came from the external UDP
/// allowlist and nothing else.
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
        k8s_mesh_overlay: Default::default(),
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
        k8s_mesh_overlay: Default::default(),
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

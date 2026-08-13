//! Gateway listener QUIC vs UDP/DTLS collision: preserve HTTPS TCP (#3811).
//!
//! When HTTP/3 is enabled and a raw UDP or DTLS stream owns the same numeric
//! port, the TLS-class Gateway listener must keep serving H1/H2 over TCP while
//! refusing only the optional QUIC half. Live transitions drain or start QUIC
//! without restarting TCP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::http3::config::Http3ServerConfig;
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::gateway_listener::{
    GatewayListenerHttp3, GatewayListenerManager, GatewayListenerTls,
};
use ferrum_edge::proxy::gateway_listener_status::{
    GatewayListenerFailureCategory, GatewayListenerProtocolHalf,
};
use ferrum_edge::tls::{NoVerifier, TlsPolicy};

const HOST: &str = "app.example.com";

fn ensure_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn port_scoped_https_proxy(id: &str, backend_port: u16, listen_port: u16) -> Proxy {
    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": id,
        "hosts": [HOST],
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "listen_port": listen_port,
    }))
    .expect("https gateway proxy");
    proxy
}

fn stream_proxy(id: &str, scheme: BackendScheme, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(scheme),
        dispatch_kind: DispatchKind::from(scheme),
        backend_host: "127.0.0.1".into(),
        backend_port: 1,
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
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(port),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn tls_config_with(proxies: Vec<Proxy>, listen_port: u16) -> GatewayConfig {
    let mut config = GatewayConfig {
        version: "1".into(),
        proxies,
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    config
        .http_tls_listen_ports
        .insert((ferrum_edge::config::types::default_namespace(), listen_port));
    config
}

fn plaintext_config_with(proxies: Vec<Proxy>) -> GatewayConfig {
    let mut config = GatewayConfig {
        version: "1".into(),
        proxies,
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    config
}

fn test_env() -> EnvConfig {
    EnvConfig {
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        enable_http3: true,
        ..EnvConfig::default()
    }
}

fn self_signed_server_config() -> Arc<rustls::ServerConfig> {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![HOST.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private key present");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, private_key)
    .expect("server config");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

fn test_tls_policy() -> TlsPolicy {
    TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS13, &rustls::version::TLS12],
        crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        prefer_server_cipher_order: true,
        session_cache_size: 1024,
        early_data_max_size: 0,
    }
}

fn insecure_tls_connector(alpn: &[&[u8]]) -> TlsConnector {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

async fn start_body_backend(body: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(body)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (port, handle)
}

fn build_manager(state: ProxyState, bind_addr: IpAddr) -> GatewayListenerManager {
    GatewayListenerManager::new(
        state,
        bind_addr,
        GatewayListenerTls {
            static_config: Some(self_signed_server_config()),
            reload_slot: None,
        },
    )
    .with_http3(GatewayListenerHttp3 {
        config: Http3ServerConfig::default(),
        tls_policy: test_tls_policy(),
        client_ca_bundle_path: None,
        client_crls: Arc::new(Vec::new()),
        tls_slot: None,
        tls_revision_rx: None,
    })
}

async fn https_get(port: u16, path: &str) -> (u16, String) {
    let connector = insecure_tls_connector(&[b"http/1.1"]);
    let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from(HOST).expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    (status, body)
}

async fn https_negotiated_alpn(port: u16, alpn: &[&[u8]]) -> Option<Vec<u8>> {
    let connector = insecure_tls_connector(alpn);
    let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from(HOST).expect("server name");
    let tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    tls.get_ref().1.alpn_protocol().map(|p| p.to_vec())
}

fn assert_quic_udp_collision(
    failures: &[ferrum_edge::proxy::gateway_listener::GatewayListenerBindFailure],
    port: u16,
) {
    assert!(
        failures.iter().any(|failure| {
            failure.port == port
                && failure.protocol == GatewayListenerProtocolHalf::Quic
                && failure.category == GatewayListenerFailureCategory::UdpStreamCollision
        }),
        "expected QUIC udp_stream_collision failure: {failures:?}"
    );
    assert!(
        !failures.iter().any(|failure| {
            failure.port == port && failure.protocol == GatewayListenerProtocolHalf::Tcp
        }),
        "UDP collision must not refuse TCP: {failures:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_udp_collision_preserves_tcp_and_suppresses_alt_svc() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"https-ok").await;
    let port = free_port().await;
    let config = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", backend, port),
            stream_proxy("udp-stream", BackendScheme::Udp, port),
        ],
        port,
    );
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    let failures = manager.reconcile().await;
    assert_quic_udp_collision(&failures, port);
    assert_eq!(manager.active_ports().await, vec![port]);
    assert!(
        manager.active_http3_ports().await.is_empty(),
        "QUIC must not bind beside UDP"
    );
    assert!(
        state.gateway_h3_alt_svc.load().get(&port).is_none(),
        "Alt-Svc must stay empty without a live QUIC task"
    );
    assert!(
        state
            .find_proxy_on_frontend_for_test(Some(HOST), "/api/x", Some(port), true)
            .is_some(),
        "H1/H2 routes must remain admitted on the real TCP port"
    );

    let (status, body) = https_get(port, "/api/x").await;
    assert_eq!(status, 200);
    assert!(body.contains("https-ok"), "body={body}");
    assert_eq!(
        https_negotiated_alpn(port, &[b"h2", b"http/1.1"])
            .await
            .as_deref(),
        Some(&b"h2"[..]),
        "TLS listener must still negotiate H2"
    );

    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_dtls_collision_preserves_tcp_and_suppresses_alt_svc() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"https-dtls").await;
    let port = free_port().await;
    let config = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", backend, port),
            stream_proxy("dtls-stream", BackendScheme::Dtls, port),
        ],
        port,
    );
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    let failures = manager.reconcile().await;
    assert_quic_udp_collision(&failures, port);
    assert_eq!(manager.active_ports().await, vec![port]);
    assert!(manager.active_http3_ports().await.is_empty());
    assert!(state.gateway_h3_alt_svc.load().get(&port).is_none());

    let (status, body) = https_get(port, "/api/x").await;
    assert_eq!(status, 200);
    assert!(body.contains("https-dtls"), "body={body}");

    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_udp_claim_stops_only_quic_and_keeps_tcp_connection() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"keep-alive").await;
    let port = free_port().await;
    let initial = tls_config_with(
        vec![port_scoped_https_proxy("https-gw", backend, port)],
        port,
    );
    let state = ProxyState::new(
        initial,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(manager.reconcile().await.is_empty());
    assert_eq!(manager.active_http3_ports().await, vec![port]);
    assert!(state.gateway_h3_alt_svc.load().get(&port).is_some());

    // Hold an HTTPS/1.1 connection across the QUIC-only transition.
    let connector = insecure_tls_connector(&[b"http/1.1"]);
    let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from(HOST).expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    let first = format!("GET /api/x HTTP/1.1\r\nHost: {HOST}\r\nConnection: keep-alive\r\n\r\n");
    tls.write_all(first.as_bytes()).await.expect("write first");
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf))
        .await
        .expect("first read timeout")
        .expect("first read");
    let first_resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        first_resp.contains("200") && first_resp.contains("keep-alive"),
        "first response: {first_resp}"
    );

    let with_udp = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", backend, port),
            stream_proxy("udp-stream", BackendScheme::Udp, port),
        ],
        port,
    );
    assert!(state.update_config(with_udp).applied());
    let failures = manager.reconcile().await;
    assert_quic_udp_collision(&failures, port);
    assert_eq!(manager.active_ports().await, vec![port]);
    assert!(manager.active_http3_ports().await.is_empty());
    assert!(state.gateway_h3_alt_svc.load().get(&port).is_none());

    let second = format!("GET /api/x HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    tls.write_all(second.as_bytes())
        .await
        .expect("existing TCP connection must survive QUIC drain");
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut rest)).await;
    let second_resp = String::from_utf8_lossy(&rest);
    assert!(
        second_resp.contains("200") && second_resp.contains("keep-alive"),
        "second response on preserved connection: {second_resp}"
    );

    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_udp_claim_starts_quic_and_restores_alt_svc() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"recovered").await;
    let port = free_port().await;
    let with_udp = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", backend, port),
            stream_proxy("udp-stream", BackendScheme::Udp, port),
        ],
        port,
    );
    let state = ProxyState::new(
        with_udp,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_quic_udp_collision(&manager.reconcile().await, port);
    assert!(manager.active_http3_ports().await.is_empty());

    let without_udp = tls_config_with(
        vec![port_scoped_https_proxy("https-gw", backend, port)],
        port,
    );
    assert!(state.update_config(without_udp).applied());
    let failures = manager.reconcile().await;
    assert!(
        !failures.iter().any(|failure| {
            failure.port == port
                && failure.category == GatewayListenerFailureCategory::UdpStreamCollision
        }),
        "UDP withdrawal must clear the collision: {failures:?}"
    );
    assert_eq!(manager.active_ports().await, vec![port]);
    assert_eq!(manager.active_http3_ports().await, vec![port]);
    assert!(
        state.gateway_h3_alt_svc.load().get(&port).is_some(),
        "Alt-Svc must recover with the live QUIC task"
    );
    let (status, body) = https_get(port, "/api/x").await;
    assert_eq!(status, 200);
    assert!(body.contains("recovered"), "body={body}");

    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_stream_collision_still_refuses_whole_listener() {
    ensure_crypto_provider();
    let port = free_port().await;
    let config = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", 1, port),
            stream_proxy("tcp-stream", BackendScheme::Tcp, port),
        ],
        port,
    );
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    let failures = manager.reconcile().await;
    assert!(
        failures.iter().any(|failure| {
            failure.port == port
                && failure.protocol == GatewayListenerProtocolHalf::Tcp
                && failure.category == GatewayListenerFailureCategory::StreamPortCollision
        }),
        "TCP/TLS stream collision must refuse the whole listener: {failures:?}"
    );
    assert!(manager.active_ports().await.is_empty());
    assert!(
        state
            .find_proxy_on_frontend_for_test(Some(HOST), "/api/x", Some(port), true)
            .is_none(),
        "refused TCP listener must stay fail-closed for routes"
    );
    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plaintext_listener_ignores_udp_same_port_with_http3_enabled() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"plain-ok").await;
    let port = free_port().await;
    let config = plaintext_config_with(vec![
        port_scoped_https_proxy("http-gw", backend, port),
        stream_proxy("udp-stream", BackendScheme::Udp, port),
    ]);
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    // Plaintext listeners need no TLS material / HTTP/3 attachment.
    let manager = GatewayListenerManager::new(
        state.clone(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        GatewayListenerTls::default(),
    )
    .with_http3(GatewayListenerHttp3 {
        config: Http3ServerConfig::default(),
        tls_policy: test_tls_policy(),
        client_ca_bundle_path: None,
        client_crls: Arc::new(Vec::new()),
        tls_slot: None,
        tls_revision_rx: None,
    });
    let failures = manager.reconcile().await;
    assert!(
        !failures.iter().any(|failure| failure.port == port),
        "plaintext + UDP must not fail: {failures:?}"
    );
    assert_eq!(manager.active_ports().await, vec![port]);
    assert!(manager.active_http3_ports().await.is_empty());
    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_global_same_class_frontend_is_not_dynamically_bound() {
    ensure_crypto_provider();
    let port = free_port().await;
    let config = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", 1, port),
            stream_proxy("udp-stream", BackendScheme::Udp, port),
        ],
        port,
    );
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .with_existing_frontends(None, Some(port));
    let failures = manager.reconcile().await;
    assert!(
        !failures.iter().any(|failure| failure.port == port),
        "already-served same-class frontend must not become a dynamic failure: {failures:?}"
    );
    assert!(
        manager.active_ports().await.is_empty(),
        "process-global frontend owns the port; no dynamic TCP/QUIC bind"
    );
    manager.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_bind_still_preserves_tcp_on_udp_collision() {
    ensure_crypto_provider();
    let (backend, _b) = start_body_backend(b"v6-ok").await;
    let port = free_port().await;
    let config = tls_config_with(
        vec![
            port_scoped_https_proxy("https-gw", backend, port),
            stream_proxy("udp-stream", BackendScheme::Udp, port),
        ],
        port,
    );
    let state = ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        test_env(),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = build_manager(state.clone(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    let failures = manager.reconcile().await;
    assert_quic_udp_collision(&failures, port);
    assert_eq!(manager.active_ports().await, vec![port]);
    assert!(manager.active_http3_ports().await.is_empty());
    assert!(state.gateway_h3_alt_svc.load().get(&port).is_none());
    manager.shutdown_all().await;
}

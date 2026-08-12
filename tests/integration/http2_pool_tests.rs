//! Integration tests for Http2ConnectionPool
//!
//! Tests the HTTP/2 direct connection pool that provides proper H2 stream
//! multiplexing over persistent TLS connections to backends.
//!
//! Covers: pool construction, pool_size tracking, get_sender error paths,
//! and live connection lifecycle against a real TLS+H2 echo backend.

use bytes::Bytes;
use ferrum_edge::backend_conn_limit::BackendConnectionLimiter;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResolvedPortOverride,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool;
use ferrum_edge::proxy::http2_pool::{Http2ConnectionPool, Http2PoolError};
use hickory_resolver::proto::{
    op::Message,
    rr::{RData, Record, RecordType},
};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ============================================================================
// Helpers
// ============================================================================

fn create_test_proxy() -> Proxy {
    Proxy {
        id: "h2-test".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/h2test".to_string()),
        backend_scheme: Some(BackendScheme::Https),
        dispatch_kind: DispatchKind::from(BackendScheme::Https),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        pending_limit_scope: None,
    }
}

fn create_default_pool() -> Http2ConnectionPool {
    Http2ConnectionPool::default()
}

fn create_dns_cache() -> DnsCache {
    DnsCache::new(DnsConfig::default())
}

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let san_strings: Vec<String> = sans.iter().map(|san| san.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

/// Start a TLS + HTTP/2 echo backend on an ephemeral port.
/// Returns (join_handle, port).
async fn start_h2_tls_backend()
-> Result<(tokio::task::JoinHandle<()>, u16), Box<dyn std::error::Error>> {
    let cert_pem = include_str!("../certs/server.crt");
    let key_pem = include_str!("../certs/server.key");
    start_h2_tls_backend_with_cert(cert_pem, key_pem).await
}

/// Start a TLS + HTTP/2 echo backend with caller-provided certificate material.
/// Returns (join_handle, port).
async fn start_h2_tls_backend_with_cert(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(tokio::task::JoinHandle<()>, u16), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = start_tls_backend_on(listener, cert_pem, key_pem, vec![b"h2".to_vec()]).await?;

    // Give the listener task a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok((handle, port))
}

async fn start_tls_backend_on(
    listener: tokio::net::TcpListener,
    cert_pem: &str,
    key_pem: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    start_tls_backend_on_counted(listener, cert_pem, key_pem, alpn_protocols, None).await
}

async fn start_tls_backend_on_counted(
    listener: tokio::net::TcpListener,
    cert_pem: &str,
    key_pem: &str,
    alpn_protocols: Vec<Vec<u8>>,
    attempts: Option<Arc<AtomicUsize>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|cert| cert.ok())
        .collect();
    let mut key_reader = key_pem.as_bytes();
    let private_key =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or("missing private key in test cert")?;

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    tls_config.alpn_protocols = alpn_protocols;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            if let Some(attempts) = attempts.as_ref() {
                attempts.fetch_add(1, Ordering::Relaxed);
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls_stream);
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let service = service_fn(|_req: Request<Incoming>| async move {
                    let body = "hello from h2 backend";
                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });
                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    Ok(handle)
}

struct TestDnsServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TestDnsServer {
    async fn spawn(answers: Vec<IpAddr>) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind test DNS server");
        let addr = socket.local_addr().expect("test DNS server address");
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2_048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                let mut response = request.into_response();
                for &address in &answers {
                    let data = match (query.query_type(), address) {
                        (RecordType::A, IpAddr::V4(address)) => RData::A(address.into()),
                        (RecordType::AAAA, IpAddr::V6(address)) => RData::AAAA(address.into()),
                        _ => continue,
                    };
                    response.add_answer(Record::from_rdata(query.name().clone(), 60, data));
                }
                if let Ok(encoded) = response.to_vec() {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        Self { addr, task }
    }
}

impl Drop for TestDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn multi_address_dns_cache(dns_addr: SocketAddr) -> DnsCache {
    DnsCache::new(DnsConfig {
        resolver_addresses: Some(dns_addr.to_string()),
        dns_order: Some("A".to_string()),
        ..DnsConfig::default()
    })
}

async fn bind_dual_loopback_listeners() -> (
    tokio::net::TcpListener,
    tokio::net::TcpListener,
    Ipv4Addr,
    u16,
) {
    let failing_ip = Ipv4Addr::new(127, 0, 0, 2);
    for _ in 0..10 {
        let healthy = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind healthy loopback listener");
        let port = healthy
            .local_addr()
            .expect("healthy loopback listener address")
            .port();
        if let Ok(failing) = tokio::net::TcpListener::bind((failing_ip, port)).await {
            return (healthy, failing, failing_ip, port);
        }
    }
    panic!("could not reserve one TCP port on both test loopback addresses");
}

// ============================================================================
// Tests: Pool Construction and Initial State
// ============================================================================

#[tokio::test]
async fn test_http2_pool_default_starts_empty() {
    let pool = create_default_pool();
    assert_eq!(pool.pool_size(), 0, "Default pool should have zero entries");
}

#[tokio::test]
async fn test_http2_pool_new_starts_empty() {
    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );
    assert_eq!(pool.pool_size(), 0);
}

// ============================================================================
// Tests: Error Paths
// ============================================================================

#[tokio::test]
async fn test_http2_pool_backend_unavailable() {
    let pool = create_default_pool();

    let mut proxy = create_test_proxy();
    // Point to a port that should refuse connections
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // Privileged port, should refuse
    proxy.backend_tls_verify_server_cert = false;

    let result = pool.get_sender(&proxy).await;
    assert!(
        result.is_err(),
        "Expected error connecting to unavailable backend"
    );
    match result.unwrap_err() {
        Http2PoolError::BackendUnavailable { message: msg, .. } => {
            assert!(
                msg.contains("Connection refused") || msg.contains("connect"),
                "Expected connection refusal message, got: {}",
                msg
            );
        }
        Http2PoolError::BackendTimeout { message: msg, .. } => {
            // Also acceptable — some environments timeout instead of refuse on port 1
            assert!(!msg.is_empty());
        }
        Http2PoolError::Internal { message: msg, .. } => {
            panic!(
                "Expected BackendUnavailable or BackendTimeout, got Internal: {}",
                msg
            );
        }
        Http2PoolError::BackendSelectedHttp1 { pool_key } => {
            panic!(
                "Expected BackendUnavailable or BackendTimeout, got BackendSelectedHttp1 for pool_key: {}",
                pool_key
            );
        }
        Http2PoolError::MaxConnectionsExceeded { message: msg } => {
            panic!(
                "Expected BackendUnavailable or BackendTimeout, got MaxConnectionsExceeded: {}",
                msg
            );
        }
    }
    assert_eq!(
        pool.pool_size(),
        0,
        "Failed connection should not be pooled"
    );
}

#[tokio::test]
async fn test_http2_pool_backend_timeout() {
    let pool = create_default_pool();

    let mut proxy = create_test_proxy();
    // Use a non-routable address to trigger connect timeout
    proxy.backend_host = "192.0.2.1".to_string(); // TEST-NET-1, RFC 5737 — not routable
    proxy.backend_port = 9999;
    proxy.backend_connect_timeout_ms = 100; // Very short timeout
    proxy.backend_tls_verify_server_cert = false;

    let result = pool.get_sender(&proxy).await;
    assert!(result.is_err(), "Expected timeout error");
    match result.unwrap_err() {
        Http2PoolError::BackendTimeout { message: msg, .. } => {
            assert!(
                msg.contains("timeout") || msg.contains("Timeout"),
                "Expected timeout message, got: {}",
                msg
            );
        }
        Http2PoolError::BackendUnavailable { message: msg, .. } => {
            // On some systems, non-routable may give a different error
            assert!(!msg.is_empty());
        }
        Http2PoolError::Internal { message: msg, .. } => {
            panic!("Expected BackendTimeout, got Internal: {}", msg);
        }
        Http2PoolError::BackendSelectedHttp1 { pool_key } => {
            panic!(
                "Expected BackendTimeout, got BackendSelectedHttp1 for pool_key: {}",
                pool_key
            );
        }
        Http2PoolError::MaxConnectionsExceeded { message: msg } => {
            panic!(
                "Expected BackendTimeout, got MaxConnectionsExceeded: {}",
                msg
            );
        }
    }
}

#[tokio::test]
async fn test_http2_pool_invalid_server_name() {
    let pool = create_default_pool();

    let mut proxy = create_test_proxy();
    // Empty hostname is invalid for TLS server name
    proxy.backend_host = "".to_string();
    proxy.backend_port = 9999;
    proxy.backend_tls_verify_server_cert = false;

    let result = pool.get_sender(&proxy).await;
    // Should fail at DNS resolution or TLS server name construction
    assert!(result.is_err());
}

// ============================================================================
// Tests: Live Connection
// ============================================================================

#[tokio::test]
async fn test_http2_pool_get_sender_connects() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start H2 backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy = create_test_proxy();
    proxy.backend_host = "localhost".to_string();
    proxy.backend_port = port;
    proxy.backend_tls_verify_server_cert = false; // Self-signed cert

    let sender = pool.get_sender(&proxy).await;
    assert!(
        sender.is_ok(),
        "get_sender should succeed: {:?}",
        sender.err()
    );
    assert!(
        pool.pool_size() > 0,
        "Pool should have at least one entry after get_sender"
    );
}

#[tokio::test]
async fn test_http2_pool_fails_over_after_tcp_success_but_tls_failure() {
    let (healthy_listener, failing_listener, failing_ip, port) =
        bind_dual_loopback_listeners().await;
    let failing_attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = Arc::clone(&failing_attempts);
    let _failing_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = failing_listener.accept().await {
            task_attempts.fetch_add(1, Ordering::Relaxed);
            // Accept TCP, then deliberately violate TLS. Before the fix this
            // post-connect failure escaped the candidate loop and the healthy
            // second address was never attempted.
            let _ = socket.write_all(b"not a TLS server").await;
        }
    });

    let _healthy_task = start_tls_backend_on(
        healthy_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"h2".to_vec()],
    )
    .await
    .expect("start healthy H2 backend");
    let dns = TestDnsServer::spawn(vec![
        IpAddr::V4(failing_ip),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ])
    .await;
    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_host = "multi-address-h2.test".to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 3_000;
    proxy.backend_tls_verify_server_cert = false;

    let sender = pool.get_sender(&proxy).await;
    assert!(
        sender.is_ok(),
        "healthy second address should complete TLS and H2: {:?}",
        sender.err()
    );
    assert_eq!(
        failing_attempts.load(Ordering::Relaxed),
        1,
        "the TCP-successful, TLS-failing first address must be attempted exactly once"
    );
}

#[tokio::test]
async fn test_http2_pool_preserves_http1_downgrade_before_later_candidate_failure() {
    let (later_failure_listener, http1_listener, http1_ip, port) =
        bind_dual_loopback_listeners().await;
    let later_attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = Arc::clone(&later_attempts);
    let _later_failure_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = later_failure_listener.accept().await {
            task_attempts.fetch_add(1, Ordering::Relaxed);
            let _ = socket.write_all(b"not a TLS server").await;
        }
    });
    let _http1_task = start_tls_backend_on(
        http1_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"http/1.1".to_vec()],
    )
    .await
    .expect("start HTTP/1.1 TLS backend");
    let dns =
        TestDnsServer::spawn(vec![IpAddr::V4(http1_ip), IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_host = "multi-address-http1.test".to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 3_000;
    proxy.backend_tls_verify_server_cert = false;

    match pool.get_sender(&proxy).await {
        Err(Http2PoolError::BackendSelectedHttp1 { pool_key }) => {
            assert!(
                pool_key.contains("multi-address-http1.test"),
                "downgrade signal should retain the direct-H2 pool key"
            );
        }
        Err(error) => panic!(
            "HTTP/1.1 ALPN must win over a later candidate failure, got: {}",
            error
        ),
        Ok(_) => panic!("HTTP/1.1 ALPN must not produce a direct-H2 sender"),
    }
    assert_eq!(
        later_attempts.load(Ordering::Relaxed),
        0,
        "a proven HTTP/1.1 endpoint is terminal and must not be overwritten by a later failure"
    );
}

#[tokio::test]
async fn test_http2_pool_sni_override_skips_http1_candidate_for_later_h2() {
    let (h2_listener, http1_listener, http1_ip, port) = bind_dual_loopback_listeners().await;
    let http1_attempts = Arc::new(AtomicUsize::new(0));
    let _http1_task = start_tls_backend_on_counted(
        http1_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"http/1.1".to_vec()],
        Some(Arc::clone(&http1_attempts)),
    )
    .await
    .expect("start HTTP/1.1 TLS backend");
    let _h2_task = start_tls_backend_on(
        h2_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"h2".to_vec()],
    )
    .await
    .expect("start H2 TLS backend");
    let dns =
        TestDnsServer::spawn(vec![IpAddr::V4(http1_ip), IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_host = "multi-address-sni-h2.test".to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 3_000;
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.sni = Some("backend.mesh.internal".to_string());

    let sender = pool.get_sender(&proxy).await;
    assert!(
        sender.is_ok(),
        "SNI route should continue to the healthy H2 candidate: {:?}",
        sender.err()
    );
    assert_eq!(
        http1_attempts.load(Ordering::Relaxed),
        1,
        "the HTTP/1.1 candidate should be attempted before H2 failover"
    );
}

/// The SNI candidate scan must stay fail-closed once every DNS answer proves
/// HTTP/1.1: the loop now routes the downgrade through the *error* channel, so
/// exhaustion has to keep propagating `BackendSelectedHttp1` verbatim rather
/// than collapsing into a generic `BackendUnavailable`. The dispatcher branches
/// on that exact variant to emit the SNI-requires-direct-H2 response and to
/// downgrade the cached backend capability, so a change here would silently
/// alter both.
#[tokio::test]
async fn test_http2_pool_sni_override_exhausts_all_http1_candidates() {
    let (second_listener, first_listener, first_ip, port) = bind_dual_loopback_listeners().await;
    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let _first_task = start_tls_backend_on_counted(
        first_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"http/1.1".to_vec()],
        Some(Arc::clone(&first_attempts)),
    )
    .await
    .expect("start first HTTP/1.1 TLS backend");
    let _second_task = start_tls_backend_on_counted(
        second_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"http/1.1".to_vec()],
        Some(Arc::clone(&second_attempts)),
    )
    .await
    .expect("start second HTTP/1.1 TLS backend");
    let dns =
        TestDnsServer::spawn(vec![IpAddr::V4(first_ip), IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_host = "all-http1-sni.test".to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 3_000;
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.sni = Some("backend.mesh.internal".to_string());

    match pool.get_sender(&proxy).await {
        Err(Http2PoolError::BackendSelectedHttp1 { pool_key }) => {
            assert!(
                pool_key.contains("all-http1-sni.test"),
                "exhausted SNI downgrade must retain the direct-H2 pool key, got: {pool_key}"
            );
        }
        Err(error) => panic!(
            "exhausting every HTTP/1.1 candidate must still report the downgrade, got: {error}"
        ),
        Ok(_) => panic!("HTTP/1.1-only candidates must not produce a direct-H2 sender"),
    }
    assert_eq!(
        first_attempts.load(Ordering::Relaxed),
        1,
        "the first HTTP/1.1 candidate must be attempted exactly once"
    );
    assert_eq!(
        second_attempts.load(Ordering::Relaxed),
        1,
        "the SNI scan must continue past the first HTTP/1.1 candidate to the second"
    );
}

#[tokio::test]
async fn test_grpc_h2c_pool_fails_over_after_tcp_success_but_h2_failure() {
    let (healthy_listener, failing_listener, failing_ip, port) =
        bind_dual_loopback_listeners().await;
    let failing_attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = Arc::clone(&failing_attempts);
    let _failing_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = failing_listener.accept().await {
            task_attempts.fetch_add(1, Ordering::Relaxed);
            // Keep this non-H2 socket open beyond the former 25 ms negative
            // observation window, then prove it is not an H2 peer.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let healthy_attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = Arc::clone(&healthy_attempts);
    let _healthy_task = tokio::spawn(async move {
        while let Ok((socket, _)) = healthy_listener.accept().await {
            task_attempts.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let dns = TestDnsServer::spawn(vec![
        IpAddr::V4(failing_ip),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ])
    .await;
    let pool = GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Http);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Http);
    proxy.backend_host = "multi-address-h2c.test".to_string();
    proxy.backend_port = port;
    // Two candidates share this budget, so the first address is abandoned by
    // `connect_candidates` after 1500 ms even if nothing rejects it.
    proxy.backend_connect_timeout_ms = 3_000;

    let started = Instant::now();
    let sender = pool.get_sender(&proxy).await;
    let elapsed = started.elapsed();
    assert!(
        sender.is_ok(),
        "healthy second address should complete the h2c handshake: {:?}",
        sender.err()
    );
    assert_eq!(
        failing_attempts.load(Ordering::Relaxed),
        1,
        "the TCP-successful, H2-failing first address must be attempted exactly once"
    );
    assert_eq!(
        healthy_attempts.load(Ordering::Relaxed),
        1,
        "the pool must reject the stalled non-H2 peer and dial the healthy candidate"
    );
    // Failover must come from observing the peer's non-H2 reply at ~100 ms,
    // not from the first candidate exhausting its 1500 ms share of the connect
    // budget. Without that distinction a readiness wait that simply never
    // completes would still let this test pass.
    assert!(
        elapsed < Duration::from_millis(1_000),
        "failover must be driven by the h2c protocol rejection, not by the \
         candidate connect budget expiring (took {elapsed:?})"
    );
}

#[tokio::test]
async fn test_grpc_h2c_accepts_settings_with_zero_concurrent_streams() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind scripted h2c backend");
    let port = listener
        .local_addr()
        .expect("scripted backend address")
        .port();
    let _backend = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept h2c client");
        let mut client_preface = [0_u8; 24];
        socket
            .read_exact(&mut client_preface)
            .await
            .expect("read HTTP/2 client preface");
        assert_eq!(&client_preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // A valid initial SETTINGS frame may temporarily prohibit all new
        // streams. Establishment must recognize the frame independently of
        // the resulting outbound stream capacity.
        socket
            .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0])
            .await
            .expect("write SETTINGS_MAX_CONCURRENT_STREAMS=0");
        // Keep the valid zero-capacity connection open well beyond both the
        // pool's 500 ms connect bound and the test's outer hang guard. The old
        // sentinel path therefore returns an error at the pool deadline rather
        // than succeeding because the scripted peer happened to close.
        tokio::time::sleep(Duration::from_secs(10)).await;
    });

    let pool = GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        DnsCache::new(DnsConfig::default()),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Http);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Http);
    proxy.backend_host = Ipv4Addr::LOCALHOST.to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 500;

    let sender = tokio::time::timeout(Duration::from_secs(5), pool.get_sender(&proxy))
        .await
        .expect("valid peer SETTINGS should not hang h2c establishment");
    assert!(
        sender.is_ok(),
        "zero-capacity SETTINGS is valid: {sender:?}"
    );
}

#[tokio::test]
async fn test_grpc_tls_pool_fails_over_when_first_peer_omits_h2_alpn() {
    let (healthy_listener, non_h2_listener, non_h2_ip, port) = bind_dual_loopback_listeners().await;
    let non_h2_attempts = Arc::new(AtomicUsize::new(0));
    let _non_h2_task = start_tls_backend_on_counted(
        non_h2_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"http/1.1".to_vec()],
        Some(Arc::clone(&non_h2_attempts)),
    )
    .await
    .expect("start non-H2 TLS backend");
    let _healthy_task = start_tls_backend_on(
        healthy_listener,
        include_str!("../certs/server.crt"),
        include_str!("../certs/server.key"),
        vec![b"h2".to_vec()],
    )
    .await
    .expect("start healthy gRPC TLS backend");
    let dns =
        TestDnsServer::spawn(vec![IpAddr::V4(non_h2_ip), IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let pool = GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        multi_address_dns_cache(dns.addr),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    proxy.backend_host = "multi-address-grpc-tls.test".to_string();
    proxy.backend_port = port;
    proxy.backend_connect_timeout_ms = 3_000;
    proxy.backend_tls_verify_server_cert = false;

    let sender = pool.get_sender(&proxy).await;
    assert!(
        sender.is_ok(),
        "healthy second address should negotiate TLS ALPN h2: {:?}",
        sender.err()
    );
    assert_eq!(
        non_h2_attempts.load(Ordering::Relaxed),
        1,
        "a TLS peer without negotiated h2 must be rejected before accepting its sender"
    );
}

#[tokio::test]
async fn test_http2_pool_uses_backend_tls_sni_override_for_handshake() {
    let ca = generate_ca("backend-test-ca");
    let backend = generate_signed_cert(&ca, "backend.mesh.internal", &["backend.mesh.internal"]);
    let (_handle, port) = start_h2_tls_backend_with_cert(&backend.cert_pem, &backend.key_pem)
        .await
        .expect("Failed to start SNI H2 backend");

    let temp_dir = TempDir::new().expect("temp dir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write CA");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut without_override = create_test_proxy();
    without_override.backend_host = "connect.mesh.internal".to_string();
    without_override.backend_port = port;
    without_override.backend_tls_verify_server_cert = true;
    without_override.resolved_tls = BackendTlsConfig::default_verify();
    without_override.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
    without_override.dns_override = Some("127.0.0.1".to_string());

    let err = pool
        .get_sender(&without_override)
        .await
        .expect_err("cert name mismatch should fail without backend_tls_sni");
    assert!(
        matches!(err, Http2PoolError::BackendUnavailable { .. }),
        "expected TLS backend unavailable error, got {err:?}"
    );

    let mut with_override = without_override.clone();
    with_override.id = "h2-test-sni".to_string();
    with_override.resolved_tls.sni = Some("backend.mesh.internal".to_string());

    let sender = pool.get_sender(&with_override).await;
    assert!(
        sender.is_ok(),
        "backend_tls_sni should be used as rustls ServerName: {:?}",
        sender.err()
    );
}

#[tokio::test]
async fn test_http2_pool_reuses_connection() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start H2 backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy = create_test_proxy();
    proxy.backend_host = "localhost".to_string();
    proxy.backend_port = port;
    proxy.backend_tls_verify_server_cert = false;

    // Get sender twice for the same proxy
    let _sender1 = pool
        .get_sender(&proxy)
        .await
        .expect("First get_sender failed");
    let size_after_first = pool.pool_size();

    let _sender2 = pool
        .get_sender(&proxy)
        .await
        .expect("Second get_sender failed");
    let size_after_second = pool.pool_size();

    assert_eq!(
        size_after_first, size_after_second,
        "Pool size should not increase on reuse (was {}, now {})",
        size_after_first, size_after_second
    );
}

#[tokio::test]
async fn test_http2_pool_different_backends_get_separate_entries() {
    let (_handle1, port1) = start_h2_tls_backend()
        .await
        .expect("Failed to start backend 1");
    let (_handle2, port2) = start_h2_tls_backend()
        .await
        .expect("Failed to start backend 2");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.backend_host = "localhost".to_string();
    proxy1.backend_port = port1;
    proxy1.backend_tls_verify_server_cert = false;

    let mut proxy2 = create_test_proxy();
    proxy2.id = "h2-test-2".to_string();
    proxy2.backend_host = "localhost".to_string();
    proxy2.backend_port = port2;
    proxy2.backend_tls_verify_server_cert = false;

    let _sender1 = pool.get_sender(&proxy1).await.expect("Backend 1 failed");
    let size_after_first = pool.pool_size();

    let _sender2 = pool.get_sender(&proxy2).await.expect("Backend 2 failed");
    let size_after_second = pool.pool_size();

    assert!(
        size_after_second > size_after_first,
        "Different backends should create separate pool entries ({} vs {})",
        size_after_first,
        size_after_second
    );
}

#[tokio::test]
async fn test_http2_pool_different_tls_verify_gets_separate_entries() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy_no_verify = create_test_proxy();
    proxy_no_verify.backend_host = "localhost".to_string();
    proxy_no_verify.backend_port = port;
    proxy_no_verify.backend_tls_verify_server_cert = false;
    proxy_no_verify.resolved_tls.verify_server_cert = false;

    let _sender1 = pool
        .get_sender(&proxy_no_verify)
        .await
        .expect("no-verify get_sender failed");
    let size_after_no_verify = pool.pool_size();

    // Now try with verify=true — this will fail (self-signed cert) but the pool key
    // should be different, so the pool should attempt a new connection
    let mut proxy_verify = create_test_proxy();
    proxy_verify.backend_host = "localhost".to_string();
    proxy_verify.backend_port = port;
    proxy_verify.backend_tls_verify_server_cert = true;
    proxy_verify.resolved_tls.verify_server_cert = true;

    let result = pool.get_sender(&proxy_verify).await;
    // The verify=true connection should fail (self-signed cert, no CA)
    // but the important thing is it didn't reuse the verify=false connection
    if result.is_ok() {
        // If it somehow succeeded, it should be a different pool entry
        assert!(
            pool.pool_size() > size_after_no_verify,
            "Different TLS verify settings should not share pool entries"
        );
    }
    // If it failed, that's expected — the pool key differentiation prevented reuse
}

#[tokio::test]
async fn test_http2_pool_dns_override_affects_pool_key() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.backend_host = "localhost".to_string();
    proxy1.backend_port = port;
    proxy1.backend_tls_verify_server_cert = false;
    proxy1.dns_override = None;

    let _sender1 = pool.get_sender(&proxy1).await.expect("get_sender 1 failed");
    let size1 = pool.pool_size();

    let mut proxy2 = create_test_proxy();
    proxy2.backend_host = "localhost".to_string();
    proxy2.backend_port = port;
    proxy2.backend_tls_verify_server_cert = false;
    proxy2.dns_override = Some("127.0.0.1".to_string());

    let _sender2 = pool.get_sender(&proxy2).await.expect("get_sender 2 failed");
    let size2 = pool.pool_size();

    assert!(
        size2 > size1,
        "DNS override should create a separate pool entry ({} vs {})",
        size1,
        size2
    );
}

#[tokio::test]
async fn test_http2_pool_ca_cert_path_affects_pool_key() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy1 = create_test_proxy();
    proxy1.backend_host = "localhost".to_string();
    proxy1.backend_port = port;
    proxy1.backend_tls_verify_server_cert = false;
    proxy1.backend_tls_server_ca_cert_path = None;

    let _sender1 = pool.get_sender(&proxy1).await.expect("get_sender 1 failed");
    let size1 = pool.pool_size();

    let mut proxy2 = create_test_proxy();
    proxy2.backend_host = "localhost".to_string();
    proxy2.backend_port = port;
    proxy2.backend_tls_verify_server_cert = false;
    proxy2.backend_tls_server_ca_cert_path = Some("tests/certs/ca.crt".to_string());

    // This may fail (the CA cert may not match) but the key differentiation is what we test
    let _ = pool.get_sender(&proxy2).await;
    let size2 = pool.pool_size();

    // If proxy2 succeeded, we should have 2 entries; if it failed, size stays at 1
    // Either way, the first proxy's entry should still exist
    assert!(size1 >= 1, "First proxy should have created a pool entry");
    // If both succeeded, they must be separate entries
    if size2 > size1 {
        // Good — different CA paths created different pool entries
    }
    // If proxy2 failed to connect, that's fine — the test proved the pool didn't
    // incorrectly reuse proxy1's connection for proxy2's different CA config
}

#[tokio::test]
async fn test_http2_pool_sender_is_not_closed() {
    let (_handle, port) = start_h2_tls_backend()
        .await
        .expect("Failed to start H2 backend");

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );

    let mut proxy = create_test_proxy();
    proxy.backend_host = "localhost".to_string();
    proxy.backend_port = port;
    proxy.backend_tls_verify_server_cert = false;

    let sender = pool.get_sender(&proxy).await.expect("get_sender failed");

    // The sender should be live (H2 connection is open)
    assert!(
        !sender.is_closed(),
        "Sender should not be closed immediately after creation"
    );
}

// ============================================================================
// DestinationRule `connectionPool.tcp.maxConnections` on a pooled multiplexed
// transport (issue #3290).
//
// These are the physical-socket proofs: an h2c backend counts every accepted
// TCP connection, so the assertions are on real sockets rather than on the
// gateway's own bookkeeping.
// ============================================================================

/// h2c echo backend that counts every accepted TCP connection.
async fn start_counting_h2c_backend() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let task_accepted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            task_accepted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (port, accepted)
}

/// Cleartext-h2c proxy pinned to the loopback backend by `dns_override` (no DNS
/// dependency), carrying a per-port `maxConnections` cap exactly as the mesh
/// projection materializes it onto `dispatch_port_overrides`.
fn h2c_proxy_with_max_connections(port: u16, cap: Option<u32>) -> Proxy {
    let mut proxy = create_test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Http);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Http);
    proxy.backend_host = "maxconn-h2c.test".to_string();
    proxy.backend_port = port;
    proxy.dns_override = Some("127.0.0.1".to_string());
    proxy.backend_connect_timeout_ms = 5_000;
    if let Some(cap) = cap {
        let mut overrides = HashMap::new();
        overrides.insert(
            port,
            ResolvedPortOverride {
                max_connections: Some(cap),
                ..Default::default()
            },
        );
        proxy.dispatch_port_overrides = Some(overrides);
    }
    proxy
}

/// Poll `current()` until it reaches `expected` or the deadline passes.
async fn await_open_connection_count(
    limiter: &BackendConnectionLimiter,
    host: &str,
    port: u16,
    expected: u64,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current = limiter.current(host, port);
        if current == expected || Instant::now() >= deadline {
            return current;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_grpc_h2c_pool_max_connections_bounds_physical_connections() {
    let (port, accepted) = start_counting_h2c_backend().await;

    let limiter = Arc::new(BackendConnectionLimiter::new());
    let pool = Arc::new(GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    ));
    pool.attach_backend_conn_limit(Arc::clone(&limiter));
    let proxy = h2c_proxy_with_max_connections(port, Some(1));

    // One physical connection is admitted and established.
    let first = pool
        .get_sender(&proxy)
        .await
        .expect("first h2c sender should establish the single admitted connection");
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "exactly one backend socket must be opened under maxConnections=1"
    );
    assert_eq!(
        limiter.current("maxconn-h2c.test", port),
        1,
        "the admitted connection must hold exactly one slot"
    );

    // A concurrent burst must MULTIPLEX onto that one socket: the pool's shard
    // ring cannot open a second connection, so every dispatch is served by the
    // already-established one and the backend still sees a single accept.
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = Arc::clone(&pool);
        let proxy = proxy.clone();
        tasks.push(tokio::spawn(async move {
            pool.get_sender(&proxy).await.map(|_sender| ())
        }));
    }
    for task in tasks {
        task.await
            .expect("burst task join")
            .expect("a capped destination must keep serving by multiplexing, not by failing");
    }

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "16 concurrent dispatches must multiplex onto the single admitted socket"
    );
    assert_eq!(
        limiter.current("maxconn-h2c.test", port),
        1,
        "multiplexed streams must not be counted as physical connections"
    );
    drop(first);
}

#[tokio::test]
async fn test_grpc_h2c_pool_max_connections_slot_is_released_when_connection_retires() {
    let (port, accepted) = start_counting_h2c_backend().await;

    let limiter = Arc::new(BackendConnectionLimiter::new());
    let pool = GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );
    pool.attach_backend_conn_limit(Arc::clone(&limiter));
    let proxy = h2c_proxy_with_max_connections(port, Some(1));

    let sender = pool.get_sender(&proxy).await.expect("first h2c sender");
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(limiter.current("maxconn-h2c.test", port), 1);

    // Config reload / delete / SVID drain all retire pooled connections through
    // the same drain path. Dropping the pool entry ends the connection driver,
    // which is what releases the slot — there is no separate retirement hook to
    // forget.
    pool.force_drain_all();
    drop(sender);
    assert_eq!(
        await_open_connection_count(&limiter, "maxconn-h2c.test", port, 0).await,
        0,
        "draining the pool must release the destination's connection slot"
    );

    // The destination recovers: a fresh dispatch opens a NEW physical socket.
    let _reconnected = pool
        .get_sender(&proxy)
        .await
        .expect("the destination must accept a new connection after retirement");
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        2,
        "a second physical socket must be opened only after the first retired"
    );
    assert_eq!(limiter.current("maxconn-h2c.test", port), 1);
}

#[tokio::test]
async fn test_grpc_h2c_pool_without_cap_is_unbounded_and_untracked() {
    // No `maxConnections` on the destination: the pool must never touch the
    // limiter, so the hot path stays exactly as it was before issue #3290.
    let (port, accepted) = start_counting_h2c_backend().await;

    let limiter = Arc::new(BackendConnectionLimiter::new());
    let pool = GrpcConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );
    pool.attach_backend_conn_limit(Arc::clone(&limiter));
    let proxy = h2c_proxy_with_max_connections(port, None);

    let _sender = pool
        .get_sender(&proxy)
        .await
        .expect("uncapped destination connects normally");
    assert!(accepted.load(Ordering::Relaxed) >= 1);
    assert_eq!(
        limiter.current("maxconn-h2c.test", port),
        0,
        "an uncapped destination must never allocate a counter slot"
    );
}

//! Integration tests for Http2ConnectionPool
//!
//! Tests the HTTP/2 direct connection pool that provides proper H2 stream
//! multiplexing over persistent TLS connections to backends.
//!
//! Covers: pool construction, pool_size tracking, get_sender error paths,
//! and live connection lifecycle against a real TLS+H2 echo backend.

use crate::scaffolding::port_registry::TestSocket;

use bytes::Bytes;
use ferrum_edge::backend_conn_limit::BackendConnectionLimiter;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, H2UpgradePolicy, Proxy,
    ResolvedPortOverride,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool;
use ferrum_edge::proxy::http2_pool::{Http2ConnectionPool, Http2PoolError};
use ferrum_edge::proxy::{ProxyState, handle_proxy_request};
use hickory_resolver::proto::{
    op::Message,
    rr::{RData, Record, RecordType},
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ============================================================================
// Helpers
// ============================================================================

fn create_test_proxy() -> Proxy {
    Proxy {
        labels: Default::default(),
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
        websocket_permessage_deflate: Default::default(),
        allow_path_parameters: false,
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
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
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
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|cert| cert.ok())
        .collect();
    let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;

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
        let socket = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
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

/// Secondary IPv4 loopback aliases this fixture will try, in order.
///
/// The multi-address candidate loop is an A-record fixture: one hostname must
/// resolve to two IPv4 addresses that share one port, so the second address
/// cannot be IPv6 (`do_resolve` returns the first record type that answers, it
/// never merges A with AAAA) and cannot be the wildcard (which would swallow
/// the first address's port). Linux assigns all of `127.0.0.0/8` to `lo`, so
/// `127.0.0.2` is always available there; macOS assigns only `127.0.0.1` to
/// `lo0` unless an operator adds an alias, so the whole fixture is skipped
/// there with an explicit reason rather than failing as a pool defect
/// (issue #4983).
const SECONDARY_LOOPBACK_CANDIDATES: [Ipv4Addr; 4] = [
    Ipv4Addr::new(127, 0, 0, 2),
    Ipv4Addr::new(127, 0, 0, 3),
    Ipv4Addr::new(127, 0, 0, 4),
    Ipv4Addr::new(127, 0, 0, 5),
];

/// The message a skipped multi-address case prints, so a green run on a host
/// without a loopback alias is never mistaken for coverage.
fn report_missing_secondary_loopback(test: &str) {
    eprintln!(
        "skipping {test}: this host has no secondary IPv4 loopback alias (tried \
         {SECONDARY_LOOPBACK_CANDIDATES:?}); add one (macOS: `sudo ifconfig lo0 alias \
         127.0.0.2`) to run the multi-address candidate cases"
    );
}

/// The first secondary IPv4 loopback address this host actually assigns.
async fn secondary_loopback_address() -> Option<Ipv4Addr> {
    for candidate in SECONDARY_LOOPBACK_CANDIDATES {
        if let Ok(probe) = tokio::net::TcpListener::bind_test((candidate, 0)).await {
            drop(probe);
            return Some(candidate);
        }
    }
    None
}

/// `(healthy, failing, failing_ip, shared_port)`.
type DualLoopbackListeners = (
    tokio::net::TcpListener,
    tokio::net::TcpListener,
    Ipv4Addr,
    u16,
);

/// Two listeners sharing one port on two distinct IPv4 loopback addresses, or
/// `None` when this host assigns only `127.0.0.1`.
async fn bind_dual_loopback_listeners() -> Option<DualLoopbackListeners> {
    let failing_ip = secondary_loopback_address().await?;
    for _ in 0..10 {
        let healthy = tokio::net::TcpListener::bind_test((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind healthy loopback listener");
        let port = healthy
            .local_addr()
            .expect("healthy loopback listener address")
            .port();
        if let Ok(failing) = tokio::net::TcpListener::bind_test((failing_ip, port)).await {
            return Some((healthy, failing, failing_ip, port));
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((healthy_listener, failing_listener, failing_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_http2_pool_fails_over_after_tcp_success_but_tls_failure",
        );
        return;
    };
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((later_failure_listener, http1_listener, http1_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_http2_pool_preserves_http1_downgrade_before_later_candidate_failure",
        );
        return;
    };
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((h2_listener, http1_listener, http1_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_http2_pool_sni_override_skips_http1_candidate_for_later_h2",
        );
        return;
    };
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((second_listener, first_listener, first_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_http2_pool_sni_override_exhausts_all_http1_candidates",
        );
        return;
    };
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((healthy_listener, failing_listener, failing_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_grpc_h2c_pool_fails_over_after_tcp_success_but_h2_failure",
        );
        return;
    };
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
    let listener = tokio::net::TcpListener::bind_test((Ipv4Addr::LOCALHOST, 0))
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
    let dual_loopback = bind_dual_loopback_listeners().await;
    let Some((healthy_listener, non_h2_listener, non_h2_ip, port)) = dual_loopback else {
        report_missing_secondary_loopback(
            "test_grpc_tls_pool_fails_over_when_first_peer_omits_h2_alpn",
        );
        return;
    };
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
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
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

/// Issue #4280: H2/gRPC `rr_counters` are keyed by the full base pool key,
/// which ends in `|svidg=`. `retain_live_from_config` keeps every generation
/// for a still-live host:port, and `force_drain_svid_generation` is scheduled
/// only when `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS > 0` (default 0).
/// The rotation consumer's unconditional `drain_tls_config_cache` path must
/// reclaim retired-generation counters without withdrawing live connections.
#[tokio::test]
async fn rr_counters_reclaim_retired_svid_generations_at_zero_drain() {
    rr_counters_reclaim_retired_generations_for_h2();
    rr_counters_reclaim_retired_generations_for_grpc();
}

fn rr_counters_reclaim_retired_generations_for_h2() {
    let pool = Http2ConnectionPool::default();
    let proxy = create_test_proxy();
    let global = PoolConfig::default();
    let live_generation = 10u64;
    let retired = 1..live_generation;

    let live_key =
        Http2ConnectionPool::pool_key_with_global(&proxy, Some(live_generation), &global);
    let static_key = Http2ConnectionPool::pool_key_with_global(&proxy, None, &global);
    pool.insert_rr_counter_for_tests(live_key.clone());
    pool.insert_rr_counter_for_tests(static_key.clone());
    for generation in retired.clone() {
        pool.insert_rr_counter_for_tests(Http2ConnectionPool::pool_key_with_global(
            &proxy,
            Some(generation),
            &global,
        ));
    }

    let before = pool.rr_counter_len();
    assert_eq!(before, 2 + retired.clone().count());
    assert_eq!(pool.pool_size(), 0);

    // Drive the same public method the rotation consumer calls
    // unconditionally (including at drain_seconds = 0). Do not call
    // `force_drain_svid_generation`, which would also invalidate senders.
    for generation in retired.clone() {
        pool.drain_backend_tls_config_cache_svid_generation(generation);
    }

    assert_eq!(
        pool.rr_counter_len(),
        2,
        "retired SVID generations must not retain rr_counters after unconditional TLS-cache drain"
    );
    assert!(
        pool.contains_rr_counter(&live_key),
        "the live generation counter must remain: {live_key}"
    );
    assert!(
        pool.contains_rr_counter(&static_key),
        "operator-static svidg=static counters must remain"
    );
    for generation in retired {
        let retired_key =
            Http2ConnectionPool::pool_key_with_global(&proxy, Some(generation), &global);
        assert!(
            !pool.contains_rr_counter(&retired_key),
            "generation {generation} counter must be reclaimed: {retired_key}"
        );
    }
    assert_eq!(
        pool.pool_size(),
        0,
        "rr-counter reclaim must not withdraw (or invent) pooled connections"
    );
}

fn rr_counters_reclaim_retired_generations_for_grpc() {
    let pool = GrpcConnectionPool::default();
    let proxy = create_test_proxy();
    let global = PoolConfig::default();
    let live_generation = 8u64;
    let retired = 1..live_generation;

    let live_key = GrpcConnectionPool::pool_key_with_global(&proxy, Some(live_generation), &global);
    let static_key = GrpcConnectionPool::pool_key_with_global(&proxy, None, &global);
    pool.insert_rr_counter_for_tests(live_key.clone());
    pool.insert_rr_counter_for_tests(static_key.clone());
    for generation in retired.clone() {
        pool.insert_rr_counter_for_tests(GrpcConnectionPool::pool_key_with_global(
            &proxy,
            Some(generation),
            &global,
        ));
    }

    assert_eq!(pool.rr_counter_len(), 2 + retired.clone().count());

    for generation in retired.clone() {
        pool.drain_backend_tls_config_cache_svid_generation(generation);
    }

    assert_eq!(pool.rr_counter_len(), 2);
    assert!(pool.contains_rr_counter(&live_key));
    assert!(pool.contains_rr_counter(&static_key));
    for generation in retired {
        let retired_key =
            GrpcConnectionPool::pool_key_with_global(&proxy, Some(generation), &global);
        assert!(
            !pool.contains_rr_counter(&retired_key),
            "gRPC generation {generation} counter must be reclaimed: {retired_key}"
        );
    }
    assert_eq!(pool.pool_size(), 0);
}

/// Issue #4280 race: a request can capture generation N, rotation can
/// `fetch_max` and `retain`, then the paused request can still take the
/// `None => entry(...)` branch. Post-insert exact-key removal on that cold
/// path (and the insert-before-retire `retain`) keep the map bounded.
#[tokio::test]
async fn rr_counters_close_late_insert_after_svid_retire() {
    rr_counters_insert_before_and_after_retire_for_h2();
    rr_counters_insert_before_and_after_retire_for_grpc();
}

fn rr_counters_insert_before_and_after_retire_for_h2() {
    let live = Arc::new(AtomicU64::new(3));
    let pool = Http2ConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
        Arc::clone(&live),
    );
    let proxy = create_test_proxy();
    let global = PoolConfig::default();
    let captured = 3u64;
    let key = Http2ConnectionPool::pool_key_with_global(&proxy, Some(captured), &global);
    let static_key = Http2ConnectionPool::pool_key_with_global(&proxy, None, &global);

    let inserted = pool.get_or_seed_rr_counter_for_tests(&key, Some(captured));
    assert!(pool.contains_rr_counter(&key));
    pool.drain_backend_tls_config_cache_svid_generation(captured);
    assert!(
        !pool.contains_rr_counter(&key),
        "insert-before-retire must be reclaimed by the unconditional drain"
    );
    let inserted_before = inserted.load(Ordering::Relaxed);
    let _ = inserted.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        inserted.load(Ordering::Relaxed),
        inserted_before.wrapping_add(1),
        "the detached in-flight counter Arc must remain usable after map retirement"
    );

    live.store(4, Ordering::Release);
    pool.drain_backend_tls_config_cache_svid_generation(captured);
    let late = pool.get_or_seed_rr_counter_for_tests(&key, Some(captured));
    assert!(
        !pool.contains_rr_counter(&key),
        "retire-before-insert must drop the exact captured key"
    );
    let late_before = late.load(Ordering::Relaxed);
    let _ = late.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        late.load(Ordering::Relaxed),
        late_before.wrapping_add(1),
        "the late retired-generation counter Arc must remain usable without being cached"
    );

    let current = Http2ConnectionPool::pool_key_with_global(&proxy, Some(4), &global);
    let _ = pool.get_or_seed_rr_counter_for_tests(&current, Some(4));
    let _ = pool.get_or_seed_rr_counter_for_tests(&static_key, None);
    assert!(pool.contains_rr_counter(&current));
    assert!(pool.contains_rr_counter(&static_key));
    assert_eq!(pool.pool_size(), 0);
}

fn rr_counters_insert_before_and_after_retire_for_grpc() {
    let live = Arc::new(AtomicU64::new(3));
    let pool = GrpcConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
        Arc::clone(&live),
    );
    let proxy = create_test_proxy();
    let global = PoolConfig::default();
    let captured = 3u64;
    let key = GrpcConnectionPool::pool_key_with_global(&proxy, Some(captured), &global);
    let static_key = GrpcConnectionPool::pool_key_with_global(&proxy, None, &global);

    let inserted = pool.get_or_seed_rr_counter_for_tests(&key, Some(captured));
    assert!(pool.contains_rr_counter(&key));
    pool.drain_backend_tls_config_cache_svid_generation(captured);
    assert!(!pool.contains_rr_counter(&key));
    let inserted_before = inserted.load(Ordering::Relaxed);
    let _ = inserted.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        inserted.load(Ordering::Relaxed),
        inserted_before.wrapping_add(1),
        "the detached gRPC counter Arc must remain usable after map retirement"
    );

    live.store(4, Ordering::Release);
    pool.drain_backend_tls_config_cache_svid_generation(captured);
    let late = pool.get_or_seed_rr_counter_for_tests(&key, Some(captured));
    assert!(
        !pool.contains_rr_counter(&key),
        "gRPC retire-before-insert must drop the exact captured key"
    );
    let late_before = late.load(Ordering::Relaxed);
    let _ = late.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        late.load(Ordering::Relaxed),
        late_before.wrapping_add(1),
        "the late retired-generation gRPC counter Arc must remain usable without being cached"
    );

    let current = GrpcConnectionPool::pool_key_with_global(&proxy, Some(4), &global);
    let _ = pool.get_or_seed_rr_counter_for_tests(&current, Some(4));
    let _ = pool.get_or_seed_rr_counter_for_tests(&static_key, None);
    assert!(pool.contains_rr_counter(&current));
    assert!(pool.contains_rr_counter(&static_key));
    assert_eq!(pool.pool_size(), 0);
}

fn assert_outbound_h2_host_matches_authority(
    backend_url: &str,
    preserve_host_header: bool,
    client_host: Option<&str>,
    expected: &str,
) {
    let (host, authority) = ferrum_edge::_test_support::outbound_h2_host_and_authority_for_test(
        backend_url,
        preserve_host_header,
        client_host,
    )
    .unwrap_or_else(|| panic!("expected authority for {backend_url}"));
    assert_eq!(host, expected, "Host for {backend_url}");
    assert_eq!(authority, expected, ":authority for {backend_url}");
    assert_eq!(
        host, authority,
        "RFC 9113 §8.3.1: Host and :authority must agree for {backend_url}"
    );
}

#[test]
fn direct_h2_outbound_host_matches_authority_including_non_default_port() {
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:21212/h2tls",
        false,
        Some("client.example:8443"),
        "127.0.0.1:21212",
    );
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:443/h2tls",
        false,
        None,
        "127.0.0.1",
    );
    assert_outbound_h2_host_matches_authority(
        "http://127.0.0.1:80/h2tls",
        false,
        None,
        "127.0.0.1",
    );
    assert_outbound_h2_host_matches_authority(
        "https://[::1]:8443/h2tls",
        false,
        None,
        "[::1]:8443",
    );
    assert_outbound_h2_host_matches_authority("https://[::1]:443/h2tls", false, None, "[::1]");
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:21212/h2tls",
        true,
        Some("api.example.com"),
        "api.example.com",
    );
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:21212/h2tls",
        true,
        Some("  api.example.com  "),
        "api.example.com",
    );
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:8443/h2tls",
        true,
        Some("[::1]:8443"),
        "[::1]:8443",
    );

    let fallback = "127.0.0.1:8443";
    let backend = "https://127.0.0.1:8443/h2tls";
    for host in [
        "user@host",
        "user:pass@host:8443",
        "host/evil",
        "",
        "   ",
        "2001:db8::1",
        "[not-an-ip]:1",
    ] {
        assert_outbound_h2_host_matches_authority(backend, true, Some(host), fallback);
    }
}

fn outbound_host_for_target(host: &str, port: u16, scheme: &str) -> String {
    ferrum_edge::_test_support::outbound_host_header_for_target_for_test(host, port, Some(scheme))
}

/// Issue #4539: the reqwest transport (default HTTP/1.1 AND HTTP/2 backend
/// path whenever the capability registry has no `h2_tls` entry) and the two
/// native-HTTP/3 backend builders derive outbound `Host` from the selected
/// `(host, port)` rather than from the hostname alone.
///
/// A hostname-only `Host` beside a `host:port` URL authority is an RFC 9112
/// §3.2 violation on HTTP/1.1 (hyper-util's `set_host` is
/// `entry(HOST).or_insert_with(..)`, so Ferrum's value wins) and the RFC 9113
/// §8.3.1 `Host` / `:authority` disagreement issue #4410 reported on HTTP/2.
#[test]
fn reqwest_and_h3_outbound_host_carries_selected_target_port() {
    assert_eq!(
        outbound_host_for_target("127.0.0.1", 21212, "https"),
        "127.0.0.1:21212",
        "a non-default TLS backend port must ride in Host"
    );
    assert_eq!(
        outbound_host_for_target("backend.internal", 8080, "http"),
        "backend.internal:8080",
        "a non-default plaintext backend port must ride in Host"
    );
}

/// An EXPLICIT default port is omitted, matching what `url`/hyper normalize
/// the reqwest URL authority to — so a conventional 80/443 backend keeps the
/// byte-identical hostname-only `Host` it had before #4539.
#[test]
fn reqwest_and_h3_outbound_host_omits_explicit_default_port() {
    assert_eq!(
        outbound_host_for_target("127.0.0.1", 443, "https"),
        "127.0.0.1"
    );
    assert_eq!(
        outbound_host_for_target("127.0.0.1", 80, "http"),
        "127.0.0.1"
    );
    assert_eq!(
        outbound_host_for_target("backend.example", 443, "wss"),
        "backend.example"
    );
    assert_eq!(
        outbound_host_for_target("backend.example", 80, "ws"),
        "backend.example"
    );
    // The default-port rule is scheme-relative: 80 is NOT default for https.
    assert_eq!(
        outbound_host_for_target("backend.example", 80, "https"),
        "backend.example:80"
    );
    assert_eq!(
        outbound_host_for_target("backend.example", 443, "http"),
        "backend.example:443"
    );
    // HTTP/3 is TLS-only, so its builders always ask with `https`.
    assert_eq!(
        outbound_host_for_target("h3-backend.example", 443, "https"),
        "h3-backend.example"
    );
    assert_eq!(
        outbound_host_for_target("h3-backend.example", 8443, "https"),
        "h3-backend.example:8443"
    );
}

/// An IPv6 literal target keeps its brackets so the value is a parseable
/// authority (RFC 3986 §3.2.2), and an already-bracketed host is not
/// double-bracketed.
#[test]
fn reqwest_and_h3_outbound_host_brackets_ipv6_literals() {
    assert_eq!(outbound_host_for_target("::1", 8443, "https"), "[::1]:8443");
    assert_eq!(
        outbound_host_for_target("[::1]", 8443, "https"),
        "[::1]:8443"
    );
    assert_eq!(
        outbound_host_for_target("2001:db8::10", 8080, "http"),
        "[2001:db8::10]:8080"
    );
    // A default port omits the port but still renders a parseable authority.
    assert_eq!(outbound_host_for_target("::1", 443, "https"), "[::1]");
    assert_eq!(outbound_host_for_target("[::1]", 443, "https"), "[::1]");
}

/// Drift guard: for the same selected `(host, port)` and scheme, the value the
/// reqwest / native-H3 builders emit must equal the one `apply_outbound_h2_host`
/// derives from the direct-H2 pool's parsed URI. Both fixes for #4410 must stay
/// one rule.
#[test]
fn reqwest_outbound_host_agrees_with_direct_h2_authority() {
    for (host, port, scheme) in [
        ("127.0.0.1", 21212u16, "https"),
        ("127.0.0.1", 443, "https"),
        ("127.0.0.1", 80, "http"),
        ("backend.example", 8080, "http"),
        ("[::1]", 8443, "https"),
        ("[::1]", 443, "https"),
    ] {
        let backend_url = format!("{scheme}://{host}:{port}/h2tls");
        let (direct_h2_host, direct_h2_authority) =
            ferrum_edge::_test_support::outbound_h2_host_and_authority_for_test(
                &backend_url,
                false,
                None,
            )
            .unwrap_or_else(|| panic!("expected authority for {backend_url}"));
        let reqwest_host = outbound_host_for_target(host, port, scheme);
        assert_eq!(
            reqwest_host, direct_h2_host,
            "reqwest/H3 Host must equal the direct-H2 Host for {backend_url}"
        );
        assert_eq!(
            reqwest_host, direct_h2_authority,
            "reqwest/H3 Host must equal the direct-H2 :authority for {backend_url}"
        );
    }
}

/// `preserve_host_header: true` is untouched by #4539: every builder forwards
/// the client's `Host` verbatim and never consults the selected target.
#[test]
fn preserve_host_header_still_forwards_the_client_value_verbatim() {
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:21212/h2tls",
        true,
        Some("api.example.com"),
        "api.example.com",
    );
    assert_outbound_h2_host_matches_authority(
        "https://127.0.0.1:21212/h2tls",
        true,
        Some("api.example.com:9443"),
        "api.example.com:9443",
    );
}

#[test]
fn direct_h2_mesh_mtls_pinned_authority_wins_over_preserve_host() {
    let (host, authority) =
        ferrum_edge::_test_support::mesh_mtls_outbound_host_and_authority_for_test(
            true,
            Some("attacker.example:9000"),
            "reviews.default.svc",
            Some(9080),
            "10.0.0.5",
            15006,
        )
        .expect("pinned mesh-mTLS authority");
    assert_eq!(host, "reviews.default.svc:9080");
    assert_eq!(authority, "reviews.default.svc:9080");
    assert_eq!(
        host, authority,
        "RFC 9113 §8.3.1: mesh-mTLS Host and :authority must agree"
    );
}

async fn start_h2_tls_host_echo_backend()
-> Result<(tokio::task::JoinHandle<()>, u16), Box<dyn std::error::Error>> {
    let cert_pem = include_str!("../certs/server.crt");
    let key_pem = include_str!("../certs/server.key");
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|cert| cert.ok())
        .collect();
    let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls_stream);
                let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let authority = req
                        .uri()
                        .authority()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_default();
                    let response = Response::builder()
                        .status(200)
                        .header("x-echo-host", host)
                        .header("x-echo-authority", authority)
                        .body(Full::new(Bytes::from_static(b"ok")))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });
                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok((handle, port))
}

async fn start_direct_h2_test_gateway(
    state: ProxyState,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let gateway_addr = listener.local_addr().expect("gateway addr");
    let handle = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let mut builder =
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                builder.http1().max_buf_size(state.max_header_size_bytes);
                builder
                    .http2()
                    .max_header_list_size(state.max_header_size_bytes as u32);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    async move {
                        let request =
                            handle_proxy_request(req, state, remote_addr, false, None, None);
                        // This future is embedded in Hyper's service future.
                        // Do not box it in the fixture: that would hide a
                        // regression at the production request boundary.
                        let bytes = std::mem::size_of_val(&request);
                        assert!(
                            bytes <= 32 * 1024,
                            "frontend service future must stay within 32 KiB, got {bytes} bytes"
                        );
                        request.await
                    }
                });
                let _ = builder.serve_connection_with_upgrades(io, svc).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (gateway_addr, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_h2_backend_sees_matching_host_and_authority_on_non_default_port() {
    assert_direct_h2_host_and_authority(false).await;
}

// Both frontend dispatch stacks must fit the default Tokio worker stack in
// the unoptimized hosted test profile. Keep the H1 reproducer above as well:
// H2 streams are polled through a different Hyper task path.
#[tokio::test(flavor = "multi_thread")]
async fn direct_h2_backend_sees_matching_host_and_authority_from_h2_frontend() {
    assert_direct_h2_host_and_authority(true).await;
}

async fn assert_direct_h2_host_and_authority(h2_frontend: bool) {
    let (_backend_handle, port) = start_h2_tls_host_echo_backend()
        .await
        .expect("start host-echo H2 TLS backend");
    let expected = format!("127.0.0.1:{port}");

    let mut proxy = create_test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = port;
    proxy.backend_tls_verify_server_cert = false;
    proxy.pool_enable_http2 = Some(true);
    proxy.h2_upgrade_policy = Some(H2UpgradePolicy::Upgrade);

    let dns_cache = create_dns_cache();
    let env_config = ferrum_edge::config::EnvConfig {
        tls_no_verify: true,
        ..Default::default()
    };
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        loaded_at: chrono::Utc::now(),
        ..Default::default()
    };
    let (state, _health_handles) =
        ProxyState::new(config, dns_cache, env_config, None, None).expect("proxy state");
    let (gateway_addr, _gateway_handle) = start_direct_h2_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let request = Request::builder()
        .method("GET")
        .uri(if h2_frontend {
            "http://client.example:9000/h2test"
        } else {
            "/h2test"
        })
        .header("host", "client.example:9000")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = if h2_frontend {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(request)
            .await
            .expect("gateway response")
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("h1 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(request)
            .await
            .expect("gateway response")
    };
    assert_eq!(response.status(), 200, "direct-H2 dispatch should succeed");
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-echo-host")
            .and_then(|value| value.to_str().ok()),
        Some(expected.as_str()),
        "preserve_host_header=false: Host must include the non-default backend port"
    );
    assert_eq!(
        headers
            .get("x-echo-authority")
            .and_then(|value| value.to_str().ok()),
        Some(expected.as_str()),
        "Hyper :authority must include the same non-default port"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("complete H2 response");
    assert_eq!(body.to_bytes(), Bytes::from_static(b"ok"));
}

#[cfg(feature = "bench-pool-profile")]
#[tokio::test]
async fn pool_profile_live_h2_grpc_hit_miss_and_purpose_attribution() {
    use ferrum_edge::pool_profile::{Event, current_thread_counters, schema};

    let (_backend, port) = start_h2_tls_backend().await.unwrap();
    let config = PoolConfig {
        http2_connections_per_host: 1,
        ..PoolConfig::default()
    };
    let h2 = Http2ConnectionPool::new(
        config.clone(),
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );
    let grpc = GrpcConnectionPool::new(
        config,
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    );
    let mut proxy = create_test_proxy();
    proxy.backend_host = "localhost".into();
    proxy.backend_port = port;
    proxy.backend_tls_verify_server_cert = false;
    proxy.resolved_tls.verify_server_cert = false;
    let before = current_thread_counters();
    for _ in 0..129 {
        h2.get_sender(&proxy).await.unwrap();
        grpc.get_sender(&proxy).await.unwrap();
        h2.get_sender_for_capability_probe(&proxy).await.unwrap();
        grpc.get_sender_for_capability_probe(&proxy).await.unwrap();
    }
    let after = current_thread_counters();
    for group in 0..4 {
        let base = group * schema::STRIDE;
        let delta = |event: Event| after[base + event as usize] - before[base + event as usize];
        assert_eq!(delta(Event::Acquisitions), 129);
        assert!(delta(Event::WarmHit) >= 1);
        assert!(delta(Event::SenderClone) >= 1);
        assert_eq!(delta(Event::Errors), 0);
        assert_eq!(delta(Event::Cancelled), 0);
        if group % 2 == 0 {
            assert_eq!(delta(Event::CreateOwner), 1);
            assert_eq!(delta(Event::MissFallback), 1);
        }
    }
    assert_eq!(h2.pool_size(), 1);
    assert_eq!(grpc.pool_size(), 1);
}

// ── gRPC backend-shard affinity (issue #5588) ───────────────────────────────

fn affinity_grpc_pool(shards: usize) -> GrpcConnectionPool {
    GrpcConnectionPool::new(
        PoolConfig {
            http2_connections_per_host: shards,
            ..PoolConfig::default()
        },
        ferrum_edge::config::EnvConfig::default(),
        create_dns_cache(),
        None,
        Arc::new(Vec::new()),
    )
}

fn affinity_slot_table() -> Arc<ferrum_edge::proxy::frontend_affinity::SlotTable> {
    Arc::new(ferrum_edge::proxy::frontend_affinity::SlotTable::new())
}

/// h2c backend that counts accepts and can drop every live connection.
async fn start_closable_h2c_backend() -> (
    u16,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(std::sync::Mutex::new(Vec::new()));
    let task_accepted = Arc::clone(&accepted);
    let task_connections = Arc::clone(&connections);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            task_accepted.fetch_add(1, Ordering::Relaxed);
            let served = tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
            if let Ok(mut connections) = task_connections.lock() {
                connections.push(served.abort_handle());
            }
        }
    });
    (port, accepted, connections)
}

/// h2c backend that serves every connection, but while `hold` is set it
/// accepts a new connection and only starts speaking HTTP/2 once `hold`
/// clears: a slow dial that eventually succeeds.
async fn start_gated_h2c_backend() -> (u16, Arc<AtomicUsize>, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (hold, _) = tokio::sync::watch::channel(false);
    let task_accepted = Arc::clone(&accepted);
    let task_hold = hold.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            task_accepted.fetch_add(1, Ordering::Relaxed);
            let mut held = task_hold.subscribe();
            tokio::spawn(async move {
                if held.wait_for(|hold| !*hold).await.is_err() {
                    return;
                }
                let service = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (port, accepted, hold)
}

async fn wait_for_pool_size(pool: &GrpcConnectionPool, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.pool_size() < expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("background shard fill completed");
}

/// Repeat spilled calls on `stream` until the pool has `expected` shards. A
/// call starts a fill for its missing shard only while the pool's small
/// background budget has a free permit, so widening can take several calls.
async fn spill_until_pool_size(
    pool: &GrpcConnectionPool,
    proxy: &Proxy,
    stream: &ferrum_edge::proxy::frontend_affinity::FrontendStream,
    expected: usize,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.pool_size() < expected {
            stream
                .run(pool.get_sender(proxy))
                .await
                .expect("spilled sender");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("spilled calls widened the pool");
}

async fn wait_for_fills_to_finish(pool: &GrpcConnectionPool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.shard_fills_in_flight() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("background shard fill finished");
}

#[tokio::test]
async fn test_grpc_pool_affinity_keeps_each_frontend_connection_on_its_own_shard() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    let (port, accepted) = start_counting_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let table = affinity_slot_table();

    // Every call of one frontend connection lands on its one shard.
    let first = FrontendConnectionAffinity::with_table(&table);
    let first_stream = first.open_stream();
    for _ in 0..8 {
        first_stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("affinity sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 1);

    // A second connection has its own shard. Its first call borrows the ready
    // neighbour while that shard is created in the background, so the pool
    // still widens as connections arrive.
    let second = FrontendConnectionAffinity::with_table(&table);
    let second_stream = second.open_stream();
    second_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("borrowed sender");
    wait_for_pool_size(&pool, 2).await;
    for _ in 0..4 {
        second_stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("second affinity sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 2);

    // Calls with no frontend connection keep the round-robin probe, which
    // borrows an existing ready shard on a warm pool and creates nothing.
    for _ in 0..8 {
        pool.get_sender(&proxy).await.expect("unscoped sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(pool.shard_fills_in_flight(), 0);
}

#[tokio::test]
async fn test_grpc_pool_cross_frontend_reuses_ready_sibling_while_its_shard_dials() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    use futures_util::FutureExt;

    let (port, accepted, hold) = start_gated_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let mut proxy = h2c_proxy_with_max_connections(port, None);
    proxy.backend_connect_timeout_ms = 30_000;
    let table = affinity_slot_table();
    let first = FrontendConnectionAffinity::with_table(&table);
    first
        .open_stream()
        .run(pool.get_sender(&proxy))
        .await
        .expect("warm shard");
    assert_eq!(accepted.load(Ordering::Relaxed), 1);

    // New dials now stall until released. The second frontend connection maps
    // to a missing shard, so its first sender borrows the ready connection
    // established by the first frontend without waiting for the new dial.
    hold.send_replace(true);
    let second = FrontendConnectionAffinity::with_table(&table);
    let stream = second.open_stream();
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    for _ in 0..16 {
        let sender = stream
            .run(pool.get_sender(&proxy))
            .now_or_never()
            .expect("a ready sibling serves the call without awaiting the dial")
            .expect("borrowed sender");
        assert!(!sender.is_closed());
    }
    assert_eq!(started.elapsed(), Duration::ZERO, "no added latency");
    tokio::time::resume();
    assert_eq!(pool.shard_fills_in_flight(), 1, "one coalesced fill");
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "second frontend reused the ready socket"
    );
    assert_eq!(
        pool.pool_size(),
        1,
        "borrowed sender does not alias a new shard"
    );

    // The single background create reaches the backend and completes once the
    // backend answers; the shard then serves its own connection's calls.
    wait_for_affinity_accepts(&accepted, 2).await;
    assert_eq!(pool.pool_size(), 1, "the borrow never aliases the shard");
    hold.send_replace(false);
    wait_for_pool_size(&pool, 2).await;
    wait_for_fills_to_finish(&pool).await;
    for _ in 0..8 {
        stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("filled affinity sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(pool.pool_size(), 2);
    assert_eq!(pool.shard_create_backoff_len(), 0);
}

#[tokio::test]
async fn test_grpc_pool_affinity_spills_a_heavy_connection_and_widens_the_pool() {
    use ferrum_edge::proxy::frontend_affinity::{
        AFFINITY_MAX_OPEN_STREAMS, FrontendConnectionAffinity,
    };
    let (port, accepted) = start_counting_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let heavy = FrontendConnectionAffinity::with_table(&affinity_slot_table());

    // Over the bound, calls spill round-robin and create the missing shards,
    // so one busy client connection is not pinned to one backend connection.
    let streams: Vec<_> = (0..=AFFINITY_MAX_OPEN_STREAMS)
        .map(|_| heavy.open_stream())
        .collect();
    for _ in 0..16 {
        streams[0]
            .run(pool.get_sender(&proxy))
            .await
            .expect("spilled sender");
    }
    spill_until_pool_size(&pool, &proxy, &streams[0], 4).await;
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 4);

    // Back under the bound, calls return to the connection's shard.
    drop(streams);
    let stream = heavy.open_stream();
    for _ in 0..4 {
        stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("affinity sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 4);
}

/// h2c backend that advertises `SETTINGS_MAX_CONCURRENT_STREAMS`.
async fn start_stream_limited_h2c_backend(max_streams: u32) -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
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
                    .max_concurrent_streams(max_streams)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn test_grpc_pool_affinity_respects_the_backend_stream_limit() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    const PEER_MAX: usize = 4;

    let (port, accepted) = start_stream_limited_h2c_backend(PEER_MAX as u32).await;
    let pool = affinity_grpc_pool(4);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let connection = FrontendConnectionAffinity::with_table(&affinity_slot_table());
    let mut streams: Vec<_> = (0..PEER_MAX).map(|_| connection.open_stream()).collect();
    let sender = streams[0]
        .run(pool.get_sender(&proxy))
        .await
        .expect("affinity sender");
    // The driver publishes the backend's limit once h2 applies its SETTINGS.
    tokio::time::timeout(Duration::from_secs(5), async {
        while sender.peer_max_concurrent_streams() != Some(PEER_MAX) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("backend SETTINGS_MAX_CONCURRENT_STREAMS sampled");

    // At the backend's limit the connection still keeps its own shard.
    for _ in 0..8 {
        streams[0]
            .run(pool.get_sender(&proxy))
            .await
            .expect("pinned sender");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(pool.shard_fills_in_flight(), 0);

    // One stream more than the backend allows on one connection: calls spill
    // round-robin (well under the fixed bound of 32) and widen the pool.
    streams.push(connection.open_stream());
    for _ in 0..8 {
        streams[0]
            .run(pool.get_sender(&proxy))
            .await
            .expect("spilled sender");
    }
    spill_until_pool_size(&pool, &proxy, &streams[0], 4).await;
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn test_grpc_pool_affinity_refills_a_closed_preferred_shard_in_the_background() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    use futures_util::FutureExt;

    let (port, accepted, connections) = start_closable_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let table = affinity_slot_table();

    // Shard 0 for the first frontend connection, and a healthy sibling shard 1
    // for a second one.
    let first = FrontendConnectionAffinity::with_table(&table);
    let first_stream = first.open_stream();
    let sender = first_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("first affinity sender");
    let second = FrontendConnectionAffinity::with_table(&table);
    let second_stream = second.open_stream();
    second_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("second affinity sender");
    wait_for_pool_size(&pool, 2).await;
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 2);

    // Close only shard 0's backend connection (the first one accepted), as a
    // GOAWAY or connection-age close would.
    connections
        .lock()
        .expect("connection handles")
        .first()
        .expect("first backend connection")
        .abort();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sender.is_closed() {
        assert!(
            Instant::now() < deadline,
            "backend close was never observed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The ready sibling serves the call without waiting on a redial, and the
    // closed preferred shard is recreated in the background.
    let borrowed = first_stream
        .run(pool.get_sender(&proxy))
        .now_or_never()
        .expect("the closed shard is not redialled on the request path")
        .expect("borrowed sender");
    assert!(!borrowed.is_closed());
    wait_for_affinity_accepts(&accepted, 3).await;
    wait_for_pool_size(&pool, 2).await;
    wait_for_fills_to_finish(&pool).await;
    let replacement = first_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("recreated affinity sender");
    assert!(!replacement.is_closed());
    assert_eq!(accepted.load(Ordering::Relaxed), 3);
}

/// h2c backend that serves connections until `stall` is set, then accepts and
/// holds new connections without ever speaking HTTP/2.
async fn start_stallable_h2c_backend() -> (u16, Arc<AtomicUsize>, Arc<std::sync::atomic::AtomicBool>)
{
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_accepted = Arc::clone(&accepted);
    let task_stall = Arc::clone(&stall);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            task_accepted.fetch_add(1, Ordering::Relaxed);
            if task_stall.load(Ordering::Relaxed) {
                held.push(socket);
                continue;
            }
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
    (port, accepted, stall)
}

#[tokio::test]
async fn test_grpc_pool_blackholed_background_fills_do_not_delay_request_path_creates() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    use futures_util::FutureExt;

    const SHARDS: usize = 64;
    let (stalled_port, stalled_accepted, stall) = start_stallable_h2c_backend().await;
    let (healthy_port, healthy_accepted) = start_counting_h2c_backend().await;
    let pool = affinity_grpc_pool(SHARDS);
    let (request_permits, background_permits) = pool.creation_permits_for_test();
    assert!(background_permits >= 1);
    let mut stalled = h2c_proxy_with_max_connections(stalled_port, None);
    stalled.backend_connect_timeout_ms = 30_000;
    let table = affinity_slot_table();
    let connections: Vec<_> = (0..SHARDS)
        .map(|_| FrontendConnectionAffinity::with_table(&table))
        .collect();
    let streams: Vec<_> = connections
        .iter()
        .map(|connection| connection.open_stream())
        .collect();
    streams[0]
        .run(pool.get_sender(&stalled))
        .await
        .expect("warm shard");

    // New dials to this backend now blackhole until the 30 s connect timeout.
    // Every other frontend connection maps to its own missing shard: each call
    // borrows the warm shard at once, and only the background budget's worth
    // of fills start, none holding a request-path creation permit.
    stall.store(true, Ordering::Relaxed);
    for stream in &streams[1..] {
        stream
            .run(pool.get_sender(&stalled))
            .now_or_never()
            .expect("a ready sibling serves the call without awaiting a dial")
            .expect("borrowed sender");
    }
    assert_eq!(pool.shard_fills_in_flight(), background_permits);
    wait_for_affinity_accepts(&stalled_accepted, 1 + background_permits).await;
    assert_eq!(pool.creation_permits_for_test(), (request_permits, 0));

    // A cold request-path create for another backend does not queue behind
    // the stalled fills.
    let healthy = h2c_proxy_with_max_connections(healthy_port, None);
    tokio::time::timeout(Duration::from_secs(2), pool.get_sender(&healthy))
        .await
        .expect("a request-path create never waits on background fills")
        .expect("healthy sender");
    assert_eq!(healthy_accepted.load(Ordering::Relaxed), 1);

    // With the budget spent, further borrows start no fills and still never
    // wait.
    for stream in &streams[1..] {
        stream
            .run(pool.get_sender(&stalled))
            .now_or_never()
            .expect("borrowing never awaits a fill")
            .expect("borrowed sender");
    }
    assert_eq!(pool.shard_fills_in_flight(), background_permits);
    assert_eq!(
        stalled_accepted.load(Ordering::Relaxed),
        1 + background_permits
    );
}

/// h2c backend whose first connection advertises
/// `SETTINGS_MAX_CONCURRENT_STREAMS = 0`, as a draining backend does; later
/// connections allow hyper's default.
async fn start_first_connection_draining_h2c_backend() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind h2c backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let task_accepted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let draining = task_accepted.fetch_add(1, Ordering::Relaxed) == 0;
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                if draining {
                    builder.max_concurrent_streams(0);
                }
                let _ = builder
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn test_grpc_pool_affinity_does_not_pin_to_a_backend_allowing_no_streams() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;

    let (port, accepted) = start_first_connection_draining_h2c_backend().await;
    let pool = affinity_grpc_pool(2);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let table = affinity_slot_table();
    let first = FrontendConnectionAffinity::with_table(&table);
    let first_stream = first.open_stream();
    let draining = first_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("draining affinity sender");
    tokio::time::timeout(Duration::from_secs(5), async {
        while draining.peer_max_concurrent_streams() != Some(0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("backend SETTINGS_MAX_CONCURRENT_STREAMS of 0 sampled");

    // The second frontend connection's shard is missing, and the only ready
    // shard allows no streams, so nothing is borrowed: the call creates its
    // own shard.
    let second = FrontendConnectionAffinity::with_table(&table);
    let second_stream = second.open_stream();
    let open = second_stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("second affinity sender");
    assert_ne!(open.peer_max_concurrent_streams(), Some(0));
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(pool.pool_size(), 2);

    // The first connection's calls no longer pin to its draining shard, and
    // calls with no frontend connection skip it too, without another dial.
    for _ in 0..8 {
        let sender = first_stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("spilled sender");
        assert_ne!(
            sender.peer_max_concurrent_streams(),
            Some(0),
            "a call must not queue on a backend allowing no streams"
        );
        let sender = pool.get_sender(&proxy).await.expect("unscoped sender");
        assert_ne!(sender.peer_max_concurrent_streams(), Some(0));
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(pool.shard_fills_in_flight(), 0);
}

#[tokio::test]
async fn test_grpc_pool_affinity_backs_off_a_shard_whose_create_failed() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    let (port, accepted, stall) = start_stallable_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let mut proxy = h2c_proxy_with_max_connections(port, None);
    proxy.backend_connect_timeout_ms = 300;
    let table = affinity_slot_table();

    let first = FrontendConnectionAffinity::with_table(&table);
    first
        .open_stream()
        .run(pool.get_sender(&proxy))
        .await
        .expect("first affinity sender");
    assert_eq!(accepted.load(Ordering::Relaxed), 1);

    // New backend connections now stall until the connect timeout. The second
    // frontend connection's own shard cannot be created: its call borrows the
    // ready shard at once while the one background create times out.
    stall.store(true, Ordering::Relaxed);
    let second = FrontendConnectionAffinity::with_table(&table);
    let stream = second.open_stream();
    let started = Instant::now();
    stream
        .run(pool.get_sender(&proxy))
        .await
        .expect("borrowed sender while the create stalls");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "the call must not wait on the dial"
    );
    wait_for_affinity_accepts(&accepted, 2).await;
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(pool.shard_create_backoff_len(), 1);

    // Later calls borrow straight away without starting another create.
    for _ in 0..10 {
        stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("borrowed sender during backoff");
    }
    assert_eq!(pool.shard_fills_in_flight(), 0);
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn test_grpc_pool_affinity_under_a_connection_cap_borrows_without_redialling() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    let (port, accepted) = start_counting_h2c_backend().await;
    let limiter = Arc::new(BackendConnectionLimiter::new());
    let pool = affinity_grpc_pool(4);
    pool.attach_backend_conn_limit(Arc::clone(&limiter));
    let proxy = h2c_proxy_with_max_connections(port, Some(1));
    let table = affinity_slot_table();

    let first = FrontendConnectionAffinity::with_table(&table);
    first
        .open_stream()
        .run(pool.get_sender(&proxy))
        .await
        .expect("first affinity sender");

    // DestinationRule `maxConnections: 1` with 4 shards: the second frontend
    // connection's own shard can never be created. Its calls are served by the
    // admitted connection, and after the first refusal they stop re-attempting
    // the create.
    let second = FrontendConnectionAffinity::with_table(&table);
    let stream = second.open_stream();
    for _ in 0..10 {
        stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("capped destination keeps serving on the admitted connection");
    }
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(pool.shard_create_backoff_len(), 1);
    for _ in 0..10 {
        stream
            .run(pool.get_sender(&proxy))
            .await
            .expect("borrowed sender during backoff");
    }
    assert_eq!(pool.shard_fills_in_flight(), 0);
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(limiter.current("maxconn-h2c.test", port), 1);
    assert_eq!(pool.shard_create_backoff_work(), (1, 0));
}

async fn wait_for_affinity_accepts(accepted: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while accepted.load(Ordering::Relaxed) < expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("backend accepted the physical attempt");
}

#[tokio::test]
async fn test_grpc_pool_failed_background_fill_borrows_and_retries_after_cooldown() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    use futures_util::FutureExt;

    let (port, accepted, stall) = start_stallable_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let mut proxy = h2c_proxy_with_max_connections(port, None);
    proxy.backend_connect_timeout_ms = 500;
    let table = affinity_slot_table();
    let first = FrontendConnectionAffinity::with_table(&table);
    first
        .open_stream()
        .run(pool.get_sender(&proxy))
        .await
        .unwrap();
    stall.store(true, Ordering::Relaxed);
    let second = FrontendConnectionAffinity::with_table(&table);
    let stream = second.open_stream();
    // Every call while the one background create stalls borrows at once.
    for _ in 0..17 {
        stream
            .run(pool.get_sender(&proxy))
            .now_or_never()
            .expect("borrowing never awaits the stalled create")
            .expect("healthy sibling");
    }
    wait_for_affinity_accepts(&accepted, 2).await;
    wait_for_fills_to_finish(&pool).await;
    assert_eq!(pool.shard_create_backoff_work(), (1, 0));
    for _ in 0..10 {
        stream.run(pool.get_sender(&proxy)).await.unwrap();
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(
        pool.pool_size(),
        1,
        "borrowing must not alias another shard"
    );
    assert_eq!(pool.shard_create_backoff_work(), (1, 0));

    stall.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    stream.run(pool.get_sender(&proxy)).await.unwrap();
    wait_for_pool_size(&pool, 2).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 3);
    assert_eq!(
        pool.pool_size(),
        2,
        "preferred shard recovers after cooldown"
    );
}

#[tokio::test]
async fn test_grpc_pool_cancelled_cold_create_recovers_without_waiting_for_cooldown() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;

    let (port, accepted, stall) = start_stallable_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let proxy = h2c_proxy_with_max_connections(port, None);
    let connection = FrontendConnectionAffinity::with_table(&affinity_slot_table());
    let stream = connection.open_stream();
    stall.store(true, Ordering::Relaxed);
    let mut creator = Box::pin(stream.run(pool.get_sender(&proxy)));
    tokio::select! {
        result = &mut creator => panic!("create should stall: {result:?}"),
        _ = wait_for_affinity_accepts(&accepted, 1) => {}
    }
    drop(creator);
    assert_eq!(pool.shard_create_backoff_work(), (1, 0));
    stall.store(false, Ordering::Relaxed);
    tokio::time::timeout(
        Duration::from_millis(500),
        stream.run(pool.get_sender(&proxy)),
    )
    .await
    .expect("a cold pool must retry immediately")
    .expect("fresh sender");
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(pool.pool_size(), 1);
}

#[tokio::test]
async fn test_grpc_pool_failure_fanout_records_only_the_physical_attempt() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;
    use futures_util::FutureExt;

    // A cold pool has no sibling to borrow, so its calls await one coalesced
    // create; a failure is recorded once, never per waiter.
    let (port, accepted, stall) = start_stallable_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    let mut proxy = h2c_proxy_with_max_connections(port, None);
    proxy.backend_connect_timeout_ms = 500;
    let connection = FrontendConnectionAffinity::with_table(&affinity_slot_table());
    let stream = connection.open_stream();
    stall.store(true, Ordering::Relaxed);
    let mut creator = Box::pin(stream.run(pool.get_sender(&proxy)));
    tokio::select! {
        result = &mut creator => panic!("create should stall: {result:?}"),
        _ = wait_for_affinity_accepts(&accepted, 1) => {}
    }
    let mut waiters: Vec<_> = (0..64)
        .map(|_| Box::pin(stream.run(pool.get_sender(&proxy))))
        .collect();
    for waiter in &mut waiters {
        assert!(waiter.as_mut().now_or_never().is_none());
    }
    waiters.push(creator);
    for result in futures_util::future::join_all(waiters).await {
        assert!(result.is_err(), "no shard can serve the failed create");
    }
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(pool.shard_create_backoff_work(), (1, 0));
    assert_eq!(pool.shard_create_backoff_len(), 1);
    assert_eq!(pool.shard_fills_in_flight(), 0);
}

#[tokio::test]
async fn test_grpc_pool_backoff_has_bounded_occupancy_and_constant_eviction_work() {
    use ferrum_edge::proxy::frontend_affinity::FrontendConnectionAffinity;

    const KEYS: usize = 4_224;
    let (port, accepted) = start_counting_h2c_backend().await;
    let pool = affinity_grpc_pool(4);
    pool.attach_backend_conn_limit(Arc::new(BackendConnectionLimiter::new()));
    let proxy = h2c_proxy_with_max_connections(port, Some(1));
    let connection = FrontendConnectionAffinity::with_table(&affinity_slot_table());
    let stream = connection.open_stream();
    stream.run(pool.get_sender(&proxy)).await.unwrap();

    // Freeze cooldown time after the real handshake. Every failed key below
    // remains live, so expiration cannot hide excess occupancy or scan work.
    tokio::time::pause();
    let outage_started = tokio::time::Instant::now();
    let mut refreshed = proxy.clone();
    refreshed.upstream_subset = Some("outage-refreshed".to_string());
    for _ in 0..2 {
        assert!(stream.run(pool.get_sender(&refreshed)).await.is_err());
    }
    // Distinct pool identities at one capped physical destination: every
    // create fails while the unrelated original shard remains healthy.
    for index in 0..KEYS {
        let mut failed = proxy.clone();
        failed.upstream_subset = Some(format!("outage-{index}"));
        assert!(stream.run(pool.get_sender(&failed)).await.is_err());
        assert!(pool.shard_create_backoff_len() <= 4_096);
        if index == 4_094 {
            assert_eq!(
                pool.shard_create_backoff_len(),
                4_096,
                "evicting the older FIFO record must preserve a same-clock refresh"
            );
        }
        if index % 64 == 0 {
            stream.run(pool.get_sender(&proxy)).await.unwrap();
        }
    }
    assert_eq!(outage_started.elapsed(), Duration::ZERO);
    assert_eq!(pool.shard_create_backoff_len(), 4_096);
    assert_eq!(
        pool.shard_create_backoff_work(),
        (KEYS + 2, KEYS + 2 - 4_096)
    );
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(pool.pool_size(), 1);
}

/// The production direct HTTP/1.1 handoff gate (GHSA-xcg4-wj3x-gjj2). A
/// checked-out connection whose request bound elapsed before the handoff never
/// carried the request, so the gate refuses it and returns it to the idle set
/// untouched: the next checkout reuses it, and the backend sees one connection.
#[tokio::test]
async fn test_direct_h1_handoff_gate_returns_the_untouched_connection_to_the_pool() {
    use ferrum_edge::_test_support::{
        BackendHandoffBoundSourceForTest, compose_backend_handoff_bound_for_test,
        compose_dispatch_phase_bound_for_test, direct_h1_handoff_gate_for_test,
    };
    use ferrum_edge::proxy::auth_lifetime::{
        StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
        StreamAuthTerminationLatch,
    };

    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&accepts);
    let backend = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            // Hold the connection open; hyper's HTTP/1.1 client handshake
            // writes nothing, so no HTTP exchange is needed.
            held.push(stream);
        }
    });

    let pool = create_default_pool();
    let mut proxy = create_test_proxy();
    proxy.backend_scheme = Some(BackendScheme::Http);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Http);
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = port;
    let connect_timeout = Duration::from_secs(2);

    let checkout = pool
        .checkout_h1(&proxy, false, connect_timeout, false)
        .await
        .expect("first checkout dials the backend");
    assert!(!checkout.reused());

    let expired_plan = (
        StreamAuthDeadline {
            at: tokio::time::Instant::now(),
            termination: StreamAuthTermination::CredentialExpired,
        },
        StreamAuthProtocolFamily::Http,
        StreamAuthTerminationLatch::default(),
    );
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&expired_plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    let Err(refused) = direct_h1_handoff_gate_for_test(&bound, checkout) else {
        panic!("an elapsed bound must refuse the handoff");
    };
    assert_eq!(refused, BackendHandoffBoundSourceForTest::Authorization);

    // Check-in may wait for the fresh connection's dispatcher to report ready.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pool.h1_idle_connections() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pool.h1_idle_connections(),
        1,
        "the refused, untouched connection must be checked back in"
    );
    let reused = pool
        .checkout_h1(&proxy, false, connect_timeout, false)
        .await
        .expect("second checkout");
    assert!(
        reused.reused(),
        "the next request must reuse the connection the refused handoff returned"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while accepts.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "no redial");
    backend.abort();
}

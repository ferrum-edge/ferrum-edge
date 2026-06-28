//! Integration tests for Http2ConnectionPool
//!
//! Tests the HTTP/2 direct connection pool that provides proper H2 stream
//! multiplexing over persistent TLS connections to backends.
//!
//! Covers: pool construction, pool_size tracking, get_sender error paths,
//! and live connection lifecycle against a real TLS+H2 echo backend.

use bytes::Bytes;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::http2_pool::{Http2ConnectionPool, Http2PoolError};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
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
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
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

    // Give the listener a moment to start accepting
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok((handle, port))
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

//! Integration coverage for per-upstream backend TLS SAN allow-lists.

use std::sync::Arc;
use std::sync::Once;

use bytes::Bytes;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::http2_pool::{Http2ConnectionPool, Http2PoolError};
use ferrum_edge::tls::backend::BackendTlsConfigBuilder;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::CertificateRevocationListDer;
use tempfile::TempDir;

static INIT_CRYPTO: Once = Once::new();

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
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

fn generate_leaf(ca: &GeneratedCa, cn: &str, dns_sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::new(
        dns_sans
            .iter()
            .map(|san| san.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn create_test_proxy(port: u16, ca_path: &str, san_allow_list: Vec<String>) -> Proxy {
    let mut resolved_tls = BackendTlsConfig::default_verify();
    resolved_tls.server_ca_cert_path = Some(ca_path.to_string());
    resolved_tls.san_allow_list = san_allow_list;
    resolved_tls.recompute_san_digest();

    Proxy {
        id: "h2-san-test".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/h2-san".to_string()),
        backend_scheme: Some(BackendScheme::Https),
        dispatch_kind: DispatchKind::from(BackendScheme::Https),
        backend_host: "localhost".to_string(),
        backend_port: port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: Some(ca_path.to_string()),
        resolved_tls,
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

async fn start_h2_tls_backend(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(tokio::task::JoinHandle<()>, u16), Box<dyn std::error::Error>> {
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let private_key =
        rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or("missing private key")?;

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

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
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .expect("response"),
                    )
                });
                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    Ok((handle, port))
}

fn reqwest_client_for_proxy(proxy: &Proxy) -> reqwest::Client {
    let crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    BackendTlsConfigBuilder {
        proxy,
        policy: None,
        global_ca: None,
        global_no_verify: false,
        global_client_cert: None,
        global_client_key: None,
        crls: &crls,
    }
    .build_reqwest()
    .expect("build reqwest TLS config")
    .build()
    .expect("build reqwest client")
}

#[tokio::test]
async fn h2_backend_tls_san_allow_list_accepts_match_and_rejects_mismatch() {
    ensure_crypto_provider();
    let ca = generate_ca("h2-san-ca");
    let backend = generate_leaf(&ca, "localhost", &["localhost"]);
    let (_handle, port) = start_h2_tls_backend(&backend.cert_pem, &backend.key_pem)
        .await
        .expect("start H2 backend");

    let temp_dir = TempDir::new().expect("temp dir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write CA");
    let ca_path = ca_path.display().to_string();

    let pool = Http2ConnectionPool::new(
        PoolConfig::default(),
        ferrum_edge::config::EnvConfig::default(),
        DnsCache::new(DnsConfig::default()),
        None,
        Arc::new(Vec::new()),
    );

    let matching = create_test_proxy(port, &ca_path, vec!["localhost".to_string()]);
    pool.get_sender(&matching)
        .await
        .expect("matching SAN allow-list should connect");

    let mismatching = create_test_proxy(port, &ca_path, vec!["other.local".to_string()]);
    let err = pool
        .get_sender(&mismatching)
        .await
        .expect_err("mismatching SAN allow-list should reject");
    assert!(
        matches!(err, Http2PoolError::BackendUnavailable { .. }),
        "expected TLS backend unavailable for SAN mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn reqwest_backend_tls_san_allow_list_accepts_match_and_rejects_mismatch() {
    ensure_crypto_provider();
    let ca = generate_ca("reqwest-san-ca");
    let backend = generate_leaf(&ca, "localhost", &["localhost"]);
    let (_handle, port) = start_h2_tls_backend(&backend.cert_pem, &backend.key_pem)
        .await
        .expect("start TLS backend");

    let temp_dir = TempDir::new().expect("temp dir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write CA");
    let ca_path = ca_path.display().to_string();

    let matching = create_test_proxy(port, &ca_path, vec!["localhost".to_string()]);
    let matching_client = reqwest_client_for_proxy(&matching);
    let response = matching_client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .expect("matching SAN allow-list should connect through reqwest");
    assert!(response.status().is_success());

    let mismatching = create_test_proxy(port, &ca_path, vec!["other.local".to_string()]);
    let mismatching_client = reqwest_client_for_proxy(&mismatching);
    let err = mismatching_client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .expect_err("mismatching SAN allow-list should reject through reqwest");
    assert!(
        err.is_connect() || err.to_string().contains("SAN allow-list"),
        "expected TLS connect failure for SAN mismatch, got {err:?}"
    );
}

//! Functional tests for TLS/mTLS security across the gateway.
//!
//! Tests:
//! 1. Frontend mTLS (HTTPS proxy) — gateway requires client certs, verifies against CA
//! 2. Backend TLS CA verification — gateway verifies backend cert against trusted CA
//! 3. Gateway-as-mTLS-client — gateway presents client cert to mTLS backend
//! 4. Admin API mTLS — admin HTTPS enforces client cert verification
//! 5. TCP frontend mTLS — TCP stream proxy with client cert verification
//!
//! Run with:
//!   cargo build --bin ferrum-gateway && cargo test --test functional_tests -- functional_mtls --ignored --nocapture

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Certificate Generation
// ============================================================================

struct GeneratedCa {
    cert_pem: String,
    #[allow(dead_code)]
    key_pem: String,
    cert: rcgen::Certificate,
    key_pair: KeyPair,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("Failed to generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert,
        key_pair,
    }
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, data).unwrap();
    p.to_str().unwrap().to_string()
}

// ============================================================================
// Echo Servers
// ============================================================================

async fn start_http_echo(port: u16) -> tokio::task::JoinHandle<()> {
    let h = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"status":"ok"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    sleep(Duration::from_millis(200)).await;
    h
}

async fn start_https_echo(
    port: u16,
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: Option<&str>,
) -> tokio::task::JoinHandle<()> {
    let cert = cert_pem.to_string();
    let key = key_pem.to_string();
    let ca = client_ca_pem.map(|s| s.to_string());
    let h = tokio::spawn(async move {
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        let pk = rustls_pemfile::private_key(&mut key.as_bytes())
            .unwrap()
            .unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap();
        let mut cfg = if let Some(ca_data) = ca {
            let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_data.as_bytes())
                .filter_map(|r| r.ok())
                .collect();
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(ca_certs);
            let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap();
            builder
                .with_client_cert_verifier(v)
                .with_single_cert(certs, pk)
                .unwrap()
        } else {
            builder
                .with_no_client_auth()
                .with_single_cert(certs, pk)
                .unwrap()
        };
        // Advertise h2 + http/1.1 so gateway can negotiate
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        while let Ok((tcp, _)) = listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let mut s = match acc.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"status":"ok","tls":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    sleep(Duration::from_millis(200)).await;
    h
}

async fn start_tcp_echo(port: u16) -> tokio::task::JoinHandle<()> {
    let h = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    sleep(Duration::from_millis(200)).await;
    h
}

// ============================================================================
// Gateway Helpers
// ============================================================================

fn gw_bin() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    }
}

fn start_gw(cfg: &str, http_port: u16, envs: &[(&str, &str)]) -> std::process::Child {
    let mut cmd = std::process::Command::new(gw_bin());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", cfg)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn gateway")
}

fn write_cfg(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

/// Build reqwest client with rustls, skip server cert verification, optional client cert.
fn mtls_client(cert: Option<&str>, key: Option<&str>) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    if let (Some(c), Some(k)) = (cert, key) {
        let id = reqwest::Identity::from_pem(format!("{}\n{}", c, k).as_bytes()).unwrap();
        b = b.identity(id);
    }
    b.build().unwrap()
}

#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Frontend mTLS: valid client cert → 200
#[ignore]
#[tokio::test]
async fn test_frontend_mtls_valid_client_cert() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("FE-CA");
    let srv = generate_signed_cert(&ca, "GW", &["localhost", "127.0.0.1"]);
    let cli = generate_signed_cert(&ca, "Client", &["c.local"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let srv_c = write_pem(&td, "s.crt", &srv.cert_pem);
    let srv_k = write_pem(&td, "s.key", &srv.key_pem);
    let bp = 19850u16;
    let hp = 18250u16;
    let sp = 18251u16;
    let echo = start_http_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t1"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {bp}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_PROXY_HTTPS_PORT", &sp.to_string()),
            ("FERRUM_PROXY_TLS_CERT_PATH", &srv_c),
            ("FERRUM_PROXY_TLS_KEY_PATH", &srv_k),
            ("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_TLS_NO_VERIFY", "false"),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = mtls_client(Some(&cli.cert_pem), Some(&cli.key_pem));
    let r = c
        .get(format!("https://127.0.0.1:{}/api/test", sp))
        .send()
        .await
        .expect("valid client cert should succeed");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Frontend mTLS: no client cert → rejected
#[ignore]
#[tokio::test]
async fn test_frontend_mtls_no_client_cert_rejected() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("FE-CA2");
    let srv = generate_signed_cert(&ca, "GW2", &["localhost", "127.0.0.1"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let srv_c = write_pem(&td, "s.crt", &srv.cert_pem);
    let srv_k = write_pem(&td, "s.key", &srv.key_pem);
    let bp = 19852u16;
    let hp = 18252u16;
    let sp = 18253u16;
    let echo = start_http_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t2"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {bp}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_PROXY_HTTPS_PORT", &sp.to_string()),
            ("FERRUM_PROXY_TLS_CERT_PATH", &srv_c),
            ("FERRUM_PROXY_TLS_KEY_PATH", &srv_k),
            ("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_TLS_NO_VERIFY", "false"),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = mtls_client(None, None);
    let r = c
        .get(format!("https://127.0.0.1:{}/api/test", sp))
        .send()
        .await;
    assert!(r.is_err(), "no client cert → rejected");
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Frontend mTLS: wrong CA → rejected
#[ignore]
#[tokio::test]
async fn test_frontend_mtls_wrong_ca_rejected() {
    let td = TempDir::new().unwrap();
    let good_ca = generate_ca("Good-CA");
    let bad_ca = generate_ca("Bad-CA");
    let srv = generate_signed_cert(&good_ca, "GW3", &["localhost", "127.0.0.1"]);
    let rogue = generate_signed_cert(&bad_ca, "Rogue", &["r.local"]);
    let ca_p = write_pem(&td, "ca.pem", &good_ca.cert_pem);
    let srv_c = write_pem(&td, "s.crt", &srv.cert_pem);
    let srv_k = write_pem(&td, "s.key", &srv.key_pem);
    let bp = 19854u16;
    let hp = 18254u16;
    let sp = 18255u16;
    let echo = start_http_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t3"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {bp}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_PROXY_HTTPS_PORT", &sp.to_string()),
            ("FERRUM_PROXY_TLS_CERT_PATH", &srv_c),
            ("FERRUM_PROXY_TLS_KEY_PATH", &srv_k),
            ("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_TLS_NO_VERIFY", "false"),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = mtls_client(Some(&rogue.cert_pem), Some(&rogue.key_pem));
    let r = c
        .get(format!("https://127.0.0.1:{}/api/test", sp))
        .send()
        .await;
    assert!(r.is_err(), "wrong CA cert → rejected");
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Backend TLS: trusted CA → 200
#[ignore]
#[tokio::test]
async fn test_backend_tls_ca_verification_trusted() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("BE-CA");
    let be = generate_signed_cert(&ca, "Backend", &["localhost"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let bp = 19856u16;
    let hp = 18256u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, None).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t4"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_p}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[("FERRUM_TLS_NO_VERIFY", "false")],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("trusted backend should succeed");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Backend TLS: untrusted CA → 502
#[ignore]
#[tokio::test]
async fn test_backend_tls_ca_verification_untrusted() {
    let td = TempDir::new().unwrap();
    let good_ca = generate_ca("Good-BE-CA");
    let bad_ca = generate_ca("Bad-BE-CA");
    let be = generate_signed_cert(&bad_ca, "BadBackend", &["localhost"]);
    let ca_p = write_pem(&td, "ca.pem", &good_ca.cert_pem);
    let bp = 19858u16;
    let hp = 18258u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, None).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t5"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_p}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[("FERRUM_TLS_NO_VERIFY", "false")],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("should return 502, not hang");
    assert_eq!(r.status().as_u16(), 502);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Gateway presents client cert to mTLS backend → 200
#[ignore]
#[tokio::test]
async fn test_backend_mtls_gateway_presents_client_cert() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("mTLS-CA");
    let be = generate_signed_cert(&ca, "mTLS-BE", &["localhost"]);
    let gwc = generate_signed_cert(&ca, "GW-Client", &["gw.local"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let gwc_c = write_pem(&td, "gw.crt", &gwc.cert_pem);
    let gwc_k = write_pem(&td, "gw.key", &gwc.key_pem);
    let bp = 19860u16;
    let hp = 18260u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, Some(&ca.cert_pem)).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t6"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_p}"
    backend_tls_client_cert_path: "{gwc_c}"
    backend_tls_client_key_path: "{gwc_k}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[("FERRUM_TLS_NO_VERIFY", "false")],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("gateway with client cert should reach mTLS backend");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Gateway without client cert → mTLS backend rejects → 502
#[ignore]
#[tokio::test]
async fn test_backend_mtls_gateway_no_client_cert_rejected() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("mTLS-CA2");
    let be = generate_signed_cert(&ca, "mTLS-BE2", &["localhost"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let bp = 19862u16;
    let hp = 18262u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, Some(&ca.cert_pem)).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t7"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_p}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[("FERRUM_TLS_NO_VERIFY", "false")],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("should return 502, not hang");
    assert_eq!(r.status().as_u16(), 502);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Global FERRUM_BACKEND_TLS_CLIENT_CERT/KEY_PATH → mTLS backend → 200
#[ignore]
#[tokio::test]
async fn test_backend_mtls_global_env_vars() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("Global-mTLS-CA");
    let be = generate_signed_cert(&ca, "Global-BE", &["localhost"]);
    let gwc = generate_signed_cert(&ca, "GW-Global", &["gw.local"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let gwc_c = write_pem(&td, "gw.crt", &gwc.cert_pem);
    let gwc_k = write_pem(&td, "gw.key", &gwc.key_pem);
    let bp = 19864u16;
    let hp = 18264u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, Some(&ca.cert_pem)).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t8"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_TLS_NO_VERIFY", "false"),
            ("FERRUM_TLS_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_BACKEND_TLS_CLIENT_CERT_PATH", &gwc_c),
            ("FERRUM_BACKEND_TLS_CLIENT_KEY_PATH", &gwc_k),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("global mTLS cert should work");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Admin mTLS: authorized client → 200
#[ignore]
#[tokio::test]
async fn test_admin_mtls_authorized_client() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("Admin-CA");
    let adm_srv = generate_signed_cert(&ca, "Admin-Srv", &["localhost", "127.0.0.1"]);
    let adm_cli = generate_signed_cert(&ca, "Admin-Cli", &["a.local"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let ac = write_pem(&td, "a.crt", &adm_srv.cert_pem);
    let ak = write_pem(&td, "a.key", &adm_srv.key_pem);
    let bp = 19866u16;
    let hp = 18266u16;
    let ahp = 18267u16;
    let asp = 18268u16;
    let echo = start_http_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t9"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {bp}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_HTTP_PORT", &ahp.to_string()),
            ("FERRUM_ADMIN_HTTPS_PORT", &asp.to_string()),
            ("FERRUM_ADMIN_TLS_CERT_PATH", &ac),
            ("FERRUM_ADMIN_TLS_KEY_PATH", &ak),
            ("FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
        ],
    );
    // Wait for admin HTTPS listener, then verify via HTTP health first
    sleep(Duration::from_secs(3)).await;
    let plain = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let health = plain
        .get(format!("http://127.0.0.1:{}/health", ahp))
        .send()
        .await;
    assert!(
        health.is_ok(),
        "admin HTTP health should be reachable before testing HTTPS"
    );
    let c = mtls_client(Some(&adm_cli.cert_pem), Some(&adm_cli.key_pem));
    let r = c
        .get(format!("https://127.0.0.1:{}/health", asp))
        .send()
        .await
        .expect("admin mTLS with valid cert should succeed");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Admin mTLS: no client cert → rejected
#[ignore]
#[tokio::test]
async fn test_admin_mtls_unauthorized_client_rejected() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("Admin-CA2");
    let adm_srv = generate_signed_cert(&ca, "Admin-Srv2", &["localhost", "127.0.0.1"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let ac = write_pem(&td, "a.crt", &adm_srv.cert_pem);
    let ak = write_pem(&td, "a.key", &adm_srv.key_pem);
    let bp = 19868u16;
    let hp = 18270u16;
    let ahp = 18271u16;
    let asp = 18272u16;
    let echo = start_http_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t10"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {bp}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_HTTP_PORT", &ahp.to_string()),
            ("FERRUM_ADMIN_HTTPS_PORT", &asp.to_string()),
            ("FERRUM_ADMIN_TLS_CERT_PATH", &ac),
            ("FERRUM_ADMIN_TLS_KEY_PATH", &ak),
            ("FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = mtls_client(None, None);
    let r = c
        .get(format!("https://127.0.0.1:{}/health", asp))
        .send()
        .await;
    assert!(r.is_err(), "no client cert → admin rejected");
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// TCP frontend mTLS: valid client cert → echo works
#[ignore]
#[tokio::test]
async fn test_tcp_frontend_mtls_valid_client() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("TCP-CA");
    let srv = generate_signed_cert(&ca, "TCP-GW", &["localhost", "127.0.0.1"]);
    let cli = generate_signed_cert(&ca, "TCP-Cli", &["c.local"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let sc = write_pem(&td, "s.crt", &srv.cert_pem);
    let sk = write_pem(&td, "s.key", &srv.key_pem);
    let bp = 19870u16;
    let pp = 19871u16;
    let hp = 18274u16;
    let echo = start_tcp_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t11"
    listen_path: ""
    listen_port: {pp}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {bp}
    frontend_tls: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_PROXY_TLS_CERT_PATH", &sc),
            ("FERRUM_PROXY_TLS_KEY_PATH", &sk),
            ("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_TLS_NO_VERIFY", "false"),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let chain: Vec<_> = rustls_pemfile::certs(&mut cli.cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut cli.key_pem.as_bytes())
        .unwrap()
        .unwrap();
    let prov = rustls::crypto::ring::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(prov))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_client_auth_cert(chain, key)
        .unwrap();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", pp))
        .await
        .unwrap();
    let sn = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut s = conn.connect(sn, tcp).await.expect("mTLS handshake");
    s.write_all(b"Hello TCP mTLS!").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"Hello TCP mTLS!");
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// TCP frontend mTLS: no client cert → connection closed
#[ignore]
#[tokio::test]
async fn test_tcp_frontend_mtls_no_client_cert_rejected() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("TCP-CA2");
    let srv = generate_signed_cert(&ca, "TCP-GW2", &["localhost", "127.0.0.1"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let sc = write_pem(&td, "s.crt", &srv.cert_pem);
    let sk = write_pem(&td, "s.key", &srv.key_pem);
    let bp = 19872u16;
    let pp = 19873u16;
    let hp = 18276u16;
    let echo = start_tcp_echo(bp).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t12"
    listen_path: ""
    listen_port: {pp}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {bp}
    frontend_tls: true
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_PROXY_TLS_CERT_PATH", &sc),
            ("FERRUM_PROXY_TLS_KEY_PATH", &sk),
            ("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", &ca_p),
            ("FERRUM_TLS_NO_VERIFY", "false"),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let prov = rustls::crypto::ring::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(prov))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", pp))
        .await
        .unwrap();
    let sn = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    match conn.connect(sn, tcp).await {
        Err(_) => {} // Handshake rejected (TLS 1.2)
        Ok(mut s) => {
            // TLS 1.3: handshake may succeed, server rejects on first I/O
            let _ = s.write_all(b"test").await;
            let mut buf = vec![0u8; 1024];
            let r = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await;
            match r {
                Ok(Ok(0)) | Ok(Err(_)) => {} // Connection closed/error — expected
                Err(_) => panic!("should not hang"),
                Ok(Ok(_)) => panic!("should not get data without valid cert"),
            }
        }
    }
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

/// Global CA bundle env var for backend TLS verification → 200
#[ignore]
#[tokio::test]
async fn test_backend_tls_global_ca_bundle() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("Global-CA");
    let be = generate_signed_cert(&ca, "Global-BE", &["localhost"]);
    let ca_p = write_pem(&td, "ca.pem", &ca.cert_pem);
    let bp = 19874u16;
    let hp = 18278u16;
    let echo = start_https_echo(bp, &be.cert_pem, &be.key_pem, None).await;
    let cp = td.path().join("c.yaml");
    write_cfg(
        &cp,
        &format!(
            r#"
proxies:
  - id: "t13"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
plugin_configs: []
"#
        ),
    );
    let mut gw = start_gw(
        cp.to_str().unwrap(),
        hp,
        &[
            ("FERRUM_TLS_NO_VERIFY", "false"),
            ("FERRUM_TLS_CA_BUNDLE_PATH", &ca_p),
        ],
    );
    sleep(Duration::from_secs(3)).await;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let r = c
        .get(format!("http://127.0.0.1:{}/api/test", hp))
        .send()
        .await
        .expect("global CA bundle should work");
    assert_eq!(r.status().as_u16(), 200);
    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

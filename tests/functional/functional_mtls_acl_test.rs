//! Functional tests for mTLS-based identity (`mtls_auth` plugin) paired with
//! the `access_control` plugin across all transports that carry client certs:
//!
//! 1. HTTP frontend mTLS (HTTPS) → mtls_auth + access_control
//! 2. TCP frontend mTLS (frontend_tls)→ mtls_auth + access_control
//! 3. UDP+DTLS frontend mTLS (frontend_tls on stream_kind=udp) → mtls_auth + access_control
//!
//! Each transport runs the same identity-mapping flow:
//!   1. The TLS/DTLS frontend validates the client cert against the configured
//!      CA bundle (handshake-layer rejection if invalid).
//!   2. `mtls_auth` extracts the configured cert field (subject CN here) and
//!      maps it to a Consumer through `consumer_index.find_by_identity`.
//!   3. `access_control` enforces the allow/deny list against the identified
//!      Consumer's username.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && \
//!     cargo test --test functional_tests -- functional_mtls_acl --ignored --nocapture

use crate::common::TestGateway;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::sleep;

// ============================================================================
// Certificate Generation (ECDSA P-256 — required by dimpl/DTLS)
// ============================================================================

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
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
    let cert_pem = cert.pem();
    GeneratedCa {
        cert_pem,
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
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

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, data).unwrap();
    p.to_str().unwrap().to_string()
}

fn write_cfg(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

// ============================================================================
// rustls helpers (skip server cert verification — gateway uses self-signed certs)
// ============================================================================

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

fn mtls_http_client(cli: &GeneratedCert) -> reqwest::Client {
    let id = reqwest::Identity::from_pem(format!("{}\n{}", cli.cert_pem, cli.key_pem).as_bytes())
        .unwrap();
    reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .identity(id)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

// ============================================================================
// Echo Servers
// ============================================================================

async fn start_http_echo_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"status":"ok","mtls":true}"#;
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
    sleep(Duration::from_millis(100)).await;
    h
}

async fn start_tcp_echo_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    let h = tokio::spawn(async move {
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
    sleep(Duration::from_millis(100)).await;
    h
}

async fn start_udp_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], src).await;
        }
    });
    sleep(Duration::from_millis(100)).await;
    (port, handle)
}

// ============================================================================
// Gateway Helpers (mirrors functional_mtls_test.rs::start_gateway_with_retry)
// ============================================================================

async fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn alloc_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

struct GatewayPorts {
    proxy_http: u16,
    proxy_https: u16,
    admin_http: u16,
    admin_https: u16,
    /// UDP listener port for stream proxies (DTLS frontend).
    stream_udp: u16,
}

async fn start_gateway_with_retry<F, G>(
    cfg_path: &std::path::Path,
    build_config: F,
    build_envs: G,
) -> (TestGateway, GatewayPorts)
where
    F: Fn(&GatewayPorts) -> String,
    G: Fn(&GatewayPorts) -> Vec<(String, String)>,
{
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = GatewayPorts {
            proxy_http: alloc_port().await,
            proxy_https: alloc_port().await,
            admin_http: alloc_port().await,
            admin_https: alloc_port().await,
            stream_udp: alloc_udp_port().await,
        };

        let config_content = build_config(&ports);
        write_cfg(cfg_path, &config_content);

        let mut builder = TestGateway::builder()
            .mode_file(config_content)
            .max_attempts(1)
            .capture_output()
            .env("FERRUM_PROXY_HTTP_PORT", ports.proxy_http.to_string())
            .env("RUST_LOG", "ferrum_gateway=debug");
        for (key, value) in build_envs(&ports) {
            builder = builder.env(key, value);
        }

        match builder.spawn().await {
            Ok(gw) => return (gw, ports),
            Err(e) => {
                last_err = e.to_string();
                eprintln!(
                    "Gateway startup attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, last_err
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 1: HTTP frontend mTLS + mtls_auth + access_control (allow + deny)
// ============================================================================

/// Drives the HTTP mTLS+ACL flow: alice (allowed CN) → 200, eve (denied CN) → 403,
/// stranger (CN with no consumer mapping) → 401.
#[ignore]
#[tokio::test]
async fn test_http_mtls_auth_with_acl() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("MTLS-ACL-HTTP-CA");
    let server = generate_signed_cert(&ca, "ferrum-gw", &["localhost", "127.0.0.1"]);
    let alice = generate_signed_cert(&ca, "alice.client.local", &["alice.client.local"]);
    let eve = generate_signed_cert(&ca, "eve.client.local", &["eve.client.local"]);
    let stranger = generate_signed_cert(&ca, "stranger.client.local", &["stranger.client.local"]);

    let ca_pem = write_pem(&td, "ca.pem", &ca.cert_pem);
    let server_cert = write_pem(&td, "server.crt", &server.cert_pem);
    let server_key = write_pem(&td, "server.key", &server.key_pem);

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo = start_http_echo_on(backend_listener).await;

    let cfg_path = td.path().join("config.yaml");
    let (mut gw, ports) = start_gateway_with_retry(
        &cfg_path,
        |_ports| {
            format!(
                r#"
version: "1"
proxies:
  - id: "mtls-acl-http"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "p-mtls"
      - plugin_config_id: "p-acl"

consumers:
  - id: "alice"
    username: "alice"
    credentials:
      mtls_auth:
        - identity: "alice.client.local"
  - id: "eve"
    username: "eve"
    credentials:
      mtls_auth:
        - identity: "eve.client.local"

plugin_configs:
  - id: "p-mtls"
    proxy_id: "mtls-acl-http"
    plugin_name: "mtls_auth"
    scope: "proxy"
    enabled: true
    config:
      cert_field: "subject_cn"
  - id: "p-acl"
    proxy_id: "mtls-acl-http"
    plugin_name: "access_control"
    scope: "proxy"
    enabled: true
    config:
      allowed_consumers: ["alice"]
"#
            )
        },
        |ports| {
            vec![
                (
                    "FERRUM_PROXY_HTTPS_PORT".into(),
                    ports.proxy_https.to_string(),
                ),
                (
                    "FERRUM_ADMIN_HTTP_PORT".into(),
                    ports.admin_http.to_string(),
                ),
                (
                    "FERRUM_ADMIN_HTTPS_PORT".into(),
                    ports.admin_https.to_string(),
                ),
                ("FERRUM_FRONTEND_TLS_CERT_PATH".into(), server_cert.clone()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH".into(), server_key.clone()),
                (
                    "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH".into(),
                    ca_pem.clone(),
                ),
                ("FERRUM_TLS_NO_VERIFY".into(), "false".into()),
            ]
        },
    )
    .await;

    let url = format!("https://127.0.0.1:{}/api/test", ports.proxy_https);

    // alice → 200 (CN matches consumer "alice", in allow list)
    let r = mtls_http_client(&alice)
        .get(&url)
        .send()
        .await
        .expect("alice request should reach the gateway");
    assert_eq!(
        r.status().as_u16(),
        200,
        "alice should be allowed: {}",
        r.status()
    );

    // eve → 403 (CN matches consumer "eve" but not in allow list)
    let r = mtls_http_client(&eve)
        .get(&url)
        .send()
        .await
        .expect("eve request should reach the gateway");
    assert_eq!(
        r.status().as_u16(),
        403,
        "eve should be blocked by ACL: {}",
        r.status()
    );

    // stranger → 401 (valid CA-signed cert but no consumer with this identity)
    let r = mtls_http_client(&stranger)
        .get(&url)
        .send()
        .await
        .expect("stranger request should reach the gateway");
    assert_eq!(
        r.status().as_u16(),
        401,
        "stranger CN with no consumer mapping should be 401: {}",
        r.status()
    );

    gw.shutdown();
    echo.abort();
}

// ============================================================================
// Test 2: TCP+TLS frontend mTLS + mtls_auth + access_control
// ============================================================================

async fn tcp_mtls_send(
    listen_port: u16,
    cli: &GeneratedCert,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let chain: Vec<_> = rustls_pemfile::certs(&mut cli.cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut cli.key_pem.as_bytes())
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "no private key".to_string())?;
    let prov = rustls::crypto::ring::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(prov))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls builder: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("client_auth_cert: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", listen_port))
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("server name: {e}"))?;
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;
    tls_stream
        .write_all(payload)
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await {
        Ok(Ok(0)) => return Err("connection closed before any data".into()),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("read: {e}")),
        Err(_) => return Err("read timed out".into()),
    };
    Ok(buf[..n].to_vec())
}

#[ignore]
#[tokio::test]
async fn test_tcp_mtls_auth_with_acl() {
    let td = TempDir::new().unwrap();
    let ca = generate_ca("MTLS-ACL-TCP-CA");
    let server = generate_signed_cert(&ca, "ferrum-gw-tcp", &["localhost", "127.0.0.1"]);
    let alice = generate_signed_cert(&ca, "tcp-alice", &["tcp-alice"]);
    let eve = generate_signed_cert(&ca, "tcp-eve", &["tcp-eve"]);

    let ca_pem = write_pem(&td, "ca.pem", &ca.cert_pem);
    let server_cert = write_pem(&td, "server.crt", &server.cert_pem);
    let server_key = write_pem(&td, "server.key", &server.key_pem);

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo = start_tcp_echo_on(backend_listener).await;

    let cfg_path = td.path().join("config.yaml");
    let (mut gw, ports) = start_gateway_with_retry(
        &cfg_path,
        |ports| {
            // Reuse the proxy_https slot for the TCP stream listener (matches functional_mtls_test.rs convention).
            let pp = ports.proxy_https;
            format!(
                r#"
version: "1"
proxies:
  - id: "mtls-acl-tcp"
    listen_port: {pp}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    plugins:
      - plugin_config_id: "p-tcp-mtls"
      - plugin_config_id: "p-tcp-acl"

consumers:
  - id: "tcp-alice"
    username: "tcp-alice"
    credentials:
      mtls_auth:
        - identity: "tcp-alice"
  - id: "tcp-eve"
    username: "tcp-eve"
    credentials:
      mtls_auth:
        - identity: "tcp-eve"

plugin_configs:
  - id: "p-tcp-mtls"
    proxy_id: "mtls-acl-tcp"
    plugin_name: "mtls_auth"
    scope: "proxy"
    enabled: true
    config:
      cert_field: "subject_cn"
  - id: "p-tcp-acl"
    proxy_id: "mtls-acl-tcp"
    plugin_name: "access_control"
    scope: "proxy"
    enabled: true
    config:
      allowed_consumers: ["tcp-alice"]
"#
            )
        },
        |ports| {
            vec![
                // Disable the HTTPS proxy listener so the proxy_https port slot is free for the stream proxy.
                ("FERRUM_PROXY_HTTPS_PORT".into(), "0".into()),
                (
                    "FERRUM_ADMIN_HTTP_PORT".into(),
                    ports.admin_http.to_string(),
                ),
                (
                    "FERRUM_ADMIN_HTTPS_PORT".into(),
                    ports.admin_https.to_string(),
                ),
                ("FERRUM_FRONTEND_TLS_CERT_PATH".into(), server_cert.clone()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH".into(), server_key.clone()),
                (
                    "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH".into(),
                    ca_pem.clone(),
                ),
                ("FERRUM_TLS_NO_VERIFY".into(), "false".into()),
            ]
        },
    )
    .await;

    let listen_port = ports.proxy_https;

    // alice — handshake + identity match + ACL allow → echo round-trip succeeds
    let echoed = tcp_mtls_send(listen_port, &alice, b"alice-tcp-mtls").await;
    assert_eq!(
        echoed.as_deref(),
        Ok(&b"alice-tcp-mtls"[..]),
        "alice should be allowed and echo through: {:?}",
        echoed
    );

    // eve — handshake + identity match but ACL rejects → no echo (connection closed by ACL).
    //
    // The TCP relay closes immediately after the on_stream_connect Reject. With TLS 1.3 the
    // handshake itself completes, so the failure surfaces as either the immediate connection
    // close or as no echo data. Either way, eve must NOT receive the payload back.
    let echoed_eve = tcp_mtls_send(listen_port, &eve, b"eve-tcp-mtls").await;
    match echoed_eve {
        Err(_) => {} // expected — relay aborted
        Ok(bytes) => assert!(
            bytes.is_empty() || &bytes[..] != b"eve-tcp-mtls",
            "eve must NOT receive an echo of the payload, got {:?}",
            String::from_utf8_lossy(&bytes)
        ),
    }

    gw.shutdown();
    echo.abort();
}

// ============================================================================
// Test 3: UDP+DTLS frontend mTLS + mtls_auth + access_control
// ============================================================================

/// Build a DTLS client cert from a CA-signed PEM pair. dimpl needs DER bytes,
/// so we reuse the gateway's PEM→DER loader (`load_dtls_certificate`) by
/// writing the PEMs to disk. ECDSA P-256 only — dimpl rejects RSA / Ed25519.
fn dtls_client_certificate(
    td: &TempDir,
    name: &str,
    cli: &GeneratedCert,
) -> dimpl::DtlsCertificateChain {
    let cert_path = write_pem(td, &format!("{}.crt", name), &cli.cert_pem);
    let key_path = write_pem(td, &format!("{}.key", name), &cli.key_pem);
    ferrum_edge::dtls::load_dtls_certificate(&cert_path, &key_path)
        .expect("load DTLS client cert (must be ECDSA P-256/P-384)")
}

async fn dtls_send(
    proxy_port: u16,
    client_cert: dimpl::DtlsCertificateChain,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("client udp bind: {e}"))?;
    socket
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .map_err(|e| format!("udp connect: {e}"))?;

    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(dimpl::Config::default()),
        certificate: client_cert,
        server_name: None,
        server_cert_verifier: None,
        connect_timeout_ms: 5_000,
    };

    let conn = match tokio::time::timeout(
        Duration::from_secs(5),
        ferrum_edge::dtls::DtlsConnection::connect(socket, params),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(format!("dtls handshake: {e}")),
        Err(_) => return Err("dtls handshake timed out".into()),
    };

    conn.send(payload).await.map_err(|e| format!("send: {e}"))?;

    match tokio::time::timeout(Duration::from_secs(5), conn.recv()).await {
        Ok(Ok(buf)) => Ok(buf),
        Ok(Err(e)) => Err(format!("recv: {e}")),
        Err(_) => Err("recv timed out".into()),
    }
}

#[ignore]
#[tokio::test]
async fn test_udp_dtls_mtls_auth_with_acl() {
    // dimpl/rustls expect ring's CryptoProvider — install once.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let td = TempDir::new().unwrap();
    let ca = generate_ca("MTLS-ACL-DTLS-CA");
    let server = generate_signed_cert(&ca, "ferrum-gw-dtls", &["localhost", "127.0.0.1"]);
    let alice = generate_signed_cert(&ca, "dtls-alice", &["dtls-alice"]);
    let eve = generate_signed_cert(&ca, "dtls-eve", &["dtls-eve"]);

    let ca_pem = write_pem(&td, "ca.pem", &ca.cert_pem);
    let server_cert = write_pem(&td, "server.crt", &server.cert_pem);
    let server_key = write_pem(&td, "server.key", &server.key_pem);

    let (backend_port, echo) = start_udp_echo_server().await;

    let cfg_path = td.path().join("config.yaml");
    let (mut gw, ports) = start_gateway_with_retry(
        &cfg_path,
        |ports| {
            let pp = ports.stream_udp;
            format!(
                r#"
version: "1"
proxies:
  - id: "mtls-acl-dtls"
    listen_port: {pp}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    plugins:
      - plugin_config_id: "p-dtls-mtls"
      - plugin_config_id: "p-dtls-acl"

consumers:
  - id: "dtls-alice"
    username: "dtls-alice"
    credentials:
      mtls_auth:
        - identity: "dtls-alice"
  - id: "dtls-eve"
    username: "dtls-eve"
    credentials:
      mtls_auth:
        - identity: "dtls-eve"

plugin_configs:
  - id: "p-dtls-mtls"
    proxy_id: "mtls-acl-dtls"
    plugin_name: "mtls_auth"
    scope: "proxy"
    enabled: true
    config:
      cert_field: "subject_cn"
  - id: "p-dtls-acl"
    proxy_id: "mtls-acl-dtls"
    plugin_name: "access_control"
    scope: "proxy"
    enabled: true
    config:
      allowed_consumers: ["dtls-alice"]
"#
            )
        },
        |ports| {
            vec![
                ("FERRUM_PROXY_HTTPS_PORT".into(), "0".into()),
                (
                    "FERRUM_ADMIN_HTTP_PORT".into(),
                    ports.admin_http.to_string(),
                ),
                (
                    "FERRUM_ADMIN_HTTPS_PORT".into(),
                    ports.admin_https.to_string(),
                ),
                // DTLS frontend uses its own cert/key/CA env vars.
                ("FERRUM_DTLS_CERT_PATH".into(), server_cert.clone()),
                ("FERRUM_DTLS_KEY_PATH".into(), server_key.clone()),
                ("FERRUM_DTLS_CLIENT_CA_CERT_PATH".into(), ca_pem.clone()),
                ("FERRUM_TLS_NO_VERIFY".into(), "false".into()),
            ]
        },
    )
    .await;

    let listen_port = ports.stream_udp;
    let alice_cert = dtls_client_certificate(&td, "dtls-alice", &alice);
    let eve_cert = dtls_client_certificate(&td, "dtls-eve", &eve);

    // alice → echo round-trips
    let echoed = dtls_send(listen_port, alice_cert, b"alice-dtls-mtls").await;
    assert_eq!(
        echoed.as_deref(),
        Ok(&b"alice-dtls-mtls"[..]),
        "alice should be allowed and DTLS echo through: {:?}",
        echoed
    );

    // eve — handshake succeeds (cert valid against CA) but ACL rejects.
    // DTLS path runs `on_stream_connect` only after the handshake completes,
    // so the connection closes without the backend ever seeing the datagram.
    let echoed_eve = dtls_send(listen_port, eve_cert, b"eve-dtls-mtls").await;
    match echoed_eve {
        Err(_) => {} // expected — recv timed out / channel closed
        Ok(bytes) => assert!(
            bytes.is_empty() || &bytes[..] != b"eve-dtls-mtls",
            "eve must NOT receive an echo of the payload, got {:?}",
            String::from_utf8_lossy(&bytes)
        ),
    }

    gw.shutdown();
    echo.abort();
}

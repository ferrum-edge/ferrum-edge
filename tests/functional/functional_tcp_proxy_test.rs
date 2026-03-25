//! Functional tests for TCP stream proxy (plain TCP and TCP+TLS).
//!
//! Tests:
//! 1. Plain TCP bidirectional data flow through the gateway
//! 2. Frontend TLS termination (client connects with TLS, backend receives plain TCP)
//! 3. Backend TLS origination (TcpTls protocol — gateway connects to backend over TLS)
//! 4. Full TLS: frontend termination + backend origination simultaneously
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-gateway && cargo test --test functional_tests -- functional_tcp_proxy --ignored --nocapture

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// TCP Echo Server (plain)
// ============================================================================

/// Start a plain TCP echo server that reads data and echoes it back.
async fn start_tcp_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind TCP echo server on port {}", port));

        while let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    // Give the server time to bind
    sleep(Duration::from_millis(200)).await;
    handle
}

// ============================================================================
// TLS Echo Server (for testing backend TLS origination)
// ============================================================================

/// Start a TLS-enabled TCP echo server using the test certs.
async fn start_tls_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let cert_path = std::path::Path::new("tests/certs/server.crt");
        let key_path = std::path::Path::new("tests/certs/server.key");

        let cert_pem = std::fs::read(cert_path).expect("Failed to read test cert");
        let key_pem = std::fs::read(key_path).expect("Failed to read test key");

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .filter_map(|r| r.ok())
                .collect();

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("Failed to parse key PEM")
            .expect("No private key found in PEM");

        let provider = rustls::crypto::ring::default_provider();
        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("Failed to build TLS server config");

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind TLS echo server on port {}", port));

        while let Ok((tcp_stream, _addr)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("TLS accept error: {}", e);
                        return;
                    }
                };
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    sleep(Duration::from_millis(200)).await;
    handle
}

// ============================================================================
// Gateway Helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_BACKEND_TLS_NO_VERIFY", "true")
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(cert) = tls_cert_path {
        cmd.env("FERRUM_PROXY_TLS_CERT_PATH", cert);
    }
    if let Some(key) = tls_key_path {
        cmd.env("FERRUM_PROXY_TLS_KEY_PATH", key);
    }

    Ok(cmd.spawn()?)
}

fn write_config(path: &std::path::Path, content: &str) {
    let mut file = std::fs::File::create(path).expect("Failed to create config file");
    file.write_all(content.as_bytes())
        .expect("Failed to write config");
}

/// Build a TLS client connector that trusts self-signed certs (for testing).
fn insecure_tls_connector() -> tokio_rustls::TlsConnector {
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Certificate verifier that accepts any certificate (for test self-signed certs).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test 1: Plain TCP proxy — send data through the gateway, receive echo.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_plain_bidirectional() {
    let backend_port = 19800u16;
    let proxy_port = 19801u16;
    let gateway_http_port = 18200u16;

    let echo_server = start_tcp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "tcp-echo"
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_http_port, None, None)
        .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect through the TCP proxy
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to TCP proxy");

    // Send data
    let test_data = b"Hello, TCP proxy!";
    stream.write_all(test_data).await.expect("Failed to send");

    // Read echo response
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    // Send more data to verify bidirectional streaming
    let test_data2 = b"Second message through TCP proxy";
    stream
        .write_all(test_data2)
        .await
        .expect("Failed to send second message");

    let n2 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n2], test_data2, "Second echo response should match");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 2: TCP proxy with frontend TLS termination.
/// Client connects with TLS → gateway terminates TLS → forwards plain TCP to backend.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_frontend_tls_termination() {
    let backend_port = 19802u16;
    let proxy_port = 19803u16;
    let gateway_http_port = 18201u16;

    let echo_server = start_tcp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "tcp-tls-frontend"
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true

consumers: []
plugin_configs: []
"#
        ),
    );

    // Start gateway with TLS cert/key (needed for frontend_tls)
    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .expect("cert not found")
        .to_string_lossy()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .expect("key not found")
        .to_string_lossy()
        .to_string();

    let mut gateway = start_gateway(
        config_path.to_str().unwrap(),
        gateway_http_port,
        Some(&cert_path),
        Some(&key_path),
    )
    .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect through TLS to the TCP proxy
    let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to proxy port");

    let connector = insecure_tls_connector();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake failed");

    // Send data over TLS
    let test_data = b"Hello through TLS!";
    tls_stream
        .write_all(test_data)
        .await
        .expect("Failed to send");

    // Read echo response
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 3: TCP proxy with backend TLS origination (TcpTls protocol).
/// Client sends plain TCP → gateway connects to backend over TLS.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_backend_tls_origination() {
    let backend_port = 19804u16;
    let proxy_port = 19805u16;
    let gateway_http_port = 18202u16;

    let echo_server = start_tls_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "tcp-tls-backend"
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: tcp_tls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_http_port, None, None)
        .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect with plain TCP — gateway handles TLS to backend
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to TCP proxy");

    let test_data = b"Hello through backend TLS!";
    stream.write_all(test_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 4: Full TLS — frontend TLS termination + backend TLS origination.
/// Client → TLS → gateway → TLS → backend echo server.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_full_tls() {
    let backend_port = 19806u16;
    let proxy_port = 19807u16;
    let gateway_http_port = 18203u16;

    let echo_server = start_tls_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "tcp-full-tls"
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: tcp_tls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
        ),
    );

    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .expect("cert not found")
        .to_string_lossy()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .expect("key not found")
        .to_string_lossy()
        .to_string();

    let mut gateway = start_gateway(
        config_path.to_str().unwrap(),
        gateway_http_port,
        Some(&cert_path),
        Some(&key_path),
    )
    .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect through TLS
    let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect");

    let connector = insecure_tls_connector();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake failed");

    let test_data = b"End-to-end TLS data!";
    tls_stream
        .write_all(test_data)
        .await
        .expect("Failed to send");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n], test_data, "Full TLS echo should match");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 5: TCP proxy handles connection to unreachable backend gracefully.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_backend_unreachable() {
    let proxy_port = 19808u16;
    let gateway_http_port = 18204u16;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "tcp-unreachable"
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: 19899
    backend_connect_timeout_ms: 1000

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_http_port, None, None)
        .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect to proxy — should accept the TCP connection
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port)),
    )
    .await;

    match result {
        Ok(Ok(mut stream)) => {
            // Connection accepted at proxy level, but backend is down.
            // The proxy should close the connection after failing to connect to backend.
            let mut buf = vec![0u8; 1024];
            let read_result =
                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            match read_result {
                Ok(Ok(0)) => {}  // Connection closed — expected
                Ok(Ok(_)) => {}  // Some data (e.g., error) — acceptable
                Ok(Err(_)) => {} // Read error — acceptable
                Err(_) => panic!("Connection should close, not hang"),
            }
        }
        Ok(Err(_)) => {} // Connection refused — also acceptable
        Err(_) => panic!("Connection attempt should not hang"),
    }

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
}

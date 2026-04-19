//! Functional tests for TCP stream proxy (plain TCP and TCP+TLS).
//!
//! Tests:
//! 1. Plain TCP bidirectional data flow through the gateway
//! 2. Frontend TLS termination (client connects with TLS, backend receives plain TCP)
//! 3. Backend TLS origination (TcpTls protocol — gateway connects to backend over TLS)
//! 4. Full TLS: frontend termination + backend origination simultaneously
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_tcp_proxy --ignored --nocapture

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
async fn start_tcp_echo_server_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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
    })
}

// ============================================================================
// TLS Echo Server (for testing backend TLS origination)
// ============================================================================

/// Start a TLS-enabled TCP echo server using the test certs.
async fn start_tls_echo_server_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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
    })
}

// ============================================================================
// Gateway Helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if let Some(cert) = tls_cert_path {
        cmd.env("FERRUM_FRONTEND_TLS_CERT_PATH", cert);
    }
    if let Some(key) = tls_key_path {
        cmd.env("FERRUM_FRONTEND_TLS_KEY_PATH", key);
    }

    Ok(cmd.spawn()?)
}

/// Wait for the gateway health endpoint to respond.
/// Returns true if healthy, false if timed out.
async fn wait_for_health(admin_port: u16) -> bool {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = std::time::SystemTime::now() + Duration::from_secs(30);
    loop {
        if std::time::SystemTime::now() >= deadline {
            return false;
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Start the gateway with retry on port-binding failures.
///
/// Allocates fresh ephemeral proxy listen, HTTP, and admin ports on each attempt
/// to handle the bind-drop-rebind port race. The `make_config` closure receives
/// `(proxy_listen_port, config_dir)` and must return the config file content.
///
/// Returns (child, proxy_listen_port, admin_port, TempDir).
async fn start_gateway_with_retry<F>(
    make_config: F,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> (std::process::Child, u16, u16, TempDir)
where
    F: Fn(u16) -> String,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // Allocate fresh ephemeral ports each attempt
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_listen_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        drop(http_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_content = make_config(proxy_listen_port);
        std::fs::write(&config_path, &config_content).unwrap();

        let mut child = match start_gateway(
            config_path.to_str().unwrap(),
            http_port,
            admin_port,
            tls_cert_path,
            tls_key_path,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        if wait_for_health(admin_port).await {
            return (child, proxy_listen_port, admin_port, dir);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: stream={}, http={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_listen_port, http_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
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
    // Backend echo server — pass pre-bound listener (no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tcp_echo_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-echo"
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

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
    // Backend echo server — bind in-process (no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tcp_echo_server_on(backend_listener).await;

    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .expect("cert not found")
        .to_string_lossy()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .expect("key not found")
        .to_string_lossy()
        .to_string();

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-tls-frontend"
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true

consumers: []
plugin_configs: []
"#
            )
        },
        Some(&cert_path),
        Some(&key_path),
    )
    .await;

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
    // Backend TLS echo server — bind in-process (no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tls_echo_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-tls-backend"
    listen_port: {proxy_port}
    backend_protocol: tcp_tls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

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
    // Backend TLS echo server — bind in-process (no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tls_echo_server_on(backend_listener).await;

    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .expect("cert not found")
        .to_string_lossy()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .expect("key not found")
        .to_string_lossy()
        .to_string();

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-full-tls"
    listen_port: {proxy_port}
    backend_protocol: tcp_tls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
            )
        },
        Some(&cert_path),
        Some(&key_path),
    )
    .await;

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

/// Test 5: TCP idle timeout — gateway closes connection after inactivity.
///
/// Creates a TCP proxy with `tcp_idle_timeout_seconds: 2`, connects, exchanges
/// data, then idles for 3 seconds. The gateway should close the connection
/// before the test's read timeout fires.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_idle_timeout() {
    // Backend echo server — bind in-process (no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tcp_echo_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-idle-timeout"
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    tcp_idle_timeout_seconds: 2

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to TCP proxy");

    // Send data and receive echo to confirm the connection is live.
    let test_data = b"ping";
    stream.write_all(test_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Echo read timed out")
        .expect("Echo read error");
    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    // Now go idle for longer than the configured timeout (2s).
    sleep(Duration::from_secs(3)).await;

    // The gateway should have closed the connection. A read should return
    // either 0 bytes (clean close) or an error — not block indefinitely.
    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

    match read_result {
        Ok(Ok(0)) => {}  // Connection closed cleanly — expected
        Ok(Err(_)) => {} // Connection reset — also acceptable
        Ok(Ok(_)) => {
            // Some stale data arrived; attempt another read to detect closure.
            let second = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            match second {
                Ok(Ok(0)) | Ok(Err(_)) => {} // Closed after draining — ok
                Ok(Ok(_)) => {
                    panic!("Connection should be closed by idle timeout, but keeps yielding data")
                }
                Err(_) => panic!("Timed out waiting for closure after stale data"),
            }
        }
        Err(_) => panic!("Timed out waiting for idle-timeout closure; connection stayed open"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 6 (formerly 5): TCP proxy handles connection to unreachable backend gracefully.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_backend_unreachable() {
    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
proxies:
  - id: "tcp-unreachable"
    listen_port: {proxy_port}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: 19899
    backend_connect_timeout_ms: 1000

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

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

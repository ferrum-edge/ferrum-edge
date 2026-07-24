//! Functional tests for TCP stream proxy (plain TCP and TCP+TLS).
//!
//! Tests:
//! 1. Plain TCP bidirectional data flow through the gateway
//! 2. Frontend TLS termination (client connects with TLS, backend receives plain TCP)
//! 3. Backend TLS origination (TcpTls protocol — gateway connects to backend over TLS)
//! 4. Full TLS: frontend termination + backend origination simultaneously
//! 5. TCP idle timeout via per-proxy config and global `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`
//! 5. TCP backend-read inactivity timeout
//! 5. TCP idle timeout from per-proxy config and global env fallback
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_tcp_proxy --ignored --nocapture

use crate::common::{
    configure_coverage_gateway_command, explicit_test_binary, shutdown_gateway_child,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Start a TCP backend that accepts data but never writes a response.
async fn start_tcp_silent_reader_server_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => sleep(Duration::from_secs(60)).await,
                    }
                }
            });
        }
    })
}

/// Start a TCP echo server that prefixes each echoed frame with a backend tag.
async fn start_tagged_tcp_echo_server_on(
    listener: TcpListener,
    tag: &'static [u8],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(tag).await.is_err() {
                                break;
                            }
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

/// Start a TCP backend that only responds after it observes client EOF.
/// This models protocols where the client half-closes its write side after
/// sending a request and the server replies later on the still-open read side.
async fn start_half_close_response_server_on(
    listener: TcpListener,
    expected_request: &'static [u8],
    response: &'static [u8],
    response_delay: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut received = Vec::new();
                if stream.read_to_end(&mut received).await.is_err() {
                    return;
                }
                if received != expected_request {
                    return;
                }

                sleep(response_delay).await;
                if stream.write_all(response).await.is_ok() {
                    let _ = stream.shutdown().await;
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

fn gateway_binary_path() -> String {
    if let Some(path) = explicit_test_binary() {
        return path.to_string_lossy().into_owned();
    }
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge".to_string()
    } else {
        "./target/release/ferrum-edge".to_string()
    }
}

fn shutdown_gateway(gateway: &mut std::process::Child) {
    shutdown_gateway_child(gateway);
}

fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
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
    configure_coverage_gateway_command(&mut cmd);

    if let Some(cert) = tls_cert_path {
        cmd.env("FERRUM_FRONTEND_TLS_CERT_PATH", cert);
    }
    if let Some(key) = tls_key_path {
        cmd.env("FERRUM_FRONTEND_TLS_KEY_PATH", key);
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
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

async fn tagged_round_trip(
    stream: &mut tokio::net::TcpStream,
    payload: &[u8],
    expected_tag: &[u8],
) {
    stream.write_all(payload).await.expect("Failed to send");

    let mut expected = Vec::with_capacity(expected_tag.len() + payload.len());
    expected.extend_from_slice(expected_tag);
    expected.extend_from_slice(payload);

    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("Tagged echo read timed out")
        .expect("Tagged echo read error");

    assert_eq!(buf, expected, "Tagged echo response should match");
}

async fn connect_tcp_proxy(proxy_port: u16) -> tokio::net::TcpStream {
    let addr = format!("127.0.0.1:{proxy_port}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(err) if Instant::now() >= deadline => {
                panic!("Failed to connect to TCP proxy at {addr}: {err}")
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
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
    start_gateway_with_retry_extra_env(make_config, tls_cert_path, tls_key_path, &[]).await
}

async fn start_gateway_with_retry_extra_env<F>(
    make_config: F,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
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

        let mut child = match start_gateway_with_extra_env(
            config_path.to_str().unwrap(),
            http_port,
            admin_port,
            tls_cert_path,
            tls_key_path,
            extra_env,
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
        shutdown_gateway(&mut child);

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
version: "1"
proxies:
  - id: "tcp-echo"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
            )
        },
        None,
        None,
    )
    .await;

    // Connect through the TCP proxy
    let mut stream = connect_tcp_proxy(proxy_port).await;

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
    shutdown_gateway(&mut gateway);
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
version: "1"
proxies:
  - id: "tcp-tls-frontend"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    frontend_tls: true
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
    shutdown_gateway(&mut gateway);
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
version: "1"
proxies:
  - id: "tcp-tls-backend"
    listen_port: {proxy_port: ''}
    backend_scheme: tcps
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    backend_tls_verify_server_cert: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
            )
        },
        None,
        None,
    )
    .await;

    // Connect with plain TCP — gateway handles TLS to backend
    let mut stream = connect_tcp_proxy(proxy_port).await;

    let test_data = b"Hello through backend TLS!";
    stream.write_all(test_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Read timed out")
        .expect("Read error");

    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    // Cleanup
    shutdown_gateway(&mut gateway);
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
version: "1"
proxies:
  - id: "tcp-full-tls"
    listen_port: {proxy_port: ''}
    backend_scheme: tcps
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    frontend_tls: true
    backend_tls_verify_server_cert: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
    shutdown_gateway(&mut gateway);
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
version: "1"
proxies:
  - id: "tcp-idle-timeout"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    tcp_idle_timeout_seconds: 2
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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

    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Test 5b: Global TCP idle timeout — a TCP proxy without a per-proxy override
/// inherits `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_global_idle_timeout_env() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tcp_echo_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-global-idle-timeout"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
            )
        },
        None,
        None,
        &[("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "2")],
    )
    .await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to TCP proxy");

    let test_data = b"global-idle";
    stream.write_all(test_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Echo read timed out")
        .expect("Echo read error");
    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    sleep(Duration::from_secs(3)).await;

    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match read_result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => {
            let second = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            match second {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!(
                    "connection should be closed by global TCP idle timeout, but keeps yielding data"
                ),
                Err(_) => panic!("timed out waiting for closure after stale data"),
            }
        }
        Err(_) => panic!("timed out waiting for global idle-timeout closure"),
    }

    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Test 5c: TCP backend-read timeout — if the backend accepts the request bytes
/// but stops producing response bytes, the relay closes the client connection.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_backend_read_timeout() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let silent_backend = start_tcp_silent_reader_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-backend-read-timeout"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    backend_read_timeout_ms: 500
    tcp_idle_timeout_seconds: 30
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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

    stream
        .write_all(b"backend-read-timeout")
        .await
        .expect("Failed to send");

    // The proxy's watchdog ticks every 1s and closes the connection once
    // `now - b2c_read_watermark >= backend_read_timeout_ms`. Give ourselves a
    // generous 45s window: locally this fires in ~1.7s, but heavily-loaded CI
    // runners (6 functional shards x parallel jobs) have observed the client
    // read poll waking well after the proxy actually closes the socket.
    let mut buf = vec![0u8; 64];
    let read_result = tokio::time::timeout(Duration::from_secs(45), stream.read(&mut buf)).await;
    match read_result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("silent backend should not send {n} bytes before timeout"),
        Err(_) => panic!("timed out waiting for backend-read-timeout closure"),
    }

    shutdown_gateway(&mut gateway);
    silent_backend.abort();
}

/// Test 5d: TCP global idle timeout env fallback.
///
/// Leaves `tcp_idle_timeout_seconds` unset on the proxy and verifies
/// `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` is still applied by the stream listener.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_global_idle_timeout_env_fallback() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let echo_server = start_tcp_echo_server_on(backend_listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-global-idle-timeout"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
            )
        },
        None,
        None,
        &[("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "1")],
    )
    .await;

    let mut stream = connect_tcp_proxy(proxy_port).await;

    let test_data = b"global-idle";
    stream.write_all(test_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("Echo read timed out")
        .expect("Echo read error");
    assert_eq!(&buf[..n], test_data, "Echo response should match sent data");

    sleep(Duration::from_secs(2)).await;

    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match read_result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => {
            let second = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            match second {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(_)) => {
                    panic!("Connection should be closed by global TCP idle timeout")
                }
                Err(_) => panic!("Timed out waiting for closure after stale data"),
            }
        }
        Err(_) => {
            panic!("Timed out waiting for global TCP idle-timeout closure; connection stayed open")
        }
    }

    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Test 6: Client half-close keeps the response direction open for delayed backend data.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_client_half_close_allows_delayed_backend_response() {
    const REQUEST: &[u8] = b"half-close-request";
    const RESPONSE: &[u8] = b"delayed-half-close-response";

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let response_server = start_half_close_response_server_on(
        backend_listener,
        REQUEST,
        RESPONSE,
        Duration::from_millis(250),
    )
    .await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-half-close"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    tcp_idle_timeout_seconds: 5
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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

    stream
        .write_all(REQUEST)
        .await
        .expect("Failed to send half-close request");
    stream
        .shutdown()
        .await
        .expect("Failed to half-close client write side");

    let mut buf = vec![0u8; RESPONSE.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("Delayed half-close response timed out")
        .expect("Delayed half-close response read failed");
    assert_eq!(buf, RESPONSE);

    let mut eof = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut eof))
        .await
        .expect("EOF after delayed half-close response timed out")
        .expect("EOF after delayed half-close response read failed");
    assert_eq!(n, 0, "backend close should propagate after response");

    shutdown_gateway(&mut gateway);
    response_server.abort();
}

/// Test 7: Active TCP relay keeps its accepted connection epoch across config reload.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_active_connection_survives_config_reload() {
    let backend_a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_a_port = backend_a_listener.local_addr().unwrap().port();
    let backend_a = start_tagged_tcp_echo_server_on(backend_a_listener, b"A:").await;

    let backend_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_b_port = backend_b_listener.local_addr().unwrap().port();
    let backend_b = start_tagged_tcp_echo_server_on(backend_b_listener, b"B:").await;

    let (mut gateway, proxy_port, _admin_port, dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-reload-active"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_a_port: ''}
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
            )
        },
        None,
        None,
    )
    .await;

    let mut active = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to TCP proxy");
    tagged_round_trip(&mut active, b"before-reload", b"A:").await;

    let updated = format!(
        r#"
version: "1"
proxies:
  - id: "tcp-reload-active"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_b_port: ''}
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    );
    std::fs::write(dir.path().join("config.yaml"), updated).expect("rewrite config");

    #[cfg(unix)]
    {
        let pid = gateway.id();
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    #[cfg(not(unix))]
    {
        shutdown_gateway(&mut gateway);
        backend_a.abort();
        backend_b.abort();
        return;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut fresh = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .expect("Failed to connect fresh TCP stream after reload");
        fresh
            .write_all(b"after-reload")
            .await
            .expect("Failed to send fresh stream payload");

        let mut buf = vec![0u8; b"B:after-reload".len()];
        if tokio::time::timeout(Duration::from_secs(2), fresh.read_exact(&mut buf))
            .await
            .is_ok_and(|read| read.is_ok())
            && buf == b"B:after-reload"
        {
            break;
        }

        assert!(
            std::time::Instant::now() < deadline,
            "fresh TCP streams did not observe reloaded backend before timeout"
        );
        sleep(Duration::from_millis(200)).await;
    }

    tagged_round_trip(&mut active, b"still-old-epoch", b"A:").await;

    shutdown_gateway(&mut gateway);
    backend_a.abort();
    backend_b.abort();
}

/// Test 8: TCP proxy handles connection to unreachable backend gracefully.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_backend_unreachable() {
    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-unreachable"
    listen_port: {proxy_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: 19899
    backend_connect_timeout_ms: 1000
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
    shutdown_gateway(&mut gateway);
}

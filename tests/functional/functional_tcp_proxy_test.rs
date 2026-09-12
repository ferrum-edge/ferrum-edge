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

use crate::common::{GatewayChildGuard, configure_coverage_gateway_command, explicit_test_binary};
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

/// Shut a spawned gateway down early. The guard would do this on drop; calling
/// it explicitly keeps the graceful teardown at the point the test intends,
/// and is idempotent so the drop path cannot reap the child twice.
fn shutdown_gateway(gateway: &mut GatewayChildGuard) {
    gateway.shutdown();
}

fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
    identity: &crate::common::SpawnedGatewayIdentity,
) -> Result<GatewayChildGuard, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.arg("run");
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
    identity.apply_to_command(&mut cmd);

    // Owned at the instant of spawn: every path out of a fixture from here on,
    // panic included, kills and reaps this child (issue #4991).
    Ok(GatewayChildGuard::new(cmd.spawn()?))
}

/// Wait until `child` owns `admin_port`. Unauthenticated `/health` and
/// CIDR-granted health detail are not identity: a parallel test can steal
/// the bind-drop port and answer 200 after this child has already exited.
async fn wait_for_owned_gateway(
    child: &mut GatewayChildGuard,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> bool {
    crate::common::wait_for_owned_gateway_identity(
        child.child_mut(),
        admin_port,
        identity,
        Duration::from_secs(30),
    )
    .await
    .is_ok()
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
/// Returns (gateway guard, proxy_listen_port, admin_port, TempDir).
async fn start_gateway_with_retry<F>(
    make_config: F,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> (GatewayChildGuard, u16, u16, TempDir)
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
) -> (GatewayChildGuard, u16, u16, TempDir)
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

        let identity = crate::common::SpawnedGatewayIdentity::mint("tcp-proxy");

        let mut child = match start_gateway_with_extra_env(
            config_path.to_str().unwrap(),
            http_port,
            admin_port,
            tls_cert_path,
            tls_key_path,
            extra_env,
            &identity,
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

        if wait_for_owned_gateway(&mut child, admin_port, &identity).await {
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
    listen_port: {proxy_port}
    backend_scheme: tcp
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
    listen_port: {proxy_port}
    backend_scheme: tcp
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
    listen_port: {proxy_port}
    backend_scheme: tcps
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
    listen_port: {proxy_port}
    backend_scheme: tcps
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
    listen_port: {proxy_port}
    backend_scheme: tcp
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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_read_timeout_ms: 500
    tcp_idle_timeout_seconds: 30

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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    tcp_idle_timeout_seconds: 5

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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_a_port}

consumers: []
plugin_configs: []
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
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_b_port}

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(dir.path().join("config.yaml"), updated).expect("rewrite config");

    #[cfg(unix)]
    {
        let pid = gateway.id().expect("the guard still owns the child");
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
    listen_port: {proxy_port}
    backend_scheme: tcp
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
    shutdown_gateway(&mut gateway);
}

/// Live datapath: weighted_round_robin TCP upstream distributes connections
/// across tagged backends (issue #3251 L4 weighted stream selection).
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_weighted_upstream_distribution() {
    let heavy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let heavy_port = heavy_listener.local_addr().unwrap().port();
    let heavy = start_tagged_tcp_echo_server_on(heavy_listener, b"H:").await;

    let light_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let light_port = light_listener.local_addr().unwrap().port();
    let light = start_tagged_tcp_echo_server_on(light_listener, b"L:").await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-wrr"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {heavy_port}
    upstream_id: "tcp-wrr-upstream"

upstreams:
  - id: "tcp-wrr-upstream"
    algorithm: weighted_round_robin
    targets:
      - host: "127.0.0.1"
        port: {heavy_port}
        weight: 5
      - host: "127.0.0.1"
        port: {light_port}
        weight: 1

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

    let mut heavy_hits = 0u32;
    let mut light_hits = 0u32;
    for i in 0..60 {
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap_or_else(|error| panic!("connect {i} failed: {error}"));
        let payload = format!("req-{i}");
        stream
            .write_all(payload.as_bytes())
            .await
            .expect("send payload");
        let mut buf = vec![0u8; 2 + payload.len()];
        stream.read_exact(&mut buf).await.expect("read tagged echo");
        if buf.starts_with(b"H:") {
            heavy_hits += 1;
        } else if buf.starts_with(b"L:") {
            light_hits += 1;
        } else {
            panic!("unexpected tag for request {i}: {buf:?}");
        }
    }

    assert_eq!(heavy_hits + light_hits, 60);
    assert!(
        heavy_hits > light_hits * 3,
        "heavy ({heavy_hits}) should get at least 3x light ({light_hits})"
    );

    shutdown_gateway(&mut gateway);
    heavy.abort();
    light.abort();
}

type ObservedProxyV2Tuple = (std::net::SocketAddr, std::net::SocketAddr);

/// Start a TCP backend that requires a PROXY v2 header, then echoes the remainder.
/// Captures the parsed source/destination tuple for assertions.
async fn start_proxy_v2_expecting_echo_server_on(
    listener: TcpListener,
    observed_tuple: Arc<tokio::sync::Mutex<Option<ObservedProxyV2Tuple>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _addr)) = listener.accept().await {
            let observed_tuple = Arc::clone(&observed_tuple);
            tokio::spawn(async move {
                match ferrum_edge::proxy::proxy_protocol::read_proxy_header(&mut stream, Some(2))
                    .await
                {
                    Ok(ferrum_edge::proxy::proxy_protocol::ProxyProtocolResult::Forwarded {
                        src,
                        dst,
                    }) => {
                        *observed_tuple.lock().await = Some((src, dst));
                    }
                    Ok(_) | Err(_) => {
                        return;
                    }
                }
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

fn v2_header_tcp4_bytes(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    h.push(0x21);
    h.push(0x11);
    h.extend_from_slice(&12u16.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h
}

/// Test: outbound PROXY v2 advertises the direct client IP to the backend.
#[ignore]
#[tokio::test]
async fn test_tcp_outbound_proxy_protocol_v2_direct_client() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let observed_tuple = Arc::new(tokio::sync::Mutex::new(None));
    let backend =
        start_proxy_v2_expecting_echo_server_on(backend_listener, Arc::clone(&observed_tuple))
            .await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-outbound-pp"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_proxy_protocol: v2

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
    )
    .await;

    let mut stream = connect_tcp_proxy(proxy_port).await;
    let payload = b"outbound-pp-direct";
    stream.write_all(payload).await.expect("send payload");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read error");
    assert_eq!(&buf[..n], payload);

    let (src, dst) = (*observed_tuple.lock().await).expect("backend must observe PROXY header");
    assert_eq!(
        src.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "outbound PROXY src must be the direct client IP"
    );
    assert_ne!(src.port(), 0);
    assert_eq!(
        dst.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert_eq!(dst.port(), proxy_port);

    shutdown_gateway(&mut gateway);
    backend.abort();
}

/// Test: outbound PROXY v2 re-advertises the inbound PROXY-forwarded client IP.
#[ignore]
#[tokio::test]
async fn test_tcp_outbound_proxy_protocol_v2_chained_inbound() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let observed_tuple = Arc::new(tokio::sync::Mutex::new(None));
    let backend =
        start_proxy_v2_expecting_echo_server_on(backend_listener, Arc::clone(&observed_tuple))
            .await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-outbound-pp-chained"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    stream_proxy_protocol: true
    backend_proxy_protocol: v2

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
        &[("FERRUM_TRUSTED_PROXIES", "127.0.0.0/8")],
    )
    .await;

    let mut stream = connect_tcp_proxy(proxy_port).await;
    // Pretend to be an LB: advertise a distinct public client identity.
    let inbound = v2_header_tcp4_bytes([203, 0, 113, 50], [192, 0, 2, 10], 40000, 15432);
    stream
        .write_all(&inbound)
        .await
        .expect("send inbound PROXY header");
    let payload = b"outbound-pp-chained";
    stream.write_all(payload).await.expect("send payload");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read error");
    assert_eq!(&buf[..n], payload);

    let (src, dst) =
        (*observed_tuple.lock().await).expect("backend must observe outbound PROXY header");
    assert_eq!(
        src.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50)),
        "outbound PROXY must advertise the inbound-forwarded client IP"
    );
    assert_eq!(src.port(), 40000);
    assert_eq!(
        dst,
        std::net::SocketAddr::from(([192, 0, 2, 10], 15432)),
        "trusted inbound destination tuple must be re-advertised unchanged"
    );

    shutdown_gateway(&mut gateway);
    backend.abort();
}

/// `least_connections` must distribute TCP connections across every healthy
/// target (issue #4514).
///
/// Before stream load-balancer accounting existed, no TCP path incremented the
/// balancer's active-connection gauge, so `select_least_connections_*` saw every
/// target at zero and its strict `<` tie-break returned the first healthy target
/// for every connection — all 30 landed on backend A.
///
/// Each connection is held open and echo-verified before the next is opened, so
/// the gauge for the chosen target is provably armed before the next selection
/// runs.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_least_connections_distributes_across_targets() {
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let backend_a = start_tagged_tcp_echo_server_on(listener_a, b"A:").await;

    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_b = listener_b.local_addr().unwrap().port();
    let backend_b = start_tagged_tcp_echo_server_on(listener_b, b"B:").await;

    let listener_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_c = listener_c.local_addr().unwrap().port();
    let backend_c = start_tagged_tcp_echo_server_on(listener_c, b"C:").await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-least-conn"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    upstream_id: "tcp-least-conn-upstream"

upstreams:
  - id: "tcp-least-conn-upstream"
    algorithm: least_connections
    targets:
      - host: "127.0.0.1"
        port: {port_a}
      - host: "127.0.0.1"
        port: {port_b}
      - host: "127.0.0.1"
        port: {port_c}

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
        // Warmup dials would land on the balancer before the test's own
        // connections and skew the accept counts.
        &[("FERRUM_POOL_WARMUP_ENABLED", "false")],
    )
    .await;

    const CONNECTIONS: usize = 30;
    // Held open for the whole loop: a released connection would decrement the
    // gauge and let the algorithm re-pin.
    let mut held = Vec::with_capacity(CONNECTIONS);
    let mut hits_a = 0u32;
    let mut hits_b = 0u32;
    let mut hits_c = 0u32;

    for i in 0..CONNECTIONS {
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap_or_else(|error| panic!("connect {i} failed: {error}"));
        let payload = format!("conn-{i}");
        stream
            .write_all(payload.as_bytes())
            .await
            .expect("send payload");
        let mut buf = vec![0u8; 2 + payload.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("read {i} timed out"))
            .unwrap_or_else(|error| panic!("read {i} failed: {error}"));
        match &buf[..2] {
            b"A:" => hits_a += 1,
            b"B:" => hits_b += 1,
            b"C:" => hits_c += 1,
            other => panic!("unexpected tag for connection {i}: {other:?}"),
        }
        held.push(stream);
    }

    assert_eq!(hits_a + hits_b + hits_c, CONNECTIONS as u32);
    assert!(
        hits_a > 0 && hits_b > 0 && hits_c > 0,
        "least_connections must use every healthy target, got A={hits_a} B={hits_b} C={hits_c}"
    );

    drop(held);
    shutdown_gateway(&mut gateway);
    backend_a.abort();
    backend_b.abort();
    backend_c.abort();
}

/// `FERRUM_TCP_MAX_CONNECTIONS_PER_IP` must bound how many concurrent TCP
/// stream-proxy connections one source IP can hold, and must do so at accept —
/// before the frontend handshake, the `on_stream_connect` chain, and the
/// backend dial (issue #4544).
///
/// Before this bound existed the only stream-listener limits were global, so a
/// single client could occupy a listener's whole budget and take it down for
/// every other source. Each connection is echo-verified before the next is
/// opened, so the admitted connection's guard is provably armed before the next
/// acceptance decision runs.
#[ignore]
#[tokio::test]
async fn test_tcp_proxy_per_source_ip_connection_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = start_tcp_echo_server_on(listener).await;

    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-per-ip"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
"#
            )
        },
        None,
        None,
        &[
            ("FERRUM_TCP_MAX_CONNECTIONS_PER_IP", "4"),
            // A warmup dial is a backend connection, not a frontend one, but
            // keep it off so nothing races the accept-path assertions.
            ("FERRUM_POOL_WARMUP_ENABLED", "false"),
        ],
    )
    .await;

    /// Open one connection from `source_ip` and report whether the gateway
    /// relayed for it. A refused connection is closed at accept, so the echo
    /// round-trip fails (EOF or write error) rather than returning bytes.
    async fn try_relay(source_ip: &str, proxy_port: u16) -> Option<tokio::net::TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4().expect("client socket");
        socket
            .bind(format!("{source_ip}:0").parse().expect("source addr"))
            .expect("bind client source");
        let mut stream = socket
            .connect(
                format!("127.0.0.1:{proxy_port}")
                    .parse()
                    .expect("proxy addr"),
            )
            .await
            .ok()?;
        if stream.write_all(b"ping").await.is_err() {
            return None;
        }
        let mut buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) if &buf == b"ping" => Some(stream),
            _ => None,
        }
    }

    const ATTEMPTS: usize = 8;
    const LIMIT: usize = 4;
    let mut held = Vec::new();
    let mut refused = 0usize;
    for _ in 0..ATTEMPTS {
        match try_relay("127.0.0.1", proxy_port).await {
            Some(stream) => held.push(stream),
            None => refused += 1,
        }
    }

    assert_eq!(
        held.len(),
        LIMIT,
        "exactly FERRUM_TCP_MAX_CONNECTIONS_PER_IP connections from one source must be admitted"
    );
    assert_eq!(
        refused,
        ATTEMPTS - LIMIT,
        "every connection past the per-source cap must be closed at accept"
    );

    // The bound is per source, not per listener: a different source IP still
    // gets its own full budget while the first source is saturated.
    //
    // This half needs a genuinely different source ADDRESS, which a second
    // ephemeral port cannot supply. Linux assigns all of `127.0.0.0/8` to `lo`,
    // so `127.0.0.2` is always bindable there; macOS assigns only `127.0.0.1`
    // to `lo0` unless an operator adds an alias (issue #4983). Report the
    // missing prerequisite explicitly rather than failing as a per-source-cap
    // defect — the cap assertions above already ran on every host.
    let mut other_source = None;
    let mut second_source_bound = false;
    for candidate in ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"] {
        if std::net::TcpListener::bind((candidate, 0)).is_err() {
            continue;
        }
        second_source_bound = true;
        other_source = try_relay(candidate, proxy_port).await;
        break;
    }
    if second_source_bound {
        assert!(
            other_source.is_some(),
            "a second source IP must still be admitted while another source is at its cap"
        );
    } else {
        eprintln!(
            "skipping the second-source half of \
             test_tcp_proxy_per_source_ip_connection_limit: this host assigns no secondary \
             IPv4 loopback address"
        );
    }

    drop(other_source);
    drop(held);
    shutdown_gateway(&mut gateway);
    backend.abort();
}

#[ignore]
#[tokio::test]
async fn test_userspace_tls_write_timeout_preserves_request_then_push_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if stream.read_u8().await.ok() != Some(b'S') {
                    return;
                }
                for byte in 0..30u8 {
                    if stream.write_all(&[byte]).await.is_err() {
                        return;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                if stream.read_u8().await.ok() == Some(b'Q') {
                    let _ = stream.write_all(b"!").await;
                }
            });
        }
    });
    let cert_path = std::fs::canonicalize("tests/certs/server.crt")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let key_path = std::fs::canonicalize("tests/certs/server.key")
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (mut gateway, proxy_port, _admin_port, _dir) = start_gateway_with_retry_extra_env(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "userspace-request-then-push"
    listen_port: {proxy_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    backend_write_timeout_ms: 500
    backend_read_timeout_ms: 0
    tcp_idle_timeout_seconds: 30
consumers: []
plugin_configs: []
"#
            )
        },
        Some(&cert_path),
        Some(&key_path),
        &[("FERRUM_KTLS_ENABLED", "false")],
    )
    .await;
    let socket = connect_tcp_proxy(proxy_port).await;
    let mut stream = insecure_tls_connector()
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(b"S").await.unwrap();
        for expected in 0..30u8 {
            assert_eq!(stream.read_u8().await.unwrap(), expected);
        }
        stream.write_all(b"Q").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'!');
    })
    .await
    .expect("userspace TLS relay must not time out a drained client write queue");
    shutdown_gateway(&mut gateway);
    backend_task.abort();
}

/// Issue #4991: a fixture that panics after a successful startup must still
/// kill and reap its gateway, and release the ports that child owned.
///
/// A raw `std::process::Child` does nothing on drop, so before
/// [`crate::common::GatewayChildGuard`] every assertion failure between spawn
/// and the explicit shutdown call left a live gateway reparented to init,
/// holding its listen ports against every later run. This forces exactly that
/// shape — a real gateway, proven relaying, then a panic — and asserts the
/// teardown that must follow it.
#[ignore]
#[tokio::test]
async fn test_gateway_guard_reaps_the_child_on_a_panicking_fixture() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = start_tcp_echo_server_on(listener).await;

    let (gateway, proxy_port, admin_port, _dir) = start_gateway_with_retry(
        |proxy_port| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-teardown-regression"
    listen_port: {proxy_port}
    backend_scheme: tcp
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

    // Prove the child is genuinely up and owns the proxy port before the panic,
    // so a passing teardown assertion cannot come from a gateway that never
    // started.
    let mut stream = connect_tcp_proxy(proxy_port).await;
    stream.write_all(b"alive").await.expect("relay write");
    let mut echoed = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("relay read timed out")
        .expect("relay read");
    assert_eq!(&echoed, b"alive");
    drop(stream);

    let pid = gateway.id().expect("the guard still owns the child");

    // The failure shape from the issue: a fixture panics with the gateway in
    // scope. The guard is dropped by the unwind, not by any explicit call.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _gateway = gateway;
        panic!("deliberate teardown-regression panic, not a real failure");
    }));
    assert!(outcome.is_err(), "the fixture must actually have panicked");

    // The child is gone, not merely killed-and-unreaped: `shutdown_gateway_child`
    // waits, so the pid must no longer name a live process.
    assert!(
        !process_is_alive(pid),
        "the unwind must have killed and reaped the gateway child (pid {pid})"
    );

    // ...and both ports it owned are bindable again.
    for port in [proxy_port, admin_port] {
        assert!(
            wait_for_bindable_port(port).await,
            "port {port} must be released once the gateway child is reaped"
        );
    }

    backend.abort();
}

/// Whether `pid` still names a live process. `kill(pid, 0)` reports
/// permissions/existence without delivering a signal.
#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

/// Bind `port` on loopback, retrying briefly: a killed listener's socket can
/// stay claimed for a moment while the kernel finishes closing it.
async fn wait_for_bindable_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            drop(listener);
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

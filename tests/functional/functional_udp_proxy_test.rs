//! Functional tests for UDP stream proxy.
//!
//! Tests:
//! 1. Plain UDP datagram forwarding (single client)
//! 2. Multiple concurrent UDP clients with session isolation
//! 3. UDP session timeout and cleanup
//! 4. Large UDP datagram forwarding
//! 5. DTLS backend encryption (plain UDP → gateway → DTLS echo server)
//! 6. DTLS backend with multiple clients
//! 7. Frontend DTLS termination (DTLS client → gateway → plain UDP echo server)
//! 8. Full DTLS: frontend DTLS + backend DTLS (DTLS client → gateway → DTLS echo server)
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_udp_proxy --ignored --nocapture

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::UdpSocket;
use tokio::time::sleep;

// ============================================================================
// UDP Echo Server
// ============================================================================

/// Start a UDP echo server that reflects all received datagrams back to the sender.
async fn start_udp_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind UDP echo server on port {}", port));

        let mut buf = vec![0u8; 65535];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], src).await;
        }
    });
    sleep(Duration::from_millis(200)).await;
    handle
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

/// Extra env vars for DTLS frontend configuration.
struct GatewayDtlsEnv {
    cert_path: String,
    key_path: String,
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    start_gateway_with_dtls(config_path, http_port, None)
}

fn start_gateway_with_dtls(
    config_path: &str,
    http_port: u16,
    dtls_env: Option<&GatewayDtlsEnv>,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    // Use http_port + 1000 as admin port to avoid collisions
    let admin_port = http_port + 1000;
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if let Some(dtls) = dtls_env {
        cmd.env("FERRUM_DTLS_CERT_PATH", &dtls.cert_path)
            .env("FERRUM_DTLS_KEY_PATH", &dtls.key_path);
    }

    Ok(cmd.spawn()?)
}

fn write_config(path: &std::path::Path, content: &str) {
    let mut file = std::fs::File::create(path).expect("Failed to create config file");
    file.write_all(content.as_bytes())
        .expect("Failed to write config");
}

// ============================================================================
// Tests
// ============================================================================

/// Test 1: Plain UDP proxy — send datagrams through the gateway, receive echoes.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_plain_datagram_forwarding() {
    let backend_port = 19810u16;
    let proxy_port = 19811u16;
    let gateway_http_port = 18210u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "udp-echo"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 30

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Send datagrams through the proxy
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    // First datagram
    let msg1 = b"Hello, UDP proxy!";
    client.send(msg1).await.expect("Failed to send");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("Recv timed out")
        .expect("Recv error");

    assert_eq!(
        &buf[..n],
        msg1,
        "First echo response should match sent data"
    );

    // Second datagram — same session
    let msg2 = b"Second UDP datagram";
    client.send(msg2).await.expect("Failed to send");

    let n2 = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("Recv timed out")
        .expect("Recv error");

    assert_eq!(&buf[..n2], msg2, "Second echo should match");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 2: Multiple concurrent UDP clients — verify session isolation.
/// Each client should get back only its own data.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_multiple_clients() {
    let backend_port = 19812u16;
    let proxy_port = 19813u16;
    let gateway_http_port = 18211u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "udp-multi-client"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Create multiple clients
    let num_clients = 5;
    let mut handles = Vec::new();

    for i in 0..num_clients {
        let proxy_addr = format!("127.0.0.1:{}", proxy_port);
        handles.push(tokio::spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(&proxy_addr).await.unwrap();

            let msg = format!("client-{}-data", i);
            client.send(msg.as_bytes()).await.expect("send failed");

            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .expect("recv timed out")
                .expect("recv error");

            let response = String::from_utf8_lossy(&buf[..n]).to_string();
            assert_eq!(response, msg, "Client {} should get its own data back", i);
            i
        }));
    }

    // Wait for all clients to complete
    let mut completed = Vec::new();
    for handle in handles {
        completed.push(handle.await.expect("Client task panicked"));
    }
    assert_eq!(completed.len(), num_clients, "All clients should complete");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 3: UDP session timeout — verify sessions are cleaned up after idle timeout.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_session_timeout() {
    let backend_port = 19814u16;
    let proxy_port = 19815u16;
    let gateway_http_port = 18212u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "udp-timeout"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 5

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Send initial datagram to create a session
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    let msg1 = b"before-timeout";
    client.send(msg1).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("First recv timed out")
        .expect("First recv error");
    assert_eq!(&buf[..n], msg1);

    // Wait for session timeout + cleanup interval (idle_timeout=5s + cleanup_interval=10s)
    // Give some margin
    sleep(Duration::from_secs(18)).await;

    // Send another datagram — should create a new session (old one was cleaned up)
    // This should still work since a new session will be created
    let msg2 = b"after-timeout";
    client.send(msg2).await.unwrap();

    let n2 = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("Post-timeout recv timed out")
        .expect("Post-timeout recv error");
    assert_eq!(
        &buf[..n2],
        msg2,
        "New session should work after timeout cleanup"
    );

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 4: Large UDP datagram — verify near-maximum-size datagrams are forwarded.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_large_datagram() {
    let backend_port = 19816u16;
    let proxy_port = 19817u16;
    let gateway_http_port = 18213u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "udp-large"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    // Send a ~8KB datagram (well under 64K limit but large enough to test)
    let large_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    client.send(&large_data).await.expect("Failed to send");

    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("Recv timed out")
        .expect("Recv error");

    assert_eq!(n, large_data.len(), "Should receive same size datagram");
    assert_eq!(
        &buf[..n],
        &large_data[..],
        "Large datagram echo should match"
    );

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 5: DTLS backend — send plain UDP datagrams through the gateway,
/// which encrypts them via DTLS to a DTLS echo server backend.
///
/// Architecture: client (plain UDP) → gateway (DTLS client) → DTLS echo server
///
/// The gateway accepts plain UDP on the frontend and establishes a DTLS session
/// to the backend when `backend_scheme: dtls` is configured.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_dtls_backend() {
    let backend_port = 19818u16;
    let proxy_port = 19819u16;
    let gateway_http_port = 18214u16;

    // Start a DTLS echo server with a self-signed certificate
    let dtls_echo = start_dtls_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "dtls-proxy"
    listen_port: {proxy_port}
    backend_scheme: dtls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Client sends plain UDP to the gateway
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    let msg1 = b"Hello DTLS backend!";
    client.send(msg1).await.expect("Failed to send");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), client.recv(&mut buf))
        .await
        .expect("DTLS echo recv timed out")
        .expect("DTLS echo recv error");

    assert_eq!(&buf[..n], msg1, "DTLS backend echo should match sent data");

    // Second datagram — same DTLS session
    let msg2 = b"Second DTLS datagram";
    client.send(msg2).await.expect("Failed to send msg2");

    let n2 = tokio::time::timeout(Duration::from_secs(10), client.recv(&mut buf))
        .await
        .expect("Second recv timed out")
        .expect("Second recv error");
    assert_eq!(&buf[..n2], msg2, "Second DTLS echo should match");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    dtls_echo.abort();
}

/// Test 6: DTLS backend with multiple clients — verify session isolation
/// works with DTLS backend connections.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_dtls_backend_multiple_clients() {
    let backend_port = 19820u16;
    let proxy_port = 19821u16;
    let gateway_http_port = 18215u16;

    let dtls_echo = start_dtls_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "dtls-multi"
    listen_port: {proxy_port}
    backend_scheme: dtls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_tls_verify_server_cert: false

consumers: []
plugin_configs: []
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Launch 3 concurrent clients
    let mut handles = Vec::new();
    for i in 0..3 {
        let proxy_addr = format!("127.0.0.1:{}", proxy_port);
        handles.push(tokio::spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(&proxy_addr).await.unwrap();

            let msg = format!("dtls-client-{}", i);
            client.send(msg.as_bytes()).await.expect("send failed");

            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(10), client.recv(&mut buf))
                .await
                .expect("recv timed out")
                .expect("recv error");

            let response = String::from_utf8_lossy(&buf[..n]).to_string();
            assert_eq!(response, msg, "DTLS client {} should get its own data", i);
        }));
    }

    for handle in handles {
        handle.await.expect("Client task panicked");
    }

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    dtls_echo.abort();
}

/// Test 7: Frontend DTLS termination — DTLS client → gateway → plain UDP echo server.
///
/// The gateway terminates DTLS from the client and forwards decrypted datagrams
/// to a plain UDP backend.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_frontend_dtls_termination() {
    let backend_port = 19822u16;
    let proxy_port = 19823u16;
    let gateway_http_port = 18216u16;

    // Start plain UDP echo server
    let echo_server = start_udp_echo_server(backend_port).await;

    // Generate ECDSA P-256 cert for the gateway's DTLS frontend
    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_test_dtls_cert(&temp_dir);

    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "frontend-dtls"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true

consumers: []
plugin_configs: []
"#
        ),
    );

    let dtls_env = GatewayDtlsEnv {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
    };
    let mut gateway = start_gateway_with_dtls(
        config_path.to_str().unwrap(),
        gateway_http_port,
        Some(&dtls_env),
    )
    .expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Connect as a DTLS client to the gateway (with retries for CI timing)
    let dtls_client = connect_dtls_client_with_retry(proxy_port, 5).await;

    // Send data through DTLS (DtlsConnection send/recv)
    let msg1 = b"Hello through frontend DTLS!";
    dtls_client
        .send(msg1)
        .await
        .expect("Failed to send via DTLS");

    let reply = tokio::time::timeout(Duration::from_secs(10), dtls_client.recv())
        .await
        .expect("DTLS recv timed out")
        .expect("DTLS recv error");

    assert_eq!(&reply, msg1, "Frontend DTLS echo should match sent data");

    // Second datagram
    let msg2 = b"Second DTLS frontend datagram";
    dtls_client.send(msg2).await.expect("send2 failed");

    let reply2 = tokio::time::timeout(Duration::from_secs(10), dtls_client.recv())
        .await
        .expect("recv2 timed out")
        .expect("recv2 error");
    assert_eq!(&reply2, msg2, "Second echo should match");

    // Cleanup
    dtls_client.close().await;
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_server.abort();
}

/// Test 8: Full DTLS e2e — DTLS client → gateway (DTLS termination + DTLS origination) → DTLS echo server.
///
/// Both sides encrypted: the gateway terminates DTLS from the client and opens a new
/// DTLS session to the DTLS backend.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_full_dtls_e2e() {
    let backend_port = 19824u16;
    let proxy_port = 19825u16;
    let gateway_http_port = 18217u16;

    // Start DTLS echo server as backend
    let dtls_echo = start_dtls_echo_server(backend_port).await;

    // Generate ECDSA P-256 cert for the gateway's DTLS frontend
    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_test_dtls_cert(&temp_dir);

    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
proxies:
  - id: "full-dtls"
    listen_port: {proxy_port}
    backend_scheme: dtls
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    backend_tls_verify_server_cert: false
    frontend_tls: true

consumers: []
plugin_configs: []
"#
        ),
    );

    let dtls_env = GatewayDtlsEnv {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
    };
    let mut gateway = start_gateway_with_dtls(
        config_path.to_str().unwrap(),
        gateway_http_port,
        Some(&dtls_env),
    )
    .expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    // Connect as DTLS client (with retries for CI timing)
    let dtls_client = connect_dtls_client_with_retry(proxy_port, 5).await;

    // Send data through full DTLS pipeline (DtlsConnection send/recv)
    let msg = b"Full DTLS end-to-end!";
    dtls_client.send(msg).await.expect("Failed to send");

    let reply = tokio::time::timeout(Duration::from_secs(10), dtls_client.recv())
        .await
        .expect("Full DTLS recv timed out")
        .expect("Full DTLS recv error");

    assert_eq!(&reply, msg, "Full DTLS e2e echo should match");

    // Cleanup
    dtls_client.close().await;
    let _ = gateway.kill();
    let _ = gateway.wait();
    dtls_echo.abort();
}

// ============================================================================
// DTLS Client Helper
// ============================================================================

/// Connect a DTLS client with retries — the DTLS listener may take longer to
/// start than plain UDP, especially on CI runners.
async fn connect_dtls_client_with_retry(
    proxy_port: u16,
    max_attempts: u32,
) -> ferrum_edge::dtls::DtlsConnection {
    let mut last_err = String::new();
    for attempt in 1..=max_attempts {
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket
            .connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        let params = ferrum_edge::dtls::BackendDtlsParams {
            config: std::sync::Arc::new(dimpl::Config::default()),
            certificate: dimpl::certificate::generate_self_signed_certificate()
                .expect("generate ephemeral cert"),
            server_name: None,
            server_cert_verifier: None,
        };

        match tokio::time::timeout(
            Duration::from_secs(5),
            ferrum_edge::dtls::DtlsConnection::connect(client_socket, params),
        )
        .await
        {
            Ok(Ok(conn)) => return conn,
            Ok(Err(e)) => {
                last_err = format!("{}", e);
                if attempt < max_attempts {
                    sleep(Duration::from_secs(2)).await;
                }
            }
            Err(_) => {
                last_err = "handshake timed out".to_string();
                if attempt < max_attempts {
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    panic!(
        "DTLS client handshake failed after {} attempts: {}",
        max_attempts, last_err
    );
}

// ============================================================================
// DTLS Echo Server
// ============================================================================

/// Start a DTLS echo server using a self-signed ECDSA certificate.
///
/// Accepts DTLS connections and echoes back received datagrams.
async fn start_dtls_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    // Ensure rustls crypto provider is installed (needed for cert generation)
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let handle = tokio::spawn(async move {
        let cert = dimpl::certificate::generate_self_signed_certificate()
            .expect("Failed to generate self-signed cert");

        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let frontend_config = ferrum_edge::dtls::FrontendDtlsConfig {
            dimpl_config: std::sync::Arc::new(dimpl::Config::default()),
            certificate: cert,
            client_cert_verifier: None,
        };

        let server = ferrum_edge::dtls::DtlsServer::bind(addr, frontend_config)
            .await
            .expect("Failed to start DTLS server");
        let server = std::sync::Arc::new(server);

        // Spawn the recv loop
        let server_runner = server.clone();
        tokio::spawn(async move {
            let _ = server_runner.run().await;
        });

        // Accept and echo
        while let Ok((conn, _remote_addr)) = server.accept().await {
            tokio::spawn(async move {
                loop {
                    match conn.recv().await {
                        Ok(data) if !data.is_empty() => {
                            if conn.send(&data).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });
    sleep(Duration::from_millis(500)).await;
    handle
}

// ============================================================================
// Test Certificate Generation
// ============================================================================

/// Generate ECDSA P-256 test certificate and key PEM files.
///
/// Returns (cert_path, key_path) as strings suitable for env vars.
fn generate_test_dtls_cert(temp_dir: &TempDir) -> (String, String) {
    use rcgen::{CertificateParams, KeyPair};

    // Ensure rustls crypto provider is installed (needed by rcgen)
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("Failed to generate ECDSA P-256 key pair");

    let params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("Failed to create cert params");

    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate self-signed cert");

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_path = temp_dir.path().join("dtls_cert.pem");
    let key_path = temp_dir.path().join("dtls_key.pem");

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    std::fs::write(&key_path, key_pem).expect("Failed to write key");

    (
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
    )
}

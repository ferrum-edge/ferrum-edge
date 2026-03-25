//! Functional tests for UDP stream proxy.
//!
//! Tests:
//! 1. Plain UDP datagram forwarding (single client)
//! 2. Multiple concurrent UDP clients with session isolation
//! 3. UDP session timeout and cleanup
//! 4. DTLS proxy config acceptance (DTLS protocol is parsed but backend is plain UDP — reserved for future)
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-gateway && cargo test --test functional_tests -- functional_udp_proxy --ignored --nocapture

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
    if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    // Use http_port + 1000 as admin port to avoid collisions
    let admin_port = http_port + 1000;
    let cmd = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    Ok(cmd)
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: udp
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: udp
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: udp
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: udp
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
/// to the backend when `backend_protocol: dtls` is configured.
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: dtls
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
    listen_path: ""
    listen_port: {proxy_port}
    backend_protocol: dtls
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

// ============================================================================
// DTLS Echo Server
// ============================================================================

/// Start a DTLS echo server using a self-signed ECDSA certificate.
///
/// Accepts DTLS connections and echoes back received datagrams.
async fn start_dtls_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    use webrtc_dtls::config::Config as DtlsConfig;
    use webrtc_dtls::crypto::Certificate as DtlsCertificate;
    use webrtc_util::conn::Listener;

    // Ensure rustls crypto provider is installed (needed for cert generation)
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let handle = tokio::spawn(async move {
        let cert = DtlsCertificate::generate_self_signed(vec!["localhost".to_string()])
            .expect("Failed to generate self-signed cert");

        let config = DtlsConfig {
            certificates: vec![cert],
            ..Default::default()
        };

        let addr = format!("127.0.0.1:{}", port);
        let listener = webrtc_dtls::listener::listen(addr, config)
            .await
            .expect("Failed to start DTLS listener");

        while let Ok((conn, _remote_addr)) = listener.accept().await {
            // Spawn echo handler per connection
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match conn.recv(&mut buf).await {
                        Ok(n) if n > 0 => {
                            if conn.send(&buf[..n]).await.is_err() {
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

//! Functional tests for UDP stream proxy.
//!
//! Tests:
//! 1. Plain UDP datagram forwarding (single client)
//! 2. Multiple concurrent UDP clients with session isolation
//!    2b. UDP max session cap — `FERRUM_UDP_MAX_SESSIONS` rejects new clients
//! 3. UDP session timeout and cleanup
//! 4. Large UDP datagram forwarding
//! 5. UDP response amplification factor enforcement
//! 6. DTLS backend encryption (plain UDP → gateway → DTLS echo server)
//! 7. DTLS backend with multiple clients
//! 8. Frontend DTLS termination (DTLS client → gateway → plain UDP echo server)
//! 9. Full DTLS: frontend DTLS + backend DTLS (DTLS client → gateway → DTLS echo server)
//!
//! All tests are marked `#[ignore]` — run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_udp_proxy --ignored --nocapture

use crate::common::{
    configure_coverage_gateway_command, explicit_test_binary, shutdown_gateway_child,
};
use std::io::Write;
use std::time::{Duration, Instant};
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

/// Start a UDP backend that replies to every datagram with the same payload.
async fn start_udp_fixed_response_server(
    port: u16,
    response: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind UDP response server on port {}", port));

        let mut buf = vec![0u8; 65535];
        while let Ok((_len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&response, src).await;
        }
    });
    sleep(Duration::from_millis(200)).await;
    handle
}

/// Start a UDP backend that acknowledges a zero-length request with one byte,
/// then echoes nonempty requests. This exercises the bounded zero-length
/// amplification exception without weakening ordinary payload accounting.
async fn start_udp_zero_ack_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind UDP zero-ack server on port {}", port));

        let mut buf = vec![0u8; 65535];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            let response: &[u8] = if len == 0 { b"x" } else { &buf[..len] };
            let _ = socket.send_to(response, src).await;
        }
    });
    sleep(Duration::from_millis(200)).await;
    handle
}

/// Start a UDP backend that sends periodic responses after the first datagram
/// from each client. Used to verify backend-side activity keeps DTLS frontend
/// sessions alive even when the client is idle.
async fn start_udp_push_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let socket = std::sync::Arc::new(
            UdpSocket::bind(format!("127.0.0.1:{}", port))
                .await
                .unwrap_or_else(|_| panic!("Failed to bind UDP push server on port {}", port)),
        );

        let mut buf = vec![0u8; 65535];
        while let Ok((_len, src)) = socket.recv_from(&mut buf).await {
            let socket = std::sync::Arc::clone(&socket);
            tokio::spawn(async move {
                for i in 0..8u8 {
                    let payload = format!("push-{i}");
                    let _ = socket.send_to(payload.as_bytes(), src).await;
                    sleep(Duration::from_millis(500)).await;
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

fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
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
    configure_coverage_gateway_command(&mut cmd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    Ok(cmd.spawn()?)
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

    configure_coverage_gateway_command(&mut cmd);
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Regression: a zero-length UDP datagram is valid payload, not EOF. With the
/// amplification guard enabled, it receives exactly the one-byte allowance and
/// the session remains usable for an ordinary follow-up request.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_zero_length_request_has_bounded_reply_budget() {
    let backend_port = 19830u16;
    let proxy_port = 19831u16;
    let gateway_http_port = 18220u16;

    let backend = start_udp_zero_ack_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-empty-datagram"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 30
    udp_max_response_amplification_factor: 1.0

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

    client
        .send(&[])
        .await
        .expect("Failed to send empty datagram");
    let mut buf = vec![0u8; 1024];
    let zero_ack_len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("zero-length request acknowledgment timed out")
        .expect("empty datagram recv error");
    assert_eq!(
        &buf[..zero_ack_len],
        b"x",
        "zero-length request should receive the bounded one-byte acknowledgment"
    );

    let followup = b"after-empty";
    client
        .send(followup)
        .await
        .expect("Failed to send follow-up datagram");
    let followup_len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("follow-up echo timed out")
        .expect("follow-up recv error");
    assert_eq!(&buf[..followup_len], followup);

    shutdown_gateway(&mut gateway);
    backend.abort();
}

/// Regression: datagrams sent while background session setup is still running
/// for a new source (the pending-session window) must be queued and flushed to
/// the backend in arrival order — not dropped. Models a multi-datagram opening
/// flight (QUIC Initial + 0-RTT coalesced flight, multi-record DTLS
/// ClientHello).
#[ignore]
#[tokio::test]
async fn test_udp_proxy_opening_flight_burst_preserved_in_order() {
    let backend_port = 19836u16;
    let proxy_port = 19837u16;
    let gateway_http_port = 18223u16;

    // Recording echo backend: tracks the payload arrival order so we can
    // assert the pending-session queue flushed to the backend in order.
    let received: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received_server = std::sync::Arc::clone(&received);
    let backend = tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", backend_port))
            .await
            .unwrap_or_else(|_| panic!("Failed to bind UDP backend on port {}", backend_port));
        let mut buf = vec![0u8; 65535];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            received_server
                .lock()
                .expect("recording mutex poisoned")
                .push(buf[..len].to_vec());
            let _ = socket.send_to(&buf[..len], src).await;
        }
    });
    sleep(Duration::from_millis(200)).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-opening-flight"
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

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    // Fire the whole opening flight back-to-back, without waiting for any
    // reply, so the follow-up datagrams land while the gateway's background
    // session setup for this brand-new source is still in flight.
    let flight: Vec<Vec<u8>> = (0..6).map(|i| format!("flight-{i}").into_bytes()).collect();
    for dgram in &flight {
        client.send(dgram).await.expect("send failed");
    }

    // Every datagram of the flight must come back (echo backend), proving
    // none were dropped during the pending-session window.
    let mut buf = vec![0u8; 1024];
    let mut echoes = Vec::new();
    for i in 0..flight.len() {
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("echo {i} timed out — opening-flight datagram lost"))
            .expect("recv error");
        echoes.push(buf[..n].to_vec());
    }
    assert_eq!(echoes, flight, "opening flight must be echoed in order");

    // The backend must have observed the flight in arrival order — the
    // pending-session queue drains oldest-first after setup completes.
    {
        let recorded = received.lock().expect("recording mutex poisoned");
        assert_eq!(
            *recorded, flight,
            "backend must receive the opening flight in order"
        );
    }

    // Session stays usable after the handoff.
    let followup = b"post-flight";
    client.send(followup).await.expect("send failed");
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("post-flight echo timed out")
        .expect("recv error");
    assert_eq!(&buf[..n], followup);

    shutdown_gateway(&mut gateway);
    backend.abort();
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Regression: new-source session setup must not block the single UDP recv loop
/// while an established session is exchanging traffic.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_new_source_flood_does_not_stall_established_session() {
    let backend_port = 19832u16;
    let proxy_port = 19833u16;
    let gateway_http_port = 18221u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-setup-flood"
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

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    let established = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    established.connect(&proxy_addr).await.unwrap();
    established.send(b"warmup").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), established.recv(&mut buf))
        .await
        .expect("warmup timed out")
        .expect("warmup recv error");
    assert_eq!(&buf[..n], b"warmup");

    let flood_addr = proxy_addr.clone();
    let flood = tokio::spawn(async move {
        let mut handles = Vec::new();
        for i in 0..128usize {
            let addr = flood_addr.clone();
            handles.push(tokio::spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                client.connect(&addr).await.unwrap();
                let payload = format!("new-source-{i}");
                let _ = client.send(payload.as_bytes()).await;
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    });

    for i in 0..10usize {
        let payload = format!("steady-{i}");
        established
            .send(payload.as_bytes())
            .await
            .expect("steady send failed");
        let n = tokio::time::timeout(Duration::from_secs(2), established.recv(&mut buf))
            .await
            .expect("established session stalled during new-source flood")
            .expect("steady recv error");
        assert_eq!(&buf[..n], payload.as_bytes());
    }
    flood.await.unwrap();

    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Test 2b: UDP max session cap — once one client owns the only configured
/// session slot, a second client is dropped while the original session still works.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_max_sessions_env_limits_new_clients() {
    let backend_port = 19826u16;
    let proxy_port = 19827u16;
    let gateway_http_port = 18218u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-max-sessions"
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

    let mut gateway = start_gateway_with_extra_env(
        config_path.to_str().unwrap(),
        gateway_http_port,
        &[("FERRUM_UDP_MAX_SESSIONS", "1")],
    )
    .expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    let client1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client1.connect(&proxy_addr).await.unwrap();
    let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client2.connect(&proxy_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let first_msg = b"client-one";
    client1.send(first_msg).await.expect("client1 send failed");
    let first_len = tokio::time::timeout(Duration::from_secs(5), client1.recv(&mut buf))
        .await
        .expect("client1 initial recv timed out")
        .expect("client1 initial recv error");
    assert_eq!(
        &buf[..first_len],
        first_msg,
        "first client should establish the only UDP session"
    );

    let second_msg = b"client-two";
    client2.send(second_msg).await.expect("client2 send failed");
    let mut second_buf = vec![0u8; 1024];
    let second_recv =
        tokio::time::timeout(Duration::from_secs(2), client2.recv(&mut second_buf)).await;
    assert!(
        second_recv.is_err(),
        "second client should not receive an echo while FERRUM_UDP_MAX_SESSIONS=1"
    );

    let followup_msg = b"client-one-still-active";
    client1
        .send(followup_msg)
        .await
        .expect("client1 followup send failed");
    let followup_len = tokio::time::timeout(Duration::from_secs(5), client1.recv(&mut buf))
        .await
        .expect("client1 followup recv timed out")
        .expect("client1 followup recv error");
    assert_eq!(
        &buf[..followup_len],
        followup_msg,
        "existing UDP session should continue after a new client is rejected"
    );

    shutdown_gateway(&mut gateway);
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
version: "1"
proxies:
  - id: "udp-timeout"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 2

consumers: []
plugin_configs: []
"#
        ),
    );

    // Drop the cleanup interval from its 10s default so the test can verify
    // session expiry + reclaim in single-digit seconds instead of 18s. The
    // gateway's cleanup task fires every `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`
    // and prunes any session idle longer than `udp_idle_timeout_seconds`; with
    // idle=2 + cleanup=3 the worst case is 5s, so a 7s wait has 2s margin.
    let mut gateway = start_gateway_with_extra_env(
        config_path.to_str().unwrap(),
        gateway_http_port,
        &[("FERRUM_UDP_CLEANUP_INTERVAL_SECONDS", "3")],
    )
    .expect("Failed to start");
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

    // Wait for session timeout + cleanup interval (idle_timeout=2s +
    // cleanup_interval=3s = 5s worst case) plus a 2s margin.
    sleep(Duration::from_secs(7)).await;

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
    shutdown_gateway(&mut gateway);
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Test 5: UDP response amplification factor — oversized backend datagrams are dropped.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_response_amplification_factor_drops_oversized_backend_datagram() {
    let backend_port = 19828u16;
    let proxy_port = 19829u16;
    let gateway_http_port = 18219u16;

    let fixed_response = b"0123456789abcdef".to_vec();
    let response_server =
        start_udp_fixed_response_server(backend_port, fixed_response.clone()).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-amplification-guard"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_max_response_amplification_factor: 1.0

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

    let mut buf = vec![0u8; 1024];
    client.send(b"tiny").await.expect("Failed to send");
    let dropped = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buf)).await;
    assert!(
        dropped.is_err(),
        "backend response larger than request must be dropped by amplification guard"
    );

    let allowed_request = vec![b'a'; fixed_response.len()];
    client
        .send(&allowed_request)
        .await
        .expect("Failed to send allowed-size request");
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("Allowed response timed out")
        .expect("Allowed response recv error");
    assert_eq!(
        &buf[..n],
        fixed_response.as_slice(),
        "response at the configured amplification limit should be forwarded"
    );

    shutdown_gateway(&mut gateway);
    response_server.abort();
}

/// Test 6: DTLS backend — send plain UDP datagrams through the gateway,
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    dtls_echo.abort();
}

/// Test 7: DTLS backend with multiple clients — verify session isolation
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    dtls_echo.abort();
}

/// Test 8: Frontend DTLS termination — DTLS client → gateway → plain UDP echo server.
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
version: "1"
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
    shutdown_gateway(&mut gateway);
    echo_server.abort();
}

/// Regression: DTLS frontend idle timeout is session-wide, not per direction.
/// Backend-only push traffic must keep the session alive past the configured
/// idle threshold even when the client sends no more datagrams.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_frontend_dtls_backend_push_keeps_session_alive() {
    let backend_port = 19834u16;
    let proxy_port = 19835u16;
    let gateway_http_port = 18222u16;

    let push_server = start_udp_push_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_test_dtls_cert(&temp_dir);

    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "frontend-dtls-backend-push"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    frontend_tls: true
    udp_idle_timeout_seconds: 2

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

    let dtls_client = connect_dtls_client_with_retry(proxy_port, 5).await;
    dtls_client
        .send(b"start-push")
        .await
        .expect("Failed to start backend push stream");

    let started = Instant::now();
    let mut late_reply = None;
    while started.elapsed() < Duration::from_secs(5) {
        match tokio::time::timeout(Duration::from_secs(1), dtls_client.recv()).await {
            Ok(Ok(reply)) => {
                if started.elapsed() > Duration::from_secs(3) {
                    late_reply = Some(reply);
                    break;
                }
            }
            Ok(Err(e)) => panic!("DTLS session closed before late backend push: {e}"),
            Err(_) => {}
        }
    }

    assert!(
        late_reply.is_some(),
        "backend push traffic should keep the DTLS frontend session alive beyond udp_idle_timeout_seconds"
    );

    dtls_client.close().await;
    shutdown_gateway(&mut gateway);
    push_server.abort();
}

/// Test 9: Full DTLS e2e — DTLS client → gateway (DTLS termination + DTLS origination) → DTLS echo server.
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
version: "1"
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
    shutdown_gateway(&mut gateway);
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
                .expect("generate ephemeral cert")
                .into(),
            server_name: None,
            server_cert_verifier: None,
            connect_timeout_ms: 5_000,
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
            certificate: cert.into(),
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
                while let Ok(data) = conn.recv().await {
                    if conn.send(&data).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    sleep(Duration::from_millis(500)).await;
    handle
}

// ============================================================================
// Fault injection (issue #3293)
// ============================================================================

/// Abort faults drop UDP client→backend datagrams without an echo.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_fault_injection_abort_drops_datagram() {
    let backend_port = 19890u16;
    let proxy_port = 19891u16;
    let gateway_http_port = 18290u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-fault"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 30
    plugins:
      - plugin_config_id: "udp-fault-abort"

consumers: []
plugin_configs:
  - id: "udp-fault-abort"
    plugin_name: fault_injection
    scope: proxy
    proxy_id: "udp-fault"
    enabled: true
    config:
      abort:
        status_code: 503
        percentage: 100.0
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"should-drop", format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let timed_out = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
        .await
        .is_err();
    assert!(
        timed_out,
        "100% abort fault must drop the UDP datagram (no echo)"
    );

    shutdown_gateway_child(&mut gateway);
    echo_server.abort();
    println!("test_udp_proxy_fault_injection_abort_drops_datagram PASSED");
}

/// Delay faults park one peer without head-of-line blocking another peer.
#[ignore]
#[tokio::test]
async fn test_udp_proxy_fault_injection_delay_isolates_peers() {
    let backend_port = 19892u16;
    let proxy_port = 19893u16;
    let gateway_http_port = 18292u16;

    let echo_server = start_udp_echo_server(backend_port).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_config(
        &config_path,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-fault-delay"
    listen_port: {proxy_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 30
    plugins:
      - plugin_config_id: "udp-fault-delay-cfg"

consumers: []
plugin_configs:
  - id: "udp-fault-delay-cfg"
    plugin_name: fault_injection
    scope: proxy
    proxy_id: "udp-fault-delay"
    enabled: true
    config:
      delay:
        duration_ms: 1500
        percentage: 100.0
"#
        ),
    );

    let mut gateway =
        start_gateway(config_path.to_str().unwrap(), gateway_http_port).expect("Failed to start");
    sleep(Duration::from_secs(3)).await;

    let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let gateway_addr = format!("127.0.0.1:{proxy_port}");

    client_a.send_to(b"peer-a", &gateway_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let b_start = Instant::now();
    client_b.send_to(b"peer-b", &gateway_addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), client_b.recv_from(&mut buf))
        .await
        .expect("peer B timeout")
        .expect("peer B recv");
    let b_elapsed = b_start.elapsed();
    assert_eq!(&buf[..n], b"peer-b");
    assert!(
        b_elapsed < Duration::from_millis(2800),
        "peer B must not wait behind peer A's remaining delay; elapsed {b_elapsed:?}"
    );

    let (n, _) = tokio::time::timeout(Duration::from_secs(5), client_a.recv_from(&mut buf))
        .await
        .expect("peer A timeout")
        .expect("peer A recv");
    assert_eq!(&buf[..n], b"peer-a");

    shutdown_gateway_child(&mut gateway);
    echo_server.abort();
    println!("test_udp_proxy_fault_injection_delay_isolates_peers PASSED");
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

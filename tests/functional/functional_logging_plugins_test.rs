//! Functional Tests for TCP and UDP Logging Plugins (E2E)
//!
//! Tests:
//! - tcp_logging plugin sends transaction logs to a TCP endpoint
//! - udp_logging plugin sends transaction logs as UDP datagrams
//!
//! Uses file mode via the shared `TestGateway` harness + shared echo backend.
//! Mock log receivers (TCP + UDP) are kept local — they are plugin-specific
//! and small. Receivers hold their listener/socket inside the spawned task to
//! avoid the bind-drop-rebind race documented in CLAUDE.md.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_logging_plugins

use crate::common::{TestGateway, spawn_http_echo};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::sleep;

// ============================================================================
// Mock Log Receivers (specific to this file — log endpoints, not echo
// backends). Each returns its bound port so the gateway config can target
// it; the listener/socket stays owned by the background task.
// ============================================================================

async fn start_tcp_log_receiver() -> (u16, Arc<AtomicBool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP log receiver");
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicBool::new(false));
    let flag = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            flag.store(true, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
        }
    });
    (port, received)
}

async fn start_udp_log_receiver() -> (u16, Arc<AtomicBool>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP log receiver");
    let port = socket.local_addr().unwrap().port();
    let received = Arc::new(AtomicBool::new(false));
    let flag = received.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((n, _)) = socket.recv_from(&mut buf).await
                && n > 0
            {
                flag.store(true, Ordering::SeqCst);
            }
        }
    });
    (port, received)
}

// ============================================================================
// Functional Tests
// ============================================================================

/// Test that the tcp_logging plugin sends transaction logs to a TCP endpoint.
#[ignore]
#[tokio::test]
async fn test_tcp_logging_sends_to_endpoint() {
    let backend = spawn_http_echo().await.expect("spawn echo");
    let (tcp_log_port, tcp_received) = start_tcp_log_receiver().await;

    let config = format!(
        r#"
proxies:
  - id: "tcp-log-proxy"
    listen_path: "/tcp-log-test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "tcp-log-plugin-1"

consumers: []

plugin_configs:
  - id: "tcp-log-plugin-1"
    proxy_id: "tcp-log-proxy"
    plugin_name: "tcp_logging"
    scope: "proxy"
    enabled: true
    config:
      host: "127.0.0.1"
      port: {tcp_log_port}
      tls: false
      batch_size: 1
      flush_interval_ms: 500

upstreams: []
"#,
        backend_port = backend.port,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();
    let resp = client
        .get(gateway.proxy_url("/tcp-log-test/hello"))
        .header("User-Agent", "tcp-logging-test/1.0")
        .send()
        .await
        .expect("Proxy request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Request through gateway should succeed"
    );

    // Wait for async log delivery (tcp_logging batches and flushes asynchronously)
    sleep(Duration::from_secs(2)).await;

    assert!(
        tcp_received.load(Ordering::SeqCst),
        "TCP log receiver should have received transaction log data"
    );
}

/// Test that the udp_logging plugin sends transaction logs as UDP datagrams.
#[ignore]
#[tokio::test]
async fn test_udp_logging_sends_to_endpoint() {
    let backend = spawn_http_echo().await.expect("spawn echo");
    let (udp_log_port, udp_received) = start_udp_log_receiver().await;

    let config = format!(
        r#"
proxies:
  - id: "udp-log-proxy"
    listen_path: "/udp-log-test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "udp-log-plugin-1"

consumers: []

plugin_configs:
  - id: "udp-log-plugin-1"
    proxy_id: "udp-log-proxy"
    plugin_name: "udp_logging"
    scope: "proxy"
    enabled: true
    config:
      host: "127.0.0.1"
      port: {udp_log_port}
      batch_size: 1
      flush_interval_ms: 500

upstreams: []
"#,
        backend_port = backend.port,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();
    let resp = client
        .get(gateway.proxy_url("/udp-log-test/hello"))
        .header("User-Agent", "udp-logging-test/1.0")
        .send()
        .await
        .expect("Proxy request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Request through gateway should succeed"
    );

    // Wait for async log delivery
    sleep(Duration::from_secs(2)).await;

    assert!(
        udp_received.load(Ordering::SeqCst),
        "UDP log receiver should have received transaction log data"
    );
}

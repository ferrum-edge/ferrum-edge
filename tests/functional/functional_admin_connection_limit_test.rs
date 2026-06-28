//! Functional coverage for the admin listener connection cap
//! (`FERRUM_ADMIN_MAX_CONNECTIONS`).
//!
//! The cap is enforced in the admin accept loop after the CIDR allowlist and
//! before the per-connection task / TLS handshake. These tests open raw idle
//! TCP connections: with the admin header-read timeout (plaintext) or TLS
//! handshake timeout (HTTPS) disabled, an accepted-but-idle connection holds
//! its limiter permit indefinitely, so the cap can be exercised deterministically
//! without juggling keep-alive HTTP or a TLS client. Over-cap connections are
//! dropped (TCP RST) by the accept loop, which the client observes as an
//! immediate EOF/reset rather than a held-open socket.

use crate::common::TestGateway;
use crate::scaffolding::reserve_port;

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio::time::timeout;

const ADMIN_CONFIG: &str = r#"
version: "1"
proxies:
  - id: dummy
    listen_path: /dummy
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: 9
consumers: []
upstreams: []
plugin_configs: []
"#;

/// Open a raw TCP connection that sends no bytes. On an admin listener with the
/// relevant pre-request timeout disabled, this holds a limiter permit until the
/// connection is closed.
async fn connect_raw(port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect(("127.0.0.1", port)).await
}

/// Whether the server dropped the connection. A rejected connection is closed
/// by the accept loop (read returns EOF/reset quickly); a held connection stays
/// open with no data (the read blocks and times out).
async fn is_dropped(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
        Ok(Ok(0)) => true,  // clean EOF: server closed the socket
        Ok(Ok(_)) => false, // unexpected data; treat as held
        Ok(Err(_)) => true, // reset: server closed the socket
        Err(_) => false,    // timed out: still held open
    }
}

async fn scrape_metrics(port: u16) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let body = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/metrics"))
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .text()
        .await?;
    Ok(body)
}

#[ignore]
#[tokio::test]
async fn functional_admin_connection_cap_plaintext_rejects_over_limit() {
    let mut gw = TestGateway::builder()
        .mode_file(ADMIN_CONFIG)
        .log_level("warn")
        .env("FERRUM_ADMIN_MAX_CONNECTIONS", "2")
        // Idle raw connections must hold their permits for the duration.
        .env("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "0")
        .spawn()
        .await
        .expect("start admin-cap gateway");
    gw.wait_for_health(Duration::from_secs(30))
        .await
        .expect("admin healthy");

    let port = gw.admin_port;

    // Hold the full cap (2) with idle connections.
    let mut c1 = connect_raw(port).await.expect("c1 connects");
    let mut c2 = connect_raw(port).await.expect("c2 connects");
    // Let the accept loop process both before probing the cap.
    sleep(Duration::from_millis(400)).await;
    assert!(!is_dropped(&mut c1).await, "c1 should be held open");
    assert!(!is_dropped(&mut c2).await, "c2 should be held open");

    // A 3rd connection is over the cap: accepted at the TCP layer, then dropped.
    let mut c3 = connect_raw(port).await.expect("c3 connects at TCP layer");
    assert!(
        is_dropped(&mut c3).await,
        "3rd admin connection over the cap should be dropped"
    );

    // Releasing a permit lets a new connection in.
    drop(c1);
    sleep(Duration::from_millis(400)).await;
    let mut c4 = connect_raw(port).await.expect("c4 connects");
    assert!(
        !is_dropped(&mut c4).await,
        "connection after a release should be admitted"
    );

    // Free the remaining held connections so the /metrics scrape can get a permit.
    drop(c2);
    drop(c3);
    drop(c4);
    sleep(Duration::from_millis(400)).await;

    let metrics = scrape_metrics(port).await.expect("scrape /metrics");
    assert!(
        metrics.contains("ferrum_admin_max_connections"),
        "cap gauge should be exposed; got:\n{metrics}"
    );
    let rejected_nonzero = metrics.lines().any(|line| {
        line.starts_with("ferrum_admin_rejected_connections_total{reason=\"max_connections\"")
            && !line.trim_end().ends_with(" 0")
    });
    assert!(
        rejected_nonzero,
        "rejected counter should be incremented; got:\n{metrics}"
    );

    gw.shutdown();
}

/// Start a file-mode gateway with a TLS admin listener (cap = `max_conns`),
/// allocating a FRESH `FERRUM_ADMIN_HTTPS_PORT` on each attempt. The
/// reserve-drop-rebind window lets a parallel test steal the port before the
/// gateway binds it; rather than reuse the already-stolen port (which the
/// harness's own retry would do, since the env value is fixed), this retries
/// with a new port — per the functional-test port-allocation rule. File-mode
/// startup fails closed when the admin HTTPS port cannot bind (the listener's
/// readiness signal gates `startup_ready`), so a successful `spawn()` implies
/// the HTTPS listener is bound.
async fn start_tls_admin_gateway(max_conns: &str) -> (TestGateway, u16) {
    for attempt in 1..=5u32 {
        let https = reserve_port().await.expect("reserve admin https port");
        let https_port = https.port;
        drop(https);

        let result = TestGateway::builder()
            .mode_file(ADMIN_CONFIG)
            .log_level("warn")
            // Drive retries here (fresh port per attempt) instead of letting the
            // harness retry against the fixed FERRUM_ADMIN_HTTPS_PORT.
            .max_attempts(1)
            .env("FERRUM_ADMIN_MAX_CONNECTIONS", max_conns)
            .env("FERRUM_ADMIN_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_ADMIN_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_ADMIN_TLS_KEY_PATH", "tests/certs/server.key")
            // Idle raw connections stall in the TLS handshake wait, holding permits.
            .env("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "0")
            .spawn()
            .await;
        match result {
            Ok(gw) => return (gw, https_port),
            Err(e) if attempt < 5 => {
                eprintln!("admin-cap TLS gateway start attempt {attempt} failed: {e}");
            }
            Err(e) => panic!("start admin-cap TLS gateway after retries: {e}"),
        }
    }
    unreachable!("loop returns Ok or panics on the final attempt")
}

#[ignore]
#[tokio::test]
async fn functional_admin_connection_cap_tls_rejects_over_limit() {
    // Health is served on the plaintext admin port; the cap is shared.
    let (mut gw, https_port) = start_tls_admin_gateway("2").await;

    // Hold the full cap (2) with idle TCP connections to the HTTPS port. The
    // permit is acquired before the TLS handshake, so no TLS client is needed.
    let mut c1 = connect_raw(https_port).await.expect("c1 connects");
    let mut c2 = connect_raw(https_port).await.expect("c2 connects");
    sleep(Duration::from_millis(400)).await;
    assert!(
        !is_dropped(&mut c1).await,
        "c1 should be held open (TLS path)"
    );
    assert!(
        !is_dropped(&mut c2).await,
        "c2 should be held open (TLS path)"
    );

    // The 3rd HTTPS connection is over the shared cap and is dropped before the
    // TLS handshake even begins.
    let mut c3 = connect_raw(https_port)
        .await
        .expect("c3 connects at TCP layer");
    assert!(
        is_dropped(&mut c3).await,
        "3rd admin TLS connection over the cap should be dropped"
    );

    gw.shutdown();
}

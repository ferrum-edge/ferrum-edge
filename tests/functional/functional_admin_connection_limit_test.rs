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

/// Admin connection cap used by both cap tests.
///
/// The cap is a single global semaphore shared across the plaintext and TLS
/// admin listeners (`AdminConnLimiter`, cloned into both `admin_http_limiter`
/// and `admin_https_limiter`). The harness's `/health` probe opens a *plaintext*
/// admin connection, and its server-side permit is released only after the
/// serving task observes the socket close — which lags the client-side drop
/// under CI load. So a couple of just-closed management-plane probe permits can
/// still be held at the instant a test begins probing the listener under test.
///
/// A cap of 2 (the original value) could be fully occupied by that transient
/// background, starving the listener under test to zero admitted connections and
/// tripping the `!held.is_empty()` assertion intermittently. A larger cap keeps
/// comfortable headroom over the bounded background occupancy while still proving
/// the listener admits a bounded set and rejects beyond it.
const CAP: usize = 6;

/// How many connections each test opens while probing the cap. Must exceed `CAP`
/// so a rejection is always observed once the listener's permits are exhausted
/// (background occupancy only makes the rejection happen sooner, never later).
const PROBE_FANOUT: usize = 12;

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
        .env("FERRUM_ADMIN_MAX_CONNECTIONS", CAP.to_string())
        // Idle raw connections must hold their permits for the duration.
        .env("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "0")
        // `/metrics` is gated by default; this test scrapes it from loopback to
        // read the connection-cap gauges, so allowlist the loopback scrape.
        .env("FERRUM_METRICS_ALLOWED_CIDRS", "127.0.0.1/32,::1")
        .spawn()
        .await
        .expect("start admin-cap gateway");
    gw.wait_for_health(Duration::from_secs(30))
        .await
        .expect("admin healthy");

    let port = gw.admin_port;

    // Hold connections until the cap rejects one. Robust to the management-plane
    // permits the harness health probe may briefly hold (the cap is shared
    // across admin listeners and CAP carries headroom over that background), so
    // this checks the rejection boundary rather than an exact admitted count.
    let (held, rejected) = hold_until_rejected(port, PROBE_FANOUT).await;
    assert!(
        !held.is_empty(),
        "at least one admin connection should be admitted"
    );
    assert!(rejected, "an over-cap admin connection should be dropped");
    assert!(
        held.len() <= CAP,
        "admitted {} connections, exceeding the cap of {CAP}",
        held.len()
    );

    // Releasing the held connections lets a new one in.
    drop(held);
    sleep(Duration::from_millis(500)).await;
    let mut readmitted = connect_raw(port).await.expect("connect after release");
    assert!(
        !is_dropped(&mut readmitted).await,
        "a connection after releasing the cap should be admitted"
    );
    drop(readmitted);
    sleep(Duration::from_millis(500)).await;

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
async fn start_tls_admin_gateway(max_conns: usize) -> (TestGateway, u16) {
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
            .env("FERRUM_ADMIN_MAX_CONNECTIONS", max_conns.to_string())
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

/// Open admin connections to `port`, holding each open, until the cap drops one
/// (a rejected connection is closed promptly post-accept) or `max_open` are
/// admitted. Returns the still-held connections and whether a rejection was
/// observed. Used by the TLS test because the management-plane cap is shared
/// across the HTTP and HTTPS admin listeners, so the harness health probe can
/// transiently hold a permit — this asserts the rejection boundary rather than
/// an exact admitted count.
async fn hold_until_rejected(port: u16, max_open: usize) -> (Vec<TcpStream>, bool) {
    let mut held = Vec::new();
    while held.len() < max_open {
        let mut c = match connect_raw(port).await {
            Ok(c) => c,
            // A refused connect is an unambiguous rejection.
            Err(_) => return (held, true),
        };
        let mut buf = [0u8; 1];
        match timeout(Duration::from_millis(400), c.read(&mut buf)).await {
            // Server closed the socket post-accept → over the cap.
            Ok(Ok(0)) | Ok(Err(_)) => return (held, true),
            // Still open (read timed out, or unexpected data) → admitted.
            _ => held.push(c),
        }
    }
    (held, false)
}

#[ignore]
#[tokio::test]
async fn functional_admin_connection_cap_tls_rejects_over_limit() {
    // Health is served on the plaintext admin port; the cap is shared across the
    // HTTP and HTTPS admin listeners, so a management-plane probe may transiently
    // hold one or more permits (see CAP). Idle raw connections to the HTTPS port
    // hold a permit (acquired before the TLS handshake, which is disabled-timeout),
    // so no TLS client is needed. Assert the rejection boundary, not exact counts.
    let (mut gw, https_port) = start_tls_admin_gateway(CAP).await;

    let (held, rejected) = hold_until_rejected(https_port, PROBE_FANOUT).await;
    assert!(
        !held.is_empty(),
        "at least one admin TLS connection should be admitted"
    );
    assert!(
        rejected,
        "an over-cap admin TLS connection should be dropped before the handshake"
    );
    assert!(
        held.len() <= CAP,
        "admitted {} TLS connections, exceeding the cap of {CAP}",
        held.len()
    );

    gw.shutdown();
}

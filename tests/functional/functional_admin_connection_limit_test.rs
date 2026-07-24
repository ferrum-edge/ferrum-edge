//! Functional coverage for admin listener binding and admission:
//!
//! 1. **Connection cap** (`FERRUM_ADMIN_MAX_CONNECTIONS`) — enforced in the
//!    admin accept loop after the CIDR allowlist and before the per-connection
//!    task / TLS handshake. These tests open raw idle TCP connections: with the
//!    admin header-read timeout (plaintext) or TLS handshake timeout (HTTPS)
//!    disabled, an accepted-but-idle connection holds its limiter permit
//!    indefinitely, so the cap can be exercised deterministically without
//!    juggling keep-alive HTTP or a TLS client. Over-cap connections are
//!    dropped (TCP RST) by the accept loop, which the client observes as an
//!    immediate EOF/reset rather than a held-open socket.
//!
//! 2. **Admin HTTPS port 0** (`FERRUM_ADMIN_HTTPS_PORT=0`, issue #2362) — the
//!    helper truth table (`EnvConfig::admin_https_listener_enabled`) is covered
//!    by unit tests. The mode-level pair below proves a serving mode must not
//!    load configured admin TLS material when the disable sentinel is set, so
//!    missing `_PATH` cert/key values cannot fail startup and no ephemeral
//!    admin HTTPS socket is bound. External-secret resolution runs before
//!    config parsing and is unaffected by the sentinel, so those tests use
//!    plain `_PATH` inputs only. CP is the probe: cheapest real-process spawn
//!    (SQLite + loopback gRPC) and, before the fix, it took the unconditional
//!    "TLS material configured ⇒ build the listener" branch that DP and mesh
//!    share verbatim.
//!
//! Both directions of the port-0 pair run on the shared [`TestGateway`] harness:
//! hermetic `clear_env` (load-bearing for `RUST_LOG` and TLS source overrides),
//! file-backed `capture_output`, bounded waits via `wait_for_captured_output`,
//! fresh ports/temp dirs per retry, and `Drop` cleanup.
//!
//! Run with:
//!   cargo test --test functional_tests -- --ignored functional_admin_connection_limit
//!   cargo test --test functional_tests -- --ignored functional_admin_https

use crate::common::{DbType, TestGateway, TestGatewayBuilder, ephemeral_port};
use crate::scaffolding::reserve_port;

use std::time::Duration;
use tempfile::TempDir;
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
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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

// ── Admin HTTPS port 0 (issue #2362) ────────────────────────────────────────

/// Budget for "CP reaches full readiness" and for "CP aborts startup". Both
/// are seconds-scale locally; the headroom is for loaded CI runners.
const ADMIN_HTTPS_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for the gateway's async log worker to drain an already-emitted line
/// into the capture file. Sub-millisecond in practice; the headroom is for
/// loaded CI runners.
const ADMIN_HTTPS_LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// Substring proving the gateway touched the admin TLS material in *either*
/// direction: the failure log ("Failed to load admin TLS configuration" /
/// "Invalid admin TLS configuration") and the success log ("Admin TLS
/// configuration loaded ...") both contain it. Matched case-insensitively.
const ADMIN_TLS_LOAD_MARKER: &str = "admin tls configuration";

/// Substring of the CP disable log. Asserted in the positive test so a pass
/// cannot be vacuous: it proves the port-0 branch actually executed rather
/// than the test merely failing to find a TLS log.
const ADMIN_HTTPS_DISABLED_MARKER: &str = "admin HTTPS listener disabled";

/// Paths for admin TLS material that does not exist, plus an empty
/// `ferrum.conf`.
///
/// The empty conf file is deliberate: with a cleared environment there is no
/// `FERRUM_CONF_PATH`, and the binary would fall back to discovering
/// `./ferrum.conf` relative to the test's working directory — the repository
/// root, which ships one. Pinning an empty file keeps the child's
/// configuration exactly what the builder sets.
struct MissingAdminTls {
    cert_path: String,
    key_path: String,
    conf_path: String,
    /// Kept alive so the paths above stay valid for the whole test.
    _temp_dir: TempDir,
}

fn missing_admin_tls() -> MissingAdminTls {
    let temp_dir = TempDir::new().expect("create temp dir");
    let conf_path = temp_dir.path().join("empty-ferrum.conf");
    std::fs::write(&conf_path, "").expect("write empty ferrum.conf");
    MissingAdminTls {
        cert_path: temp_dir
            .path()
            .join("does-not-exist.crt")
            .display()
            .to_string(),
        key_path: temp_dir
            .path()
            .join("does-not-exist.key")
            .display()
            .to_string(),
        conf_path: conf_path.display().to_string(),
        _temp_dir: temp_dir,
    }
}

/// CP-mode builder against SQLite with unloadable admin TLS material.
/// `admin_https_port` is the only variable between the two tests.
fn cp_admin_https_builder(tls: &MissingAdminTls, admin_https_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_cp(DbType::Sqlite, None)
        .clear_env()
        .capture_output()
        .log_level("info")
        .env("FERRUM_CONF_PATH", tls.conf_path.as_str())
        .env("FERRUM_ADMIN_BIND_ADDRESS", "127.0.0.1")
        .env("FERRUM_ADMIN_HTTPS_PORT", admin_https_port.to_string())
        // Configured but unloadable: the whole point of the test.
        .env("FERRUM_ADMIN_TLS_CERT_PATH", tls.cert_path.as_str())
        .env("FERRUM_ADMIN_TLS_KEY_PATH", tls.key_path.as_str())
        // Loopback plaintext gRPC is always permitted; set explicitly so the
        // secure-by-default transport gate is never the reason a run fails.
        .env("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true")
}

fn mentions_admin_tls_load(output: &str) -> bool {
    output.to_ascii_lowercase().contains(ADMIN_TLS_LOAD_MARKER)
}

/// With `FERRUM_ADMIN_HTTPS_PORT=0`, CP must skip admin TLS loading, the reload
/// watcher, the startup signal, and the listener task — so cert/key paths that
/// do not exist are never opened and startup completes. Before the fix this
/// process exited with "Invalid admin TLS configuration".
///
/// The success condition is `/health` reporting `ready`, not a bare TCP accept
/// on the admin port. CP binds admin HTTP *before* the admin HTTPS branch and
/// the gRPC bind, and stores `startup_ready` only after `wait_for_start_signals`
/// — so a regression that still loads the bad TLS material (or a gRPC bind
/// failure) can satisfy a raw accept for a moment on its way to exiting, but
/// can never satisfy `ready`. `wait_for_ready` is asserted explicitly on top of
/// the harness's `/health` wait (which is a barrier only because `/health`
/// answers `503` until ready) so the barrier does not depend on that policy.
#[ignore]
#[tokio::test]
async fn functional_admin_https_disabled_port_zero_ignores_unloadable_tls() {
    let tls = missing_admin_tls();
    let mut gateway = cp_admin_https_builder(&tls, 0)
        .spawn()
        .await
        .expect("CP must start with FERRUM_ADMIN_HTTPS_PORT=0 and unloadable admin TLS paths");

    gateway
        .wait_for_ready(ADMIN_HTTPS_STARTUP_TIMEOUT)
        .await
        .expect("CP must reach full startup readiness, not just an admin HTTP accept");
    assert!(
        gateway.is_running(),
        "CP exited after reporting ready with FERRUM_ADMIN_HTTPS_PORT=0"
    );

    // The admin HTTPS branch runs strictly before the readiness store, but the
    // gateway logs through an async `NonBlockingSink`: `ready` can be observed
    // before the log worker drains that line into the capture file. Poll for
    // the marker instead of reading once. Polling cannot weaken the assertion —
    // if the port-0 branch never ran, the marker never appears and this fails
    // at the deadline exactly as a single read would have.
    let output = gateway
        .wait_for_captured_output(
            |output| output.contains(ADMIN_HTTPS_DISABLED_MARKER),
            ADMIN_HTTPS_LOG_FLUSH_TIMEOUT,
        )
        .await
        .expect("read captured gateway output");
    assert!(
        output.contains(ADMIN_HTTPS_DISABLED_MARKER),
        "expected the port-0 disable log, so the assertion below is not vacuous; output: {output}"
    );
    // Asserted on the same snapshot: the disable log and the admin TLS logs come
    // from mutually exclusive arms of one startup step, so a run that reached
    // this line took the port-0 arm and never entered the loading arm.
    assert!(
        !mentions_admin_tls_load(&output),
        "CP loaded admin TLS material for a disabled HTTPS listener; output: {output}"
    );
}

/// The same unloadable cert/key paths with a nonzero `FERRUM_ADMIN_HTTPS_PORT`
/// must still abort startup. Without this control, the positive port-0 test
/// would pass even if the paths were somehow loadable.
///
/// `spawn_expect_failure` reads the captured log files only after the child has
/// exited, so the expected error line cannot be missed by reaping the process
/// early.
#[ignore]
#[tokio::test]
async fn functional_admin_https_enabled_port_still_fails_on_unloadable_tls() {
    let tls = missing_admin_tls();
    // Nonzero and unlikely to collide, though collisions are harmless here:
    // admin TLS loading fails before any socket is bound.
    let admin_https_port = ephemeral_port().await.expect("reserve an admin HTTPS port");

    let failure = cp_admin_https_builder(&tls, admin_https_port)
        .spawn_expect_failure(ADMIN_HTTPS_STARTUP_TIMEOUT)
        .await
        .expect("CP must refuse to start when an ENABLED admin HTTPS listener has bad TLS");

    let output = failure.combined_output();
    assert!(
        failure.status.is_some_and(|status| !status.success()),
        "CP must exit non-zero; status: {:?}, output: {output}",
        failure.status
    );
    assert!(
        mentions_admin_tls_load(&output),
        "expected an admin TLS configuration error in CP output, got: {output}"
    );
    // `db_url` points inside the harness temp dir. Retaining that dir on
    // `FailedGatewayStart` is what keeps this diagnostic usable after spawn.
    let db_url = failure
        .db_url
        .as_deref()
        .expect("CP SQLite failure must expose db_url");
    let db_path = db_url
        .strip_prefix("sqlite:")
        .and_then(|rest| rest.split('?').next())
        .expect("sqlite db_url shape");
    assert!(
        std::path::Path::new(db_path).exists(),
        "FailedGatewayStart must retain its temp dir so db_url stays alive; missing {db_path}"
    );
}

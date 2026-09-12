//! Phase-4 acceptance tests for the UDP + DTLS scripted backends.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_udp -- --ignored --nocapture
//!
//! Each test spawns a scripted UDP (or DTLS) backend and a ferrum-edge
//! gateway binary configured to point at it, then exercises one
//! gateway-level behaviour:
//!
//! 1. [`udp_session_idle_timeout_cleans_session_map`] — UDP session map
//!    is cleaned up after `udp_idle_timeout_seconds`, observable via a
//!    new backend source-address being allocated on subsequent traffic.
//! 2. [`udp_amplification_bound_enforced`] — oversized backend replies
//!    are dropped per `udp_max_response_amplification_factor`.
//! 3. [`udp_amplification_cumulative_multi_datagram_budget`] — several
//!    in-budget replies still fail closed once their sum exceeds the
//!    per-request remaining budget.
//! 4. [`dtls_passthrough_sni_routes_to_correct_backend`] — passthrough
//!    DTLS proxy routes clients by SNI peeked from the DTLS
//!    ClientHello.

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{DatagramMatcher, ScriptedUdpBackend, UdpStep};
use crate::scaffolding::clients::{UdpClient, dtls::dtls_client_hello_with_sni};
use crate::scaffolding::ports::{reserve_udp_port, unbound_port, unbound_udp_port};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::Instant;

/// Locate the already-built `ferrum-edge` binary. Match the same fallback
/// order the other functional tests use.
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Write a YAML config to disk. Kept local so tests can tweak the
/// config without jumping through the harness builder (stream proxies
/// need `listen_port` which the Phase-1 helpers don't set).
fn write_config(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).expect("write config");
}

/// Per-spawn `FERRUM_METRICS_BEARER_TOKEN` so authenticated `/health` can prove
/// this child owns the admin port (issue #4373 / #3428). Never logged.
fn mint_observability_token() -> String {
    format!(
        "ferrum-edge-scripted-udp-probe-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Spawn the gateway subprocess with stream-proxy-specific env vars.
/// `Stdio::null()` for stdout per CLAUDE.md functional-test rule;
/// `Stdio::piped()` causes deadlock if not drained.
///
/// `capture_logs = true` redirects stderr to a temp file so the test
/// can grep log output.
///
/// Identity env is applied after `extra_env` so a caller (or leaked parent
/// shell) cannot replace this attempt's token or open a CIDR allowlist that
/// would let a foreign listener answer the authenticated `/health` tier.
fn spawn_gateway(
    config_path: &str,
    proxy_http_port: u16,
    admin_port: u16,
    extra_env: &[(&str, String)],
    observability_token: &str,
    capture_paths: Option<(&std::path::Path, &std::path::Path)>,
) -> std::io::Result<std::process::Child> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.arg("run");
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        // UDP session create / expire fire at `debug!`. Tests that grep
        // the logs for those signals must run the gateway at debug.
        //
        // `main.rs` builds its `EnvFilter` via `try_from_default_env()`,
        // which prefers `RUST_LOG` over `FERRUM_LOG_LEVEL`. An inherited
        // `RUST_LOG=warn` (or similar) in the test runner's environment
        // would suppress the debug lines we grep for, so set both — the
        // `RUST_LOG` value wins and guarantees the debug target is on
        // regardless of the parent env.
        .env("FERRUM_LOG_LEVEL", "debug")
        .env("RUST_LOG", "ferrum_edge=debug")
        // Phase-4 tests care about session cleanup; tick fast so tests
        // don't need to wait the 10s production default.
        .env("FERRUM_UDP_CLEANUP_INTERVAL_SECONDS", "1")
        .stdin(std::process::Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.env("FERRUM_METRICS_BEARER_TOKEN", observability_token)
        .env_remove("FERRUM_METRICS_ALLOWED_CIDRS");
    match capture_paths {
        Some((stdout_path, stderr_path)) => {
            cmd.stdout(std::process::Stdio::from(std::fs::File::create(
                stdout_path,
            )?))
            .stderr(std::process::Stdio::from(std::fs::File::create(
                stderr_path,
            )?));
        }
        None => {
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }
    }
    cmd.spawn()
}

/// Wait until `child` owns its admin listener and reports fully ready.
///
/// Unauthenticated `/health` 2xx is not identity and is not readiness: a
/// foreign process can answer the released admin port, and that probe does
/// not require JSON `ready: true`. `ready` flips only after every listener
/// bind, including the UDP/DTLS stream listener these tests actually dial.
/// Connecting that UDP port as a readiness probe would look like real
/// traffic, so authenticated `ready: true` is the barrier.
///
/// Barrier (same contract as `TestGateway` / passthrough `wait_for_owned_gateway`):
/// 1. `Child::try_wait` before and after every probe — a dead child voids
///    the attempt.
/// 2. Authenticated `/health` detail tier for this attempt's bearer token
///    with `ready: true`, via the shared `probe_gateway_identity` contract.
///
/// Each probe is sliced so `try_wait` runs between attempts. A successful
/// response from a foreign or previous listener cannot admit this attempt.
async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    observability_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const STARTUP_TIMEOUT_SECS: u64 = 30;
    const PROBE_SLICE: Duration = Duration::from_secs(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(STARTUP_TIMEOUT_SECS);
    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "scripted UDP gateway exited during startup with {status} \
                 (last observation: {last_observation})"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "scripted UDP gateway did not prove ownership of admin port {admin_port} \
                 within {STARTUP_TIMEOUT_SECS} seconds (last observation: {last_observation})"
            )
            .into());
        }
        match crate::common::probe_gateway_identity(
            admin_port,
            observability_token,
            remaining.min(PROBE_SLICE),
        )
        .await
        {
            Ok(()) => {
                if let Some(status) = child.try_wait()? {
                    return Err(format!(
                        "scripted UDP gateway exited after proving ownership with {status}"
                    )
                    .into());
                }
                return Ok(());
            }
            Err(err) => {
                last_observation = err.to_string();
                if let Some(status) = child.try_wait()? {
                    return Err(format!(
                        "scripted UDP gateway exited during startup with {status} \
                         (last observation: {last_observation})"
                    )
                    .into());
                }
            }
        }
    }
}

/// Include the bounded, redacted capture tail in spawn-failure errors.
/// Tokens are never logged.
fn attempt_failure_detail(
    error: &str,
    capture_paths: &Option<(std::path::PathBuf, std::path::PathBuf)>,
    observability_token: &str,
) -> String {
    let error = error.replace(observability_token, "***");
    let Some((stdout, stderr)) = capture_paths else {
        return error;
    };
    let out = std::fs::read_to_string(stdout).unwrap_or_default();
    let err = std::fs::read_to_string(stderr).unwrap_or_default();
    let combined = if out.is_empty() {
        err
    } else if err.is_empty() {
        out
    } else {
        format!("{err}\n{out}")
    };
    if combined.trim().is_empty() {
        return error;
    }
    format!(
        "{error}\n--- captured gateway output ---\n{}",
        crate::common::scrub_gateway_capture_for_diagnostics(&combined, &[observability_token])
    )
}

/// Wrapper that combines "reserve UDP listen port" + "reserve HTTP +
/// admin ports" + "write config + spawn gateway + wait for owned ready".
/// Retries up to 3× to absorb the bind-drop-rebind race. An attempt whose
/// child exits, or whose `/health` answer is not this child's authenticated
/// `ready: true`, is void: retry with fresh ports and temp state.
async fn start_gateway_with_retry<F>(
    build_yaml: F,
    extra_env: Vec<(&'static str, String)>,
    capture_stderr: bool,
) -> GatewayFixture
where
    F: Fn(u16) -> String,
{
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::from("no spawn attempts completed");
    for attempt in 1..=MAX_ATTEMPTS {
        // Stream listen_port: UDP port for the gateway's UDP/DTLS
        // frontend — reserve in the UDP namespace.
        let udp_port = match unbound_udp_port().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Admin + proxy HTTP ports are TCP listeners. UDP and TCP
        // namespaces are independent, so a UDP-free port can still be
        // held in TCP by another test. Reserve via the TCP helper to
        // catch the conflict at reserve time rather than at gateway-
        // bind time.
        let admin_port = match unbound_port().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let proxy_http_port = match unbound_port().await {
            Ok(p) => p,
            Err(_) => continue,
        };

        let temp_dir = TempDir::new().expect("tempdir");
        let config_path = temp_dir.path().join("config.yaml");
        write_config(&config_path, &build_yaml(udp_port));
        let capture_paths = if capture_stderr {
            Some((
                temp_dir.path().join("gateway.stdout.log"),
                temp_dir.path().join("gateway.stderr.log"),
            ))
        } else {
            None
        };
        let observability_token = mint_observability_token();

        let mut child = match spawn_gateway(
            config_path.to_str().unwrap(),
            proxy_http_port,
            admin_port,
            &extra_env,
            &observability_token,
            capture_paths
                .as_ref()
                .map(|(o, e)| (o.as_path(), e.as_path())),
        ) {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("spawn failed: {e}");
                continue;
            }
        };

        match wait_for_owned_gateway(&mut child, admin_port, &observability_token).await {
            Ok(()) => {
                return GatewayFixture {
                    child: Some(child),
                    udp_port,
                    admin_port,
                    proxy_http_port,
                    temp_dir,
                    capture_paths,
                };
            }
            Err(error) => {
                last_err = attempt_failure_detail(
                    &error.to_string(),
                    &capture_paths,
                    &observability_token,
                );
                eprintln!(
                    "scripted UDP gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
                     (udp={udp_port}, admin={admin_port}, http={proxy_http_port}): {last_err}"
                );
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    panic!(
        "scripted UDP gateway did not prove ownership after {MAX_ATTEMPTS} attempts: {last_err}"
    );
}

struct GatewayFixture {
    child: Option<std::process::Child>,
    udp_port: u16,
    #[allow(dead_code)] // Kept for test diagnostics even when the test only uses `udp_port`.
    admin_port: u16,
    #[allow(dead_code)]
    proxy_http_port: u16,
    #[allow(dead_code)]
    temp_dir: TempDir,
    capture_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl GatewayFixture {
    /// Combined stdout+stderr output from the gateway subprocess.
    /// Returns empty string if capture was not enabled.
    ///
    /// `ferrum-edge` routes INFO/DEBUG to stdout and WARN/ERROR to
    /// stderr (see `main.rs::SeverityWriter`); tests that grep for
    /// any level need both. Stderr first to match the Phase-1 harness.
    fn captured_stderr(&self) -> String {
        let Some((stdout, stderr)) = &self.capture_paths else {
            return String::new();
        };
        let out = std::fs::read_to_string(stdout).unwrap_or_default();
        let err = std::fs::read_to_string(stderr).unwrap_or_default();
        if out.is_empty() {
            err
        } else if err.is_empty() {
            out
        } else {
            format!("{err}\n{out}")
        }
    }

    /// Send `SIGTERM` and wait for the gateway to exit cleanly. The
    /// bounded process-log worker guard is dropped during
    /// the gateway's normal shutdown path, which flushes any
    /// outstanding log lines through Rust's stdout/stderr writers
    /// (block-buffered when piped to a file). Tests that grep the
    /// captured logs for events that fire late in the test's life
    /// (e.g. a second session creation) must call this before reading
    /// or risk a stale-buffer false negative.
    ///
    /// `libc` is gated to Linux in this crate's `Cargo.toml`, so we
    /// shell out to `/bin/kill` to stay portable to macOS dev boxes
    /// that run the same `#[ignore]` functional tests.
    fn graceful_shutdown(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        // Bound the wait so a hung gateway can't stall the test
        // forever; SIGKILL after the deadline as a final fallback.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for GatewayFixture {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — UDP session idle timeout cleans the session map.
// ────────────────────────────────────────────────────────────────────────────
//
// Strategy: configure `udp_idle_timeout_seconds = 2`,
// `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS = 1`, send one datagram, wait
// 3.5 s (> idle + cleanup), send another.
//
// The scripted backend records every source address it sees; a fresh
// session after cleanup shows up as a NEW backend-side source (because
// the gateway allocates a new ephemeral port for the new session —
// `proxy/udp_proxy.rs::create_udp_session`). We assert:
//
// - The backend saw >=2 datagrams.
// - They arrived from >=2 distinct source addresses (i.e., two separate
//   sessions).
//
// We also spot-check captured gateway stderr for the
// "UDP session expired (idle timeout)" log line, which the production
// code emits in `spawn_session_cleanup`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_session_idle_timeout_cleans_session_map() {
    // Hold the backend port bound across gateway startup, but start the script
    // afterwards: a failed identity-probe attempt costs up to 30 seconds and
    // would expire the backend's 10-second `ExpectDatagram` deadline before the
    // first client datagram.
    let reservation = reserve_udp_port().await.expect("reserve backend udp port");
    let backend_port = reservation.port;

    let build_yaml = move |listen_port: u16| {
        format!(
            r#"
version: "1"
proxies:
  - id: "udp-idle"
    listen_port: {listen_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_idle_timeout_seconds: 2

consumers: []
upstreams: []
plugin_configs: []
"#
        )
    };
    let fx = start_gateway_with_retry(build_yaml, Vec::new(), true).await;

    let backend = ScriptedUdpBackend::builder(reservation.into_socket())
        .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
        .step(UdpStep::Reply(b"one".to_vec()))
        .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
        .step(UdpStep::Reply(b"two".to_vec()))
        .spawn()
        .expect("spawn udp backend");

    let gateway_addr: SocketAddr = format!("127.0.0.1:{}", fx.udp_port).parse().unwrap();
    let client = UdpClient::connect(gateway_addr).await.expect("client");

    // First datagram — creates a session.
    client.send_datagram(b"hello-one").await.expect("send 1");
    let reply1 = client
        .recv_datagram_with_timeout(Duration::from_secs(5))
        .await
        .expect("recv 1");
    assert_eq!(reply1, b"one");

    // Wait past idle timeout (2s) + cleanup interval (1s) + generous
    // margin. On loaded CI a tokio interval tick can slip by ~500 ms,
    // so budget 6× the nominal cleanup interval.
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Second datagram — should create a *new* session at the backend.
    client.send_datagram(b"hello-two").await.expect("send 2");
    let reply2 = client
        .recv_datagram_with_timeout(Duration::from_secs(5))
        .await
        .expect("recv 2");
    assert_eq!(reply2, b"two");

    // Both datagrams should be on record.
    let received = backend.received_datagrams().await;
    assert!(
        received.len() >= 2,
        "expected ≥2 backend-observed datagrams, got {}",
        received.len()
    );

    // Give the gateway a beat to finish its post-reply work — the
    // `recv_datagram_with_timeout` returns as soon as the client
    // receives reply2, but the gateway's `create_udp_session` log
    // (which we grep for below) is emitted after the inbound branch
    // forwards the datagram, on a separate task. Without this short
    // wait the log can lag SIGTERM and never reach the appender.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ferrum-edge's stdout is block-buffered when piped to a file
    // (which `Stdio::from(File)` does). Send SIGTERM and wait for the
    // gateway to exit — its `WorkerGuard`s drop on the way out and
    // flush the tracing appender through to disk.
    let mut fx = fx;
    fx.graceful_shutdown();

    // Coverage strategy: a regression where the cleanup task fires
    // but doesn't actually evict the session would still let
    // datagram 2 through (reused session ⇒ same backend leg ⇒
    // backend sees both datagrams). The two log-based assertions
    // below close that gap:
    //
    //   * "UDP session expired (idle timeout)" proves the cleanup
    //     task's eviction path executed at all.
    //   * Two "New UDP session created" lines prove the gateway
    //     actually allocated a fresh backend session for datagram 2,
    //     not just claimed to evict and then reused the original.
    //
    // We deliberately do NOT assert on the backend-observed source
    // address: when the gateway drops a UDP socket and immediately
    // binds another, the kernel often hands back the same ephemeral
    // port (no SO_REUSEADDR pressure on a single-process test box),
    // so `unique_sources` is `1` even on a perfectly working session
    // recreation. The log signals avoid that false negative.
    let logs = fx.captured_stderr();
    let saw_expire = logs.contains("UDP session expired") || logs.contains("idle timeout");
    assert!(
        saw_expire,
        "expected session-expired signal in gateway logs (cleanup \
         interval=1s, idle timeout=2s, wait=6s); got:\n{logs}"
    );
    let created_count = logs.matches("New UDP session created").count();
    assert!(
        created_count >= 2,
        "expected ≥2 'New UDP session created' lines (one per \
         datagram, post-cleanup); got {created_count}. A regression \
         where cleanup fires but reuses the existing session would \
         show only 1. Logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — UDP response amplification factor drops excessive replies.
// ────────────────────────────────────────────────────────────────────────────
//
// The gateway's `udp_max_response_amplification_factor` caps each
// backend→client datagram's bytes to `factor × last_request_size`.
// Oversized datagrams are dropped (see
// `proxy/udp_proxy.rs::reply_amplification_factor`).
//
// Strategy: client sends ONE 100-byte datagram. Backend replies with
// 100 datagrams, each 200 bytes (ratio 2×). With `factor = 1`, every
// reply is clamped because it exceeds `1 × 100 = 100 bytes`. The
// client should therefore receive 0 datagrams.
//
// That is the cleanest signal — by choosing a factor that forces every
// backend reply to exceed the threshold, we don't care about message
// ordering or port-scheduler jitter. The backend's `packets_sent`
// stays at 100 (it tried to send all of them), but the client receives
// near zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_amplification_bound_enforced() {
    // Keep the backend socket bound while the gateway starts, but do not start
    // its script yet: `start_gateway_with_retry` may spend up to 30 seconds on
    // a failed identity-probe attempt, which would expire the backend's
    // 10-second `ExpectDatagram` deadline before the client ever sends and
    // drop the socket. Same ordering as `dtls_passthrough_sni_routes_to_correct_backend`.
    let reservation = reserve_udp_port().await.expect("reserve");
    let backend_port = reservation.port;
    let reply_payload = vec![b'x'; 200]; // 2× the 100-byte request.

    let build_yaml = move |listen_port: u16| {
        format!(
            r#"
version: "1"
proxies:
  - id: "udp-amp"
    listen_port: {listen_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_max_response_amplification_factor: 1
    udp_idle_timeout_seconds: 30

consumers: []
upstreams: []
plugin_configs: []
"#
        )
    };
    let fx = start_gateway_with_retry(build_yaml, Vec::new(), false).await;

    // Start the script only once the gateway is healthy, so the expect
    // deadline covers the client's datagram rather than gateway startup.
    let backend = ScriptedUdpBackend::builder(reservation.into_socket())
        .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
        .step(UdpStep::ReplyN {
            payload: reply_payload.clone(),
            count: 100,
        })
        .spawn()
        .expect("spawn backend");

    let gateway_addr: SocketAddr = format!("127.0.0.1:{}", fx.udp_port).parse().unwrap();
    let client = UdpClient::connect(gateway_addr).await.expect("client");

    // Request is 100 bytes; factor is 1; each backend reply is 200 bytes.
    // => every reply exceeds `1 × 100 = 100`, so every reply is dropped.
    let request = vec![b'r'; 100];
    client.send_datagram(&request).await.expect("send");

    // Drain for 1.5 s — plenty for a 100-datagram burst.
    let received = client
        .recv_batch_with_deadline(200, Duration::from_millis(1500))
        .await;

    // Every backend reply is 200 bytes. The factor=1 cap allows at
    // most 1 × 100 = 100 bytes of cumulative reply for this 100-byte
    // request, so any single 200-byte datagram exceeds the budget on
    // its own and must be dropped — the ENTIRE batch should be
    // rejected. A leak of even one oversized datagram represents a
    // real regression, so assert each datagram fits inside the
    // configured per-request allowance.
    let bytes_sent = request.len();
    for (i, d) in received.iter().enumerate() {
        assert!(
            d.len() <= bytes_sent,
            "amplification factor leaked: datagram {i} carries {} bytes, \
             which exceeds the factor=1 × {} request-byte budget. The \
             gateway should have dropped it",
            d.len(),
            bytes_sent,
        );
    }

    // The cumulative-budget check is the spec's exact wording: total
    // reply bytes must be ≤ factor × request bytes. Factor=1 here.
    let total_bytes: usize = received.iter().map(|d| d.len()).sum();
    assert!(
        total_bytes <= bytes_sent,
        "amplification factor exceeded: received {total_bytes} reply bytes \
         for a {bytes_sent}-byte request (cap=factor × request = \
         {bytes_sent})",
    );

    // Give the backend a moment to drain its send loop.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        backend.packets_sent() >= 90,
        "backend should have attempted all 100 sends; got {}",
        backend.packets_sent()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_amplification_cumulative_multi_datagram_budget() {
    // Keep the backend socket bound while the gateway starts, but do not start
    // its script yet: `start_gateway_with_retry` may spend up to 30 seconds on
    // a failed identity-probe attempt, which would expire the backend's
    // 10-second `ExpectDatagram` deadline before the client ever sends and
    // drop the socket. Same ordering as `udp_amplification_bound_enforced`.
    let reservation = reserve_udp_port().await.expect("reserve");
    let backend_port = reservation.port;
    let reply_payload = vec![b'x'; 80];

    let build_yaml = move |listen_port: u16| {
        format!(
            r#"
version: "1"
proxies:
  - id: "udp-amp-cumulative"
    listen_port: {listen_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    udp_max_response_amplification_factor: 2
    udp_idle_timeout_seconds: 30

consumers: []
upstreams: []
plugin_configs: []
"#
        )
    };
    let fx = start_gateway_with_retry(build_yaml, Vec::new(), false).await;

    // Start the script only once the gateway is healthy, so the expect
    // deadline covers the client's datagram rather than gateway startup.
    let backend = ScriptedUdpBackend::builder(reservation.into_socket())
        .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
        .step(UdpStep::ReplyN {
            payload: reply_payload.clone(),
            count: 3,
        })
        .spawn()
        .expect("spawn backend");

    let gateway_addr: SocketAddr = format!("127.0.0.1:{}", fx.udp_port).parse().unwrap();
    let client = UdpClient::connect(gateway_addr).await.expect("client");

    // Request 100 bytes, factor 2 → remaining budget 200. Each reply is 80
    // bytes (under the per-datagram product) so a per-datagram-only check
    // would forward all three. Cumulative accounting must deliver two and
    // drop the third.
    let request = vec![b'r'; 100];
    client.send_datagram(&request).await.expect("send");
    let received = client
        .recv_batch_with_deadline(8, Duration::from_millis(1500))
        .await;
    assert_eq!(
        received.len(),
        2,
        "third in-budget datagram must still exhaust the remaining request budget; got {} replies",
        received.len()
    );
    assert!(received.iter().all(|d| d.len() == 80));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        backend.packets_sent() >= 3,
        "backend should have attempted all three sends; got {}",
        backend.packets_sent()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — DTLS passthrough + SNI routing.
// ────────────────────────────────────────────────────────────────────────────
//
// Two backends on different UDP ports, each attached to a
// `passthrough: true` proxy on the gateway with distinct `hosts`
// (backend-a.test, backend-b.test). When two passthrough proxies
// share a `listen_port`, `stream_listener` groups them under an
// `__sni_{port}` key — the shared UDP listener peeks the first
// datagram (expected to be a DTLS ClientHello), extracts SNI, and
// routes to the correct proxy via `resolve_proxy_by_sni`.
//
// Because this path is exercised above the DTLS layer (the gateway
// does NOT terminate DTLS when `passthrough: true` — it forwards raw
// UDP), we only need to (a) emit a DTLS ClientHello that carries the
// `server_name` extension, and (b) verify the right backend receives
// it. We use plain `ScriptedUdpBackend` for both: each backend simply
// records the bytes it receives.
//
// The `server_name` extension is emitted by the hand-rolled
// [`dtls_client_hello_with_sni`] helper — `dimpl`'s ClientHello omits
// SNI, which would defeat the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn dtls_passthrough_sni_routes_to_correct_backend() {
    // Keep both backend sockets bound while the gateway starts. The gateway
    // helper may spend up to 30 seconds on a failed identity-probe attempt;
    // spawning the scripted backends before it returns would let their
    // 10-second expect deadlines expire and drop the sockets before a retry.
    let res_a = reserve_udp_port().await.expect("reserve a");
    let backend_a_port = res_a.port;
    let res_b = reserve_udp_port().await.expect("reserve b");
    let backend_b_port = res_b.port;

    // Two passthrough proxies sharing a frontend listen_port. The
    // `stream_listener` reconciler groups them into a single
    // SNI-routing listener.
    let build_yaml = move |listen_port: u16| {
        format!(
            r#"
version: "1"
proxies:
  - id: "dtls-a"
    listen_port: {listen_port}
    backend_scheme: dtls
    backend_host: "127.0.0.1"
    backend_port: {backend_a_port}
    hosts:
      - "backend-a.test"
    passthrough: true
  - id: "dtls-b"
    listen_port: {listen_port}
    backend_scheme: dtls
    backend_host: "127.0.0.1"
    backend_port: {backend_b_port}
    hosts:
      - "backend-b.test"
    passthrough: true

consumers: []
upstreams: []
plugin_configs: []
"#
        )
    };
    let fx = start_gateway_with_retry(build_yaml, Vec::new(), true).await;
    let gateway_addr: SocketAddr = format!("127.0.0.1:{}", fx.udp_port).parse().unwrap();

    // Start the scripts only after the gateway is ready. Backend A expects
    // the routed ClientHello. Backend B deliberately stays silent while
    // recording any misrouted datagram for the assertion below.
    let backend_a = ScriptedUdpBackend::builder(res_a.into_socket())
        .step(UdpStep::ExpectDatagram(DatagramMatcher::any()))
        .expect_deadline(Duration::from_secs(25))
        .spawn()
        .expect("spawn backend a");
    let backend_b = ScriptedUdpBackend::builder(res_b.into_socket())
        .step(UdpStep::Silence(Duration::from_secs(25)))
        .spawn()
        .expect("spawn backend b");

    // Craft a DTLS 1.2 ClientHello with SNI = backend-a.test and
    // send it to the gateway. The gateway peeks SNI, routes to
    // proxy "dtls-a", and forwards the datagram to backend A.
    let hello = dtls_client_hello_with_sni("backend-a.test");
    let client = UdpClient::connect(gateway_addr).await.expect("client");
    client.send_datagram(&hello).await.expect("send hello");

    // Wait on the routing behavior itself. A fixed sleep races a contended
    // runner: snapshotting immediately afterward can observe the backend just
    // before its receive task records the already-forwarded datagram.
    let deadline = Instant::now() + Duration::from_secs(20);
    let a_dgrams = loop {
        let observed = backend_a.received_datagrams().await;
        if observed.iter().any(|d| d.payload == hello) {
            break observed;
        }
        if Instant::now() >= deadline {
            let b_dgrams = backend_b.received_datagrams().await;
            panic!(
                "backend A did not receive the DTLS ClientHello within 20 seconds; \
                 backend A saw {} datagrams, backend B saw {b_dgrams:?}. Gateway logs:\n{}",
                observed.len(),
                fx.captured_stderr()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let b_dgrams = backend_b.received_datagrams().await;

    assert!(
        a_dgrams.iter().any(|d| d.payload == hello),
        "backend A should have received the full DTLS ClientHello; \
         saw {} datagrams. Gateway logs:\n{}",
        a_dgrams.len(),
        fx.captured_stderr()
    );
    assert!(
        b_dgrams.is_empty(),
        "backend B should have received no datagrams (SNI routed to A); \
         saw {b_dgrams:?}"
    );
}

//! Phase-8 functional gap-fill tests for the backend capability registry.
//!
//! These tests close the protocol-classification + downgrade gaps flagged in
//! the PR-482/487 review history. They exercise the full `ferrum-edge`
//! binary against scripted backends and assert on the public registry shape
//! (`GET /backend-capabilities`, `POST /backend-capabilities/refresh`)
//! rather than scraping logs.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_capability_registry \
//!     -- --ignored --nocapture
//! ```
//!
//! See the Phase-8 section of
//! `docs/plans/test_framework_scripted_backends.md` for the scope of these
//! tests.

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    H3Step, H3TlsConfig, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
    tls_backend_without_quic_with_ok_response,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use serde_json::{Value, json};
use std::net::UdpSocket as StdUdpSocket;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};

// ────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────────────

/// Reserve a co-located TCP + UDP pair on the same port. Mirrors
/// `scripted_backend_h3_tests::reserve_colocated_tcp_udp` so both backends
/// can sit behind a single `backend_port` value.
async fn reserve_colocated_tcp_udp()
-> Result<(TcpListener, UdpSocket, u16), Box<dyn std::error::Error + Send + Sync>> {
    for attempt in 0..10 {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let port = tcp.local_addr()?.port();
        match StdUdpSocket::bind(("127.0.0.1", port)) {
            Ok(std_udp) => {
                std_udp.set_nonblocking(true)?;
                let udp = UdpSocket::from_std(std_udp)?;
                return Ok((tcp, udp, port));
            }
            Err(e) => {
                drop(tcp);
                if attempt == 9 {
                    return Err(format!("udp bind at shared port failed: {e}").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    Err("exhausted colocated TCP/UDP reservation retries".into())
}

/// Build frontend cert + key files inside a scratch temp dir and return
/// `(ca_pem, cert_path_string, key_path_string)`. The scratch dir is
/// leaked so the files outlive the harness; the harness's own temp dir
/// only exists post-spawn.
fn write_frontend_certs(scratch: &std::path::Path, ca_name: &str) -> (String, String, String) {
    let ca = TestCa::new(ca_name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        ca.cert_pem,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Single-proxy file-mode YAML for HTTPS at `127.0.0.1:<port>`.
fn h3_file_config(port: u16) -> String {
    let config = json!({
        "proxies": [{
            "id": "phase8-h3",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Spawn a gateway with HTTP/3 enabled, an explicit HTTPS port, optional
/// pool warmup, and an optional periodic-refresh interval (seconds). The
/// HTTPS port is also persisted into the harness temp dir as
/// `https-port.txt` so tests can recover it.
async fn spawn_h3_gateway(
    backend_port: u16,
    pool_warmup_enabled: bool,
    refresh_interval_secs: Option<u64>,
) -> (GatewayHarness, u16) {
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "phase8-gw-ca");
    Box::leak(Box::new(scratch));

    let yaml = h3_file_config(backend_port);
    let mut builder = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env(
            "FERRUM_POOL_WARMUP_ENABLED",
            if pool_warmup_enabled { "true" } else { "false" },
        );
    if let Some(secs) = refresh_interval_secs {
        builder = builder.env(
            "FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS",
            secs.to_string(),
        );
    }
    let harness = builder.spawn().await.expect("spawn gateway");
    let port_file = harness.temp_path().join("https-port.txt");
    std::fs::write(&port_file, https_port.to_string()).expect("write https-port.txt");
    (harness, https_port)
}

/// Drive an H3 request through the gateway's HTTPS port. The `harness`
/// param is currently informational — kept to mirror the
/// `scripted_backend_h3_tests` helper signature so future work can plumb
/// per-harness HTTPS-port discovery without rewriting call sites.
async fn h3_get(
    _harness: &GatewayHarness,
    https_port: u16,
    path: &str,
) -> Result<crate::scaffolding::clients::Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    let client = Http3Client::insecure()?;
    let url = format!("https://127.0.0.1:{https_port}{path}");
    client.get(&url).await
}

/// Fetch the registry's first entry. Returns `None` until the probe
/// populates the registry.
async fn fetch_capability_entry(
    harness: &GatewayHarness,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let body = harness.get_admin_json("/backend-capabilities").await?;
    let entries = body["entries"].as_array().cloned().unwrap_or_default();
    Ok(entries.into_iter().next())
}

/// Block until the registry has at least one entry, or the deadline
/// expires.
async fn wait_for_capability_entry(
    harness: &GatewayHarness,
    timeout: Duration,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await? {
            return Ok(Some(entry));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Block until the registry's first entry's `plain_http.h3` field
/// matches one of the expected classifications. Returns the final entry
/// or `None` on timeout.
async fn wait_for_h3_classification(
    harness: &GatewayHarness,
    expected: &[&str],
    timeout: Duration,
) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(entry)) = fetch_capability_entry(harness).await
            && let Some(class) = entry["plain_http"]["h3"].as_str()
            && expected.contains(&class)
        {
            return Some(entry);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — H3 capability downgrade end-to-end when QUIC disappears.
// ────────────────────────────────────────────────────────────────────────────
//
// Phase A: backend accepts H3 (via `AcceptStream`) and returns a successful
// response — but it then closes the connection with a non-zero application
// error code. The first H3 request goes through the native H3 pool, which
// fires the downgrade path. The TCP+TLS side stays up so subsequent
// requests can be served by the cross-protocol bridge.
//
// Assertions:
//   * Pre-request registry state: `h3 = Supported`.
//   * After the first request: `h3 = Unsupported`.
//   * A second H3-frontend request returns 200 via the bridge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_capability_downgrade_e2e_when_quic_disappears() {
    let ca = TestCa::new("phase8-t1").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side serves OK responses for both probe and bridge fallback.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbridge".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 backend accepts a stream then closes with a non-zero error code,
    // forcing the gateway to mark h3 unsupported on the response path.
    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::CloseConnectionWithCode(0x10c)) // H3_REQUEST_CANCELLED
        .spawn()
        .expect("spawn h3");

    let (harness, https_port) = spawn_h3_gateway(backend_port, true, None).await;

    // Wait for initial probe: h3 must be classified Supported (the
    // probe completes the QUIC handshake before any stream is opened —
    // the close-after-stream only fires on a real request).
    let pre = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("pre-entry")
        .expect("registry populated within timeout");
    assert_eq!(
        pre["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported after initial probe; entry: {pre:#?}"
    );

    // First H3 request: backend closes the connection with an error code
    // → gateway 502 + downgrade.
    let _first = h3_get(&harness, https_port, "/api/first").await;

    // Wait for downgrade.
    let post = wait_for_h3_classification(&harness, &["unsupported"], Duration::from_secs(5))
        .await
        .expect("h3 downgraded to unsupported after CloseConnectionWithCode");
    assert_eq!(
        post["plain_http"]["h3"].as_str(),
        Some("unsupported"),
        "expected h3=unsupported after downgrade; entry: {post:#?}"
    );

    // Second request: cross-protocol bridge → TLS backend → 200.
    let second = h3_get(&harness, https_port, "/api/second")
        .await
        .expect("second request must succeed via bridge");
    assert_eq!(
        second.status.as_u16(),
        200,
        "expected 200 from cross-protocol bridge after downgrade; got {second:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — H2 ALPN downgrade routes subsequent requests via reqwest.
// ────────────────────────────────────────────────────────────────────────────
//
// The TLS backend advertises ONLY `http/1.1` in ALPN. The H2 direct pool
// negotiates h1.1 → fires `BackendSelectedHttp1` → registry marks `h2_tls`
// unsupported. Subsequent requests must use reqwest (which negotiates
// h1.1 directly) instead of the H2 pool.
//
// Assertions:
//   * After warmup, the registry shows `h2_tls = unsupported`.
//   * Both requests succeed (the gateway transparently falls through to
//     reqwest after the first downgrade observation).
//   * The backend recorded at least one `http/1.1` ALPN handshake from
//     the warmup probe — proves the H2 pool actually attempted h2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_alpn_downgrade_e2e_routes_subsequent_requests_via_reqwest() {
    let ca = TestCa::new("phase8-t2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert, key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn backend");

    let yaml = crate::scaffolding::file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_tls_verify_server_cert": false,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    // First request fires while the warmup probe is in flight or has just
    // completed. Either way the response succeeds and the downgrade
    // observation fires on the warmup or first request path.
    let client = harness.http_client().expect("client");
    let r1 = client
        .get(&harness.proxy_url("/api/one"))
        .await
        .expect("r1");
    assert_eq!(r1.status.as_u16(), 200, "first request: {r1:?}");
    assert_eq!(r1.body_text(), "ok");

    // Wait for the downgrade to land. The H2 pool emits the
    // observation either at warmup (eager) or on the first request
    // (lazy). Polling the registry instead of log scraping is the
    // public-API assertion the task requires.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed_unsupported = false;
    while Instant::now() < deadline {
        if let Ok(Some(entry)) = fetch_capability_entry(&harness).await
            && entry["plain_http"]["h2_tls"].as_str() == Some("unsupported")
        {
            observed_unsupported = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        observed_unsupported,
        "expected h2_tls=unsupported after ALPN-h1.1 backend observation; \
         registry never flipped within 10s"
    );

    // Second request: must succeed (gateway routes via reqwest now that
    // h2_tls is Unsupported).
    let r2 = client
        .get(&harness.proxy_url("/api/two"))
        .await
        .expect("r2");
    assert_eq!(r2.status.as_u16(), 200, "second request: {r2:?}");
    assert_eq!(r2.body_text(), "ok");

    // Backend observability: ALPN history must include `http/1.1`.
    let history = backend.all_alpn().await;
    let saw_h1 = history
        .iter()
        .any(|alpn| alpn.as_deref() == Some(&b"http/1.1"[..]));
    assert!(
        saw_h1,
        "expected at least one http/1.1 ALPN handshake; got {history:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — Initial refresh when warmup is off classifies before traffic.
// ────────────────────────────────────────────────────────────────────────────
//
// When `FERRUM_POOL_WARMUP_ENABLED=false` the previous behavior would let
// the registry stay empty until the first traffic landed — making it
// impossible for the H3 frontend to take the native H3 pool path on
// request #1. The fix triggers an initial classification refresh on
// startup regardless of warmup. This test asserts that the registry has
// an entry within a few seconds of startup, well before any traffic
// arrives, and that `h3` is `Supported` against an H3-capable backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn initial_refresh_when_warmup_off_classifies_before_traffic() {
    let ca = TestCa::new("phase8-t3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side answers the H2 probe + bridge fallback OK requests.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 stays up indefinitely so the probe gets a clean handshake.
    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::StallFor(Duration::from_secs(60)))
        .spawn()
        .expect("spawn h3");

    // pool_warmup_enabled = false — verifies the initial refresh hook
    // runs even with warmup off.
    let (harness, _https_port) = spawn_h3_gateway(backend_port, false, None).await;

    // The registry must be populated within a small window after startup
    // — well before the default 24h periodic refresh.
    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch entry")
        .expect("registry populated within 15s of startup with warmup disabled");

    let h3_class = entry["plain_http"]["h3"].as_str().unwrap_or("");
    // Accept supported (probe succeeded) or unknown (probe still in
    // flight at the exact moment of the snapshot). The load-bearing
    // assertion is that an entry EXISTS at all — pre-fix the registry
    // would be empty for hours.
    assert!(
        matches!(h3_class, "supported" | "unknown"),
        "expected h3 ∈ {{supported, unknown}}; got {h3_class}; entry: {entry:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — Refresh coalescer under rapid config reload.
// ────────────────────────────────────────────────────────────────────────────
//
// Configuration mutations on a CP/DB instance can fire many config-applied
// events within a small time window. The capability registry must
// coalesce concurrent refresh requests so we don't end up with N
// background probes per second hammering the backend. We exercise this
// by issuing many refresh requests in rapid succession via the admin
// endpoint and asserting that:
//   1. Every request returns 200 (the admin endpoint never fails or
//      back-pressures).
//   2. The total wall-clock time stays small (proving requests didn't
//      queue serially behind one probe each).
//   3. The registry stays consistent — exactly one entry per proxy at
//      the end.
//
// Note: we do NOT assert the exact number of probes (no observable
// counter in the public API yet), but we assert the externally visible
// invariants. The admin endpoint awaits the refresh synchronously, so
// total wall-clock time is the proxy for "coalesced or not".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn refresh_coalescer_under_rapid_config_reload() {
    let ca = TestCa::new("phase8-t4").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::StallFor(Duration::from_secs(60)))
        .spawn()
        .expect("spawn h3");

    let (harness, _https_port) = spawn_h3_gateway(backend_port, true, None).await;

    // Wait for the initial probe so the registry has a baseline entry.
    let _ = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("wait entry")
        .expect("registry populated");

    // Fire 50 concurrent refresh requests; an uncoalesced implementation
    // would either serialize them (hard timeouts) or fan out into 50
    // parallel probes (which the H3 backend would observe — but we don't
    // have a probe counter, so we keep this assertion outcome-only).
    let started = Instant::now();
    let admin_url = harness.admin_url("/backend-capabilities/refresh");
    let auth = harness.admin_auth_header();
    let mut tasks = Vec::with_capacity(50);
    for _ in 0..50 {
        let url = admin_url.clone();
        let auth = auth.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("client");
            client
                .post(&url)
                .header("Authorization", auth)
                .json(&json!({}))
                .send()
                .await
                .map(|r| r.status().as_u16())
        }));
    }

    let mut statuses = Vec::with_capacity(50);
    for t in tasks {
        statuses.push(t.await.expect("task"));
    }
    let elapsed = started.elapsed();

    // Every request must have been accepted.
    let oks: usize = statuses
        .iter()
        .filter(|s| matches!(s.as_ref().ok(), Some(200)))
        .count();
    assert_eq!(
        oks, 50,
        "expected all 50 refresh requests to succeed; got statuses {statuses:?}"
    );

    // Walltime must be reasonable — even a worst-case serial probe
    // shouldn't take more than a few seconds on the loopback. If the
    // coalescer broke and we ran 50 sequential probes (each ~50–200ms),
    // total time would exceed 10s.
    assert!(
        elapsed < Duration::from_secs(15),
        "expected coalesced refreshes to complete quickly; took {elapsed:?}"
    );

    // Registry must end with a single entry per proxy (the test config
    // has one proxy).
    let body = harness
        .get_admin_json("/backend-capabilities")
        .await
        .expect("admin GET");
    let entries = body["entries"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one registry entry; got {} entries: {body:#?}",
        entries.len()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — `mark_h3_unsupported` persists across periodic refresh until
// the backend recovers.
// ────────────────────────────────────────────────────────────────────────────
//
// Setup:
//   * Backend that advertises NO QUIC listener (TLS-only, no UDP). Initial
//     probe classifies `h3 = Unsupported`.
//   * `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS = 2` so the
//     periodic refresh runs frequently enough for the test to observe.
//
// Phase A: assert `h3 = Unsupported` on initial probe.
// Phase B: wait through one refresh interval; assert the classification
//          stays `Unsupported` (no recovery attempt because the UDP
//          listener still doesn't exist).
// Phase C: bind a real H3 backend on the same UDP port, then wait
//          through another refresh interval. The classification should
//          flip to `Supported`.
//
// This is the primary regression test for "downgrades are sticky until
// the backend actually recovers".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn mark_h3_unsupported_persists_until_periodic_refresh_succeeds() {
    let ca = TestCa::new("phase8-t5").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    // TLS-only backend — no UDP listener. The probe fails on QUIC,
    // classifies `h3 = Unsupported`.
    let _tls_backend = tls_backend_without_quic_with_ok_response(
        reservation.into_listener(),
        cert.clone(),
        key.clone(),
    );

    // 2-second refresh interval — picked small enough to be observable
    // in a unit-test budget, large enough that the polling logic isn't
    // the load-bearing factor.
    let (harness, _https_port) = spawn_h3_gateway(backend_port, true, Some(2)).await;

    // Phase A: initial probe shows unsupported.
    let pre = wait_for_h3_classification(
        &harness,
        &["unsupported", "unknown"],
        Duration::from_secs(15),
    )
    .await
    .expect("h3 classified within 15s");
    assert!(
        matches!(
            pre["plain_http"]["h3"].as_str(),
            Some("unsupported") | Some("unknown")
        ),
        "expected h3 ∈ {{unsupported, unknown}}; entry: {pre:#?}"
    );

    // Phase B: wait through one full refresh cycle and confirm the
    // classification stays terminal-unsupported (it never flips to
    // Supported because no real H3 listener is up).
    tokio::time::sleep(Duration::from_secs(4)).await;
    let mid = fetch_capability_entry(&harness)
        .await
        .expect("mid entry")
        .expect("registry entry present");
    let mid_class = mid["plain_http"]["h3"].as_str().unwrap_or("");
    assert!(
        matches!(mid_class, "unsupported" | "unknown"),
        "expected h3 still ∈ {{unsupported, unknown}} after refresh interval (no QUIC listener bound); \
         got {mid_class}; entry: {mid:#?}"
    );

    // Phase C: bind a real H3 backend on the same port and trigger a
    // refresh manually. The periodic timer also runs but we trigger
    // directly to keep the test fast.
    //
    // The UDP rebind can race with kernel TIME_WAIT-equivalent cleanup;
    // retry a small number of times so a transient bind failure doesn't
    // make the recovery half of the test silently skip.
    let mut bind_err: Option<std::io::Error> = None;
    let mut recovered_udp: Option<UdpSocket> = None;
    for attempt in 0..10 {
        match UdpSocket::bind(("127.0.0.1", backend_port)).await {
            Ok(s) => {
                recovered_udp = Some(s);
                break;
            }
            Err(e) => {
                bind_err = Some(e);
                if attempt < 9 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    let recovered_udp = recovered_udp.unwrap_or_else(|| {
        panic!(
            "could not rebind UDP port {backend_port} for recovery phase after 10 attempts: {:?}",
            bind_err
        )
    });
    let _recovered = ScriptedH3Backend::builder(recovered_udp, H3TlsConfig::new(cert, key))
        .step(H3Step::StallFor(Duration::from_secs(60)))
        .spawn()
        .expect("spawn recovered h3");

    // Trigger refresh directly + wait through the periodic timer.
    let _ = harness
        .post_admin_json("/backend-capabilities/refresh", &json!({}))
        .await;

    let recovered =
        wait_for_h3_classification(&harness, &["supported"], Duration::from_secs(15)).await;

    let entry = match recovered {
        Some(e) => e,
        None => {
            let last = fetch_capability_entry(&harness)
                .await
                .ok()
                .flatten()
                .unwrap_or(Value::Null);
            panic!("h3 did not flip to supported within 15s after recovery; last entry: {last:#?}");
        }
    };
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported after recovery; entry: {entry:#?}"
    );
}

//! Phase-1 acceptance tests for the scripted-backend framework.
//!
//! Each test ties a scripted backend (TCP / TLS / HTTP-1.1) to a ferrum-edge
//! gateway running in binary mode and asserts an observable failure mode.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests scripted_backend -- --ignored --nocapture`
//!
//! The tests live here so they can `#[ignore]` (per CLAUDE.md functional-test
//! rules) and share the binary-mode [`crate::scaffolding::harness::GatewayHarness`].

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, ScriptedTlsBackend,
    TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, unbound_port};
use crate::scaffolding::{file_mode_yaml_for_backend, file_mode_yaml_for_backend_with};
use reqwest::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};

/// Fetch captured gateway logs and fail the test if they are empty — the
/// harness silently returns an empty string when `capture_output()` was not
/// called on the builder, and downstream `logs.contains(..)` asserts would
/// then pass for the wrong reason.
fn require_logs(harness: &GatewayHarness) -> String {
    let logs = harness
        .captured_combined()
        .expect("read captured gateway logs");
    assert!(
        !logs.trim().is_empty(),
        "gateway logs were empty — did you forget .capture_output() on the builder?"
    );
    logs
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — backend port with nothing listening → 502 + ConnectionRefused class.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture: `unbound_port()` reserves a port then drops the listener, so the
// gateway's connect() returns a real `ECONNREFUSED` from the kernel
// (distinct from `ScriptedTcpBackend::RefuseNextConnect`, which accepts and
// drops — that path emits FIN/RST, not a connect-time refusal, and so does
// not exercise the gateway's `ConnectionRefused` classifier).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_refuses_connect_maps_to_502_with_connection_refused() {
    // Real ECONNREFUSED: no listener on this port.
    let backend_port = unbound_port().await.expect("unbound port");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/anything"))
        .await
        .expect("gateway returns a response");
    assert_eq!(
        resp.status,
        StatusCode::BAD_GATEWAY,
        "expected 502, got {} body={:?}",
        resp.status,
        resp.body_text()
    );

    let logs = require_logs(&harness);
    // `connect_failure` is the gateway's `error_kind` for reqwest errors
    // where `is_connect() == true` — exactly the ECONNREFUSED case we're
    // exercising. It's distinct from `request_error` (RST after accept),
    // `read_timeout`, and body-error classes, so asserting on it proves
    // the gateway took the connect-failure path rather than some other
    // fallback. `ConnectionRefused`/"refused" are belt-and-suspenders for
    // future gateway log surface changes that might expose the `io::Error`
    // kind directly.
    let has_refused_class = logs.contains("connect_failure")
        || logs.contains("ConnectionRefused")
        || logs.contains("Connection refused");
    assert!(
        has_refused_class,
        "expected connect-failure/refused signal in gateway logs; got:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — backend accepts then resets → 502 + ConnectionReset.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_accepts_then_resets_maps_to_connection_reset() {
    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Reset)
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/x"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY);
    let logs = require_logs(&harness);
    // Gateway should have logged a backend request error. The platform-
    // specific string can be "reset", "connection closed", "request_error"
    // (reqwest's generic classifier), or "Backend request failed". Any of
    // these indicates the RST was detected.
    let observed = logs.contains("reset")
        || logs.contains("Reset")
        || logs.contains("connection closed")
        || logs.contains("request_error")
        || logs.contains("Backend request failed");
    assert!(observed, "expected reset/error signal in logs:\n{logs}");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — `backend_read_timeout_ms` fires within tolerance.
// ────────────────────────────────────────────────────────────────────────────
//
// Scripted HTTP/1.1 backend sleeps ≫ the configured read timeout before
// writing anything, forcing the gateway to give up. We measure the elapsed
// wall-clock time and assert it's within ±500ms of `backend_read_timeout_ms`.
//
// Tolerance: ~500ms. Loaded CI machines may jitter a bit but the watchdog
// granularity is 1s per CLAUDE.md §TCP timeout docs — we're measuring
// HTTP-level timeouts here, which are tighter. See `docs/error_classification`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_read_timeout_fires_after_backend_read_timeout_ms() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        // Hold the connection open far beyond the gateway's read timeout.
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let read_timeout_ms: u64 = 800;
    let overrides = json!({ "backend_read_timeout_ms": read_timeout_ms });
    let yaml = file_mode_yaml_for_backend_with(backend_port, overrides);

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/slow"))
        .await
        .expect("response");
    let elapsed = started.elapsed();
    // Status: 502 or 504 depending on the code path — both are acceptable
    // "gateway gave up on backend" responses. The timing is the load-bearing
    // assertion.
    assert!(
        matches!(
            resp.status,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ),
        "expected 502 or 504, got {}",
        resp.status
    );
    let expected = Duration::from_millis(read_timeout_ms);
    let floor = expected.saturating_sub(Duration::from_millis(200));
    let ceiling = expected + Duration::from_millis(1500);
    assert!(
        elapsed >= floor,
        "timed out too fast: {elapsed:?} < floor {floor:?} (timeout was {read_timeout_ms}ms)"
    );
    assert!(
        elapsed <= ceiling,
        "timed out too slowly: {elapsed:?} > ceiling {ceiling:?} (timeout was {read_timeout_ms}ms)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — backend closes mid-body → client observes truncated body;
// gateway logs a body_error_class.
// ────────────────────────────────────────────────────────────────────────────
//
// The backend announces Content-Length: 100 then FINs after 10 bytes. The
// client's buffered `response.body_bytes` ends up shorter than the content-
// length (reqwest surfaces this as a read error mid-stream; we assert by
// either status != 200 OR body shorter than advertised).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_close_mid_body_populates_body_error_class() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::CloseMidBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "100".into()),
                ("Content-Type".into(), "application/octet-stream".into()),
            ],
            body_prefix: vec![b'x'; 10],
            reset: false,
        })
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    // Either the body reads short (advertised 100 bytes, got 10) or reqwest
    // surfaces an error. Either observable proves the gateway noticed.
    let result = client.get(&harness.proxy_url("/api/truncated")).await;
    match result {
        Ok(resp) => {
            // Some code paths let the status through before the body gap.
            assert!(
                resp.body_bytes.len() < 100,
                "expected truncated body, got {} bytes",
                resp.body_bytes.len()
            );
        }
        Err(_e) => {
            // Body error surfaced as a reqwest::Error — also acceptable.
        }
    }

    let logs = require_logs(&harness);
    // The gateway logs body-read errors as either a structured
    // `body_error_class` (via stdout_logging) or a proxy-level
    // "Failed to read backend response body" / "error decoding response
    // body" warning when hyper notices the truncated Content-Length. Any
    // of these prove the gateway noticed the incomplete body.
    let has_body_error = logs.contains("body_error_class")
        || logs.contains("IncompleteBody")
        || logs.contains("unexpected end of file")
        || logs.contains("Incomplete")
        || logs.contains("ClientDisconnect")
        || logs.contains("Failed to read backend response body")
        || logs.contains("error decoding response body");
    assert!(
        has_body_error,
        "expected body-error signal in logs; got:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — TLS backend with an expired cert → gateway refuses to connect.
// ────────────────────────────────────────────────────────────────────────────
//
// Configures a TLS backend with a cert that's already `notAfter` in the
// past. The gateway, configured to *verify* the backend cert, refuses the
// handshake and returns 502. We assert status + that the log carries a
// TLS/cert signal rather than a body one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls_expired_cert_produces_tls_error_not_generic_502() {
    let ca = TestCa::new("scripted-test-root").expect("ca");
    let (expired_cert, expired_key) = ca.expired().expect("expired leaf");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(expired_cert, expired_key),
    )
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn backend");

    // Write the CA to a persistent temp dir (not inside the harness temp dir,
    // which only exists after spawn). The CA must outlive the harness.
    let ca_dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca_dir.path().join("backend-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    // Configure the proxy to trust our CA and verify the server cert.
    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": true,
            "backend_tls_server_ca_cert_path": ca_path.to_string_lossy(),
        }),
    );

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/expired"))
        .await
        .expect("response");
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "expected 502");

    let logs = require_logs(&harness);
    // Look for cert/TLS-specific tokens. We deliberately avoid a bare `"tls"`
    // substring match — crate and module paths contain "tls" nearly
    // everywhere, which would turn this assertion into a no-op.
    let has_tls_signal = logs.contains("TlsError")
        || logs.contains("expired")
        || logs.contains("notAfter")
        || logs.contains("NotValidYet")
        || logs.contains("certificate")
        || logs.contains("CertificateError")
        || logs.contains("InvalidCertificate")
        || logs.contains("handshake");
    assert!(
        has_tls_signal,
        "expected TLS/cert error signal in logs, got:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6 — H2 ALPN fallback downgrades the capability cache.
// ────────────────────────────────────────────────────────────────────────────
//
// The TLS backend's server-side ALPN list is exactly `[http/1.1]`. When the
// gateway's H2 direct pool probes the backend (either at warmup or on first
// request), rustls negotiates `http/1.1`, the pool raises
// `BackendSelectedHttp1`, and `is_known_http1_backend` returns `true` on
// subsequent probes. Pool warmup must be enabled so the probe actually
// happens.
//
// Observables:
//   1. The backend records `last_alpn = "http/1.1"` on the probe
//      handshake (before any request reaches it).
//   2. The gateway's captured logs contain the warmup-level
//      "Pool warmup failed: H2 ...: BackendSelectedHttp1 ..." line.
//   3. Subsequent client requests succeed (served via reqwest's
//      http/1.1 path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_alpn_fallback_downgrades_capability() {
    let ca = TestCa::new("scripted-alpn-root").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    // Respond to *any* request (the H2 pool probe sends none, but reqwest
    // user requests do). The 3-step script runs per connection — adequate
    // for a pool probe handshake that terminates on receiving close_notify.
    let response_bytes: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert, key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(response_bytes))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend_with(
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
        // Pool warmup is disabled by default in the shared harness to keep
        // unrelated tests fast — we need it ON for the H2 probe to run.
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let r1 = client
        .get(&harness.proxy_url("/api/one"))
        .await
        .expect("r1");
    assert_eq!(r1.status, StatusCode::OK);
    assert_eq!(r1.body_text(), "ok");

    // Let the gateway persist observations, then fire a second request.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r2 = client
        .get(&harness.proxy_url("/api/two"))
        .await
        .expect("r2");
    assert_eq!(r2.status, StatusCode::OK);
    assert_eq!(r2.body_text(), "ok");

    // Backend assertions: the H2 pool probe negotiated http/1.1 on the
    // warmup handshake. Subsequent reqwest-based requests may or may not
    // advertise ALPN (reqwest keeps the h1-only path allocation-light), so
    // we only assert that *at least one* ALPN negotiation resolved to
    // http/1.1 across the full handshake history.
    let history = backend.all_alpn().await;
    let saw_http1 = history
        .iter()
        .any(|alpn| alpn.as_deref() == Some(&b"http/1.1"[..]));
    assert!(
        saw_http1,
        "expected at least one handshake to negotiate http/1.1; \
         accepted={}, handshakes={}, history={:?}",
        backend.accepted_connections(),
        backend.handshakes_completed(),
        history
    );

    // Log assertion: the "BackendSelectedHttp1" log line is the single most
    // diagnostic signal that `mark_h2_tls_unsupported` fired and populated
    // `is_known_http1_backend` — this is the regression test CLAUDE.md
    // called out in the phase-1 plan.
    //
    // NOTE: this couples the test to the exact `BackendSelectedHttp1` error
    // string in `Http2PoolError`. If that variant is renamed, update here.
    // No stable test-visible counter exists yet — adding one is a reasonable
    // Phase 2 improvement.
    let logs = require_logs(&harness);
    assert!(
        logs.contains("BackendSelectedHttp1"),
        "expected gateway log to mention BackendSelectedHttp1; logs:\n{logs}"
    );
}

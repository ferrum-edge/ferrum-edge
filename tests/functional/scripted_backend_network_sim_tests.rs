//! Phase-5 acceptance tests — network-simulation wrappers.
//!
//! These tests insert a [`crate::scaffolding::network::NetworkSimProxy`]
//! middleman between the gateway and a scripted backend so each accepted
//! connection goes through a `DelayedStream` / `BandwidthLimitedStream`
//! / `TruncatedStream` pipeline. The gateway sees a "slow network" to
//! the backend; the tests assert the gateway's timing + metrics behave
//! correctly against it.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_network_sim -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::network::NetworkSimProxy;
use crate::scaffolding::ports::reserve_port;
use reqwest::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};

/// YAML config for the TTFB test: one HTTP proxy pointed at `backend_port`
/// plus a single `stdout_logging` plugin so the gateway emits its
/// `TransactionSummary` (which carries `latency_backend_ttfb_ms`) on
/// the `access_log` tracing target. Without this plugin the TTFB
/// assertion has nothing structured to inspect.
///
/// `global` scope is used so the log hook fires regardless of the
/// runtime proxy-id match — the simpler setup reduces the chance of
/// a silent mis-wiring masking a real TTFB regression.
fn ttfb_test_config(backend_port: u16) -> String {
    let config = json!({
        "proxies": [{
            "id": "scripted",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 10000,
            "backend_write_timeout_ms": 10000,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "ttfb-logger",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {},
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

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
// Test 1 — slow backend (within the gateway's read timeout) completes OK.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - `ScriptedHttp1Backend` sending a normal 200 OK response.
//   - `NetworkSimProxy` in front with 400 ms read+write latency.
//   - Gateway configured with `backend_read_timeout_ms = 2000` — well
//     above the injected delay.
//
// Expected: request returns 200, total elapsed ≥ 400 ms (proving the
// latency was actually injected and not no-op'd away).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn slow_backend_within_read_timeout_completes() {
    // Inner scripted HTTP backend.
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    // Middleman proxy with latency.
    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_latency(Duration::from_millis(400))
        .spawn()
        .expect("spawn middleman");

    // Gateway pointed at the middleman, with a read timeout comfortably
    // above the injected latency.
    let yaml =
        file_mode_yaml_for_backend_with(middleman_port, json!({ "backend_read_timeout_ms": 2000 }));
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

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body_text(), "ok");
    // Latency fires on every read+write; one full request requires at
    // least 2 round-trips (write + read), so ≥ 400 ms is a floor even
    // on a fast host.
    assert!(
        elapsed >= Duration::from_millis(400),
        "expected latency to propagate (≥400 ms), got {elapsed:?}"
    );
    // And well under the 2 s read timeout.
    assert!(
        elapsed < Duration::from_millis(1800),
        "took too long ({elapsed:?}) — gateway may have read-timeout'd"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — throttled backend + tight backend_read_timeout fires 502.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - `ScriptedHttp1Backend` that responds **immediately** with a large
//     body. No backend `Sleep` — if the bandwidth limiter is a no-op,
//     the full body transfers in a few ms and the gateway returns 200
//     under the tight 400 ms budget. That makes the bandwidth wrapper
//     the sole forcing function for this test.
//   - `NetworkSimProxy` with a 1 KiB/s bandwidth cap. With a 16 KiB
//     body, after the 1-second burst there is still ~15 KiB left to
//     drain at 1024 B/s ≈ 15 s — well past the gateway's 400 ms budget.
//   - Gateway with `backend_read_timeout_ms = 400`.
//
// Expected: 502 or 504, elapsed near the gateway's timeout, gateway
// logs carry a read-timeout / connection-abort signal (not a body-
// mid-stream one, to distinguish from other Phase-1 tests).
//
// Note: the plan calls this a "write timeout" because the gateway
// writes the client's body to the backend and the backend consumes
// slowly. That behaviour is only observable via
// `backend_write_timeout_ms` on *raw TCP* proxies (see
// `src/proxy/tcp_proxy.rs`); for HTTP/1 via reqwest the gateway's
// per-request budget is `backend_read_timeout_ms`. This test
// exercises the HTTP path — the only surface that matters for
// scripted HTTP backends. The TCP write-timeout path has its own
// Phase-1 coverage via `backend_read_timeout_fires_after_backend_read_timeout_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_bandwidth_below_budget_triggers_write_timeout() {
    // 16 KiB response body. At 1024 B/s with a 1-second burst, the
    // first ~1 KiB arrives instantly and the remaining 15 KiB takes
    // ~15 seconds to drain — which is what makes the bandwidth
    // wrapper the causal agent for the 400 ms gateway timeout.
    const BODY_SIZE: usize = 16 * 1024;
    let body = vec![b'x'; BODY_SIZE];

    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        // Respond promptly with a large body. If the bandwidth limiter
        // is a no-op, the whole thing transfers in a few ms and this
        // test fails — which is the regression the earlier
        // `HttpStep::Sleep(30s)` version could not catch.
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: BODY_SIZE.to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(body))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    // Middleman with tight bandwidth + a little latency. Bandwidth
    // alone is enough to exceed the 400 ms budget for a 16 KiB body;
    // the latency is retained to reinforce the slow-network shape.
    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_bandwidth_limit(1024) // 1 KB/s
        .with_latency(Duration::from_millis(50))
        .spawn()
        .expect("spawn middleman");

    let yaml =
        file_mode_yaml_for_backend_with(middleman_port, json!({ "backend_read_timeout_ms": 400 }));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
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

    assert!(
        matches!(
            resp.status,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ),
        "expected 502/504, got {}",
        resp.status
    );
    // Should time out within ~1.5× the configured budget plus latency.
    assert!(
        elapsed <= Duration::from_millis(2500),
        "took too long ({elapsed:?}); gateway should have given up at ~400ms"
    );
    // Verify the gateway's error classification matches a timeout path
    // rather than, say, a connect-refused or body-error path. Any of
    // these tokens indicates the gateway gave up on the backend.
    let logs = require_logs(&harness);
    let saw_timeout_signal = logs.contains("read_timeout")
        || logs.contains("Timeout")
        || logs.contains("timeout")
        || logs.contains("GatewayTimeout")
        || logs.contains("502")
        || logs.contains("Backend request failed");
    assert!(
        saw_timeout_signal,
        "expected timeout/502 signal in gateway logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — high latency preserves TTFB metric.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - Backend that responds immediately.
//   - Middleman with 300 ms latency on reads and writes.
//   - Gateway with generous `backend_read_timeout_ms`, and a
//     `stdout_logging` plugin wired onto the proxy so
//     `TransactionSummary` JSON hits the `access_log` tracing target.
//
// Expected:
//   - Total elapsed ≥ 300 ms (round trips see the latency).
//   - The gateway's logged `latency_backend_ttfb_ms` for this request
//     is ≥ 250 ms — i.e., the gateway's TTFB measurement tracks the
//     real backend response time and isn't collapsed to zero by a
//     plugin shortcut or cache.
//
// The plan's exact text calls for "TTFB ≥ 200ms AND total ≥ 200ms, and
// both visible in admin `/metrics` or log output". Ferrum's admin
// metrics don't split TTFB vs. total latency publicly, so we rely on
// the `stdout_logging` plugin's structured output — a first-class
// `TransactionSummary` field — for the log-side assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn high_latency_preserves_first_byte_latency_metrics() {
    // Send multiple requests so we have plenty of access_log output.
    // Each incoming connection replays the script, so we give the
    // backend enough steps to serve every request.
    const REQUEST_COUNT: usize = 5;

    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let mut backend_builder = ScriptedHttp1Backend::builder(backend_res.into_listener());
    for _ in 0..REQUEST_COUNT {
        backend_builder = backend_builder
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "5".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Connection".into(),
                value: "close".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"hello".to_vec()))
            .step(HttpStep::RespondBodyEnd);
    }
    let _backend = backend_builder.spawn().expect("spawn http backend");

    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_latency(Duration::from_millis(300))
        .spawn()
        .expect("spawn middleman");

    // Bespoke config with `stdout_logging` attached so we actually
    // observe the TTFB signal rather than skipping the assertion when
    // no logger is wired.
    let yaml = ttfb_test_config(middleman_port);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        // `main.rs` builds its `EnvFilter` via `try_from_default_env()`,
        // so an inherited `RUST_LOG=warn` in the test runner's env
        // would silence the `access_log` target and defeat the
        // structured latency assertion below. Pin `RUST_LOG`
        // explicitly.
        .env("RUST_LOG", "info,access_log=info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");

    // Round-trip floor: a successful request below the injected
    // latency would indicate a spurious cache hit or the middleman
    // no-op'ing.
    let first_start = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/ttfb"))
        .await
        .expect("response");
    let first_elapsed = first_start.elapsed();
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body_text(), "hello");
    assert!(
        first_elapsed >= Duration::from_millis(300),
        "expected ≥300 ms round trip on the first request, got {first_elapsed:?}"
    );

    // Send the remaining requests to flood the gateway's stdout
    // buffer so the access_log entries are flushed by the time we
    // read. The Rust stdout used by `tracing_appender::non_blocking`
    // is line-buffered when connected to a terminal but block-
    // buffered when piped to a file; without enough volume a single
    // access_log entry can sit in the buffer past the test deadline.
    for _ in 1..REQUEST_COUNT {
        let resp = client
            .get(&harness.proxy_url("/api/ttfb"))
            .await
            .expect("followup response");
        assert_eq!(resp.status, StatusCode::OK);
    }

    // Let the non-blocking tracing appender drain. Matches the
    // pattern used in `tests/functional/functional_logging_test.rs`.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Mandatory TTFB assertion on the structured access log.
    // `stdout_logging` emits `TransactionSummary` as JSON on the
    // `access_log` target; `latency_backend_ttfb_ms` is the purpose-
    // built field for this signal (vs. `latency_total_ms`, which also
    // includes plugin post-processing).
    let logs = harness.captured_combined().expect("capture");
    let ttfb_ms = extract_f64_field(&logs, "latency_backend_ttfb_ms").unwrap_or_else(|| {
        panic!(
            "expected a `latency_backend_ttfb_ms` entry from stdout_logging; \
             did RUST_LOG suppress the access_log target or the plugin fail \
             to wire? Logs:\n{logs}"
        )
    });
    assert!(
        ttfb_ms >= 250.0,
        "gateway logged latency_backend_ttfb_ms={ttfb_ms} but injected \
         latency was 300ms — TTFB measurement may be broken. Logs:\n{logs}"
    );
}

/// Extract the numeric value of the first `"<field>": <number>` entry in
/// `logs`. Returns `None` when the field is missing or the value isn't
/// parseable as `f64`.
///
/// Handles both raw JSON (e.g., `"latency_backend_ttfb_ms":1.0`) and
/// the double-escaped form that appears inside
/// `tracing-subscriber`'s JSON writer when the `stdout_logging` plugin
/// serializes `TransactionSummary` as a string inside the outer
/// `fields.message` field (e.g., `\"latency_backend_ttfb_ms\":1.0`).
fn extract_f64_field(logs: &str, field: &str) -> Option<f64> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = logs.find(&needle) {
            let tail = logs[pos + needle.len()..].trim_start();
            let end = tail
                .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e'))
                .unwrap_or(tail.len());
            if let Ok(v) = tail[..end].parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

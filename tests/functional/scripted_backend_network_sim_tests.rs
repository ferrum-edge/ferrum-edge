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
/// `TransactionSummary` (which carries `latency_backend_ttfb_ms`) as a
/// JSON line on stdout. Without this plugin the TTFB assertion has
/// nothing structured to inspect.
///
/// `global` scope is used so the log hook fires regardless of the
/// runtime proxy-id match — the simpler setup reduces the chance of
/// a silent mis-wiring masking a real TTFB regression.
fn ttfb_test_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
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
// Migrated to `HarnessMode::InProcess` — asserts only on status + body +
// timing, so it benefits from the ~10× faster in-process startup.
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
        .mode_in_process()
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
// Expected: one of the two valid "bandwidth wrapper did its job"
// outcomes, because ferrum-edge can legitimately reach either:
//   - the gateway fully times out before forwarding any body to the
//     client → `502 Bad Gateway` (or `504 Gateway Timeout`);
//   - the gateway streams the headers it already got from the
//     first-burst window, then times out mid-body → client sees
//     `200 OK` with a body shorter than the advertised
//     `Content-Length` (i.e., truncated). Which path fires depends on
//     whether the gateway eagerly buffered the response or streamed
//     it; both prove the bandwidth wrapper forced a timeout. We also
//     check elapsed ≥ a floor below the timeout, so a no-op limiter
//     (instant 200 + full body) still fails the test.
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

    // Floor below the 400 ms budget — a no-op bandwidth limiter would
    // finish in a few ms, so `elapsed >= 200 ms` catches that
    // regression without being flaky on a loaded host.
    assert!(
        elapsed >= Duration::from_millis(200),
        "bandwidth wrapper should have slowed the transfer past 200 ms; \
         got {elapsed:?} — is the limiter a no-op?"
    );
    // Upper bound: gateway must give up promptly, not hang the whole
    // test. ~1.5× the configured budget plus a generous margin.
    assert!(
        elapsed <= Duration::from_millis(3000),
        "took too long ({elapsed:?}); gateway should have given up at ~400ms"
    );

    let is_upstream_timeout = matches!(
        resp.status,
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
    );
    let is_truncated_body = resp.status == StatusCode::OK && resp.body_bytes.len() < BODY_SIZE;
    assert!(
        is_upstream_timeout || is_truncated_body,
        "expected either 502/504 (eager-buffered path timed out) or \
         200 with truncated body (streamed path timed out mid-body); \
         got status={} body_bytes={} after {:?}. Full body would indicate \
         a no-op bandwidth limiter.",
        resp.status,
        resp.body_bytes.len(),
        elapsed,
    );

    // Verify the gateway's logs carry a bandwidth-induced failure
    // signal. Depending on whether ferrum-edge eager-buffered or
    // streamed the response, this surfaces as either a plain timeout
    // string (eager-buffered path) or a body-read failure like
    // "Failed to read backend response body" (streamed path — reqwest
    // drops the connection once its per-request `.timeout(400ms)`
    // fires, which shows up as a decode error in the streaming body
    // reader). Both indicate the gateway gave up on the backend.
    let logs = require_logs(&harness);
    let saw_timeout_signal = logs.contains("read_timeout")
        || logs.contains("Timeout")
        || logs.contains("timeout")
        || logs.contains("GatewayTimeout")
        || logs.contains("502")
        || logs.contains("Backend request failed")
        || logs.contains("Failed to read backend response body")
        || logs.contains("error decoding response body");
    assert!(
        saw_timeout_signal,
        "expected timeout/502 or body-read-failure signal in gateway logs:\n{logs}"
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
//     `TransactionSummary` JSON is written to stdout.
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
        // `stdout_logging` writes access-log JSON straight to the
        // non-blocking stdout sink, independent of the
        // `FERRUM_LOG_LEVEL` / `RUST_LOG` tracing filter, so the latency
        // assertion below holds regardless of any inherited `RUST_LOG`.
        // We still pin `RUST_LOG=info` so runtime diagnostics stay
        // visible in the captured output.
        .env("RUST_LOG", "info")
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
    // `stdout_logging` emits `TransactionSummary` as a JSON line on
    // stdout; `latency_backend_ttfb_ms` is the purpose-built field for
    // this signal (vs. `latency_total_ms`, which also includes plugin
    // post-processing).
    let logs = harness.captured_combined().expect("capture");
    let ttfb_ms = extract_f64_field(&logs, "latency_backend_ttfb_ms").unwrap_or_else(|| {
        panic!(
            "expected a `latency_backend_ttfb_ms` entry from stdout_logging; \
             did the plugin fail to wire? Logs:\n{logs}"
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

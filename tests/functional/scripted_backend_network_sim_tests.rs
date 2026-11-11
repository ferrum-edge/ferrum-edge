//! Phase-5 acceptance tests — network-simulation wrappers.
//!
//! These tests insert a [`crate::scaffolding::network::NetworkSimProxy`]
//! middleman between the gateway and a scripted backend so each accepted
//! connection goes through a `DelayedStream` / `BandwidthLimitedStream`
//! pipeline. The gateway sees a "slow network" to
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
    // No upper wall-clock bound. A request that exceeded the gateway's
    // 2 s read timeout would surface as a 5xx, so the `200 OK` + `"ok"`
    // body asserted above already proves the backend completed *within*
    // the read timeout — that is the real "within read timeout" signal.
    // A tight elapsed-time ceiling here adds nothing to that guarantee
    // and only introduces host-load flakiness (CI scheduling jitter can
    // push an otherwise-successful request past an arbitrary bound). A
    // genuine hang is still bounded by the client's 30 s request timeout.
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — a bandwidth-throttled but continuously PROGRESSING backend
// response is not killed by `backend_read_timeout_ms`.
// ────────────────────────────────────────────────────────────────────────────
//
// `backend_read_timeout_ms` is a per-direction IDLE watermark, not a
// whole-exchange clock (issues #4055 / #4057, `docs/error_classification.md`).
// It used to be installed as reqwest's `RequestBuilder::timeout()`, which runs
// from `send()` through response-body completion — so this test previously
// asserted that a 16 KiB body at 1 KiB/s must be killed at ~400 ms. That
// contract was retired deliberately: the same clock also killed a legitimate
// slow-but-progressing SSE stream, which is the whole of #4057.
//
// The bandwidth wrapper is a token bucket that hands back at least one byte
// every `1/rate` seconds, so a throttled transfer never goes idle — its
// inter-chunk gap is ~1 ms, three orders of magnitude below the watermark.
// The correct behaviour is therefore that the transfer COMPLETES, slowly.
//
// Fixture:
//   - `ScriptedHttp1Backend` that responds immediately with a `Content-Length`
//     body and no `Sleep`, so the limiter is the only thing that can slow it.
//   - `NetworkSimProxy` with a 1 KiB/s cap and 50 ms of latency.
//   - Gateway with `backend_read_timeout_ms = 400`.
//
// Expected: `200 OK` with the COMPLETE body, taking materially longer than an
// unthrottled transfer. The elapsed floor is what still catches a no-op
// limiter (which would finish in a few ms); the full body is what catches the
// idle watermark being re-armed on anything other than real backend progress.
//
// The "backend consumes the gateway's write slowly" direction is
// `backend_write_timeout_ms`, covered for raw TCP in `src/proxy/tcp_proxy.rs`
// and for the HTTP family by the gateway-owned upload pump
// (`scripted_backend_tests::h1_backend_write_timeout_maps_to_504_backend_timeout`
// and its H2/H3 siblings). A bandwidth cap cannot exercise it: the backend here
// keeps reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_bandwidth_below_budget_does_not_trip_idle_read_timeout() {
    // 4 KiB at 1024 B/s with a 1-second burst: ~3 s of drain. Enough to be
    // unambiguously throttled, small enough to keep the test cheap.
    const BODY_SIZE: usize = 4 * 1024;
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

    // A no-op bandwidth limiter would finish in a few ms. This floor is well
    // above the configured 400 ms watermark, so it also proves the transfer
    // ran PAST the watermark without being killed.
    assert!(
        elapsed >= Duration::from_millis(600),
        "bandwidth wrapper should have slowed the transfer past 600 ms; \
         got {elapsed:?} — is the limiter a no-op?"
    );
    // A generous hang guard only. There is deliberately no tight ceiling: the
    // gateway is not supposed to give up on a progressing stream, so the
    // wall-clock here is the limiter's, not a gateway budget's.
    assert!(
        elapsed <= Duration::from_secs(20),
        "throttled transfer hung ({elapsed:?}); expected ~3 s at 1 KiB/s"
    );

    assert_eq!(
        resp.status,
        StatusCode::OK,
        "a throttled but continuously progressing response must not be \
         classified as a backend timeout; got status={} body_bytes={} after {:?}",
        resp.status,
        resp.body_bytes.len(),
        elapsed
    );
    assert_eq!(
        resp.body_bytes.len(),
        BODY_SIZE,
        "the idle watermark must re-arm on every received chunk, so the \
         complete body must survive; got status={} body_bytes={} after {:?}",
        resp.status,
        resp.body_bytes.len(),
        elapsed,
    );

    // The complementary half of the contract: the gateway must not have
    // *diagnosed* a per-direction watermark either. A 200 with a complete body
    // could in principle coexist with a spurious warning, and that warning is
    // what an operator dashboard and the circuit breaker would act on.
    let (stdout, stderr) = harness.captured_output().expect("captured output");
    let logs = format!("{stdout}{stderr}");
    for marker in [
        "read_write_timeout",
        "Backend read timeout",
        "Backend response body read timed out",
    ] {
        assert!(
            !logs.contains(marker),
            "a throttled but progressing response must not be classified as a \
             backend watermark expiry; found {marker:?} in gateway logs:\n{logs}"
        );
    }
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

    // Send the remaining requests so several `TransactionSummary`
    // entries are emitted; the poll below reads whichever flushes first.
    // Request volume is no longer load-bearing for the flush — the
    // bounded poll, not the count, absorbs the non-blocking appender's
    // lag.
    for _ in 1..REQUEST_COUNT {
        let resp = client
            .get(&harness.proxy_url("/api/ttfb"))
            .await
            .expect("followup response");
        assert_eq!(resp.status, StatusCode::OK);
    }

    // Mandatory TTFB assertion on the structured access log.
    // `stdout_logging` emits `TransactionSummary` as a JSON line on
    // stdout; `latency_backend_ttfb_ms` is the purpose-built field for
    // this signal (vs. `latency_total_ms`, which also includes plugin
    // post-processing).
    //
    // Poll until the field flushes through Ferrum's bounded
    // non-blocking writer instead of reading once after a fixed sleep:
    // the access-log line lags the client-visible response, so a single
    // snapshot races the flush and intermittently misses an
    // already-emitted entry. Polling can only turn that miss into a hit.
    let logs = harness
        .wait_for_log_contains(
            &|logs: &str| extract_f64_field(logs, "latency_backend_ttfb_ms").is_some(),
            Duration::from_secs(5),
        )
        .await;
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

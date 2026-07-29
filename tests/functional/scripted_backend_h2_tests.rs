//! Phase-2 acceptance tests for the scripted-backend framework.
//!
//! Each test ties the H2 / gRPC scripted backend to a ferrum-edge gateway
//! running in binary mode and asserts an observable failure-mode behavior
//! at the HTTP/2 + gRPC layer: GOAWAY classification, stream reset
//! classification, missing-trailer fallback, gRPC status preservation,
//! gRPC trailer sanitization, flow-control write timeouts, and H2-pool
//! connection reuse.
//! gRPC request header sanitization, flow-control write timeouts, and
//! H2-pool connection reuse.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests scripted_backend_h2 -- --ignored --nocapture`.
//!
//! See `docs/plans/test_framework_scripted_backends.md` Phase 2 for the
//! scope of these tests.
//!
//! Step-vocabulary audit: every `GrpcStep` is exercised in this file.
//! `H2Step::SendGoawayAndClose`, `H2Step::SendRstStream`, and
//! `H2Step::DropConnection` are exercised through the corresponding
//! `GrpcStep::{SendGoaway,SendRstStream,CloseAfterHeaders}` lowering.
//! `GrpcStep::{AcceptStreamingRpc,ExpectReset}` cover the live bidi deadline
//! cancellation path.
//! `GrpcStep::AwaitTestSignal` / `H2Step::AwaitTestSignal` gate the pooled
//! GOAWAY canceled-send regression so response headers land before GOAWAY.
//! `H2Step::SendGoaway` (the non-closing graceful form) is intentionally
//! reserved for in-flight graceful-drain coverage: the round-2 matrix needs
//! a terminal connection fault, so it uses `SendGoawayAndClose` instead.

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    ConnectionSettings, GrpcStep, H2Step, MatchHeaders, MatchRpc, ScriptedGrpcBackend,
    ScriptedH2Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GrpcClient, Http2Client};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use crate::scaffolding::to_file_mode_yaml;
use bytes::Bytes;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// Test-side signals proving the gateway took the gRPC backend-error
/// path. The assertion below is satisfied when ANY of these appear in
/// the captured log; each is a structured marker tied to a specific
/// gateway code path and is absent from happy-path / startup logs.
///
/// We intentionally keep multiple signals because no single one is
/// available in every reviewer environment:
///
/// * `BACKEND_ERROR_LOG` — `error!()` line at the `ferrum_edge::proxy::
///   grpc_proxy` target. Fires whenever `sender.send_request(...)`
///   returns Err on the streaming-body dispatch (GOAWAY pre-headers,
///   RST during early header exchange). Emitted at ERROR level so it
///   survives any `RUST_LOG` filter that doesn't suppress ERROR (the
///   gateway's default is `warn`, which still shows ERROR). This is the
///   signal a reviewer
///   testing with restrictive `RUST_LOG` will see and was the only
///   one they reported.
/// * `BODY_ERROR_CLASS_FIELD` — `"body_error_class":"..."` in the
///   `TransactionSummary` access-log JSON, fired by the deferred body
///   logger when the response stream errors after headers were already
///   forwarded. Requires the `stdout_logging` plugin (wired in by
///   `spawn_grpc_harness`); the access-log JSON is written straight to
///   stdout, independent of `RUST_LOG` / `FERRUM_LOG_LEVEL`.
/// * `REJECTION_PHASE_FIELD` — `"rejection_phase":"grpc_backend_error"`
///   inside the access-log JSON's metadata, fired by the synchronous
///   gRPC backend-error path in `src/proxy/mod.rs`. Same loading
///   requirements as `BODY_ERROR_CLASS_FIELD`.
///
/// Escape-form note for the access-log signals: the `TransactionSummary`
/// JSON is serialized into the *outer* tracing JSON's `fields.message`
/// string, so `"` becomes `\"` on disk. Patterns below use the escaped
/// form (`\\\"field\\\":\\\"` in Rust source, `\"field\":\"` on disk).
const BACKEND_ERROR_LOG: &str = "gRPC backend request failed";
const BODY_ERROR_CLASS_FIELD: &str = "\\\"body_error_class\\\":\\\"";
const REJECTION_PHASE_FIELD: &str = "\\\"rejection_phase\\\":\\\"grpc_backend_error\\\"";

fn has_backend_error_signal(logs: &str) -> bool {
    logs.contains(BACKEND_ERROR_LOG)
        || logs.contains(BODY_ERROR_CLASS_FIELD)
        || logs.contains(REJECTION_PHASE_FIELD)
}

/// Poll the captured output until a backend-error signal appears, then
/// return the full snapshot. Polling is necessary because the
/// `stdout_logging` access-log routes through Ferrum's bounded
/// non-blocking writer, which lags the response by tens of ms; a bare
/// `captured_combined()` snapshot races the flush.
///
/// We force a drain by sending a couple of admin `/health` probes
/// through the same gateway after the failing RPC: each probe emits
/// its own log events, which travel through the same writer thread,
/// guaranteeing that everything queued before them (including our
/// target access-log line) has reached the underlying writer.
///
/// On timeout, return the latest snapshot so the panic message shows
/// what WAS logged. The polling loop exits as soon as ANY of the
/// signals (`BACKEND_ERROR_LOG`, `BODY_ERROR_CLASS_FIELD`,
/// `REJECTION_PHASE_FIELD`) appears — see [`has_backend_error_signal`]
/// for the rationale.
async fn collect_flushed_logs(harness: &GatewayHarness) -> String {
    if let Ok(base) = harness.admin_url("/health").parse::<reqwest::Url>() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .expect("reqwest client");
        for _ in 0..2 {
            let _ = client.get(base.clone()).send().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let logs = harness.captured_combined().unwrap_or_default();
        if has_backend_error_signal(&logs) {
            return logs;
        }
        if Instant::now() >= deadline {
            return logs;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// GET the backend capability registry and return the single entry (tests
/// configure a single proxy so the registry holds exactly one). Returns
/// `None` until the async warmup probe has classified the backend.
async fn fetch_capability_entry(harness: &GatewayHarness) -> Option<Value> {
    let body = harness.get_admin_json("/backend-capabilities").await.ok()?;
    body["entries"].as_array()?.first().cloned()
}

/// Poll the capability registry until the backend is classified
/// `plain_http.h2_tls == "supported"`, or the deadline expires. Direct-H2
/// dispatch (`ResponseBody::StreamingH2`) only engages once the backend is
/// proven h2-over-TLS capable; before that the request falls back to the
/// reqwest arm, so tests that mean to exercise the direct-H2 inspector must
/// gate on this first.
async fn wait_for_h2_tls_supported(harness: &GatewayHarness, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await
            && entry["plain_http"]["h2_tls"].as_str() == Some("supported")
        {
            return Some(entry);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Build a file-mode YAML that points a gRPC proxy at the given port over
/// plain HTTP (h2c — the gateway's gRPC pool performs an h2c handshake
/// when `backend_scheme: http`). Callers can merge additional overrides
/// into the proxy definition via `overrides`.
fn grpc_file_config(port: u16, overrides: Value) -> String {
    grpc_file_config_with_log_config(port, overrides, json!({}))
}

fn grpc_file_config_with_log_config(port: u16, overrides: Value, log_config: Value) -> String {
    let mut proxy = json!({
        "id": "grpc-scripted",
        "listen_path": "/grpc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
    });
    if let (Some(proxy_obj), Some(overrides_obj)) = (proxy.as_object_mut(), overrides.as_object()) {
        for (k, v) in overrides_obj {
            proxy_obj.insert(k.clone(), v.clone());
        }
    }
    // `stdout_logging` emits the `TransactionSummary` as a JSON line on
    // stdout, independent of the log-level filter. This is what the
    // protocol-classification assertions below grep for (`"error_class":"..."` and
    // `"rejection_phase":"grpc_backend_error"`) — structured signals that
    // beat the old broad substring checks ("grpc", "backend"), which
    // matched ordinary startup / routing logs and would have silently
    // passed against a gateway regression that logged no classifier at all.
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "access-log",
            "plugin_name": "stdout_logging",
            "config": log_config,
            "scope": "global",
            "enabled": true,
        }],
    });
    // `to_file_mode_yaml` tags the enum-typed nodes an override may carry
    // (`retry.backoff`); a bare `serde_yaml::to_string` emits the JSON
    // singleton-map spelling, which the file loader rejects.
    to_file_mode_yaml(&config)
}

fn grpc_chargeback_file_config(port: u16, overrides: Value) -> String {
    let mut proxy = json!({
        "id": "grpc-chargeback",
        "listen_path": "/grpc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "auth_mode": "single",
        "plugins": [
            {"plugin_config_id": "grpc-chargeback-key-auth"},
            {"plugin_config_id": "grpc-chargeback-pricing"}
        ],
    });
    if let (Some(proxy_obj), Some(overrides_obj)) = (proxy.as_object_mut(), overrides.as_object()) {
        for (key, value) in overrides_obj {
            proxy_obj.insert(key.clone(), value.clone());
        }
    }
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [{
            "id": "grpc-chargeback-consumer",
            "username": "grpc-chargeback-user",
            "credentials": {
                "keyauth": [{"key": "grpc-chargeback-key-99887766"}]
            }
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-chargeback-key-auth",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "grpc-chargeback",
                "enabled": true,
                "config": {"key_location": "header:x-api-key"},
            },
            {
                "id": "grpc-chargeback-pricing",
                "plugin_name": "api_chargeback",
                "scope": "proxy",
                "proxy_id": "grpc-chargeback",
                "enabled": true,
                "config": {
                    "pricing_tiers": [
                        {"status_codes": [200], "price_per_call": 0.001},
                        {"status_codes": [503], "price_per_call": 0.009}
                    ],
                    "render_cache_ttl_seconds": 0,
                    "cache_invalidation_min_age_ms": 0,
                    "cleanup_interval_seconds": 0,
                },
            }
        ],
    });
    serde_yaml::to_string(&config).expect("serialize gRPC chargeback yaml")
}

async fn wait_for_chargeback_statuses(
    harness: &GatewayHarness,
    consumer: &str,
    proxy_id: &str,
    expected: &[(u16, u64)],
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let charges = harness
            .get_admin_json("/charges?format=json")
            .await
            .expect("fetch chargeback JSON");
        let by_status = &charges["consumers"][consumer]["proxies"][proxy_id]["by_status"];
        if expected.iter().all(|(status, calls)| {
            let status = status.to_string();
            by_status
                .get(status.as_str())
                .and_then(|entry| entry["calls"].as_u64())
                == Some(*calls)
        }) {
            return charges;
        }
        assert!(
            Instant::now() < deadline,
            "chargeback statuses did not settle: expected={expected:?}, charges={charges:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// gRPC scripted-backend config with one proxy-scoped `grpc_deadline`
/// policy. Kept separate from `grpc_file_config` so the broad scripted H2
/// suite retains its existing stdout-only plugin chain.
fn grpc_deadline_file_config(port: u16, deadline_config: Value) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-deadline-scripted",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "plugins": [{ "plugin_config_id": "grpc-deadline" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-deadline",
            "plugin_name": "grpc_deadline",
            "config": deadline_config,
            "scope": "proxy",
            "proxy_id": "grpc-deadline-scripted",
            "enabled": true,
        }],
    });
    serde_yaml::to_string(&config).expect("serialize grpc_deadline yaml")
}

/// Add a one-failure circuit breaker to the deadline fixture. A follow-up
/// healthy RPC then proves client-owned deadline expiry was recorded as neutral
/// rather than poisoning backend health.
fn grpc_deadline_cb_file_config(port: u16, deadline_config: Value) -> String {
    let mut config: Value = serde_yaml::from_str(&grpc_deadline_file_config(port, deadline_config))
        .expect("parse grpc_deadline yaml");
    config["proxies"][0]["circuit_breaker"] = json!({
        "failure_threshold": 1,
        "success_threshold": 1,
        "timeout_seconds": 30,
        "failure_status_codes": [500, 502, 503, 504],
        "half_open_max_requests": 1,
        "trip_on_connection_errors": true,
    });
    serde_yaml::to_string(&config).expect("serialize grpc_deadline circuit-breaker yaml")
}

/// Spawn a gateway harness with the Phase-2 test defaults.
///
/// All tests in this module need the same harness setup:
///   * `.log_level("info")` so the gateway's runtime tracing logs (e.g.
///     the `gRPC backend request failed` ERROR signal) are visible,
///   * `.env("RUST_LOG", "info")` so a reviewer or CI machine with
///     `RUST_LOG=error` (or similar) in their shell doesn't suppress
///     those runtime logs — `EnvFilter` reads `RUST_LOG` first and only
///     falls back to `FERRUM_LOG_LEVEL` when it's unset. The
///     `stdout_logging` access-log JSON is written to stdout
///     independent of this filter, so the access-log signals hold
///     regardless. Matches the pattern in
///     `tests/functional/functional_logging_test.rs`.
///   * `.capture_output()` so `captured_combined()` can read back the
///     subprocess's stdout/stderr files.
///
/// Centralizing these avoids drift — Phase-1 shipped with bare
/// `.log_level("info")` on each builder call, and a reviewer's
/// inherited `RUST_LOG` caused the runtime-log signal in the
/// GOAWAY/RST tests to regress until this helper was introduced.
async fn spawn_grpc_harness(yaml: String) -> GatewayHarness {
    GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway")
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — backend GOAWAY mid-request → 502 + ProtocolError class.
// ────────────────────────────────────────────────────────────────────────────
//
// The scripted gRPC backend accepts the RPC, then immediately issues a
// GOAWAY (INTERNAL_ERROR) without answering. The gateway's gRPC pool must
// surface this as a clean failure — not a hang, not a generic 500.
//
// Observables:
//   - HTTP status on the response is 200 (gRPC wraps errors in trailers)
//     OR 502 if the gateway decided to bail before wrapping.
//   - `grpc-status` trailer is a non-OK code (UNAVAILABLE or INTERNAL).
//   - Gateway logs contain a gRPC-error signal (`grpc:` error, `GOAWAY`,
//     `h2 GOAWAY`, etc.).
//   - The backend observed exactly one request stream.
//   - `mark_h3_unsupported` MUST NOT fire — H3 is orthogonal to H2 GOAWAY.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_goaway_mid_request_handled_gracefully() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        // INTERNAL_ERROR (2) GOAWAY and close. No RespondHeaders first —
        // we want the gateway to observe the connection-level failure
        // before getting a response body.
        .step(GrpcStep::SendGoaway { error_code: 2 })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let rpc_started = Instant::now();
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("response surfaced");
    let rpc_elapsed = rpc_started.elapsed();

    // "Must not hang" is the core property of this test. `GrpcClient::unary`
    // synthesizes `stream_error: "response timed out"` after its internal
    // 20s budget, so the structural `has_error` predicate below would
    // trivially pass on a gateway hang — the client's timeout masks the
    // regression. Bound the elapsed time FIRST so a hang fails the test
    // before `has_error` gets a chance to swallow it. A correctly-behaving
    // gateway classifies the GOAWAY and responds in milliseconds; three
    // seconds is a generous CI-tolerant ceiling.
    assert!(
        rpc_elapsed < Duration::from_secs(3),
        "gateway appears to have hung on pre-headers GOAWAY — RPC took \
         {rpc_elapsed:?} (client timeout is 20s). The point of this test \
         is to verify the gateway does NOT deadlock."
    );

    // The gateway responds with a well-formed gRPC error (not a hang).
    // HTTP status may be 200 with trailers, or non-200 if the gateway
    // bailed before wrapping — either proves the gateway handled the
    // GOAWAY gracefully. A grpc-status code of OK (0) would indicate the
    // gateway incorrectly masked the failure.
    let has_error = response.http_status == 502
        || response.http_status == 503
        || response.grpc_status().is_some_and(|s| s != 0)
        || response.stream_error.is_some();
    assert!(
        has_error,
        "expected a gRPC error / transport error, got http={} grpc-status={:?} trailers={:?} stream_error={:?}",
        response.http_status,
        response.grpc_status(),
        response.trailers,
        response.stream_error
    );

    // The backend observed exactly one request stream.
    let streams = backend.received_streams().await;
    assert_eq!(
        streams.len(),
        1,
        "expected 1 stream at backend, got {:?}",
        streams
    );

    // Gateway logs: confirm the gateway emitted a *structured* backend-error
    // signal. See [`has_backend_error_signal`] for the three accepted
    // markers and why ANY of them satisfies the "gateway noticed the
    // failure and classified it" guarantee. We use `OR` (rather than
    // requiring all three) because their availability differs by
    // environment: the access-log fields are written to stdout by
    // `stdout_logging` regardless of the log filter, while the `gRPC
    // backend request failed` ERROR log fires at the gateway's default
    // level and is what reviewer environments with restrictive
    // `RUST_LOG` will see. None of the signals appear on
    // the happy path or in ordinary startup / routing logs, so each is
    // load-bearing on its own.
    let logs = collect_flushed_logs(&harness).await;
    assert!(
        has_backend_error_signal(&logs),
        "expected the gateway to emit at least one structured backend-error \
         signal — \"{BACKEND_ERROR_LOG}\" (gRPC proxy ERROR log), \
         {BODY_ERROR_CLASS_FIELD} (access-log body_error_class field), or \
         {REJECTION_PHASE_FIELD} (access-log rejection_phase metadata) — \
         after a pre-headers GOAWAY; logs:\n{logs}"
    );

    // Regression guard: H3 capability must not have been touched by an
    // H2 GOAWAY. The registry's "h3 unsupported" path is orthogonal.
    assert!(
        !logs.contains("mark_h3_unsupported") && !logs.contains("h3 = Unsupported"),
        "H2 GOAWAY incorrectly triggered an H3 capability downgrade:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — backend RST_STREAM mid-response → 502 with ProtocolError class.
// ────────────────────────────────────────────────────────────────────────────
//
// Backend accepts the RPC, sends response headers, then RST_STREAM(2)
// mid-response. Gateway classifies as ProtocolError.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_stream_reset_classified_as_protocol_error() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        // INTERNAL_ERROR (2) RST_STREAM.
        .step(GrpcStep::SendRstStream { error_code: 2 })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let rpc_started = Instant::now();
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("response surfaced");
    let rpc_elapsed = rpc_started.elapsed();

    // See the GOAWAY test for the rationale: `stream_error: "response
    // timed out"` from the client's 20s internal budget would otherwise
    // paper over a gateway hang via the `reset_observed` predicate's
    // `stream_error.is_some()` arm. Bound elapsed first.
    assert!(
        rpc_elapsed < Duration::from_secs(3),
        "gateway appears to have hung on RST_STREAM — RPC took \
         {rpc_elapsed:?} (client timeout is 20s). RST_STREAM after headers \
         should be surfaced promptly, not hung."
    );

    // RST_STREAM after headers means the gateway must emit a gRPC error
    // (non-OK status) or a stream-level error. Either proves the reset
    // was noticed — the alternative, a success with OK trailer, would
    // indicate masking.
    let reset_observed = response.http_status == 502
        || response.http_status == 503
        || response.grpc_status().is_some_and(|s| s != 0)
        || response.stream_error.is_some()
        || response.trailers.is_none(); // trailers missing also signals abnormal close
    assert!(
        reset_observed,
        "expected RST_STREAM to surface as gRPC error; got http={} grpc-status={:?} trailers={:?} stream_error={:?}",
        response.http_status,
        response.grpc_status(),
        response.trailers,
        response.stream_error,
    );

    // Same OR-of-structured-signals predicate as the GOAWAY test —
    // see [`has_backend_error_signal`] for the rationale and the
    // code-path / RUST_LOG mapping.
    //
    // Code-path note specific to RST_STREAM: the RST may arrive
    // before the gateway finishes forwarding initial response headers
    // (in which case `sender.send_request(...)` errors and the
    // `gRPC backend request failed` ERROR log fires + `rejection_phase`
    // is populated), or after (in which case `body_error_class` is
    // populated by the deferred body logger). The OR predicate
    // accepts either outcome.
    let logs = collect_flushed_logs(&harness).await;
    assert!(
        has_backend_error_signal(&logs),
        "expected the gateway to emit at least one structured backend-error \
         signal after an H2 stream reset — \"{BACKEND_ERROR_LOG}\" \
         (gRPC proxy ERROR log), {BODY_ERROR_CLASS_FIELD} (access-log \
         body_error_class field), or {REJECTION_PHASE_FIELD} (access-log \
         rejection_phase metadata); logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Round-2 error-code matrices. Error handling is asserted as a family because
// the response may be a Trailers-Only gRPC error or a transport-level stream
// error depending on whether the peer's GOAWAY/RST wins the header race.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_goaway_error_code_matrix_surfaces_error_family() {
    for (name, error_code) in [
        ("PROTOCOL_ERROR", 1_u32),
        ("REFUSED_STREAM", 7_u32),
        ("ENHANCE_YOUR_CALM", 11_u32),
    ] {
        let reservation = reserve_port().await.expect("reserve port");
        let backend_port = reservation.port;
        let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::SendGoaway { error_code })
            .spawn()
            .expect("spawn backend");

        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(grpc_file_config(backend_port, Value::Null))
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn gateway");
        let gw_port = harness
            .proxy_base_url()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .expect("gateway port");
        let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            client.unary("/grpc/ferrum.Echo/Ping", Bytes::new()),
        )
        .await
        .unwrap_or_else(|_| panic!("{name} GOAWAY hung past the outer timeout"))
        .unwrap_or_else(|error| panic!("{name} GOAWAY client error: {error}"));

        let error_family = matches!(response.http_status, 502 | 503)
            || response.grpc_status().is_some_and(|status| status != 0)
            || response.stream_error.is_some();
        assert!(
            error_family,
            "{name} GOAWAY must surface a gateway/gRPC/stream error family; response={response:?}"
        );
        assert_eq!(
            backend.received_stream_count(),
            1,
            "{name} GOAWAY must be driven by one backend RPC"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_rst_stream_error_code_matrix_surfaces_error_family() {
    for (name, error_code) in [
        ("PROTOCOL_ERROR", 1_u32),
        ("REFUSED_STREAM", 7_u32),
        ("ENHANCE_YOUR_CALM", 11_u32),
    ] {
        let reservation = reserve_port().await.expect("reserve port");
        let backend_port = reservation.port;
        let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::SendRstStream { error_code })
            .spawn()
            .expect("spawn backend");

        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(grpc_file_config(backend_port, Value::Null))
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn gateway");
        let gw_port = harness
            .proxy_base_url()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .expect("gateway port");
        let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            client.unary("/grpc/ferrum.Echo/Ping", Bytes::new()),
        )
        .await
        .unwrap_or_else(|_| panic!("{name} RST_STREAM hung past the outer timeout"))
        .unwrap_or_else(|error| panic!("{name} RST_STREAM client error: {error}"));

        let error_family = matches!(response.http_status, 502 | 503)
            || response.grpc_status().is_some_and(|status| status != 0)
            || response.stream_error.is_some()
            || response.trailers.is_none();
        assert!(
            error_family,
            "{name} RST_STREAM must surface a gateway/gRPC/stream error family; response={response:?}"
        );
        assert_eq!(
            backend.received_stream_count(),
            1,
            "{name} RST_STREAM must be driven by one backend RPC"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_pool_opens_fresh_connection_after_prior_stream_reset() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let grpc_ok_frame = Bytes::from_static(&[0, 0, 0, 0, 2, b'o', b'k']);
    let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .connection_scripts([
            vec![
                H2Step::ExpectHeaders(MatchHeaders::any()),
                H2Step::DrainRequestBody,
                H2Step::RespondHeaders(vec![
                    (":status", "200".into()),
                    ("content-type", "application/grpc".into()),
                ]),
                H2Step::SendRstStream { error_code: 7 },
            ],
            vec![
                H2Step::ExpectHeaders(MatchHeaders::any()),
                H2Step::DrainRequestBody,
                H2Step::RespondHeaders(vec![
                    (":status", "200".into()),
                    ("content-type", "application/grpc".into()),
                ]),
                H2Step::RespondData {
                    data: grpc_ok_frame,
                    end_stream: false,
                },
                H2Step::RespondTrailers(vec![("grpc-status", "0".into())]),
            ],
        ])
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_file_config(backend_port, Value::Null))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));

    let first = tokio::time::timeout(
        Duration::from_secs(4),
        client.unary("/grpc/ferrum.Echo/Reset", Bytes::new()),
    )
    .await
    .expect("first RPC bounded")
    .expect("first response surfaced");
    assert!(
        first.grpc_status().is_some_and(|status| status != 0)
            || first.stream_error.is_some()
            || first.trailers.is_none(),
        "first RPC must expose the scripted reset; response={first:?}"
    );

    // The connection-index-0 script terminates after its RST_STREAM and the
    // fixture gives the H2 driver a bounded 100ms flush tail. Wait beyond that
    // tail so request two deterministically exercises stale-pool replacement,
    // not a request-write-vs-connection-close race.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let second = tokio::time::timeout(
        Duration::from_secs(4),
        client.unary("/grpc/ferrum.Echo/Healthy", Bytes::new()),
    )
    .await
    .expect("second RPC bounded")
    .expect("second response surfaced");
    assert_eq!(second.grpc_status(), Some(0), "response={second:?}");
    assert!(
        second
            .messages
            .iter()
            .any(|message| message.as_ref() == b"ok"),
        "replacement connection did not return the healthy payload; response={second:?}"
    );
    assert!(
        backend.accepted_connections() >= 2,
        "the reset connection must not be reused; accepted_connections={} streams={:?}",
        backend.accepted_connections(),
        backend.received_streams().await
    );
    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_trailers_only_response_preserves_status_in_initial_headers() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeadersEndStream(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
            ("grpc-status", "0".into()),
            ("grpc-message", "trailers-only".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_file_config(backend_port, Value::Null))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = tokio::time::timeout(
        Duration::from_secs(4),
        client.unary("/grpc/ferrum.Echo/Ping", Bytes::new()),
    )
    .await
    .expect("trailers-only RPC bounded")
    .expect("trailers-only response surfaced");

    assert_eq!(response.http_status, 200, "response={response:?}");
    assert_eq!(response.grpc_status(), Some(0), "response={response:?}");
    assert!(response.messages.is_empty(), "response={response:?}");
    assert!(response.stream_error.is_none(), "response={response:?}");
    assert_eq!(backend.received_stream_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_close_after_headers_surfaces_clean_error_family() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::CloseAfterHeaders)
        .spawn()
        .expect("spawn backend");
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_file_config(backend_port, Value::Null))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = tokio::time::timeout(
        Duration::from_secs(4),
        client.unary("/grpc/ferrum.Echo/Ping", Bytes::new()),
    )
    .await
    .expect("close-after-headers RPC bounded")
    .expect("response surfaced");

    assert!(
        response.effective_grpc_status() != 0 || response.stream_error.is_some(),
        "backend close after headers must not become a successful RPC; response={response:?}"
    );
    assert_eq!(backend.received_stream_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_stall_after_headers_is_bounded_by_backend_read_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::StallAfterHeaders(Duration::from_secs(30)))
        .spawn()
        .expect("spawn backend");
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_file_config(
            backend_port,
            json!({ "backend_read_timeout_ms": 300 }),
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client.unary("/grpc/ferrum.Echo/Ping", Bytes::new()),
    )
    .await
    .expect("gateway read timeout must beat the scripted 30s stall")
    .expect("timeout response surfaced");

    assert!(
        response.effective_grpc_status() != 0 || response.stream_error.is_some(),
        "stalled backend must not become a successful RPC; response={response:?}"
    );
    assert_eq!(backend.received_stream_count(), 1);
}

// #2498 / #2497 — an end-to-end grpc_deadline expiry after the backend's
// initial HEADERS must terminate a no-DATA H2 stream with an explicit
// DEADLINE_EXCEEDED trailers frame. A body error or missing grpc-status is not
// protocol-equivalent: real gRPC clients otherwise surface UNKNOWN/INTERNAL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_deadline_expiry_after_headers_emits_deadline_exceeded_trailers() {
    let cases = [
        (
            "plugin-default",
            json!({
                "default_deadline_ms": 1000,
                "subtract_gateway_processing": true,
            }),
            None,
        ),
        (
            "client-timeout",
            json!({
                "max_deadline_ms": 2000,
                "subtract_gateway_processing": true,
            }),
            Some("1000m".to_string()),
        ),
    ];

    for (case, deadline_config, client_timeout) in cases {
        let reservation = reserve_port().await.expect("reserve port");
        let backend_port = reservation.port;
        let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::StallAfterHeaders(Duration::from_secs(30)))
            .spawn()
            .expect("spawn backend");
        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(grpc_deadline_file_config(backend_port, deadline_config))
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn gateway");
        let gw_port = harness
            .proxy_base_url()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .expect("gateway port");
        let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
        let headers = client_timeout
            .as_ref()
            .map(|timeout| [("grpc-timeout", timeout.clone())]);
        let extra_headers: &[(&str, String)] =
            headers.as_ref().map_or(&[], |headers| headers.as_slice());
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            client.unary_with_headers("/grpc/ferrum.Echo/Ping", Bytes::new(), extra_headers),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: RPC exceeded its deadline envelope"))
        .unwrap_or_else(|error| panic!("{case}: timeout response failed: {error}"));

        assert_eq!(response.http_status, 200, "{case}: gRPC wire status");
        assert!(
            response.stream_error.is_none(),
            "{case}: expiry must be trailers, not a body error: {response:?}"
        );
        assert_eq!(
            response
                .trailers
                .as_ref()
                .and_then(|trailers| trailers.get("grpc-status"))
                .and_then(|value| value.to_str().ok()),
            Some("4"),
            "{case}: missing DEADLINE_EXCEEDED trailer: {response:?}"
        );
        assert_eq!(
            response.effective_grpc_status(),
            4,
            "{case}: semantic status"
        );
        assert_eq!(
            backend.received_stream_count(),
            1,
            "{case}: backend attempts"
        );
    }
}

// #2498 / #2497 — exercise the real H2 body path after response DATA has
// already reached the client. Once DATA is committed the gateway cannot safely
// append a trailers-only replacement, so expiry must abort downstream, drop the
// upstream body (RST_STREAM), and remain neutral to backend health. Cover both
// a closed unary request direction (server-stream shape) and an open request
// direction (bidi shape).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_deadline_after_partial_data_resets_stream_and_preserves_backend_health() {
    let cases = [
        ("server-stream", "/ferrum.Echo/ServerStream", false),
        ("bidi", "/ferrum.Echo/Bidi", true),
    ];

    for (case, method, bidi) in cases {
        let reservation = reserve_port().await.expect("reserve port");
        let backend_port = reservation.port;
        let partial_message = Bytes::from_static(b"partial");
        let builder = ScriptedGrpcBackend::builder_plain(reservation.into_listener());
        let builder = if bidi {
            builder.step(GrpcStep::AcceptStreamingRpc(MatchRpc::method(method)))
        } else {
            builder.step(GrpcStep::AcceptRpc(MatchRpc::method(method)))
        };
        let backend = builder
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondMessage(partial_message.clone()))
            .step(GrpcStep::ExpectReset(Duration::from_secs(4)))
            .step(GrpcStep::AcceptRpc(MatchRpc::method("/ferrum.Echo/Health")))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondMessage(Bytes::from_static(b"healthy")))
            .step(GrpcStep::RespondStatus {
                code: 0,
                message: "",
            })
            .spawn()
            .expect("spawn backend");
        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(grpc_deadline_cb_file_config(
                backend_port,
                json!({
                    "default_deadline_ms": 1000,
                    "subtract_gateway_processing": true,
                }),
            ))
            // Select the production zero-buffering H2 body branch so the
            // backend's first DATA frame is committed before expiry.
            .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0")
            .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn gateway");
        let gw_port = harness
            .proxy_base_url()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .expect("gateway port");
        let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));

        let response = tokio::time::timeout(Duration::from_secs(4), async {
            if bidi {
                client
                    .bidi_with_headers(
                        &format!("/grpc{method}"),
                        Bytes::from_static(b"request remains open"),
                        &[],
                    )
                    .await
            } else {
                client.unary(&format!("/grpc{method}"), Bytes::new()).await
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{case}: partial-DATA RPC exceeded deadline envelope"))
        .unwrap_or_else(|error| panic!("{case}: response failed: {error}"));

        assert_eq!(response.http_status, 200, "{case}: initial gRPC status");
        assert_eq!(
            response.messages,
            vec![partial_message],
            "{case}: partial message must be delivered before expiry"
        );
        assert!(
            response.stream_error.is_some(),
            "{case}: post-DATA expiry must abort instead of ending cleanly: {response:?}"
        );
        assert!(
            response.trailers.is_none(),
            "{case}: terminal grpc-status cannot be appended after DATA: {response:?}"
        );
        let reset_deadline = Instant::now() + Duration::from_secs(1);
        while backend.stream_reset_count() == 0 && Instant::now() < reset_deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            backend.stream_reset_count(),
            1,
            "{case}: dropping the expired upstream body must reset its H2 stream"
        );

        let health = client
            .unary("/grpc/ferrum.Echo/Health", Bytes::new())
            .await
            .unwrap_or_else(|error| panic!("{case}: health RPC failed: {error}"));
        assert_eq!(health.grpc_status(), Some(0), "{case}: health RPC");
        assert_eq!(
            backend.received_stream_count(),
            2,
            "{case}: client deadline must not trip the one-failure circuit breaker"
        );
        backend.assert_no_matcher_mismatches().await;
        backend.assert_no_step_errors().await;
    }
}

// #2608 — the constructor's HTTP-style internal rejection is normalized to
// native gRPC wire semantics before it reaches an H2 client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_deadline_missing_required_timeout_is_http_200_trailers_only() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .spawn()
        .expect("spawn backend");
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_deadline_file_config(
            backend_port,
            json!({"reject_no_deadline": true}),
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("gateway port");
    let response = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"))
        .unary("/grpc/ferrum.Echo/Ping", Bytes::new())
        .await
        .expect("missing-deadline response");

    assert_eq!(response.http_status, 200);
    assert!(
        response
            .headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|status| status != "0"),
        "missing deadline must be a non-OK trailers-only header: {response:?}"
    );
    assert!(response.raw_body_frames.is_empty());
    assert!(response.trailers.is_none());
    assert_eq!(backend.received_stream_count(), 0);
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — gRPC backend omits trailers → client sees a well-formed
//          non-OK status, not a hang.
// ────────────────────────────────────────────────────────────────────────────
//
// Backend responds with headers + a DATA frame (end_stream=true) but no
// `grpc-status` trailer. The `effective_grpc_status()` helper maps this
// to UNKNOWN (2) per the canonical HTTP-to-gRPC mapping doc ("every
// other code ⇒ UNKNOWN"). The gateway must pass this through
// deterministically — either by synthesizing a non-OK trailer itself
// or by forwarding the backend's missing-trailer response so the
// client's spec-following synthesis kicks in. The critical regression
// guard is that the effective status is NOT OK (0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_trailers_missing_produces_non_ok_status() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        // Respond with a body but NO trailers.
        .step(GrpcStep::OmitTrailers {
            body: Some(Bytes::from_static(b"partial")),
        })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config_with_log_config(
        backend_port,
        Value::Null,
        json!({"filter": {"errors_only": true}}),
    );
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("response surfaced");

    // The client got a well-formed response — not a hang. Assert first
    // that SOMETHING came back.
    assert!(
        response.http_status > 0,
        "client never received any response (likely a hang); got {:?}",
        response
    );

    // The core guarantee: the gateway must NOT surface `grpc-status: 0`
    // (OK) when the backend closed without sending trailers. Two wire
    // shapes collapse to the same semantic outcome via
    // `effective_grpc_status()`:
    //
    //   * gateway forwards the backend's missing-trailer response as-is,
    //     and the client-side `effective_grpc_status` rule returns
    //     UNKNOWN (2) per the HTTP-to-gRPC mapping doc — this is today's
    //     gateway behavior;
    //   * a future gateway hardening could synthesize a specific
    //     `grpc-status` trailer (UNKNOWN / INTERNAL / UNAVAILABLE), and
    //     the helper would return that verbatim.
    //
    // Both satisfy the regression guard below — the helper returns a
    // non-zero status in all spec-compliant cases, and a gateway
    // regression that surfaced `grpc-status: 0` would be caught because
    // `grpc_status()` would return `Some(0)` and the helper would pass
    // it through unchanged.
    let effective = response.effective_grpc_status();
    assert_ne!(
        effective,
        0,
        "gateway incorrectly surfaced grpc-status=OK despite missing backend trailers; \
         http={} grpc-status={:?} headers={:?} trailers={:?}",
        response.http_status,
        response.grpc_status(),
        response.headers,
        response.trailers,
    );
    // Pin the current expected value (UNKNOWN per the mapping doc) so a
    // drift in gateway behavior surfaces explicitly instead of silently
    // flipping between non-zero codes.
    assert_eq!(
        effective,
        2,
        "gateway did not surface UNKNOWN(2) for HTTP 200 + missing trailers \
         (per the HTTP-to-gRPC mapping doc); \
         http={} grpc-status={:?} headers={:?} trailers={:?}",
        response.http_status,
        response.grpc_status(),
        response.headers,
        response.trailers
    );
    let logs = harness
        .wait_for_log_contains(
            |logs| {
                logs.lines().any(|line| {
                    serde_json::from_str::<Value>(line).is_ok_and(|entry| {
                        entry["proxy_id"] == "grpc-scripted" && entry["grpc_status"] == 2
                    })
                })
            },
            Duration::from_secs(5),
        )
        .await;
    assert!(
        logs.lines().any(|line| {
            serde_json::from_str::<Value>(line).is_ok_and(|entry| {
                entry["proxy_id"] == "grpc-scripted"
                    && entry["response_status_code"] == 200
                    && entry["grpc_status"] == 2
            })
        }),
        "missing trailers must emit UNKNOWN(2) through errors_only; logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — DEADLINE_EXCEEDED propagates as DEADLINE_EXCEEDED, not UNAVAILABLE.
// ────────────────────────────────────────────────────────────────────────────
//
// Backend answers the RPC with `grpc-status: 4` (DEADLINE_EXCEEDED). The
// gateway's gRPC code path MUST preserve this status — collapsing to
// UNAVAILABLE would mask semantics that clients rely on for retry
// decisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_deadline_exceeded_propagates_as_deadline_exceeded_not_unavailable() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeadersOverride(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc+proto".into()),
        ]))
        // Empty data frame is fine for unary — trailers carry the status.
        .step(GrpcStep::RespondStatus {
            code: 4, // DEADLINE_EXCEEDED
            message: "backend ran out of time",
        })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("response surfaced");

    // HTTP status on a well-formed gRPC response is 200.
    assert_eq!(
        response.http_status, 200,
        "gRPC errors use HTTP 200; got {}",
        response.http_status
    );
    // The critical assertion: grpc-status is 4 (DEADLINE_EXCEEDED), not
    // 14 (UNAVAILABLE). The gateway must NOT collapse/rewrite upstream
    // status codes.
    let status = response
        .grpc_status()
        .expect("backend-provided grpc-status preserved");
    assert_eq!(
        status, 4,
        "gateway collapsed DEADLINE_EXCEEDED (4) to {}; trailers={:?}",
        status, response.trailers
    );
    // The grpc-message should also survive intact.
    assert_eq!(
        response.grpc_message(),
        Some("backend ran out of time"),
        "grpc-message was not preserved; trailers={:?}",
        response.trailers
    );
}

async fn assert_errors_only_grpc_output(overrides: Value, case: &str) {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 4,
            message: "deadline exceeded",
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondRawStatus { value: "malformed" })
        .spawn()
        .expect("spawn backend");
    let yaml = grpc_file_config_with_log_config(
        backend_port,
        overrides,
        json!({"filter": {"errors_only": true}}),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .pool_warmup_enabled(false)
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");
    let gateway_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gateway_port}"));

    let success = client
        .unary("/grpc/ferrum.Echo/Success", Bytes::new())
        .await
        .expect("successful RPC");
    assert_eq!(success.grpc_status(), Some(0), "{case}: {success:?}");
    let failure = client
        .unary("/grpc/ferrum.Echo/Failure", Bytes::new())
        .await
        .expect("failed-status RPC response");
    assert_eq!(failure.grpc_status(), Some(4), "{case}: {failure:?}");
    let malformed = client
        .unary("/grpc/ferrum.Echo/Malformed", Bytes::new())
        .await
        .expect("malformed-status RPC response");
    assert_eq!(malformed.grpc_status(), None, "{case}: {malformed:?}");

    let logs = harness
        .wait_for_log_contains(
            |logs| {
                let mut statuses: Vec<u64> = logs
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter(|entry| entry["proxy_id"] == "grpc-scripted")
                    .filter_map(|entry| entry["grpc_status"].as_u64())
                    .collect();
                statuses.sort_unstable();
                statuses.as_slice() == [4, u32::MAX as u64]
            },
            Duration::from_secs(5),
        )
        .await;
    let access_logs: Vec<Value> = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["proxy_id"] == "grpc-scripted")
        .collect();
    assert_eq!(
        access_logs.len(),
        2,
        "{case}: status-0 success must be excluded and status-4/malformed failures emitted; logs:\n{logs}"
    );
    assert!(
        access_logs
            .iter()
            .all(|entry| entry["response_status_code"] == 200),
        "{case}: {access_logs:?}"
    );
    let mut statuses: Vec<u64> = access_logs
        .iter()
        .filter_map(|entry| entry["grpc_status"].as_u64())
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses.as_slice(), &[4, u32::MAX as u64], "{case}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn stdout_errors_only_covers_streamed_and_buffered_h2_grpc_status() {
    assert_errors_only_grpc_output(Value::Null, "streamed_h2").await;
    assert_errors_only_grpc_output(
        json!({
            "retry": {
                "max_retries": 1,
                "retry_on_connect_failure": true,
            }
        }),
        "buffered_h2",
    )
    .await;
}

async fn assert_api_chargeback_uses_terminal_grpc_status(overrides: Value, case: &str) {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 14,
            message: "unavailable",
        })
        .spawn()
        .expect("spawn backend");
    let harness = GatewayHarness::builder()
        .file_config(grpc_chargeback_file_config(backend_port, overrides))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gRPC chargeback gateway");
    let gateway_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gateway_port}"));
    let auth = [("x-api-key", "grpc-chargeback-key-99887766".to_string())];

    let success = client
        .unary_with_headers("/grpc/echo.Echo/Success", Bytes::new(), &auth)
        .await
        .expect("successful RPC");
    assert_eq!(success.http_status, 200, "{case}: {success:?}");
    assert_eq!(success.grpc_status(), Some(0), "{case}: {success:?}");

    let failure = client
        .unary_with_headers("/grpc/echo.Echo/Failure", Bytes::new(), &auth)
        .await
        .expect("failed-status RPC response");
    assert_eq!(failure.http_status, 200, "{case}: {failure:?}");
    assert_eq!(failure.grpc_status(), Some(14), "{case}: {failure:?}");

    let charges = wait_for_chargeback_statuses(
        &harness,
        "grpc-chargeback-user",
        "grpc-chargeback",
        &[(200, 1), (503, 1)],
    )
    .await;
    let by_status =
        &charges["consumers"]["grpc-chargeback-user"]["proxies"]["grpc-chargeback"]["by_status"];
    let ok_charge = by_status["200"]["charges"]
        .as_f64()
        .expect("status 200 charge");
    let unavailable_charge = by_status["503"]["charges"]
        .as_f64()
        .expect("status 503 charge");
    assert!((ok_charge - 0.001).abs() < 1e-12, "{case}: {charges:#?}");
    assert!(
        (unavailable_charge - 0.009).abs() < 1e-12,
        "{case}: {charges:#?}"
    );
    assert_eq!(
        charges["consumers"]["grpc-chargeback-user"]["total_calls"].as_u64(),
        Some(2),
        "{case}: {charges:#?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn api_chargeback_prices_streamed_and_buffered_h2_grpc_terminal_status() {
    assert_api_chargeback_uses_terminal_grpc_status(Value::Null, "streamed_h2").await;
    assert_api_chargeback_uses_terminal_grpc_status(
        json!({
            "retry": {
                "max_retries": 1,
                "retry_on_connect_failure": true,
            }
        }),
        "buffered_h2",
    )
    .await;
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — gRPC backend trailers strip hop-by-hop names but preserve status.
// ────────────────────────────────────────────────────────────────────────────
//
// gRPC carries its final status in HTTP/2 trailers. The gateway must forward
// legitimate gRPC/application trailers while filtering RFC 9110 §7.6.1
// response-direction hop-by-hop names. This exercises the live streaming
// response path (`StripHopByHopTrailers`) rather than the unit-only trailer
// collector.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_grpc_response_trailers_strip_hop_by_hop_names() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::new(),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "0".into()),
            ("grpc-message", "ok".into()),
            ("x-application-trailer", "kept".into()),
            ("proxy-authenticate", "Basic realm=\"backend\"".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("unary completes");

    assert_eq!(response.http_status, 200);
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "grpc-status trailer must survive sanitization; trailers={:?}",
        response.trailers
    );
    assert_eq!(response.grpc_message(), Some("ok"));

    let trailers = response
        .trailers
        .as_ref()
        .expect("gateway should forward sanitized gRPC trailers");
    assert_eq!(
        trailers
            .get("x-application-trailer")
            .and_then(|v| v.to_str().ok()),
        Some("kept"),
        "non-hop-by-hop application trailers must be preserved; trailers={trailers:?}"
    );
    assert!(
        trailers.get("proxy-authenticate").is_none(),
        "hop-by-hop trailer `proxy-authenticate` leaked through gateway; trailers={trailers:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6 — H2 flow-control stall on the gRPC path is bounded by
//           `backend_read_timeout_ms`.
// ────────────────────────────────────────────────────────────────────────────
//
// Configures the scripted H2 backend with a tiny initial window (1 byte),
// accepts the RPC headers, then stalls. The request body stalls on the wire
// because the backend never opens the flow-control window, so the gateway
// never gets response headers either.
//
// The gRPC proxy path (`src/proxy/grpc_proxy.rs`) wraps `send_request(...)`
// in a timeout driven by `backend_read_timeout_ms` (see the
// `effective_timeout_ms` match at the top of the streaming/buffered
// dispatch). That single knob covers both the body-upload stall AND the
// time-to-first-byte wait, which is why this test asserts against it.
//
// `backend_write_timeout_ms` is TCP-proxy-only (`src/proxy/tcp_proxy.rs`
// direction-tracking watchdog); it does NOT apply to the gRPC H2 path and
// is intentionally omitted from the overrides below so the assertion is
// load-bearing on the read-timeout knob.
//
// Timing tolerance: ±200ms below, +1500ms above — same envelope as the
// Phase-1 read-timeout test. The watchdog granularity can be multi-second
// on loaded CI; we accept that spread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_window_stall_triggers_backend_read_timeout_on_grpc() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    // Shrink the initial window to one byte so that any request body
    // above that size stalls immediately.
    let settings = ConnectionSettings {
        initial_window_size: Some(1),
        initial_connection_window_size: Some(1),
        max_concurrent_streams: Some(16),
    };
    // Accept the RPC, drain the request body (this will stall on the
    // sender side because the backend never opens the flow-control
    // window), then send headers + stall. The gateway should time out
    // before it even gets response headers.
    let _backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .with_settings(settings)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        // Stall for 30s — the gateway's watchdog should fire far before this.
        .step(H2Step::StallWindowFor(Duration::from_secs(30)))
        .spawn()
        .expect("spawn backend");

    // Drive the test off `backend_read_timeout_ms` alone: it is the knob
    // that the gRPC proxy path actually honors for this stall. Use a
    // tight timeout so the test is fast.
    let read_timeout_ms: u64 = 800;
    let overrides = json!({
        "backend_read_timeout_ms": read_timeout_ms,
    });
    let yaml = grpc_file_config(backend_port, overrides);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let started = Instant::now();
    // Send a modest-sized body — the scripted backend won't issue any
    // WINDOW_UPDATE, so this request's body bytes stall on the wire.
    let _ = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from(vec![b'x'; 4096]))
        .await
        .expect("gateway returns a response or stream error");
    let elapsed = started.elapsed();

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

    let has_timeout_signal = |logs: &str| {
        logs.contains("timeout")
            || logs.contains("Timeout")
            || logs.contains("read_write_timeout")
            || logs.contains("DEADLINE_EXCEEDED")
            || logs.contains("BackendTimeout")
            || logs.contains("Backend timeout")
            || logs.contains("write timeout")
            || logs.contains("read timeout")
    };
    // Poll the captured logs: the gateway emits the timeout line through
    // non-blocking process-log worker, which lags the client-visible
    // response, so a single snapshot races the flush.
    let logs = harness
        .wait_for_log_contains(&has_timeout_signal, Duration::from_secs(5))
        .await;
    assert!(
        has_timeout_signal(&logs),
        "expected timeout signal in gateway logs; elapsed={elapsed:?}, logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6b — direct-H2 buffered response body stalls are bounded by
//            `backend_read_timeout_ms`.
// ────────────────────────────────────────────────────────────────────────────
//
// The direct HTTP/2 backend pool used to wrap only `send_request(...)` with
// `backend_read_timeout_ms`. Once response HEADERS arrived, buffered response
// body collection used an unbounded `collect().await`, so a backend could send
// `:status` and then never send DATA/END_STREAM. This pins the missing second
// deadline: every body-frame wait must also honor `backend_read_timeout_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_buffered_response_body_stall_triggers_backend_read_timeout() {
    let ca = TestCa::new("h2-response-stall").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
            ("content-length", "4".into()),
        ]))
        .step(H2Step::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn backend");

    let read_timeout_ms: u64 = 800;
    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": false,
            "backend_read_timeout_ms": read_timeout_ms,
            "response_body_mode": "buffer",
            "pool_enable_http2": true,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .pool_warmup_enabled(true)
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let started = Instant::now();
    let response = client
        .get(&format!("{}/api/stall", harness.proxy_base_url()))
        .await
        .expect("gateway returns timeout response");
    let elapsed = started.elapsed();
    let body = String::from_utf8_lossy(&response.body_bytes);

    assert_eq!(response.status, StatusCode::GATEWAY_TIMEOUT, "body={body}");
    assert!(
        body.contains("Backend timeout"),
        "unexpected timeout response body: {body}"
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
// Test 7 (bonus) — gRPC pool reuses the same H2 connection for back-to-back
// requests.
// ────────────────────────────────────────────────────────────────────────────
//
// Two sequential successful unary RPCs through the gateway must share a
// single h2 connection at the backend. If every request opens a fresh TCP
// connection, the pool isn't reusing, which is a regression.
//
// Observable: `backend.accepted_connections() == 1` after both requests.
//
// NOTE: on h2c the gateway's gRPC pool opens a connection on first use
// and holds it; when this test was authored the pool was sharded but
// reuse-on-hit. If the sharding policy changes, this test may need
// tuning (e.g. pin to shard 0 via a request header).
//
// Migrated to `HarnessMode::InProcess` — the assertion is on
// `backend.accepted_connections()` and `backend.received_streams()`,
// neither of which depend on captured gateway logs. Inline the harness
// construction (rather than reuse `spawn_grpc_harness`) so we can opt out
// of `capture_output()`, which is binary-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_direct_pool_reuses_connection_across_requests() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        // Two full happy-path RPCs back-to-back. Each matcher +
        // respond block is per-stream; the same connection serves both.
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"one")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"two")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        .spawn()
        .await
        .expect("spawn gateway");

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));

    let r1 = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("first response");
    assert_eq!(r1.grpc_status(), Some(0), "first RPC succeeded");
    assert!(
        r1.messages.iter().any(|m| m.as_ref() == b"one"),
        "first message missing from {:?}",
        r1.messages
    );

    let r2 = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("second response");
    assert_eq!(r2.grpc_status(), Some(0), "second RPC succeeded");
    assert!(
        r2.messages.iter().any(|m| m.as_ref() == b"two"),
        "second message missing from {:?}",
        r2.messages
    );

    // Give the pool a moment to settle its accepted-connection counter.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let backend_streams = backend.received_streams().await;
    assert!(
        backend_streams.len() >= 2,
        "expected at least 2 streams, got {}",
        backend_streams.len()
    );
    // The critical observation: only one TCP connection was accepted.
    // If the pool opened a fresh connection for the second request, this
    // would be >= 2.
    let accepted = backend.accepted_connections();
    assert_eq!(
        accepted, 1,
        "gRPC pool opened {accepted} TCP connections for 2 sequential RPCs; \
         expected connection reuse (each RPC should have ridden the same \
         h2 connection)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_passive_health_ejects_trailer_unavailable_target() {
    let bad_reservation = reserve_port().await.expect("reserve bad backend port");
    let bad_port = bad_reservation.port;
    let mut bad_builder = ScriptedGrpcBackend::builder_plain(bad_reservation.into_listener());
    for _ in 0..6 {
        bad_builder = bad_builder
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondStatus {
                code: 14,
                message: "unavailable",
            });
    }
    let bad_backend = bad_builder.spawn().expect("spawn bad backend");

    let good_reservation = reserve_port().await.expect("reserve good backend port");
    let good_port = good_reservation.port;
    let mut good_builder = ScriptedGrpcBackend::builder_plain(good_reservation.into_listener());
    for _ in 0..16 {
        good_builder = good_builder
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondMessage(Bytes::from_static(b"good")))
            .step(GrpcStep::RespondStatus {
                code: 0,
                message: "",
            });
    }
    let good_backend = good_builder.spawn().expect("spawn good backend");

    let yaml = serde_yaml::to_string(&json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-passive",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": bad_port,
            "strip_listen_path": true,
            "upstream_id": "grpc-passive-upstream",
            "backend_connect_timeout_ms": 1000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
        }],
        "upstreams": [{
            "id": "grpc-passive-upstream",
            "name": "gRPC passive health upstream",
            "algorithm": "round_robin",
            "targets": [
                { "host": "127.0.0.1", "port": bad_port, "weight": 1 },
                { "host": "127.0.0.1", "port": good_port, "weight": 1 },
            ],
            "health_checks": {
                "passive": {
                    "unhealthy_status_codes": [500, 502, 503],
                    "unhealthy_threshold": 1,
                    "unhealthy_window_seconds": 60,
                    "healthy_after_seconds": 60,
                },
            },
        }],
        "consumers": [],
        "plugin_configs": [],
    }))
    .expect("serialize grpc passive config");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        .spawn()
        .await
        .expect("spawn gateway");

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));

    let mut observed_bad = false;
    for i in 0..4 {
        let response = client
            .unary(
                &format!("/grpc/ferrum.Echo/Warmup{i}"),
                Bytes::from_static(b""),
            )
            .await
            .expect("warmup response");
        match response.grpc_status() {
            Some(14) => {
                observed_bad = true;
                break;
            }
            Some(0) => {}
            other => panic!(
                "unexpected warmup grpc-status={other:?}; headers={:?} trailers={:?}",
                response.headers, response.trailers
            ),
        }
    }
    assert!(
        observed_bad,
        "warmup never reached the bad target; bad_streams={} good_streams={}",
        bad_backend.received_stream_count(),
        good_backend.received_stream_count()
    );

    tokio::time::sleep(Duration::from_millis(250)).await;

    for i in 0..8 {
        let response = client
            .unary(
                &format!("/grpc/ferrum.Echo/AfterEject{i}"),
                Bytes::from_static(b""),
            )
            .await
            .expect("post-ejection response");
        assert_eq!(
            response.grpc_status(),
            Some(0),
            "passive health did not eject the grpc-status=14 target; response={response:?}"
        );
        assert!(
            response.messages.iter().any(|m| m.as_ref() == b"good"),
            "healthy backend response missing expected payload; response={response:?}"
        );
    }

    bad_backend.assert_no_step_errors().await;
    good_backend.assert_no_step_errors().await;
}

// A small-but-mighty regression test: the scripted-backend framework
// itself shouldn't prevent the `TestCa` ECDSA cert from building an h2
// ALPN server. This doesn't exercise the gateway; it catches "did we
// wire up the TLS path correctly" regressions so downstream tests don't
// chase phantom gateway bugs when the fixture is broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_tls_backend_fixture_can_complete_handshake() {
    let ca = TestCa::new("scripted-h2-tls").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::new(),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![("grpc-status", "0".into())]))
        .spawn()
        .expect("spawn");

    let client = GrpcClient::tls_insecure(format!("localhost:{port}"));
    let response = client
        .unary("/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("unary completes");
    assert_eq!(response.grpc_status(), Some(0));
    assert_eq!(backend.handshakes_completed(), 1);
}

// A bodyless request has no request-body marker for the governor's reqwest
// preference. The response must still be governed when capability warmup sends
// it through the direct-H2 `StreamingH2` arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bodyless_direct_h2_sse_response_is_governed() {
    const DENIED_SSE: &str = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"rm_rf\",\"arguments\":\"{\\\"path\\\":\\\"/etc\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n",
    );

    let ca = TestCa::new("h2-bodyless-governor").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/event-stream".into()),
            ("content-length", DENIED_SSE.len().to_string()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from_static(DENIED_SSE.as_bytes()),
            end_stream: true,
        })
        .spawn()
        .expect("spawn backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "direct-h2-governor",
            "listen_path": "/events",
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "pool_enable_http2": true,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "governor"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "governor",
            "proxy_id": "direct-h2-governor",
            "plugin_name": "ai_tool_governor",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "mode": "enforce",
                "tools": {"rm_rf": {"action": "deny"}},
                "default_action": "allow",
                "inspect": {
                    "response_tool_calls": false,
                    "streaming_response_tool_calls": true
                },
                "observability": {"emit_metadata": true}
            }
        }, {
            "id": "access-log",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {}
        }]
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        .pool_warmup_enabled(true)
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    // Direct-H2 dispatch (`ResponseBody::StreamingH2`) only engages once the
    // async warmup probe has classified the backend h2-over-TLS capable.
    // Until then the request falls back to the reqwest arm, which governed SSE
    // before this PR — so without this gate a regression that stopped wiring
    // the inspector onto `StreamingH2` could still pass here. Prove the
    // direct-H2 arm is reachable before firing the request.
    let entry = wait_for_h2_tls_supported(&harness, Duration::from_secs(15))
        .await
        .expect("backend must be classified h2_tls=supported for the direct-H2 arm");
    assert_eq!(
        entry["plain_http"]["h2_tls"].as_str(),
        Some("supported"),
        "precondition: direct-H2 streaming arm requires h2_tls=supported; entry: {entry:#?}"
    );

    let response = reqwest::Client::new()
        .get(harness.proxy_url("/events/live"))
        .send()
        .await
        .expect("bodyless request");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("content-length").is_none(),
        "an attached inspector may cut or transform the body"
    );
    let body = response.text().await.expect("response body");
    assert!(
        body.contains("ai_tool_governor_tool_blocked"),
        "governor must terminate the direct-H2 stream: {body}"
    );
    assert!(
        !body.contains("/etc"),
        "held denied tool-call frames must not leak: {body}"
    );
    let logs = harness
        .wait_for_log_contains(
            &|logs: &str| logs.contains("ai_tool_governor.decision") && logs.contains("deny"),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        logs.contains("ai_tool_governor.decision") && logs.contains("deny"),
        "stream-terminal metadata must be written before summary logging: {logs}"
    );
    assert!(backend.received_stream_count() >= 1);
    let step_errors = backend.step_errors().await;
    let unexpected_step_errors: Vec<_> = step_errors
        .iter()
        // Capability warmup may open a speculative H2 connection and drop it
        // before sending the client preface. The governed response and received
        // GET above prove the real direct-H2 connection completed; do not treat
        // that independent probe disconnect as a script failure.
        .filter(|error| {
            !error.starts_with("h2 handshake failed: connection error detected: unspecific protocol error detected")
        })
        .collect();
    assert!(
        unexpected_step_errors.is_empty(),
        "{} unexpected script step error(s): {unexpected_step_errors:?}",
        unexpected_step_errors.len()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Tests 8–10 — `preserve_host_header` semantics on the gRPC dispatch path.
// ────────────────────────────────────────────────────────────────────────────
//
// PR 492 backfilled `ctx.headers["host"]` from `:authority` whenever the
// HTTP/2 (or HTTP/3) client sent only the pseudo-header — necessary so
// X-Forwarded-Host, RFC 7239 Forwarded, and `preserve_host_header=true`
// downstream consumers see a usable Host. The plain HTTP and direct H2
// pool paths already applied the per-route `preserve_host_header=false`
// override that swaps the synthesized value for the upstream target host
// before dispatch (see `proxy::proxy_to_backend` and
// `proxy::proxy_to_backend_http2`). The gRPC dispatch path did not, so
// real H2/H3 gRPC clients (which send only `:authority` by convention)
// silently leaked their external authority to the backend even when
// `preserve_host_header` was at its default `false`.
//
// These tests pin both modes across both gRPC dispatch entry points:
//
//   - Test 8 — default (`preserve_host_header=false`), streaming fast path
//     (`proxy_grpc_request_streaming`). Backend Host == upstream target.
//   - Test 9 — `preserve_host_header=true`, streaming fast path. Backend
//     Host == client `:authority`.
//   - Test 10 — default, buffered path via `proxy_grpc_request_core`
//     (forced by configuring retries, which makes the body replayable so
//     the gateway must collect it before dispatch). Backend Host == upstream
//     target — the override fires symmetrically with the streaming path.
//
// All three drive the gateway via `GrpcClient::h2c`, which sends an H2
// HEADERS frame with `:authority = 127.0.0.1:{gw_port}` and *no* explicit
// `host` header — the canonical wire shape for hyper, tonic, grpc-go, and
// every other production gRPC client. The scripted backend captures the
// regular `host` header that appears alongside the forwarded `:authority`
// (`ReceivedStream::headers` excludes pseudo-headers). The gateway's
// upstream `:authority` is always the backend target — what these tests
// pin is the regular Host header that travels with it.

/// Streaming path (no retries, no body hooks): when `preserve_host_header`
/// is at its default `false`, the gateway must override the synthesized
/// Host with the upstream target host before forwarding to the gRPC
/// backend. Without the override, an H2/H3 client's `:authority` would
/// be leaked downstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_grpc_preserve_false_overrides_client_authority_to_target_host() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    // Default config: `preserve_host_header` omitted, so it serializes as
    // `false` and the override fires. No retries → streaming dispatch
    // (`proxy_grpc_request_streaming`).
    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("unary completes");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "RPC must succeed for the host assertion to be meaningful"
    );

    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 1, "expected exactly one RPC at backend");
    let host_header = streams[0].header("host");
    assert_eq!(
        host_header,
        Some("127.0.0.1"),
        "preserve_host_header=false: backend Host should be the upstream target host (127.0.0.1), \
         not the client's :authority. Without the override the synthesized Host (= client \
         :authority `127.0.0.1:{gw_port}`) would leak to the gRPC backend. \
         received headers: {:?}",
        streams[0].headers
    );
}

/// Streaming path with `preserve_host_header=true`: the synthesized Host
/// must be forwarded unchanged so the backend sees the client's
/// `:authority`. Pins the symmetric "preserve actually preserves" half
/// of the contract for the gRPC dispatch path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_grpc_preserve_true_forwards_client_authority_as_host() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let overrides = json!({ "preserve_host_header": true });
    let yaml = grpc_file_config(backend_port, overrides);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("unary completes");
    assert_eq!(response.grpc_status(), Some(0));

    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 1, "expected exactly one RPC at backend");
    let expected_host = format!("127.0.0.1:{gw_port}");
    let host_header = streams[0].header("host");
    assert_eq!(
        host_header,
        Some(expected_host.as_str()),
        "preserve_host_header=true: backend Host should equal the H2 client's :authority \
         ({expected_host}). Without the synthesis fix from PR 492, no Host would reach \
         the backend at all. received headers: {:?}",
        streams[0].headers
    );
}

/// Buffered gRPC path: when retries are configured the gateway must collect
/// the request body before dispatch so it can replay on retry, exercising the
/// buffered code path rather than the streaming fast path. The override must
/// fire there too — regression guard against drift between buffered and
/// streaming dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_grpc_preserve_false_buffered_path_overrides_host_to_target() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    // Configure retries so the gateway picks buffered dispatch instead of the
    // streaming fast path. The first attempt succeeds, so no actual retry
    // fires — we just need the buffered code path executed once.
    let overrides = json!({
        "retry": {
            "max_retries": 1,
            "retry_on_connect_failure": true,
        }
    });
    let yaml = grpc_file_config(backend_port, overrides);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary("/grpc/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("unary completes");
    assert_eq!(response.grpc_status(), Some(0));

    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 1, "expected exactly one RPC at backend");
    let host_header = streams[0].header("host");
    assert_eq!(
        host_header,
        Some("127.0.0.1"),
        "preserve_host_header=false on the buffered gRPC path: backend Host should be \
         the upstream target host (127.0.0.1). Drift between proxy_grpc_request_streaming \
         and proxy_grpc_request_core would surface here. received headers: {:?}",
        streams[0].headers
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Request-side gRPC metadata sanitization.
// ────────────────────────────────────────────────────────────────────────────
//
// `proxy-authorization` is hop-by-hop on backend-bound requests and must not
// leak to the gRPC upstream. Normal end-to-end metadata must still pass, and
// the gRPC-specific `te: trailers` requirement must be present on the backend
// request even if the generic hop-by-hop strip removes client-supplied `te`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_grpc_request_headers_strip_hop_by_hop_metadata() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"ok")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_file_config(backend_port, Value::Null);
    let harness = spawn_grpc_harness(yaml).await;

    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));
    let response = client
        .unary_with_headers(
            "/grpc/ferrum.Echo/Ping",
            Bytes::from_static(b""),
            &[
                ("authorization", "Bearer keep".to_string()),
                ("x-application-header", "kept".to_string()),
                ("proxy-authorization", "Bearer strip".to_string()),
            ],
        )
        .await
        .expect("unary completes");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "RPC must succeed for backend header assertions; response={response:?}"
    );

    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 1, "expected exactly one RPC at backend");
    let stream = &streams[0];
    assert_eq!(
        stream.header("authorization"),
        Some("Bearer keep"),
        "end-to-end authorization metadata must be forwarded; headers={:?}",
        stream.headers
    );
    assert_eq!(
        stream.header("x-application-header"),
        Some("kept"),
        "application metadata must be forwarded; headers={:?}",
        stream.headers
    );
    assert_eq!(
        stream.header("te"),
        Some("trailers"),
        "gRPC backend requests must include te: trailers; headers={:?}",
        stream.headers
    );
    assert!(
        stream.header("proxy-authorization").is_none(),
        "backend MUST NOT see hop-by-hop proxy-authorization metadata; headers={:?}",
        stream.headers
    );
}

/// #2934: retry attempts must preserve duplicate metadata field lines from
/// the real collected HeaderMap (not rebuild from stringified ctx.headers).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_retry_preserves_duplicate_metadata_on_second_attempt() {
    let down = reserve_port().await.expect("reserve down port");
    let down_port = down.port;
    drop(down); // refuse connections

    let up = reserve_port().await.expect("reserve up port");
    let up_port = up.port;
    let backend = ScriptedGrpcBackend::builder_plain(up.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let proxy = json!({
        "id": "grpc-scripted",
        "listen_path": "/grpc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": down_port,
        "strip_listen_path": true,
        "upstream_id": "grpc-retry-md",
        "retry": {
            "max_retries": 1,
            "retry_on_connect_failure": true,
            "backoff": { "fixed": { "delay_ms": 1 } },
        },
        "backend_connect_timeout_ms": 500,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
    });
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [{
            "id": "grpc-retry-md",
            "algorithm": "round_robin",
            "targets": [
                { "host": "127.0.0.1", "port": down_port, "weight": 100 },
                { "host": "127.0.0.1", "port": up_port, "weight": 100 },
            ],
        }],
        "plugin_configs": [{
            "id": "access-log",
            "plugin_name": "stdout_logging",
            "config": {},
            "scope": "global",
            "enabled": true,
        }],
    });
    // Tagged-enum aware: `retry.backoff` must reach the loader as `!fixed`.
    let yaml = to_file_mode_yaml(&config);
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .env("RUST_LOG", "info")
        // Warmup would dial both targets at startup and advance the
        // round-robin counter, so attempt 1 could land on the LIVE target and
        // the retry path would never run — the assertion below would then
        // pass against the un-fixed code.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");
    let gw_port = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gw_port}"));

    let response = client
        .unary_with_headers(
            "/grpc/ferrum.Echo/Ping",
            Bytes::from_static(b""),
            &[("x-md", "a".to_string()), ("x-md", "b".to_string())],
        )
        .await
        .expect("RPC response");
    assert_eq!(response.grpc_status(), Some(0), "{response:?}");

    // Prove the observed stream came from a RETRY, not from a first attempt
    // that happened to select the live target. Without this the duplicate-
    // metadata assertion is satisfied by the (always-correct) initial attempt.
    let saw_grpc_retry = |logs: &str| logs.contains("Retrying gRPC backend request");
    let logs = harness
        .wait_for_log_contains(&saw_grpc_retry, Duration::from_secs(5))
        .await;
    assert!(
        saw_grpc_retry(&logs),
        "the gRPC retry loop must have fired (attempt 1 hit the refused port); \
         without a retry this test cannot observe retry headers"
    );

    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 1, "only the live target should see the RPC");
    let md_values: Vec<&str> = streams[0]
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("x-md"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        md_values,
        ["a", "b"],
        "retry attempt must forward duplicate x-md as two field lines; headers={:?}",
        streams[0].headers
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Issue #2952 — spoofed client Forwarded must not survive on direct-H2.
// ────────────────────────────────────────────────────────────────────────────

/// With `FERRUM_ADD_FORWARDED_HEADER=true`, the direct-H2 builder must strip a
/// spoofed client `Forwarded` and emit exactly one gateway-owned element.
///
/// Fixture notes (hosted jobs 89647762460 / 89765485950 returned a 502 here):
///
/// 1. **Body-size gate (deterministic)**: ordinary (non-SNI) direct-H2 dispatch
///    requires `FERRUM_MAX_{REQUEST,RESPONSE}_BODY_SIZE_BYTES=0` via
///    `can_dispatch_direct_http2_pool`. Defaults leave those nonzero, so the
///    request falls through to reqwest against this ALPN-`h2`-only fixture and
///    surfaces as `502 {"error":"Backend unavailable"}` with
///    `error sending request for url (...)` — even when the registry already
///    shows `h2_tls=supported`. Mirror `bodyless_direct_h2_sse_response_is_governed`.
///
/// 2. **Pooled probe / warmup connections**: capability probing and pool
///    warmup dial this backend before the ownership GET. A one-shot script
///    closes those connections after its final step, so a later request that
///    reuses a pooled sender can 502. `repeat_script(true)` keeps every
///    accepted connection serving unbounded streams. Warmup is enabled so the
///    registry populates; the test still gates on `h2_tls=supported` before
///    firing the ownership GET.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h2_strips_spoofed_client_forwarded_when_regenerating() {
    let ca = TestCa::new("h2-forwarded-ownership").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
            ("content-length", "2".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": false,
            "pool_enable_http2": true,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        // Opt into capability probing (registry gate below) and zero body
        // limits so ordinary (non-SNI) dispatch stays on the direct-H2 pool —
        // same contract as `bodyless_direct_h2_sse_response_is_governed`.
        // `repeat_script(true)` absorbs any warmup `HEAD /` on the same
        // connection without tearing it down.
        .pool_warmup_enabled(true)
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .env("FERRUM_ADD_FORWARDED_HEADER", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    let entry = wait_for_h2_tls_supported(&harness, Duration::from_secs(15))
        .await
        .expect("backend must be classified h2_tls=supported for the direct-H2 arm");
    assert_eq!(
        entry["plain_http"]["h2_tls"].as_str(),
        Some("supported"),
        "precondition: direct-H2 ownership coverage requires h2_tls=supported; entry: {entry:#?}"
    );

    let response = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
        .get(harness.proxy_url("/api/ownership"))
        .header(reqwest::header::HOST, "example.com")
        .header("forwarded", "for=10.0.0.1;proto=https")
        .send()
        .await
        .expect("gateway response");
    let status = response.status();
    let body = response.text().await.expect("response body");
    if status != StatusCode::OK {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!(
            "direct-H2 ownership request must succeed; status={status} body={body}\n\
             --- registry: {entry:#?}\n--- logs ---\n{logs}"
        );
    }
    assert_eq!(
        body, "ok",
        "direct-H2 ownership path must reach the scripted backend"
    );

    let streams = backend.received_streams().await;
    let stream = streams
        .iter()
        .find(|s| s.method == "GET" && s.path == "/ownership")
        .unwrap_or_else(|| {
            panic!(
                "direct-H2 backend never received the ownership GET — path not exercised. \
                 streams={streams:#?}"
            )
        });
    let forwarded: Vec<&str> = stream
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("forwarded"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        forwarded,
        vec!["for=127.0.0.1;proto=http;host=example.com"],
        "direct-H2 path must emit exactly one gateway-owned Forwarded; got {forwarded:?} \
         (headers={:?})",
        stream.headers
    );
    assert!(
        forwarded.iter().all(|v| !v.contains("10.0.0.1")),
        "spoofed client Forwarded must not reach the direct-H2 backend: {forwarded:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Issue #2954 — backend TLS SNI override must serve under default nonzero
// body-size limits (direct-H2 in-path enforcement), not 502 all traffic.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_backend_tls_sni_serves_under_default_body_limits() {
    let ca = TestCa::new("h2-sni-default-limits").expect("ca");
    // Cert SAN is other.test — dial host is connect.example.com, so verification
    // only succeeds when the gateway presents backend_tls_sni=other.test.
    let (cert, key) = ca.wrong_san().expect("leaf");
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write CA");

    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
            ("content-length", "2".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn backend");

    let yaml = serde_yaml::to_string(&json!({
        "version": "1",
        "proxies": [{
            "id": "sni-proxy",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "connect.example.com",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "upstream_id": "sni-upstream",
            "pool_enable_http2": true,
            "dns_override": "127.0.0.1",
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
        }],
        "upstreams": [{
            "id": "sni-upstream",
            "name": "SNI upstream",
            "algorithm": "round_robin",
            "targets": [{
                "host": "connect.example.com",
                "port": backend_port,
                "weight": 1
            }],
            "backend_tls_sni": "other.test",
            "backend_tls_verify_server_cert": true,
            "backend_tls_server_ca_cert_path": ca_path.display().to_string(),
        }],
        "consumers": [],
        "plugin_configs": [],
    }))
    .expect("yaml");

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Intentionally leave FERRUM_MAX_*_BODY_SIZE_BYTES at defaults
        // (response default 10 MiB). Pre-fix this combination 502'd every
        // request with backend_tls_sni_requires_direct_h2.
        .pool_warmup_enabled(true)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let response = client
        .get(&format!("{}/api/sni", harness.proxy_base_url()))
        .await
        .expect("SNI override must serve under default body limits");
    let body = String::from_utf8_lossy(&response.body_bytes);
    assert_eq!(
        response.status,
        StatusCode::OK,
        "expected 200 via direct-H2 SNI under default body limits; body={body}"
    );
    assert_eq!(body, "ok");
}

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
/// `stdout_logging` access-log routes through `tracing-appender`'s
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

/// Build a file-mode YAML that points a gRPC proxy at the given port over
/// plain HTTP (h2c — the gateway's gRPC pool performs an h2c handshake
/// when `backend_scheme: http`). Callers can merge additional overrides
/// into the proxy definition via `overrides`.
fn grpc_file_config(port: u16, overrides: Value) -> String {
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
            "config": {},
            "scope": "global",
            "enabled": true,
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
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
        .step(GrpcStep::SendInitialHeaders)
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
        .step(H2Step::Sleep(Duration::from_secs(30)))
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
    // tracing-appender's non-blocking writer, which lags the client-visible
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

/// Buffered path (`proxy_grpc_request` → `proxy_grpc_request_core`): when
/// retries are configured the gateway must collect the request body before
/// dispatch so it can replay on retry, exercising the buffered code path
/// rather than the streaming fast path. The override must fire there too —
/// regression guard against drift between the two functions.
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

    // Configure retries so the gateway picks the buffered dispatch
    // (`proxy_grpc_request` → `proxy_grpc_request_core`) instead of the
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

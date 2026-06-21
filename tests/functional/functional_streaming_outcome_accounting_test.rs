//! Functional coverage for issue #1649 items 2 & 3 — streaming-body outcome
//! accounting.
//!
//! Before the fix, backend **dispatch** accounting (circuit breaker, passive
//! health, least-latency) for a streaming response was recorded at
//! response-**header** time. A backend that sends `2xx` headers then stalls the
//! body (cut by `backend_read_timeout_ms`, #1626) was banked as a healthy
//! success and never corrected. These tests assert the adversarial scenario the
//! issue calls for: a `2xx`-then-stall streaming response must record a circuit
//! breaker FAILURE (at body completion), and with `failure_threshold: 1` that
//! single stall trips the breaker so the NEXT request is short-circuited and
//! never reaches the backend.
//!
//! * gRPC streaming  → item 3 (`with_deferred_backend_dispatch_outcome` now
//!   records the breaker at body completion instead of `skip_circuit_breaker_record`).
//! * direct-H2 / HBONE streaming (`ResponseBody::StreamingH2`) → item 2 (the
//!   header-time record is deferred; the HALF_OPEN probe slot is released
//!   promptly via `record_neutral`).
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests streaming_outcome_accounting -- --ignored --nocapture`.

use crate::scaffolding::backends::{
    GrpcStep, H2Step, MatchHeaders, MatchRpc, ScriptedGrpcBackend, ScriptedH2Backend,
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

/// `circuit_breaker` config that trips on the FIRST post-wire failure
/// (`failure_threshold: 1`, `trip_on_connection_errors: true`) and stays open
/// long enough for the follow-up request to be short-circuited.
fn trip_on_first_failure_cb() -> Value {
    json!({
        "failure_threshold": 1,
        "success_threshold": 1,
        "timeout_seconds": 30,
        "failure_status_codes": [500, 502, 503, 504],
        "half_open_max_requests": 1,
        "trip_on_connection_errors": true,
    })
}

/// File-mode YAML for a gRPC (h2c) backend with a circuit breaker.
fn grpc_cb_file_config(port: u16, read_timeout_ms: u64, circuit_breaker: Value) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-cb",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "circuit_breaker": circuit_breaker,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn gateway_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port")
}

// ────────────────────────────────────────────────────────────────────────────
// Item 3 — gRPC streaming: 2xx headers then stall must trip the breaker.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_streaming_2xx_then_stall_trips_circuit_breaker() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let read_timeout_ms: u64 = 600;

    // Exactly ONE RPC sequence: accept, send 200 gRPC response headers, then
    // stall. The gateway cuts the stalled streaming response body at
    // `backend_read_timeout_ms`, which #1649 item 3 records as a circuit-breaker
    // failure at body completion. A SECOND backend stream would appear only if
    // the breaker failed to trip (the regression this guards).
    // `StallAfterHeaders` already sends the 200 `application/grpc` response
    // headers itself, then sleeps — so do NOT precede it with
    // `SendInitialHeaders` (that would emit a second HEADERS frame and the
    // gateway would error on the malformed response before the body stalls).
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::StallAfterHeaders(Duration::from_millis(
            read_timeout_ms + 2_000,
        )))
        .spawn()
        .expect("spawn backend");

    let yaml = grpc_cb_file_config(backend_port, read_timeout_ms, trip_on_first_failure_cb());
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_port(&harness)));

    // Request 1: 2xx headers + stall → gateway read-timeout → breaker records a
    // failure at body completion → trips (failure_threshold: 1). The client sees
    // 200 headers then a body/stream error when the gateway cuts the stalled body.
    let started = Instant::now();
    let _ = client
        .unary("/api/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await;
    let first_elapsed = started.elapsed();
    assert_eq!(
        backend.received_stream_count(),
        1,
        "the stall request must reach the backend"
    );
    assert!(
        first_elapsed >= Duration::from_millis(read_timeout_ms.saturating_sub(250)),
        "stall request returned too fast ({first_elapsed:?}); expected the ~{read_timeout_ms}ms read-timeout to cut the body"
    );

    // Request 2: the breaker is OPEN → short-circuited. It must NOT reach the
    // backend, must be fast (no read-timeout wait), and must surface as a
    // circuit-open gRPC reject (503 → UNAVAILABLE/14).
    let started = Instant::now();
    let second = client
        .unary("/api/ferrum.Echo/Ping", Bytes::from_static(b""))
        .await
        .expect("circuit-open reject surfaces");
    let second_elapsed = started.elapsed();
    assert_eq!(
        backend.received_stream_count(),
        1,
        "circuit breaker must short-circuit the 2nd request — it must NOT reach the backend \
         (a 2nd backend stream means the 2xx-then-stall did not record a breaker failure)"
    );
    assert!(
        second_elapsed < Duration::from_millis(read_timeout_ms),
        "2nd request was not short-circuited (took {second_elapsed:?}, ~the read timeout) — breaker did not trip"
    );
    assert_eq!(
        second.grpc_status(),
        Some(14),
        "circuit-open gRPC reject must be UNAVAILABLE (14); trailers={:?}",
        second.trailers
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Item 2 — direct-H2 (StreamingH2) streaming: 2xx headers then stall must trip
// the breaker.
// ────────────────────────────────────────────────────────────────────────────
//
// `pool_enable_http2 + warmup` route this through the direct H2 pool
// (`ResponseBody::StreamingH2`), which is the arm #1649 item 2 changed. The
// response is streamed (no `content-length`, no `response_body_mode: buffer`),
// so 200 headers reach the client before the body stalls — exactly the case
// that previously banked a phantom header-time success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_streaming_2xx_then_stall_trips_circuit_breaker() {
    h2_streaming_status_then_stall_trips_circuit_breaker(200).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_streaming_non_failure_4xx_then_stall_trips_circuit_breaker() {
    h2_streaming_status_then_stall_trips_circuit_breaker(404).await;
}

async fn h2_streaming_status_then_stall_trips_circuit_breaker(status: u16) {
    let ca = TestCa::new(&format!("h2-stall-cb-{status}")).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let read_timeout_ms: u64 = 700;

    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        // Headers WITHOUT content-length → the gateway streams (StreamingH2),
        // flushing headers to the client before the body, then stalls.
        .step(H2Step::RespondHeaders(vec![
            (":status", status.to_string()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::Sleep(Duration::from_millis(
            read_timeout_ms + 2_000,
        )))
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": false,
            "backend_read_timeout_ms": read_timeout_ms,
            "pool_enable_http2": true,
            "circuit_breaker": trip_on_first_failure_cb(),
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Direct-H2 dispatch (`can_dispatch_direct_http2_pool`) requires BOTH
        // body-size limits at 0 — otherwise the request stays on the reqwest
        // path (so local 413 checks run first) and never reaches the
        // `StreamingH2` arm this test exercises. The buffer cutoff at 0 then
        // selects the direct-streaming H2 body (no coalescing buffer).
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0")
        // Warmup classifies the backend as h2_tls in the capability registry
        // BEFORE traffic, so request 1 dispatches via the direct H2 pool
        // (StreamingH2) rather than reqwest.
        .pool_warmup_enabled(true)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let base = harness.proxy_base_url();

    // Warmup probes the backend on its own connection, so use relative deltas.
    let streams_before = backend.received_stream_count();

    // Request 1: streamable headers plus a body stall → gateway read-timeout
    // cuts it → breaker records a failure at body completion → trips.
    let started = Instant::now();
    let _ = client.get(&format!("{base}/api/stall")).await;
    let first_elapsed = started.elapsed();
    let streams_after_1 = backend.received_stream_count();
    assert_eq!(
        streams_after_1,
        streams_before + 1,
        "the stall request must reach the backend"
    );
    assert!(
        first_elapsed >= Duration::from_millis(read_timeout_ms.saturating_sub(300)),
        "stall request returned too fast ({first_elapsed:?}); expected the ~{read_timeout_ms}ms read-timeout to cut the body"
    );

    // Request 2: breaker OPEN → short-circuited 503, never reaches the backend.
    let started = Instant::now();
    let second = client
        .get(&format!("{base}/api/stall"))
        .await
        .expect("circuit-open 503 surfaces");
    let second_elapsed = started.elapsed();
    assert_eq!(
        backend.received_stream_count(),
        streams_after_1,
        "circuit breaker must short-circuit the 2nd request — it must NOT reach the backend \
         (a new backend stream means the {status}-then-stall did not record a breaker failure)"
    );
    assert_eq!(
        second.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "open circuit breaker must return 503"
    );
    assert!(
        second_elapsed < Duration::from_millis(read_timeout_ms),
        "2nd request was not short-circuited (took {second_elapsed:?}) — breaker did not trip"
    );
}

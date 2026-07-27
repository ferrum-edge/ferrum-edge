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
//! * native-H3 streaming (`ResponseBody::StreamingH3`) → #1901 (the same
//!   response-body terminal outcome now drives CB/passive-health accounting).
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests streaming_outcome_accounting -- --ignored --nocapture`.

use crate::scaffolding::backends::{
    GrpcStep, H2Step, H3Step, H3TlsConfig, MatchHeaders, MatchRpc, ScriptedGrpcBackend,
    ScriptedH2Backend, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GrpcClient, Http2Client};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};
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

async fn wait_for_h3_capability_supported(harness: &GatewayHarness, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let body = harness
            .get_admin_json("/backend-capabilities")
            .await
            .expect("backend capability registry");
        let h3 = body["entries"]
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry["plain_http"]["h3"].as_str());
        if h3 == Some("supported") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for h3=supported capability entry; latest={body:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn h3_cb_file_config(port: u16, read_timeout_ms: u64, circuit_breaker: Value) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-cb",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "circuit_breaker": circuit_breaker,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
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
    // GrpcClient uses hyper H2 prior knowledge and does not retry connect, so
    // wait until the proxy listener accepts — `/health` alone can race ahead of
    // the proxy accept queue on a loaded CI runner.
    harness
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

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
    // Same prior-knowledge H2 client race as the gRPC stall test: wait for the
    // proxy accept queue before the first client connect.
    harness
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

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

// ────────────────────────────────────────────────────────────────────────────
// #1901 — native-H3 (StreamingH3) streaming: 2xx headers then stall must trip
// the breaker at body completion, matching direct-H2.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_streaming_2xx_then_stall_trips_circuit_breaker() {
    let ca = TestCa::new("h3-stall-cb").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;
    let read_timeout_ms: u64 = 700;

    // TCP+TLS sidecar answers non-H3 capability probes on the same backend port.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls sidecar");
    Box::leak(Box::new(_tcp_backend));

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .steps(vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::StallFor(Duration::from_millis(read_timeout_ms + 2_000)),
        ])
        .spawn()
        .expect("spawn h3 backend");

    let yaml = h3_cb_file_config(backend_port, read_timeout_ms, trip_on_first_failure_cb());
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .capture_output()
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    wait_for_h3_capability_supported(&harness, Duration::from_secs(15)).await;
    let client = reqwest::Client::new();
    let base = harness.proxy_base_url();
    let requests_before = h3_backend.received_requests().await.len();

    // Request 1: streamable 200 headers plus stalled body. The client must
    // consume the body so `ProxyBody` observes the H3 read-timeout terminal and
    // deferred dispatch records the breaker failure.
    let started = Instant::now();
    let first = client
        .get(format!("{base}/api/stall"))
        .send()
        .await
        .expect("first response headers");
    assert_eq!(first.status(), StatusCode::OK);
    let _ = first.bytes().await;
    let first_elapsed = started.elapsed();
    let requests_after_1 = h3_backend.received_requests().await.len();
    assert_eq!(
        requests_after_1,
        requests_before + 1,
        "the stall request must reach the H3 backend"
    );
    assert!(
        first_elapsed >= Duration::from_millis(read_timeout_ms.saturating_sub(300)),
        "stall request returned too fast ({first_elapsed:?}); expected the ~{read_timeout_ms}ms read-timeout to cut the body"
    );

    // Request 2: breaker OPEN -> short-circuited 503, never reaches H3.
    let started = Instant::now();
    let second = client
        .get(format!("{base}/api/stall"))
        .send()
        .await
        .expect("circuit-open 503 surfaces");
    let second_elapsed = started.elapsed();
    assert_eq!(
        h3_backend.received_requests().await.len(),
        requests_after_1,
        "circuit breaker must short-circuit the 2nd request; another H3 request means the 2xx-then-stall did not record a breaker failure"
    );
    assert_eq!(
        second.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "open circuit breaker must return 503"
    );
    assert!(
        second_elapsed < Duration::from_millis(read_timeout_ms),
        "2nd request was not short-circuited (took {second_elapsed:?}) — breaker did not trip"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_streaming_complete_content_length_body_keeps_circuit_breaker_closed() {
    let ca = TestCa::new("h3-complete-content-length-cb").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;
    let read_timeout_ms: u64 = 700;

    // TCP+TLS sidecar answers non-H3 capability probes on the same backend port.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls sidecar");
    Box::leak(Box::new(_tcp_backend));

    let first_body = Bytes::from(vec![b'h'; 4096]);
    let second_body = Bytes::from_static(b"ok");
    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .steps(vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-length", first_body.len().to_string()),
                ("content-type", "application/octet-stream".to_string()),
            ]),
            H3Step::RespondData(first_body.clone()),
            H3Step::RespondTrailers(Vec::new()),
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-length", second_body.len().to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::RespondData(second_body.clone()),
            H3Step::RespondTrailers(Vec::new()),
            H3Step::StallFor(Duration::from_millis(50)),
        ])
        .spawn()
        .expect("spawn h3 backend");

    let yaml = h3_cb_file_config(backend_port, read_timeout_ms, trip_on_first_failure_cb());
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .capture_output()
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    wait_for_h3_capability_supported(&harness, Duration::from_secs(15)).await;
    let client = reqwest::Client::new();
    let base = harness.proxy_base_url();
    let requests_before = h3_backend.received_requests().await.len();

    // Request 1: a healthy native-H3 body yields exactly the declared
    // Content-Length. For an HTTP/1.x downstream, hyper can finish sending the
    // response at that byte boundary and drop the body before polling H3
    // trailers/FIN. The success-on-drop hint must classify that as success, not
    // ClientDisconnect, so the breaker stays closed.
    let first = client
        .get(format!("{base}/api/complete"))
        .send()
        .await
        .expect("first response headers");
    assert_eq!(first.status(), StatusCode::OK);
    let first_bytes = first.bytes().await.expect("first body");
    assert_eq!(first_bytes, first_body);
    let requests_after_1 = h3_backend.received_requests().await.len();
    assert_eq!(
        requests_after_1,
        requests_before + 1,
        "the complete fixed-length request must reach the H3 backend"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Request 2: the breaker should still be CLOSED. It must reach the backend;
    // a 503 here, or an unchanged H3 request count, means the completed first
    // body was misclassified as a client disconnect.
    let second = client
        .get(format!("{base}/api/after-complete"))
        .send()
        .await
        .expect("second response headers");
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "complete H3 content-length body must not trip the breaker"
    );
    let _ = second.bytes().await.expect("second body");
    assert_eq!(
        h3_backend.received_requests().await.len(),
        requests_after_1 + 1,
        "the 2nd request must reach H3; otherwise the first complete body opened the breaker"
    );
}

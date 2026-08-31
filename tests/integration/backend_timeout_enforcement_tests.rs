//! In-process HTTP-family backend timeout enforcement (#4055 / #4057 / #4411).
//!
//! `#4055` — a backend that accepts and never reads must surface a 504 write
//! timeout near `backend_write_timeout_ms`, not hang until the client gives up.
//! `#4411` — the same contract must hold when the POST fits in the local send
//! buffer, so the upload pump reaches a clean EOS without socket backpressure.
//! `#4057` — an SSE/chunked stall *after* headers must wait out
//! `backend_read_timeout_ms` (idle-between-frames) instead of tearing the
//! stream down immediately as `request_error`. Header-only stalls already 504
//! (`tests/integration/scripted_backend_smoke_tests.rs`, closed #3922).
//!
//! Protocol-path coverage beyond H1 lives in the scripted-backend functional
//! suite (`scripted_backend_tests.rs`, `scripted_backend_h2_tests.rs`,
//! `scripted_backend_h3_tests.rs`).

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, TcpStep,
};
use crate::scaffolding::clients::Http2Client;
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use ferrum_edge::_test_support::{GrpcBufferedUploadPumpProbe, ProbePumpOutcome, ProbeReplayFrame};
use futures_util::StreamExt;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const WRITE_TIMEOUT_MS: u64 = 800;
const READ_TIMEOUT_MS: u64 = 800;
// Pin the listener before accept so the backend cannot autotune a large receive
// window. The upload remains larger than ordinary sender buffers, guaranteeing
// that a backend which never reads eventually backpressures the upload pump.
const BACKEND_RECEIVE_BUFFER_BYTES: usize = 1024;
const UPLOAD_STALL_BYTES: usize = 8 * 1024 * 1024;
// Issue #4411 repro size: 2 MiB fits in a typical loopback send buffer, so the
// pump completes a clean EOS without socket backpressure. The header-wait
// write bound must still fire.
const KERNEL_ABSORB_UPLOAD_BYTES: usize = 2 * 1024 * 1024;
// Large enough to backpressure against a 1 KiB receive window so the pump
// stays in `reserve()` and genuine consume progress can refresh the idle.
const PROGRESSING_UPLOAD_BYTES: usize = 256 * 1024;
const PROGRESSING_READ_CHUNK: usize = 32 * 1024;
const SSE_FIRST_EVENT: &[u8] = b"data: hello\r\n\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_write_pump_publishes_clean_terminal_before_closing_bridge() {
    // Native gRPC defers the write watermark until sender acquisition and arms
    // before production `send_request()`. This synthetic ordering reaches EOS
    // first to prove the two shared facts cannot park the pump or start the
    // holdover early when observed in the opposite order.
    let mut probe = GrpcBufferedUploadPumpProbe::start(1, &[], 50);
    assert!(probe.pumped(), "a live write bound must install the pump");

    let frames = tokio::time::timeout(Duration::from_secs(2), probe.drain_transport(1024))
        .await
        .expect("deferred pump reaches a terminal transport frame");
    assert_eq!(
        frames,
        vec![ProbeReplayFrame::Data(1), ProbeReplayFrame::Ended],
        "a closed bridge after clean source EOS must never surface ConsumerGone"
    );
    assert!(
        probe
            .write_watermark_stays_dormant(Duration::from_millis(150))
            .await,
        "draining the transport must not arm the dispatcher-owned watermark"
    );

    // The response-wait holdover now lives independently of the coordinator
    // task. A dormant dispatcher-owned watermark therefore leaves this clean
    // body completion settled rather than parking the coordinator until cancel.
    assert_eq!(probe.cancel_and_join().await, ProbePumpOutcome::Completed);
    assert_eq!(
        probe.poll_transport_once(),
        ProbeReplayFrame::Ended,
        "response-wait cancellation must not retroactively error a completed body"
    );
}

fn assert_timeout_envelope(elapsed: Duration, timeout_ms: u64) {
    let expected = Duration::from_millis(timeout_ms);
    let floor = expected.saturating_sub(Duration::from_millis(200));
    let ceiling = expected + Duration::from_millis(1500);
    assert!(
        elapsed >= floor,
        "timed out too fast: {elapsed:?} < floor {floor:?} (timeout was {timeout_ms}ms)"
    );
    assert!(
        elapsed <= ceiling,
        "timed out too slowly: {elapsed:?} > ceiling {ceiling:?} (timeout was {timeout_ms}ms)"
    );
}

fn timeout_overrides(read_ms: u64, write_ms: u64) -> serde_json::Value {
    json!({
        "backend_read_timeout_ms": read_ms,
        "backend_write_timeout_ms": write_ms,
    })
}

fn gateway_error_header(headers: &reqwest::header::HeaderMap) -> Option<&str> {
    headers.get("x-gateway-error").and_then(|v| v.to_str().ok())
}

async fn raw_h1_upload_response(harness: &GatewayHarness) -> (String, Duration) {
    let url = reqwest::Url::parse(harness.proxy_base_url()).expect("proxy URL");
    let port = url.port().expect("proxy URL has explicit port");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to proxy");
    let request_head = format!(
        "POST /api/twrite HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {UPLOAD_STALL_BYTES}\r\n\
         Connection: close\r\n\r\n"
    );
    let started = Instant::now();
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    let (mut reader, mut writer) = stream.into_split();
    let upload = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let mut remaining = UPLOAD_STALL_BYTES;
        while remaining > 0 {
            let len = remaining.min(chunk.len());
            writer.write_all(&chunk[..len]).await?;
            remaining -= len;
        }
        std::io::Result::Ok(())
    });

    let mut response = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut response))
            .await
            .expect("gateway response completed within five seconds");
    upload.abort();
    if let Err(err) = read_result {
        assert!(
            !response.is_empty(),
            "gateway closed without a response: {err}"
        );
    }
    (
        String::from_utf8(response).expect("HTTP/1 response is UTF-8"),
        started.elapsed(),
    )
}

// #4055: backend accepts and never reads. `HttpStep::ExpectRequest` would
// drain the POST, so the fixture is raw TCP Accept (implicit) + Sleep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_backend_write_timeout_maps_to_504_backend_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let (response, elapsed) = raw_h1_upload_response(&harness).await;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .expect("HTTP/1 response has a header terminator");
    assert!(
        headers.starts_with("HTTP/1.1 504 "),
        "live backend write timeout must be 504, got {response:?}"
    );
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("\r\nx-gateway-error: backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, got {response:?}"
    );
    assert_eq!(
        body, r#"{"error":"Backend timeout"}"#,
        "timeout body must be timeout-specific"
    );
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

// Companion: `backend_write_timeout_ms: 0` leaves the upload unbounded, so a
// never-read backend must not 504 at the 800ms watermark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_backend_write_timeout_zero_does_not_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, 0));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(1_500),
        client
            .as_reqwest()
            .post(harness.proxy_url("/api/twrite"))
            .header("content-type", "application/octet-stream")
            .body(vec![b'x'; UPLOAD_STALL_BYTES])
            .send(),
    )
    .await;
    let elapsed = started.elapsed();

    match result {
        Err(_) => {
            assert!(
                elapsed >= Duration::from_millis(1_300),
                "zero write timeout must not 504 at the 800ms watermark; \
                 client gave up at {elapsed:?}"
            );
        }
        Ok(Ok(resp)) => {
            assert_ne!(
                resp.status(),
                reqwest::StatusCode::GATEWAY_TIMEOUT,
                "backend_write_timeout_ms=0 must not produce a 504"
            );
        }
        Ok(Err(err)) => {
            panic!("unexpected client error under write-timeout=0: {err}");
        }
    }
}

// #4055, buffered dispatch. `retry` forces `stream_request_body = false`, so
// the upload is collected into memory and handed to reqwest as one buffer —
// the arm that had no body adapter and therefore no watermark at all. The
// contract is the same: a backend that accepts and never reads must 504 near
// `backend_write_timeout_ms`, not run on to a much longer
// `backend_read_timeout_ms`.
//
// `ReadWriteTimeout` reached the wire, so `connection_error` is false and the
// retry loop does not replay it; the elapsed time is one watermark.
fn buffered_timeout_overrides(read_ms: u64, write_ms: u64) -> serde_json::Value {
    json!({
        "backend_read_timeout_ms": read_ms,
        "backend_write_timeout_ms": write_ms,
        "retry": {
            "max_retries": 1,
            "retryable_status_codes": [],
            "retry_on_connect_failure": true,
            "backoff": {
                "fixed": {"delay_ms": 1}
            },
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_buffered_backend_write_timeout_maps_to_504_backend_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(
        backend_port,
        buffered_timeout_overrides(8_000, WRITE_TIMEOUT_MS),
    );
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    // Retry forces gateway-side body collection before dispatch. The streaming
    // arm uses `raw_h1_upload_response` so the upload stays live while the
    // backend write watermark fires; reading concurrently during collection
    // here closes the frontend with no HTTP block (hosted CI: empty EOF at
    // split_once). Reqwest finishes the client upload before awaiting headers,
    // which matches how a buffered dispatch actually reaches the backend.
    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .as_reqwest()
        .post(harness.proxy_url("/api/twrite"))
        .header("content-type", "application/octet-stream")
        .body(vec![b'x'; UPLOAD_STALL_BYTES])
        .send()
        .await
        .expect("gateway returns a response");
    let elapsed = started.elapsed();
    let status = resp.status();
    let header = gateway_error_header(resp.headers()).map(str::to_owned);
    let body = resp.text().await.expect("body");

    assert_eq!(
        status,
        reqwest::StatusCode::GATEWAY_TIMEOUT,
        "buffered upload write timeout must be 504, got {status} body={body}"
    );
    assert_eq!(
        header.as_deref(),
        Some("backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, body={body}"
    );
    assert_eq!(
        body, r#"{"error":"Backend timeout"}"#,
        "timeout body must be timeout-specific"
    );
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

// Companion opt-out on the buffered arm: `backend_write_timeout_ms: 0` keeps
// the reusable-`Bytes` path, so a never-read backend must not 504 at 800ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_buffered_backend_write_timeout_zero_does_not_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES)
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, buffered_timeout_overrides(8_000, 0));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(1_500),
        client
            .as_reqwest()
            .post(harness.proxy_url("/api/twrite"))
            .header("content-type", "application/octet-stream")
            .body(vec![b'x'; UPLOAD_STALL_BYTES])
            .send(),
    )
    .await;
    let elapsed = started.elapsed();

    match result {
        Err(_) => {
            assert!(
                elapsed >= Duration::from_millis(1_300),
                "zero write timeout must not 504 at the 800ms watermark; \
                 client gave up at {elapsed:?}"
            );
        }
        Ok(Ok(resp)) => {
            assert_ne!(
                resp.status(),
                reqwest::StatusCode::GATEWAY_TIMEOUT,
                "buffered backend_write_timeout_ms=0 must not produce a 504"
            );
        }
        Ok(Err(err)) => {
            panic!("unexpected client error under buffered write-timeout=0: {err}");
        }
    }
}

fn http_200_ok_close() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
}

fn progressing_upload_script(body_len: usize) -> Vec<TcpStep> {
    let mut steps = vec![TcpStep::ReadUntil(b"\r\n\r\n".to_vec())];
    let mut remaining = body_len;
    while remaining > 0 {
        steps.push(TcpStep::Sleep(Duration::from_millis(200)));
        let n = remaining.min(PROGRESSING_READ_CHUNK);
        steps.push(TcpStep::ReadExact(n));
        remaining -= n;
    }
    steps.push(TcpStep::Write(http_200_ok_close()));
    steps
}

async fn post_upload(
    harness: &GatewayHarness,
    client: &reqwest::Client,
    bytes: usize,
) -> (reqwest::StatusCode, Option<String>, String, Duration) {
    let started = Instant::now();
    let resp = client
        .post(harness.proxy_url("/api/twrite"))
        .header("content-type", "application/octet-stream")
        .header("expect", "")
        .body(vec![b'x'; bytes])
        .send()
        .await
        .expect("gateway returns a response");
    let elapsed = started.elapsed();
    let status = resp.status();
    let header = gateway_error_header(resp.headers()).map(str::to_owned);
    let body = resp.text().await.expect("body");
    (status, header, body, elapsed)
}

// #4411: 2 MiB fits in a typical loopback send buffer. The pump reaches a
// clean EOS without socket backpressure; the header-wait write bound must
// still produce 504 near `backend_write_timeout_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_kernel_absorb_write_timeout_maps_to_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let (status, header, body, elapsed) =
        post_upload(&harness, client.as_reqwest(), KERNEL_ABSORB_UPLOAD_BYTES).await;
    assert_eq!(
        status,
        reqwest::StatusCode::GATEWAY_TIMEOUT,
        "kernel-absorbed never-read POST must be 504, got {status} body={body}"
    );
    assert_eq!(
        header.as_deref(),
        Some("backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, body={body}"
    );
    assert_eq!(body, r#"{"error":"Backend timeout"}"#);
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_h2c_kernel_absorb_write_timeout_maps_to_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let (status, header, body, elapsed) =
        post_upload(&harness, client.as_reqwest(), KERNEL_ABSORB_UPLOAD_BYTES).await;
    assert_eq!(
        status,
        reqwest::StatusCode::GATEWAY_TIMEOUT,
        "h2c kernel-absorbed never-read POST must be 504, got {status} body={body}"
    );
    assert_eq!(
        header.as_deref(),
        Some("backend_timeout"),
        "timeout must carry X-Gateway-Error=backend_timeout, body={body}"
    );
    assert_eq!(body, r#"{"error":"Backend timeout"}"#);
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

// Slow-but-progressing reads must refresh the write watermark. 200ms gaps
// under an 800ms bound must complete with 200, not 504.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_progressing_upload_is_not_killed_by_idle_write_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let mut backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .receive_buffer_size(BACKEND_RECEIVE_BUFFER_BYTES);
    for step in progressing_upload_script(PROGRESSING_UPLOAD_BYTES) {
        backend = backend.step(step);
    }
    let _backend = backend.spawn().expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, WRITE_TIMEOUT_MS));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let (status, header, body, _elapsed) =
        post_upload(&harness, client.as_reqwest(), PROGRESSING_UPLOAD_BYTES).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "slow-but-progressing upload must not 504, got {status} \
         x-gateway-error={header:?} body={body}"
    );
    assert_eq!(body, "ok");
}

// `backend_write_timeout_ms: 0` must still leave a kernel-absorbed never-read
// POST unbounded at the 800ms watermark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_kernel_absorb_write_timeout_zero_does_not_504() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, timeout_overrides(8_000, 0));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(1_500),
        client
            .as_reqwest()
            .post(harness.proxy_url("/api/twrite"))
            .header("content-type", "application/octet-stream")
            .header("expect", "")
            .body(vec![b'x'; KERNEL_ABSORB_UPLOAD_BYTES])
            .send(),
    )
    .await;
    let elapsed = started.elapsed();
    match result {
        Err(_) => {
            assert!(
                elapsed >= Duration::from_millis(1_300),
                "zero write timeout must not 504 at the 800ms watermark; \
                 client gave up at {elapsed:?}"
            );
        }
        Ok(Ok(resp)) => {
            assert_ne!(
                resp.status(),
                reqwest::StatusCode::GATEWAY_TIMEOUT,
                "backend_write_timeout_ms=0 must not produce a 504"
            );
        }
        Ok(Err(err)) => {
            panic!("unexpected client error under write-timeout=0: {err}");
        }
    }
}

// #4057: headers + one SSE event + stall. Client sees 200 and the first
// event; the body then aborts near `backend_read_timeout_ms`. A 504 is
// impossible once headers are committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_sse_stall_after_first_event_idles_until_read_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "text/event-stream".into(),
        })
        .step(HttpStep::RespondBodyChunk(SSE_FIRST_EVENT.to_vec()))
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(READ_TIMEOUT_MS, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssestall"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "committed SSE headers must be 200, not a 504"
    );
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first SSE event bounded")
        .expect("first SSE event present")
        .expect("first SSE event readable");
    assert!(
        first
            .windows(SSE_FIRST_EVENT.len())
            .any(|w| w == SSE_FIRST_EVENT)
            || first
                .windows(b"data: hello".len())
                .any(|w| w == b"data: hello"),
        "first event missing from {:?}; elapsed={:?}",
        first,
        started.elapsed()
    );

    let stall_started = Instant::now();
    let rest = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(item) = stream.next().await {
            item?;
        }
        Ok::<(), reqwest::Error>(())
    })
    .await;
    let stall_elapsed = stall_started.elapsed();
    match rest {
        Ok(Ok(())) => panic!(
            "SSE stall closed cleanly instead of aborting as a read timeout; \
             stall_elapsed={stall_elapsed:?}"
        ),
        Ok(Err(_)) | Err(_) => {
            assert_timeout_envelope(stall_elapsed, READ_TIMEOUT_MS);
        }
    }
}

// Slow-but-progressing SSE must keep the idle watermark fresh. Gaps of 200ms
// under an 800ms read timeout must complete, not be killed as idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_progressing_sse_is_not_killed_by_idle_read_timeout() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let body = b"data: a\n\ndata: b\n\ndata: c\n\n".to_vec();
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::TrickleBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            body,
            chunk_size: 8,
            pause: Duration::from_millis(200),
        })
        .spawn()
        .expect("spawn");

    let yaml =
        file_mode_yaml_for_backend_with(backend_port, timeout_overrides(READ_TIMEOUT_MS, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssetrickle"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.expect("progressing SSE must complete");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("data: a") && text.contains("data: c"),
        "progressing SSE body truncated: {text:?}"
    );
}

// `backend_read_timeout_ms: 0` disables the idle bound: after the first
// event the stream must still be open at 1.5s (the 800ms watermark).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_sse_read_timeout_zero_stays_open_past_watermark() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "text/event-stream".into(),
        })
        .step(HttpStep::RespondBodyChunk(SSE_FIRST_EVENT.to_vec()))
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn");

    let yaml = file_mode_yaml_for_backend_with(backend_port, timeout_overrides(0, 5_000));
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .as_reqwest()
        .get(harness.proxy_url("/api/ssestall"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("headers");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first SSE event bounded")
        .expect("first SSE event present")
        .expect("first SSE event readable");
    assert!(
        first
            .windows(b"data: hello".len())
            .any(|w| w == b"data: hello"),
        "first event missing from {first:?}"
    );

    let next = tokio::time::timeout(Duration::from_millis(1_500), stream.next()).await;
    assert!(
        next.is_err(),
        "backend_read_timeout_ms=0 must keep the SSE stream open past 800ms; \
         got {next:?}"
    );
}

//! In-process HTTP-family backend timeout enforcement (#4055 / #4057 / #4411).
//!
//! `#4055` — a backend that accepts and never reads must surface a 504 write
//! timeout near `backend_write_timeout_ms`, not hang until the client gives up.
//! `#4411` — the same watermark bounds transport write progress AFTER a clean
//! end of stream too: the local send queue is sampled while the response-header
//! wait runs, and a queue that is non-empty and never shrinks is a write stall.
//! `#4057` — an SSE/chunked stall *after* headers must wait out
//! `backend_read_timeout_ms` (idle-between-frames) instead of tearing the
//! stream down immediately as `request_error`. Header-only stalls already 504
//! (`tests/integration/scripted_backend_smoke_tests.rs`, closed #3922).
//!
//! Protocol-path coverage beyond H1 lives in the scripted-backend functional
//! suite (`scripted_backend_tests.rs`, `scripted_backend_h2_tests.rs`,
//! `scripted_backend_h3_tests.rs`).

use crate::scaffolding::Http2Client;
use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, TcpStep,
};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
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
const SSE_FIRST_EVENT: &[u8] = b"data: hello\r\n\n";

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

// #4411 regression guard, ported from the closed
// `claude/issue-4411-backend-write-timeout` branch: a slow-but-genuinely-
// progressing upload must still return 200 under an 800ms write bound. The
// post-EOS drain bound is stated on strictly decreasing send-queue depth
// precisely so this case can never be misread as a stall.
const PROGRESSING_UPLOAD_BYTES: usize = 256 * 1024;
const PROGRESSING_READ_CHUNK: usize = 32 * 1024;

fn progressing_upload_script(body_len: usize) -> Vec<TcpStep> {
    let mut steps = vec![TcpStep::ReadUntil(b"\r\n\r\n".to_vec())];
    let mut remaining = body_len;
    while remaining > 0 {
        steps.push(TcpStep::Sleep(Duration::from_millis(200)));
        let n = remaining.min(PROGRESSING_READ_CHUNK);
        steps.push(TcpStep::ReadExact(n));
        remaining -= n;
    }
    steps.push(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ));
    steps
}

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
    let response = client
        .as_reqwest()
        .post(harness.proxy_url("/api/twrite"))
        .header("content-type", "application/octet-stream")
        .header("expect", "")
        .body(vec![b'x'; PROGRESSING_UPLOAD_BYTES])
        .send()
        .await
        .expect("gateway returns a response");
    let status = response.status();
    let header = gateway_error_header(response.headers()).map(str::to_owned);
    let body = response.text().await.expect("body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "slow-but-progressing upload must not 504, got {status} \
         x-gateway-error={header:?} body={body}"
    );
    assert_eq!(body, "ok");
}

// ── #4411: the post-EOS send-queue drain bound, against a live socket ────────
//
// Once the request body has reached a clean end of stream the upload pump's
// pre-EOS idle arm can never fire again, and HTTP offers no request-side
// receipt that the backend read anything. The kernel's send-queue depth is the
// remaining evidence. These prove the mechanism end to end on a real
// connection: the syscall, the sampling cadence, and the progress rule
// together, rather than the rule alone (`tests/unit/gateway_core/
// backend_send_queue_tests.rs`).

const DRAIN_WATERMARK_MS: u64 = 400;
// Comfortably larger than any default socket send buffer, so a peer that never
// reads leaves the remainder parked in the gateway's own send queue.
const DRAIN_PROBE_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// How long `fill_send_queue` keeps offering bytes after the first short write.
const FILL_DEADLINE: Duration = Duration::from_millis(200);

/// Receive buffer pinned on the never-reading peer's listener.
///
/// Accepted sockets inherit the listening socket's `SO_RCVBUF`, so this caps
/// how much the peer's kernel can absorb on the fixture's behalf before the
/// sender sees real backpressure.
const NEVER_READING_PEER_RCVBUF: usize = 16 * 1024;

/// Fill `stream`'s send queue until it stops draining, returning the bytes
/// accepted.
///
/// A single `WouldBlock` is not evidence of a stall: it only says the socket
/// was full at that instant, and a loopback peer's kernel keeps absorbing into
/// its own receive buffer for a while afterwards, which lets the send queue
/// drain and makes the watch correctly report progress (issue #4983 observed
/// exactly that on macOS). So keep offering bytes across writable readiness
/// under a bounded deadline: the loop ends when writability stops coming back,
/// which IS persistent backpressure — the state a stalled backend leaves the
/// gateway in — or when the deadline expires.
async fn fill_send_queue(stream: &TcpStream, total: usize) -> usize {
    let chunk = vec![b'x'; 64 * 1024];
    let started = Instant::now();
    let mut written = 0;
    while written < total && started.elapsed() < FILL_DEADLINE {
        match stream.try_write(&chunk[..chunk.len().min(total - written)]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Readiness that never returns is the stall this fixture wants.
                if tokio::time::timeout(Duration::from_millis(50), stream.writable())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    written
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_queue_drain_watch_terminates_a_peer_that_never_reads() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        // Windows and anything else without a send-queue query keeps
        // `backend_read_timeout_ms` as the only bound; documented in
        // `docs/configuration.md` next to `backend_write_timeout_ms`.
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind never-reading peer");
    // Constrain what the peer's kernel will absorb for a socket nobody reads.
    // Without this the fixture can hand the whole probe upload to the peer's
    // receive buffer, the send queue drains, and the watch correctly reports
    // progress instead of the stall the test is about.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(NEVER_READING_PEER_RCVBUF)
        .expect("pin the never-reading peer receive buffer");
    let addr = listener.local_addr().expect("local addr");
    // Accept and then never call `recv()` — the #4411 backend exactly.
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(socket);
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let written = fill_send_queue(&stream, DRAIN_PROBE_UPLOAD_BYTES).await;
    assert!(
        written > 0,
        "the kernel must accept some of the upload before backpressuring"
    );

    let started = Instant::now();
    let stalled =
        ferrum_edge::_test_support::await_backend_send_queue_stall(&stream, DRAIN_WATERMARK_MS)
            .await
            .expect("a duplicated socket handle on a supported platform");
    let elapsed = started.elapsed();
    assert!(
        stalled,
        "a send queue that never drains must be charged to the write watermark"
    );
    assert!(
        elapsed >= Duration::from_millis(DRAIN_WATERMARK_MS.saturating_sub(100)),
        "the stall must not fire early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the stall must fire near the watermark, not at a later bound: {elapsed:?}"
    );
    peer.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_queue_drain_watch_lets_a_reading_peer_finish() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reading peer");
    let addr = listener.local_addr().expect("local addr");
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut sink = vec![0u8; 64 * 1024];
        // Slow but genuinely progressing: each read strictly decreases the
        // sender's queue, so the watch must never terminate it even though the
        // whole transfer takes far longer than the watermark.
        loop {
            match socket.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let written = fill_send_queue(&stream, DRAIN_PROBE_UPLOAD_BYTES).await;
    assert!(written > 0, "the kernel must accept some of the upload");

    let stalled =
        ferrum_edge::_test_support::await_backend_send_queue_stall(&stream, DRAIN_WATERMARK_MS)
            .await
            .expect("a duplicated socket handle on a supported platform");
    assert!(
        !stalled,
        "a peer that keeps reading must never be charged a write timeout"
    );
    peer.abort();
}

// ── #4411: the bundled HTTP client's HTTP/1.1 backend path ──────────────────
//
// The issue's own reproduction. 2 MiB fits comfortably inside a loopback send
// buffer plus a never-reading peer's initial receive window, so the upload pump
// reaches a clean end of stream with no bridge-capacity backpressure at all and
// the pre-EOS idle arm can never fire. Only the post-EOS send-queue drain bound
// can produce the 504 the watermark promises — and on this path it can only do
// so because vendored reqwest patch 004 reports the dialed socket to the
// gateway (`docs/upstream-reqwest-patches/004-connection-established-fd/`).

const KERNEL_ABSORB_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

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

/// The envelope check for the post-EOS drain bound, with the debug-build
/// handoff counters in the failure message so a miss names the link that
/// never happened (hook not reached, published out of scope, pump unarmed,
/// no socket, watch cancelled, queue drained) rather than only the elapsed time.
fn assert_drain_bound_envelope(elapsed: Duration) {
    let ceiling = Duration::from_millis(WRITE_TIMEOUT_MS + 1500);
    let diagnostics = ferrum_edge::_test_support::post_eos_drain_diagnostics();
    assert!(
        elapsed <= ceiling,
        "timed out too slowly: {elapsed:?} > ceiling {ceiling:?} (timeout was \
         {WRITE_TIMEOUT_MS}ms); drain handoff diagnostics: {diagnostics:?}"
    );
    assert_timeout_envelope(elapsed, WRITE_TIMEOUT_MS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_kernel_absorb_write_timeout_maps_to_504() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        // No send-queue query on this target: `backend_read_timeout_ms` is the
        // only bound, as documented next to `backend_write_timeout_ms`.
        return;
    }
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
    assert_drain_bound_envelope(elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_h2c_kernel_absorb_write_timeout_maps_to_504() {
    if !ferrum_edge::_test_support::send_queue_probe_supported() {
        return;
    }
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
    assert_drain_bound_envelope(elapsed);
}

// ── Vendored reqwest patch 004: the behavioral regression that must survive
//    retirement (`.claude/rules/dependencies.md`) ─────────────────────────────
//
// This is the ONE thing patch 004 adds: `ConnectionAdmission::established` is
// called once per NEW physical connection, with that connection's own socket.
// If the callback stops firing, or fires with a descriptor that is not the
// dialed socket, the two acceptance tests above silently degrade to
// `backend_read_timeout_ms` instead of failing loudly — this one fails loudly.
#[cfg(unix)]
mod vendored_established_hook {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingAdmission {
        /// Duplicated exactly as production does, so the assertion below reads
        /// the socket the hook named rather than a number the kernel may have
        /// recycled by then.
        sockets: Mutex<Vec<OwnedFd>>,
    }

    impl reqwest::ConnectionAdmission for RecordingAdmission {
        fn admit(
            &self,
            _dst: &http::Uri,
        ) -> Result<reqwest::ConnectionAdmissionToken, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(reqwest::ConnectionAdmissionToken::unlimited())
        }

        fn established(&self, _token: &reqwest::ConnectionAdmissionToken, fd: RawFd) {
            // SAFETY: the hook's contract is that the connection owns `fd` and
            // is alive for the duration of this call.
            let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            if let Ok(owned) = borrowed.try_clone_to_owned() {
                self.sockets.lock().expect("lock").push(owned);
            }
        }
    }

    /// A backend that answers every request on the same connection, so a second
    /// request can be a pooled reuse rather than a second dial.
    ///
    /// Every response body is the client's source port for the connection that
    /// carried the request, which is what lets the test below name the physical
    /// connection each request actually travelled over instead of assuming the
    /// pool returned one by some deadline.
    fn spawn_keepalive_backend(listener: tokio::net::TcpListener) {
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let body = peer.port().to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    // One response per complete request head, so a request that
                    // arrives across two reads cannot desynchronize the
                    // connection and make reqwest open a second one.
                    let mut pending = Vec::new();
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buf[..n]);
                        while let Some(end) =
                            pending.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            pending.drain(..end + 4);
                            if socket.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
    }

    /// Duplicate a descriptor the hook reported so it can be queried after this
    /// call, without taking ownership of the connection's own socket.
    fn probe_socket(fd: &OwnedFd) -> std::net::TcpStream {
        std::net::TcpStream::from(fd.try_clone().expect("duplicate the reported descriptor"))
    }

    /// Requests to issue while waiting for the client to reuse a pooled
    /// connection. hyper returns a finished connection to the pool from a task
    /// it spawns after the body completes, so the FIRST reuse attempt can race
    /// that return and dial again (issue #4888). Every dial that loses the race
    /// leaves one more idle connection in the pool, so the next checkout finds
    /// one; this bound only exists so a client that never pools fails loudly
    /// instead of looping forever.
    const REUSE_ATTEMPTS: usize = 8;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn established_reports_the_dialed_socket_once_per_physical_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("local addr");
        spawn_keepalive_backend(listener);

        let admission = Arc::new(RecordingAdmission::default());
        let hook: Arc<dyn reqwest::ConnectionAdmission> = admission.clone();
        let client = reqwest::Client::builder()
            .connection_admission(hook)
            .build()
            .expect("client");

        // Issue requests until the backend reports one of its connections a
        // second time: that request provably travelled over an already-open
        // physical connection, whatever the pool did on the way there.
        let url = format!("http://{addr}/");
        let mut served_by = Vec::new();
        let mut reused_port = None;
        for _ in 0..REUSE_ATTEMPTS {
            let response = client.get(url.as_str()).send().await.expect("response");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let port: u16 = response
                .text()
                .await
                .expect("body")
                .parse()
                .expect("the backend names the client source port that served the request");
            if served_by.contains(&port) {
                reused_port = Some(port);
                break;
            }
            served_by.push(port);
        }
        let reused_port = reused_port.expect(
            "the client never reused a pooled connection, so the hook's per-connection \
             contract could not be exercised",
        );

        let sockets = admission.sockets.lock().expect("lock");
        // Every connection the pool holds is still open, so source ports cannot
        // repeat: one record per port IS one record per physical connection.
        let mut reported: Vec<u16> = sockets
            .iter()
            .map(|fd| probe_socket(fd).local_addr().expect("local address").port())
            .collect();
        reported.sort_unstable();
        let mut unique = reported.clone();
        unique.dedup();
        assert_eq!(
            reported, unique,
            "established must fire exactly once per NEW physical connection; \
             a repeated source port means one connection was reported twice"
        );
        // And a request carried by an already-open connection adds no record:
        // the reused connection is named exactly once, not once per request.
        assert_eq!(
            reported.iter().filter(|port| **port == reused_port).count(),
            1,
            "established must not fire for a pooled reuse; the connection that \
             served two requests was reported {reported:?}"
        );

        // The reported descriptor is THIS connection's socket, not an arbitrary
        // open fd: its peer is the backend the client dialed.
        let probe = sockets
            .iter()
            .map(probe_socket)
            .find(|probe| {
                probe
                    .local_addr()
                    .is_ok_and(|local| local.port() == reused_port)
            })
            .expect("the reused connection must have been reported");
        assert_eq!(
            probe.peer_addr().expect("peer address").port(),
            addr.port(),
            "established reported a descriptor that is not the dialed backend socket"
        );
        // And it is still the socket the gateway would sample: a send-queue
        // query against it must be answerable on a supported target.
        if ferrum_edge::_test_support::send_queue_probe_supported() {
            assert!(
                ferrum_edge::_test_support::raw_fd_send_queue_bytes(probe.as_raw_fd()).is_some(),
                "the reported descriptor must answer a send-queue query"
            );
        }
    }
}

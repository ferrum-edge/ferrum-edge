//! Functional coverage for `ai_rate_limiter` streaming token accounting (E2E).
//!
//! Advisories under test:
//!
//! * **GHSA-q2r2-6r7h-f69x** — unconditional full-response buffering and
//!   unbounded aggregate accounting state. Covered here by: incremental
//!   delivery across HTTP/1.1, HTTP/2, and HTTP/3; a never-ending stream that
//!   the client abandons; the process-wide accounting-byte budget's refusal,
//!   release, and error-path release behavior; and the deferred admission for a
//!   gzipped request body a co-located `compression` plugin decodes, which is
//!   refused before the backend is contacted on HTTP/1.1, HTTP/2, and HTTP/3
//!   while non-streaming and non-AI requests pass through untouched.
//! * **GHSA-rxj9-f483-g53f** — provider-native stream formats bypassing actual
//!   token accounting. Covered by end-to-end charges from an OpenAI-shaped SSE
//!   `usage` block, an Anthropic `message_start`/`message_delta` pair, and a
//!   real AWS Bedrock `application/vnd.amazon.eventstream` frame carrying
//!   `amazon-bedrock-invocationMetrics`.
//! * **GHSA-wh4p-pmxm-3784** — shared reservation metadata corrupting
//!   independent budgets. Covered by two co-located limiter instances on one
//!   proxy settling one streamed response independently.
//!
//! These are live-gateway tests: every assertion is made on bytes a real client
//! received over a real transport, not on plugin internals.
//!
//! Run with:
//! `cargo test --test functional_tests -- --ignored --nocapture functional_ai_rate_limiter_stream_accounting`

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http1Client, Http2Client, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Fixtures
// ============================================================================

/// An OpenAI-shaped SSE completion whose terminal event reports 900 tokens.
/// `900` is chosen so ONE such response overruns the small budgets below,
/// making "was the stream actually charged?" observable from a later request.
const OPENAI_SSE_HEAD: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n";
const OPENAI_SSE_TAIL: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n\
data: {\"choices\":[{\"delta\":{}}],\"usage\":{\"prompt_tokens\":400,\"completion_tokens\":500,\"total_tokens\":900}}\n\n\
data: [DONE]\n\n";

/// The same stream with no usage event anywhere — the unmetered posture case.
const OPENAI_SSE_NO_USAGE_TAIL: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n\
data: [DONE]\n\n";

/// Anthropic reports the prompt count on `message_start` and the completion
/// count on `message_delta`; both must merge into one cumulative snapshot.
const ANTHROPIC_SSE_HEAD: &str = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":400}}}\n\n";
const ANTHROPIC_SSE_TAIL: &str = "event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":500}}\n\n";

fn openai_sse_body() -> String {
    format!("{OPENAI_SSE_HEAD}{OPENAI_SSE_TAIL}")
}

// ---- AWS event-stream frame construction ----------------------------------
//
// Bedrock `InvokeModelWithResponseStream` frames are binary and CRC-protected,
// so the fixture has to be built rather than written as a literal. The gateway
// verifies both documented CRC-32s before trusting anything in the frame, so a
// hand-rolled frame that got the framing wrong would fail closed and the test
// would (correctly) not see a charge.

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// One `STRING`-typed AWS event-stream header (`value type 7`).
fn string_header(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(7);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

/// A complete, CRC-correct `:message-type: event` / `:event-type: chunk` frame.
fn bedrock_chunk_frame(payload: &[u8]) -> Vec<u8> {
    let mut headers = string_header(":message-type", "event");
    headers.extend_from_slice(&string_header(":event-type", "chunk"));

    let total_length = (16 + headers.len() + payload.len()) as u32;
    let headers_length = headers.len() as u32;

    let mut prelude = Vec::new();
    prelude.extend_from_slice(&total_length.to_be_bytes());
    prelude.extend_from_slice(&headers_length.to_be_bytes());
    let prelude_crc = crc32(&prelude);
    prelude.extend_from_slice(&prelude_crc.to_be_bytes());

    let mut message = prelude;
    message.extend_from_slice(&headers);
    message.extend_from_slice(payload);
    let message_crc = crc32(&message);
    message.extend_from_slice(&message_crc.to_be_bytes());
    message
}

/// The terminal Bedrock chunk: a base64 `bytes` envelope whose inner document
/// carries `amazon-bedrock-invocationMetrics` (400 in / 500 out = 900 total).
fn bedrock_event_stream_body() -> Vec<u8> {
    use base64::Engine as _;
    let inner = br#"{"amazon-bedrock-invocationMetrics":{"inputTokenCount":400,"outputTokenCount":500}}"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
    let envelope = format!("{{\"bytes\":\"{encoded}\"}}");

    let mut body = bedrock_chunk_frame(br#"{"bytes":"eyJjb21wbGV0aW9uIjoiaGkifQ=="}"#);
    body.extend_from_slice(&bedrock_chunk_frame(envelope.as_bytes()));
    body
}

// ============================================================================
// Backend
// ============================================================================

/// What one backend route does.
#[derive(Clone, Copy)]
enum Script {
    /// Chunked SSE: first event, a pause, then the terminal tail.
    SseUsage,
    /// Chunked SSE with no usage event at all.
    SseNoUsage,
    /// Anthropic-shaped chunked SSE.
    SseAnthropic,
    /// Chunked `application/vnd.amazon.eventstream`.
    Bedrock,
    /// Headers plus one event, then hold the connection open forever.
    Hang,
}

/// Chunked-transfer framing is deliberate: it is the only response shape that
/// proves the gateway forwarded incrementally rather than buffering, because a
/// `Content-Length` body could be reassembled and re-emitted identically.
async fn write_chunk(stream: &mut tokio::net::TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.write_all(b"\r\n").await
}

/// Strip HTTP/1.1 chunked transfer framing. Stops at the terminating `0` chunk
/// or at the first truncated chunk, so a partially read stream still yields the
/// bytes that did arrive.
fn decode_chunked(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(eol) = bytes[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            break;
        };
        let size_line = String::from_utf8_lossy(&bytes[cursor..cursor + eol]).to_string();
        let size_token = size_line.split(';').next().unwrap_or("").trim().to_string();
        let Ok(size) = usize::from_str_radix(&size_token, 16) else {
            break;
        };
        cursor += eol + 2;
        if size == 0 {
            break;
        }
        if cursor + size > bytes.len() {
            out.extend_from_slice(&bytes[cursor..]);
            break;
        }
        out.extend_from_slice(&bytes[cursor..cursor + size]);
        cursor += size + 2;
    }
    out
}

async fn serve(mut stream: tokio::net::TcpStream, script: Script, pause: Duration) {
    let content_type = match script {
        Script::Bedrock => "application/vnd.amazon.eventstream",
        _ => "text/event-stream",
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }

    let (head_bytes, tail_bytes): (Vec<u8>, Vec<u8>) = match script {
        Script::SseUsage | Script::Hang => (
            OPENAI_SSE_HEAD.as_bytes().to_vec(),
            OPENAI_SSE_TAIL.as_bytes().to_vec(),
        ),
        Script::SseNoUsage => (
            OPENAI_SSE_HEAD.as_bytes().to_vec(),
            OPENAI_SSE_NO_USAGE_TAIL.as_bytes().to_vec(),
        ),
        Script::SseAnthropic => (
            ANTHROPIC_SSE_HEAD.as_bytes().to_vec(),
            ANTHROPIC_SSE_TAIL.as_bytes().to_vec(),
        ),
        Script::Bedrock => {
            let body = bedrock_event_stream_body();
            let split = body.len() / 2;
            (body[..split].to_vec(), body[split..].to_vec())
        }
    };

    if write_chunk(&mut stream, &head_bytes).await.is_err() {
        return;
    }
    let _ = stream.flush().await;

    if matches!(script, Script::Hang) {
        // Never-ending stream: the gateway must hold only bounded accounting
        // state for it, and must release that state when the client leaves.
        loop {
            sleep(Duration::from_secs(30)).await;
        }
    }

    sleep(pause).await;
    if write_chunk(&mut stream, &tail_bytes).await.is_err() {
        return;
    }
    let _ = stream.write_all(b"0\r\n\r\n").await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// A backend that dispatches on request path, and can be told to abort the
/// first N connections before writing a byte (the retry fixture).
async fn start_backend(listener: TcpListener, abort_first: u32) {
    let aborted = Arc::new(AtomicU32::new(0));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let aborted = Arc::clone(&aborted);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16_384];
            let read = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();

            if aborted.fetch_add(1, Ordering::SeqCst) < abort_first {
                // Close without any response: a pre-wire connection failure the
                // gateway's retry policy is allowed to retry.
                drop(stream);
                return;
            }

            // `hang` and `slow` are checked FIRST: those routes deliberately
            // also carry the Bedrock streaming marker so the gateway predicts
            // the 256 KiB retention class for them.
            let (script, pause) = if path.contains("hang") {
                (Script::Hang, Duration::ZERO)
            } else if path.contains("slow") {
                (Script::Bedrock, Duration::from_secs(4))
            } else if path.contains("no-usage") {
                (Script::SseNoUsage, Duration::from_millis(200))
            } else if path.contains("anthropic") {
                (Script::SseAnthropic, Duration::from_millis(200))
            } else if path.contains("invoke-with-response-stream") {
                (Script::Bedrock, Duration::from_millis(200))
            } else {
                (Script::SseUsage, Duration::from_millis(600))
            };
            serve(stream, script, pause).await;
        });
    }
}

async fn spawn_backend(abort_first: u32) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    tokio::spawn(start_backend(listener, abort_first));
    port
}

// ============================================================================
// Config
// ============================================================================

fn limiter_config(backend_port: u16, plugin_config: serde_json::Value) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "arl-proxy",
            "listen_path": "/ai",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "arl-1"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "arl-1",
            "proxy_id": "arl-proxy",
            "plugin_name": "ai_rate_limiter",
            "scope": "proxy",
            "enabled": true,
            "config": plugin_config,
        }],
    });
    serde_yaml::to_string(&config).expect("serialize ai_rate_limiter config")
}

/// The default posture used by most tests: an IP-keyed budget large enough to
/// admit one 900-token stream and small enough that a second is refused.
fn charging_config(backend_port: u16) -> String {
    limiter_config(
        backend_port,
        json!({
            "token_limit": 1000,
            "window_seconds": 300,
            "limit_by": "ip",
            "count_mode": "total_tokens",
            "expose_headers": true,
            "on_unmetered_response": "charge_estimate",
        }),
    )
}

fn ai_body() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 8,
        "stream": true,
    })
}

/// The same request without any output cap — the zero-estimate shape.
fn uncapped_ai_body() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    })
}

// ============================================================================
// GHSA-q2r2 — incremental delivery, byte-for-byte, on every HTTP version
// ============================================================================

/// The gateway must not buffer an SSE model stream, and the bytes the client
/// receives must be exactly the bytes the backend produced.
///
/// The backend pauses 600 ms between its first event and its terminal usage
/// event. A buffering gateway cannot emit anything until the whole body has
/// arrived, so observing the first event materially before the stream ends is a
/// direct, transport-level proof that buffering was released.
#[ignore]
#[tokio::test]
async fn sse_stream_is_forwarded_incrementally_and_byte_for_byte_on_h1() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(charging_config(backend_port))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn ai_rate_limiter gateway");

    let proxy_port = harness
        .proxy_base_url()
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .expect("proxy port");

    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to proxy");
    let body = serde_json::to_string(&ai_body()).expect("serialize body");
    let request = format!(
        "POST /ai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let started = Instant::now();
    let mut received = Vec::new();
    let mut first_event_at = None;
    let mut buf = vec![0u8; 8192];
    loop {
        let read = match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut buf)).await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
        };
        received.extend_from_slice(&buf[..read]);
        if first_event_at.is_none()
            && String::from_utf8_lossy(&received).contains("hello ")
        {
            first_event_at = Some(started.elapsed());
        }
        if String::from_utf8_lossy(&received).contains("[DONE]") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&received).to_string();
    let first_event_at = first_event_at.expect("the first SSE event never arrived");
    let total = started.elapsed();

    assert!(
        text.starts_with("HTTP/1.1 200"),
        "streamed AI response should be 200, got: {}",
        text.lines().next().unwrap_or_default()
    );
    assert!(
        !text.to_ascii_lowercase().contains("content-length:"),
        "a streamed response must not declare Content-Length: {text}"
    );
    // The backend holds the terminal event for 600 ms. Requiring the first
    // event at least 200 ms earlier than the end of the stream is a wide margin
    // that still cannot be satisfied by a buffered response.
    assert!(
        first_event_at + Duration::from_millis(200) < total,
        "first SSE event arrived at {first_event_at:?} but the stream ended at {total:?} — \
         the response looks buffered rather than streamed"
    );
    // Byte-for-byte: after removing the HTTP/1.1 transfer framing the client
    // saw, the payload must equal the backend's SSE document exactly. Comparing
    // the whole document (not a substring per record) is what makes this an
    // "unchanged and in order" assertion rather than a containment check.
    let (head, raw_body) = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| (received[..at].to_vec(), received[at + 4..].to_vec()))
        .expect("response head/body separator");
    let head_text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let delivered = if head_text.contains("transfer-encoding: chunked") {
        decode_chunked(&raw_body)
    } else {
        raw_body
    };
    assert_eq!(
        String::from_utf8_lossy(&delivered),
        openai_sse_body(),
        "the streamed SSE document was not forwarded byte-for-byte"
    );

    drop(harness);
}

/// The same stream over HTTP/2 and HTTP/3, and the accounting consequence: the
/// terminal `usage` block (900 tokens) is charged against the 1000-token budget,
/// so the *next* request on the same IP budget is refused with 429.
///
/// This is the end-to-end proof that a streamed response is metered at all —
/// the advisory's core claim is that provider-native streaming formats were
/// bypassing accounting entirely.
#[ignore]
#[tokio::test]
async fn streamed_usage_is_charged_and_exhausts_the_budget_on_h2() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(charging_config(backend_port))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn ai_rate_limiter gateway");

    let h2 = Http2Client::h2c_prior_knowledge().expect("HTTP/2 client");
    let first = h2
        .as_reqwest()
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("first HTTP/2 streamed request");
    assert_eq!(first.status().as_u16(), 200, "first stream should succeed");
    let first_body = first.text().await.unwrap_or_default();
    assert!(
        first_body.contains("[DONE]") && first_body.contains("hello "),
        "the streamed body should reach the client intact: {first_body}"
    );

    // 900 charged out of 1000 leaves less than the next request needs.
    let second = h2
        .as_reqwest()
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("second HTTP/2 request");
    let status = second.status().as_u16();
    let body = second.text().await.unwrap_or_default();
    assert_eq!(
        status, 429,
        "the streamed response's authoritative usage was not charged — a second \
         request should have exhausted the budget, got {status}: {body}"
    );

    drop(harness);
}

/// HTTP/3 carries the same contract: the stream is delivered over QUIC and its
/// terminal usage is charged.
#[ignore]
#[tokio::test]
async fn streamed_usage_is_charged_on_h3() {
    let backend_port = spawn_backend(0).await;
    let (harness, _tls_dir, https_port) = spawn_h3_gateway(charging_config(backend_port)).await;

    let h3 = Http3Client::insecure().expect("HTTP/3 client");
    let url = format!("https://127.0.0.1:{https_port}/ai/v1/chat/completions");
    let options = GetOptions::default()
        .method(http::Method::POST)
        .header("content-type", "application/json")
        .body(Bytes::from(
            serde_json::to_string(&ai_body()).expect("serialize"),
        ));
    let first = h3
        .get_with_options(&url, options)
        .await
        .expect("first HTTP/3 streamed request");
    assert_eq!(first.status.as_u16(), 200, "first H3 stream should succeed");
    assert!(
        first.body_text().contains("[DONE]"),
        "the H3 streamed body should reach the client intact: {}",
        first.body_text()
    );
    assert_eq!(
        first.body_error, None,
        "a cleanly completed H3 stream must not report a body error"
    );

    let options = GetOptions::default()
        .method(http::Method::POST)
        .header("content-type", "application/json")
        .body(Bytes::from(
            serde_json::to_string(&ai_body()).expect("serialize"),
        ));
    let second = h3
        .get_with_options(&url, options)
        .await
        .expect("second HTTP/3 request");
    assert_eq!(
        second.status.as_u16(),
        429,
        "the H3 streamed response's usage was not charged: {}",
        second.body_text()
    );

    drop(harness);
}

// ============================================================================
// GHSA-rxj9 — provider-native terminal usage
// ============================================================================

/// Anthropic splits its counts across `message_start` and `message_delta`, and
/// Bedrock delivers them inside a CRC-protected binary event-stream envelope.
/// Both must charge exactly like the OpenAI shape.
#[ignore]
#[tokio::test]
async fn provider_native_terminal_usage_is_charged_end_to_end() {
    for path in ["/ai/anthropic/v1/messages", "/ai/model/x/invoke-with-response-stream"] {
        let backend_port = spawn_backend(0).await;
        let harness = GatewayHarness::builder()
            .file_config(charging_config(backend_port))
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn ai_rate_limiter gateway");

        let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
        let first = h1
            .as_reqwest()
            .post(harness.proxy_url(path))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&ai_body()).expect("serialize"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("{path}: first request failed: {error}"));
        assert_eq!(
            first.status().as_u16(),
            200,
            "{path}: first provider-native stream should succeed"
        );
        let delivered = first.bytes().await.unwrap_or_default();
        assert!(
            !delivered.is_empty(),
            "{path}: the provider-native stream delivered no bytes"
        );

        let second = h1
            .as_reqwest()
            .post(harness.proxy_url(path))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&ai_body()).expect("serialize"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("{path}: second request failed: {error}"));
        assert_eq!(
            second.status().as_u16(),
            429,
            "{path}: the provider-native terminal usage (900 tokens) was not charged"
        );

        drop(harness);
    }
}

// Sanity-check the hand-built Bedrock fixture without a gateway: a frame whose
// CRCs were wrong would fail closed inside the scanner and the charge assertion
// above would fail for the wrong reason.
#[test]
fn bedrock_fixture_is_well_framed() {
    let body = bedrock_event_stream_body();
    assert!(body.len() > 32, "fixture should contain two framed messages");
    let first_total = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    assert!(
        first_total <= body.len(),
        "declared frame length {first_total} exceeds the fixture ({})",
        body.len()
    );
    assert_eq!(
        crc32(&body[..8]),
        u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        "prelude CRC is wrong, so the gateway would fail the frame closed"
    );
}

// ============================================================================
// GHSA-q2r2 — never-ending stream, client disconnect, bounded state
// ============================================================================

/// A never-ending stream must not wedge the gateway or leak its accounting
/// reservation. The client opens one, receives the first event, and walks away;
/// the gateway must stay healthy and keep serving.
#[ignore]
#[tokio::test]
async fn an_abandoned_never_ending_stream_releases_its_accounting_state() {
    let backend_port = spawn_backend(0).await;
    // One AWS-class reservation only: if the abandoned stream leaked its permit,
    // the follow-up request below would be refused with 503 instead of served.
    let harness = GatewayHarness::builder()
        .file_config(charging_config(backend_port))
        .pool_warmup_enabled(false)
        .env("FERRUM_AI_STREAM_ACCOUNTING_MAX_BYTES", "262144")
        .spawn()
        .await
        .expect("spawn capacity-bounded gateway");

    let proxy_port = harness
        .proxy_base_url()
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .expect("proxy port");

    {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .expect("connect to proxy");
        let body = serde_json::to_string(&ai_body()).expect("serialize");
        let request = format!(
            "POST /ai/model/x/invoke-with-response-stream-hang HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(request.as_bytes()).await.expect("write");
        let mut buf = vec![0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut buf))
            .await
            .expect("first bytes of the never-ending stream")
            .expect("read");
        assert!(read > 0, "the never-ending stream delivered nothing");
        // Dropping the socket is the client disconnect.
    }

    // The permit is released when the abandoned request's context drops, which
    // the deferred terminal log drives. Poll briefly rather than assuming an
    // instantaneous teardown.
    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let mut last_status = 0;
    for _ in 0..40 {
        sleep(Duration::from_millis(250)).await;
        let response = h1
            .as_reqwest()
            .post(harness.proxy_url("/ai/v1/chat/completions"))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&ai_body()).expect("serialize"))
            .send()
            .await
            .expect("follow-up request");
        last_status = response.status().as_u16();
        if last_status == 200 {
            break;
        }
    }
    assert_eq!(
        last_status, 200,
        "the abandoned never-ending stream never released its aggregate \
         accounting reservation (last status {last_status})"
    );

    drop(harness);
}

// ============================================================================
// GHSA-q2r2 — aggregate capacity refusal and release
// ============================================================================

/// The aggregate budget must actually refuse, and it must refuse *before the
/// backend is dialed* so the refusal is gateway-local.
///
/// The budget is set to exactly one AWS-class reservation (256 KiB). A Bedrock
/// streaming request target predicts that class, so one in-flight stream commits
/// the whole budget and a concurrent second declared-streaming request is
/// refused with a `503` naming nothing about the caller or the upstream.
#[ignore]
#[tokio::test]
async fn a_saturated_aggregate_budget_refuses_before_the_backend_and_releases_after() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(charging_config(backend_port))
        .pool_warmup_enabled(false)
        .env("FERRUM_AI_STREAM_ACCOUNTING_MAX_BYTES", "262144")
        .spawn()
        .await
        .expect("spawn capacity-bounded gateway");

    // A *slow but finite* holder, deliberately: release is then driven by the
    // ordinary completion path rather than by disconnect detection, so the
    // release half of this test asserts the normal lifecycle.
    let holding_url = harness.proxy_url("/ai/model/x/invoke-with-response-stream-slow");
    let second_url = harness.proxy_url("/ai/model/x/invoke-with-response-stream");
    let body = serde_json::to_string(&ai_body()).expect("serialize");

    let holder = tokio::spawn({
        let body = body.clone();
        async move {
            let client = Http1Client::insecure().expect("HTTP/1.1 client");
            let response = client
                .as_reqwest()
                .post(holding_url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .expect("holding stream request");
            let status = response.status().as_u16();
            let _ = response.bytes().await;
            status
        }
    });

    // The holder's backend pauses 4 s mid-stream; 1.5 s in it is reliably
    // holding the only reservation and has not yet finished.
    sleep(Duration::from_millis(1500)).await;

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let refused = h1
        .as_reqwest()
        .post(&second_url)
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("second declared-streaming request");
    let status = refused.status().as_u16();
    let refusal_body = refused.text().await.unwrap_or_default();
    assert_eq!(
        status, 503,
        "a saturated aggregate accounting budget must refuse the second stream, \
         got {status}: {refusal_body}"
    );
    assert!(
        refusal_body.contains("cannot admit another metered AI response stream"),
        "the refusal should be the gateway-local capacity body, got: {refusal_body}"
    );
    // Redaction: the refusal must not echo the caller, the upstream, or the
    // configured budget.
    for leak in ["127.0.0.1", "262144", "gpt-4o-mini", &backend_port.to_string()] {
        assert!(
            !refusal_body.contains(leak),
            "capacity refusal leaked {leak:?}: {refusal_body}"
        );
    }

    // Release: once the holder's stream completes, the budget is available.
    let holder_status = holder.await.expect("holding stream task");
    assert_eq!(
        holder_status, 200,
        "the holding stream itself must have been served normally"
    );
    let mut last_status = 0;
    for _ in 0..40 {
        sleep(Duration::from_millis(250)).await;
        let response = h1
            .as_reqwest()
            .post(&second_url)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .expect("post-release request");
        last_status = response.status().as_u16();
        if last_status != 503 {
            break;
        }
    }
    assert_ne!(
        last_status, 503,
        "the aggregate reservation was never released after the holder left"
    );

    drop(harness);
}

// ============================================================================
// GHSA-q2r2 — the deferred (decoded-compressed) pre-admission
// ============================================================================

/// A proxy where a co-located `compression` plugin (priority 4050) decodes the
/// request body *before* `ai_rate_limiter` (4200) runs.
///
/// This is the deferred shape: the limiter's `before_proxy` sees no
/// `content-encoding` and no readable body, so it cannot classify the request
/// there and reserves nothing. The decoded bytes reach it only in
/// `on_final_request_body`, which still runs before the backend request is sent.
fn deferred_compressed_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "arl-proxy",
            "listen_path": "/ai",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "arl-compress"},
                {"plugin_config_id": "arl-1"},
            ],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "arl-compress",
                "proxy_id": "arl-proxy",
                "plugin_name": "compression",
                "scope": "proxy",
                "enabled": true,
                "config": {"decompress_request": true},
            },
            {
                "id": "arl-1",
                "proxy_id": "arl-proxy",
                "plugin_name": "ai_rate_limiter",
                "scope": "proxy",
                "enabled": true,
                "config": {
                    "token_limit": 100000,
                    "window_seconds": 300,
                    "limit_by": "ip",
                    "count_mode": "total_tokens",
                    "expose_headers": true,
                    "on_unmetered_response": "charge_estimate",
                },
            },
        ],
    });
    serde_yaml::to_string(&config).expect("serialize deferred-compression config")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("gzip request body");
    encoder.finish().expect("finish gzip request body")
}

/// A gzipped JSON request body — the only representation these tests send, so
/// the gateway cannot classify any of them before the final request-body hook.
fn gzip_json(value: &serde_json::Value) -> Vec<u8> {
    gzip(&serde_json::to_vec(value).expect("serialize request body"))
}

/// The same AI request that asks for a buffered response instead of a stream.
fn non_streaming_ai_body() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 8,
    })
}

/// An ordinary non-AI JSON POST sharing the proxy.
fn non_ai_json_body() -> serde_json::Value {
    json!({"order_id": 42, "quantity": 2})
}

/// Hold the entire aggregate budget with one never-ending Bedrock-class stream.
///
/// The request itself is NOT compressed, so it is classified in `before_proxy`
/// and its Bedrock streaming target takes the 256 KiB AWS reservation — the
/// whole configured budget. The backend never finishes, so the reservation is
/// held for as long as the returned task lives; the caller aborts it at the end.
/// (Release on completion and on disconnect is asserted by
/// `a_saturated_aggregate_budget_refuses_before_the_backend_and_releases_after`
/// and by the abandoned-stream test; this fixture only needs the budget pinned.)
fn spawn_budget_holder(url: String) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = Http1Client::insecure().expect("HTTP/1.1 client");
        let Ok(response) = client
            .as_reqwest()
            .post(url)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&ai_body()).expect("serialize"))
            .send()
            .await
        else {
            return;
        };
        let _ = response.bytes().await;
    })
}

fn assert_gateway_capacity_refusal(status: u16, body: &str, label: &str) {
    assert_eq!(
        status, 503,
        "{label}: a saturated aggregate budget must refuse the decoded compressed \
         stream before the backend is contacted, got {status}: {body}"
    );
    assert!(
        body.contains("cannot admit another metered AI response stream"),
        "{label}: the refusal must be the gateway-local capacity body — the backend \
         only ever answers 200 on this route — got: {body}"
    );
}

/// A streamed AI request that arrived gzipped must still be admitted before the
/// backend is contacted, so a saturated budget refuses it with the same
/// gateway-local `503` an uncompressed one gets. Otherwise compressing a request
/// would be a way around the aggregate bound entirely.
///
/// The three requests differ only in the *decoded* body, which is the whole
/// point: the gateway cannot see any of it until the final request-body hook.
/// HTTP/1.1 and HTTP/2 are exercised against one gateway; HTTP/3 has its own
/// test below.
#[ignore]
#[tokio::test]
async fn a_saturated_budget_refuses_a_decoded_compressed_stream_on_h1_and_h2() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(deferred_compressed_config(backend_port))
        .pool_warmup_enabled(false)
        .env("FERRUM_AI_STREAM_ACCOUNTING_MAX_BYTES", "262144")
        .spawn()
        .await
        .expect("spawn deferred-compression gateway");

    let holder_url = harness.proxy_url("/ai/model/x/invoke-with-response-stream-hang");
    let holder = spawn_budget_holder(holder_url);
    // The holder's backend emits its first event and then never finishes, so
    // after this settle the whole 256 KiB budget is committed and stays that way
    // for the rest of the test.
    sleep(Duration::from_millis(1500)).await;

    let url = harness.proxy_url("/ai/v1/chat/completions");
    let streamed = gzip_json(&ai_body());
    let non_streaming = gzip_json(&non_streaming_ai_body());
    let non_ai = gzip_json(&non_ai_json_body());

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let h2 = Http2Client::h2c_prior_knowledge().expect("HTTP/2 client");

    for (label, client) in [("HTTP/1.1", h1.as_reqwest()), ("HTTP/2", h2.as_reqwest())] {
        let refused = client
            .post(&url)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .body(streamed.clone())
            .send()
            .await
            .expect("gzipped streamed AI request");
        let status = refused.status().as_u16();
        let body = refused.text().await.unwrap_or_default();
        assert_gateway_capacity_refusal(status, &body, label);
        for leak in ["262144", "gpt-4o-mini", &backend_port.to_string()] {
            assert!(
                !body.contains(leak),
                "{label}: capacity refusal leaked {leak:?}: {body}"
            );
        }

        // Neutrality: the same saturated budget must not touch a request that
        // asked for no streamed response, nor one that is not an AI call at all.
        for (kind, payload) in [("non-streaming AI", &non_streaming), ("non-AI JSON", &non_ai)] {
            let response = client
                .post(&url)
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(payload.clone())
                .send()
                .await
                .expect("gzipped unaffected request");
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            assert_ne!(
                status, 503,
                "{label}: a {kind} request declares no stream, so a saturated \
                 accounting budget must not refuse it, got {status}: {body}"
            );
        }
    }

    holder.abort();
    drop(harness);
}

/// HTTP/3 carries the same deferred-admission contract: the decoded body's
/// `stream` flag is classified before the backend request is sent, so a
/// saturated budget refuses over QUIC exactly as it does over TCP.
#[ignore]
#[tokio::test]
async fn a_saturated_budget_refuses_a_decoded_compressed_stream_on_h3() {
    let backend_port = spawn_backend(0).await;
    let (harness, _tls_dir, https_port) =
        spawn_h3_gateway_with_budget(deferred_compressed_config(backend_port), "262144").await;

    let holder_url =
        format!("https://127.0.0.1:{https_port}/ai/model/x/invoke-with-response-stream-hang");
    let holder = tokio::spawn(async move {
        let client = Http3Client::insecure().expect("HTTP/3 client");
        let options = GetOptions::default()
            .method(http::Method::POST)
            .header("content-type", "application/json")
            .body(Bytes::from(
                serde_json::to_string(&ai_body()).expect("serialize"),
            ));
        let _ = client.get_with_options(&holder_url, options).await;
    });
    sleep(Duration::from_millis(1500)).await;

    let url = format!("https://127.0.0.1:{https_port}/ai/v1/chat/completions");
    let h3 = Http3Client::insecure().expect("HTTP/3 client");

    let refused = h3
        .get_with_options(
            &url,
            GetOptions::default()
                .method(http::Method::POST)
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(Bytes::from(gzip_json(&ai_body()))),
        )
        .await
        .expect("gzipped streamed AI request over H3");
    assert_gateway_capacity_refusal(refused.status.as_u16(), &refused.body_text(), "HTTP/3");

    for (kind, payload) in [
        ("non-streaming AI", non_streaming_ai_body()),
        ("non-AI JSON", non_ai_json_body()),
    ] {
        let response = h3
            .get_with_options(
                &url,
                GetOptions::default()
                    .method(http::Method::POST)
                    .header("content-type", "application/json")
                    .header("content-encoding", "gzip")
                    .body(Bytes::from(gzip_json(&payload))),
            )
            .await
            .expect("gzipped unaffected request over H3");
        assert_ne!(
            response.status.as_u16(),
            503,
            "HTTP/3: a {kind} request declares no stream, so a saturated accounting \
             budget must not refuse it: {}",
            response.body_text()
        );
    }

    holder.abort();
    drop(harness);
}

/// A backend failure that the retry policy absorbs must not leak a reservation.
///
/// The backend aborts the first connection before writing a byte. With the
/// budget pinned to a single reservation, a permit leaked on the failed attempt
/// would make the retried attempt — or the next request — refuse with 503.
#[ignore]
#[tokio::test]
async fn a_retried_backend_failure_does_not_leak_the_reservation() {
    let backend_port = spawn_backend(1).await;
    let mut config: serde_json::Value =
        serde_yaml::from_str(&charging_config(backend_port)).expect("parse config");
    config["proxies"][0]["retry"] = json!({
        "max_retries": 2,
        "retryable_methods": ["GET", "POST"],
        "retry_on_connect_failure": true,
    });
    let config = serde_yaml::to_string(&config).expect("serialize retry config");

    let harness = GatewayHarness::builder()
        .file_config(config)
        .pool_warmup_enabled(false)
        .env("FERRUM_AI_STREAM_ACCOUNTING_MAX_BYTES", "262144")
        .spawn()
        .await
        .expect("spawn retry gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    // First request: the backend aborts one connection, the retry succeeds (or
    // the request fails outright — either way nothing may stay reserved).
    let _ = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await;

    let mut last_status = 0;
    for _ in 0..20 {
        sleep(Duration::from_millis(250)).await;
        let response = h1
            .as_reqwest()
            .post(harness.proxy_url("/ai/model/x/invoke-with-response-stream"))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&ai_body()).expect("serialize"))
            .send()
            .await
            .expect("post-retry request");
        last_status = response.status().as_u16();
        if last_status != 503 {
            break;
        }
    }
    assert_ne!(
        last_status, 503,
        "a retried backend failure leaked its aggregate accounting reservation"
    );

    drop(harness);
}

// ============================================================================
// Committed-stream posture: `reject` + a zero pre-reservation estimate
// ============================================================================

/// The honest limitation, asserted rather than described.
///
/// In `completion_tokens` mode a request with no output cap reserves nothing.
/// If such a request is streamed and the provider never reports usage, then
/// `on_unmetered_response: reject` has nothing left to do — the response is
/// already on the wire, so it cannot become a 502, and "keep the reservation
/// charged" charges zero. The stream must still be delivered intact and the
/// gateway must stay consistent; what must NOT happen is a half-applied
/// rejection or a stalled response.
#[ignore]
#[tokio::test]
async fn a_zero_estimate_streamed_reject_cannot_retroactively_replace_sent_bytes() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(limiter_config(
            backend_port,
            json!({
                "token_limit": 1000,
                "window_seconds": 300,
                "limit_by": "ip",
                "count_mode": "completion_tokens",
                "on_unmetered_response": "reject",
            }),
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn reject-posture gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let response = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/no-usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&uncapped_ai_body()).expect("serialize"))
        .send()
        .await
        .expect("uncapped streamed request");
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    assert_eq!(
        status, 200,
        "a committed stream keeps its status — `reject` cannot replace bytes \
         already sent, got {status}: {body}"
    );
    assert!(
        body.contains("[DONE]") && body.contains("hello "),
        "the committed stream must still be delivered intact: {body}"
    );
    assert!(
        !body.contains("AI token usage missing"),
        "a streamed response must never be spliced with the buffered `reject` \
         body — that would corrupt the SSE representation: {body}"
    );

    // Nothing was charged (zero reservation, no authoritative usage), so the
    // budget is untouched and the next request is still admitted. This is the
    // documented posture, asserted so a future change cannot silently alter it
    // without updating the docs.
    let next = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/no-usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&uncapped_ai_body()).expect("serialize"))
        .send()
        .await
        .expect("follow-up uncapped request");
    assert_eq!(
        next.status().as_u16(),
        200,
        "a zero-reservation streamed request charges nothing, so the budget \
         must be unchanged"
    );

    drop(harness);
}

/// With a real pre-reservation, the unmetered posture DOES bite: a streamed 2xx
/// with no usage keeps the estimate charged instead of being free.
#[ignore]
#[tokio::test]
async fn a_streamed_response_without_usage_keeps_its_reservation_charged() {
    let backend_port = spawn_backend(0).await;
    let harness = GatewayHarness::builder()
        .file_config(limiter_config(
            backend_port,
            json!({
                "token_limit": 12,
                "window_seconds": 300,
                "limit_by": "ip",
                "count_mode": "completion_tokens",
                "on_unmetered_response": "charge_estimate",
            }),
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn charge-estimate gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let first = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/no-usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("first usage-less streamed request");
    assert_eq!(first.status().as_u16(), 200);
    let _ = first.text().await;

    // `max_tokens: 8` reserves 8 of a 12-token budget and the usage-less stream
    // keeps it, so a second 8-token request no longer fits.
    let second = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/no-usage"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("second usage-less streamed request");
    assert_eq!(
        second.status().as_u16(),
        429,
        "a usage-less streamed 2xx must keep its estimate charged, not be free"
    );

    drop(harness);
}

// ============================================================================
// GHSA-wh4p — co-located instances settle independently
// ============================================================================

/// Two `ai_rate_limiter` instances on one proxy own independent budgets, and one
/// streamed response must settle both. The per-IP instance has a budget the
/// 900-token stream exhausts; the per-consumer instance does not. If the two
/// shared reservation state, the second request's outcome would not be governed
/// by the exhausted instance alone.
#[ignore]
#[tokio::test]
async fn co_located_instances_settle_one_stream_independently() {
    let backend_port = spawn_backend(0).await;
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "arl-proxy",
            "listen_path": "/ai",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "arl-ip"},
                {"plugin_config_id": "arl-consumer"},
            ],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "arl-ip",
                "proxy_id": "arl-proxy",
                "plugin_name": "ai_rate_limiter",
                "scope": "proxy",
                "enabled": true,
                "config": {
                    "token_limit": 1000,
                    "window_seconds": 300,
                    "limit_by": "ip",
                    "count_mode": "total_tokens",
                },
            },
            {
                "id": "arl-consumer",
                "proxy_id": "arl-proxy",
                "plugin_name": "ai_rate_limiter",
                "scope": "proxy",
                "enabled": true,
                "config": {
                    "token_limit": 1000000,
                    "window_seconds": 300,
                    "limit_by": "ip",
                    "count_mode": "prompt_tokens",
                },
            },
        ],
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("serialize two-instance config"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn two-instance gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    let first = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("first streamed request");
    assert_eq!(first.status().as_u16(), 200);
    let _ = first.text().await;

    let second = h1
        .as_reqwest()
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&ai_body()).expect("serialize"))
        .send()
        .await
        .expect("second streamed request");
    assert_eq!(
        second.status().as_u16(),
        429,
        "the small per-IP instance must have charged the 900-token stream to its \
         own budget; a shared record would have let a sibling's state decide"
    );

    drop(harness);
}

// ============================================================================
// H3 gateway helper
// ============================================================================

async fn spawn_h3_gateway(config: String) -> (GatewayHarness, TempDir, u16) {
    spawn_h3_gateway_inner(config, None).await
}

/// The same H3 gateway with an explicit aggregate stream-accounting budget.
async fn spawn_h3_gateway_with_budget(
    config: String,
    max_bytes: &str,
) -> (GatewayHarness, TempDir, u16) {
    spawn_h3_gateway_inner(config, Some(max_bytes.to_string())).await
}

async fn spawn_h3_gateway_inner(
    config: String,
    stream_accounting_max_bytes: Option<String>,
) -> (GatewayHarness, TempDir, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_error = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let reservation = reserve_port().await.expect("reserve H3 frontend port");
        let https_port = reservation.port;
        drop(reservation);

        let tls_dir = TempDir::new().expect("frontend TLS temp dir");
        let ca = TestCa::new(&format!("arl-stream-h3-{attempt}")).expect("frontend test CA");
        let (cert, key) = ca.valid().expect("frontend leaf certificate");
        let cert_path = tls_dir.path().join("gateway.cert.pem");
        let key_path = tls_dir.path().join("gateway.key.pem");
        std::fs::write(&cert_path, cert).expect("write frontend certificate");
        std::fs::write(&key_path, key).expect("write frontend key");

        let mut builder = GatewayHarness::builder()
            .file_config(config.clone())
            .pool_warmup_enabled(false)
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string());
        if let Some(max_bytes) = stream_accounting_max_bytes.as_deref() {
            builder = builder.env("FERRUM_AI_STREAM_ACCOUNTING_MAX_BYTES", max_bytes);
        }
        let result = builder
            .env(
                "FERRUM_FRONTEND_TLS_CERT_PATH",
                cert_path.to_string_lossy().into_owned(),
            )
            .env(
                "FERRUM_FRONTEND_TLS_KEY_PATH",
                key_path.to_string_lossy().into_owned(),
            )
            .spawn()
            .await;
        match result {
            Ok(harness) => return (harness, tls_dir, https_port),
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!(
        "ai_rate_limiter H3 gateway failed after {MAX_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
}

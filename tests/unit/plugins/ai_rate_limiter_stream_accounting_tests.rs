//! Advisory coverage for `ai_rate_limiter` streaming accounting.
//!
//! * GHSA-q2r2-6r7h-f69x — unconditional full-response buffering / stream-based
//!   memory exhaustion.
//! * GHSA-rxj9-f483-g53f — provider-native stream formats bypassing actual token
//!   accounting.
//! * GHSA-wh4p-pmxm-3784 — shared reservation metadata corrupting independent
//!   token budgets.
//!
//! Every test here is deterministic: nothing sleeps, nothing polls a clock, and
//! no assertion depends on scheduling order. A failure is a real defect.

use ferrum_edge::plugins::utils::ai_stream_usage::{
    MAX_SSE_LINE_BYTES, StreamUsageFormat, StreamUsageScanner, is_aws_event_stream_content_type,
};
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ai_rate_limiter::AiRateLimiter, create_response_stream_inspector,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, create_test_context};

// ─── Fixtures ───────────────────────────────────────────────────────────

fn limiter(config: serde_json::Value) -> AiRateLimiter {
    AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap()
}

fn ip_limiter(token_limit: u64) -> AiRateLimiter {
    limiter(json!({
        "token_limit": token_limit,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true
    }))
}

/// A POST JSON context whose body is a recognizable chat request with an
/// explicit output cap, so admission always takes a non-zero reservation.
fn ai_request_ctx(max_tokens: u64, prompt: &str) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens
        }))
        .unwrap(),
    );
    ctx
}

fn sse_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());
    headers
}

/// Current window usage, read by issuing a follow-up admission pass on the same
/// (IP-keyed) bucket and reading this instance's exposed usage.
async fn observed_usage(plugin: &AiRateLimiter) -> u64 {
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata
        .get("ai_ratelimit_usage")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Drive a streamed response end to end: admit, attach the inspector chain,
/// feed `chunks`, terminate with `outcome`, and run the terminal hook.
///
/// Returns the bytes the inspector forwarded downstream, so tests can assert
/// that ordinary stream bytes are preserved exactly.
async fn stream_response(
    plugin: &Arc<dyn Plugin>,
    ctx: &mut RequestContext,
    content_type: &str,
    chunks: &[&[u8]],
    outcome: BodyOutcome,
) -> Vec<u8> {
    let plugins = [Arc::clone(plugin)];
    let mut forwarded = Vec::new();
    {
        let mut inspector =
            create_response_stream_inspector(&plugins, ctx, 200, Some(content_type))
                .expect("a metered streaming response must attach an inspector");
        for chunk in chunks {
            match inspector.on_chunk(chunk).await {
                ResponseStreamAction::Forward(bytes) => forwarded.extend_from_slice(&bytes),
                ResponseStreamAction::Terminate(bytes) => {
                    if let Some(bytes) = bytes {
                        forwarded.extend_from_slice(&bytes);
                    }
                    break;
                }
            }
        }
        if outcome.body_completed {
            match inspector.on_end().await {
                ResponseStreamAction::Forward(bytes) => forwarded.extend_from_slice(&bytes),
                ResponseStreamAction::Terminate(Some(bytes)) => {
                    forwarded.extend_from_slice(&bytes)
                }
                ResponseStreamAction::Terminate(None) => {}
            }
        }
        // Dropping the inspector publishes the scan result to the request-owned
        // handoff, exactly as the real body task does.
    }
    plugin.on_response_stream_terminated(ctx, 200, &outcome).await;
    forwarded
}

// ─── GHSA-q2r2-6r7h-f69x — no unconditional buffering ───────────────────

/// A response the limiter has nothing to reconcile against must not be pinned
/// onto the buffered path at all. This is the proxy-wide blast radius the
/// advisory describes: previously EVERY response on the proxy was buffered.
#[tokio::test]
async fn non_ai_traffic_is_never_buffered() {
    let plugin = ip_limiter(10_000);
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "a request the limiter never classified as an AI call has no body to meter"
    );
}

/// An SSE model stream is released to the streaming path once the response
/// headers identify it, so incremental delivery is preserved and no per-stream
/// body accumulates.
#[tokio::test]
async fn sse_response_is_released_to_the_streaming_path() {
    let plugin = ip_limiter(10_000);
    let mut ctx = ai_request_ctx(200, "stream me");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    assert!(
        plugin.should_buffer_response_body(&ctx),
        "an admitted AI request still needs the pre-header buffering upper bound"
    );
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &sse_headers(),
        ),
        "GHSA-q2r2-6r7h-f69x: an SSE stream must never be buffered"
    );
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/vnd.amazon.eventstream"),
            200,
            &HashMap::new(),
        ),
        "a Bedrock event stream must never be buffered"
    );
    assert!(
        plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &HashMap::new(),
        ),
        "an ordinary JSON response still uses the buffered extraction path"
    );
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            500,
            &HashMap::new(),
        ),
        "a non-2xx response only releases the reservation and needs no body"
    );
}

/// The inspector is observational: every byte it sees is forwarded downstream
/// unchanged, in order, and the usage record is still extracted.
#[tokio::test]
async fn streamed_bytes_are_forwarded_exactly_while_usage_is_extracted() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = ai_request_ctx(200, "stream me");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Split mid-line and mid-token to prove reassembly across chunk boundaries.
    let chunks: [&[u8]; 4] = [
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"usage\":{\"prompt_to",
        b"kens\":40,\"completion_tokens\":60,\"total_tokens\":100}}\n\n",
        b"data: [DONE]\n\n",
    ];
    let expected: Vec<u8> = chunks.concat();

    let forwarded = stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &chunks,
        BodyOutcome::success(expected.len() as u64),
    )
    .await;

    assert_eq!(
        forwarded, expected,
        "ordinary stream bytes must pass through byte-for-byte"
    );
}

/// A never-ending stream keeps the scanner's state bounded: a single enormous
/// line is dropped rather than reassembled, and the stream is marked malformed
/// so it can never present as a clean usage-free stream.
#[test]
fn an_unbounded_sse_line_is_dropped_rather_than_retained() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    let oversized = vec![b'x'; MAX_SSE_LINE_BYTES * 4];
    scanner.observe(b"data: ");
    scanner.observe(&oversized);
    scanner.observe(b"\n\n");
    scanner.finish();

    assert!(
        scanner.malformed(),
        "an oversized event must be recorded as not fully inspectable"
    );
    assert!(
        scanner.authoritative_usage().is_none(),
        "an oversized event is never an authoritative usage record"
    );
}

/// A client that disconnects mid-stream leaves no authoritative usage, so the
/// configured posture applies. Under the default `charge_estimate` the
/// reservation stays charged — a disconnect must not make a consumed generation
/// free.
#[tokio::test]
async fn disconnected_stream_keeps_the_reservation_charged() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = ai_request_ctx(200, "disconnect me");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = observed_usage_of(&plugin).await;
    assert!(reserved > 0, "admission must reserve tokens");

    stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &[b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\n"],
        BodyOutcome::client_disconnect(48),
    )
    .await;

    assert_eq!(
        observed_usage_of(&plugin).await,
        reserved,
        "a disconnected stream must not release the reservation"
    );
}

/// A stream that completes but never reports usage takes the unmetered path
/// exactly once. Under `warn` it releases; a second terminal pass must not
/// release again.
#[tokio::test]
async fn stream_without_usage_settles_exactly_once() {
    let plugin: Arc<dyn Plugin> = Arc::new(limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true,
        "on_unmetered_response": "warn"
    })));
    let mut ctx = ai_request_ctx(200, "no usage here");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(observed_usage_of(&plugin).await > 0);

    let body: &[u8] = b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\n";
    stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &[body],
        BodyOutcome::success(body.len() as u64),
    )
    .await;
    assert_eq!(
        observed_usage_of(&plugin).await,
        0,
        "warn releases the reservation for a usage-free stream"
    );

    // A second terminal pass (e.g. a rejection re-running the terminal hooks)
    // must be a clean no-op rather than a second release.
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    assert_eq!(
        observed_usage_of(&plugin).await,
        0,
        "the reservation must never be released twice"
    );
}

async fn observed_usage_of(plugin: &Arc<dyn Plugin>) -> u64 {
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata
        .get("ai_ratelimit_usage")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Releasing a response to the streaming path must not leak the reservation.
///
/// A non-2xx (and any 2xx representation this limiter cannot decode) attaches no
/// inspector, so there is no scan result to settle from — but the reservation
/// still has to be settled, or every such request would stay charged until the
/// window expired.
#[tokio::test]
async fn streamed_non_2xx_still_releases_the_reservation() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = ai_request_ctx(200, "backend will fail");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = observed_usage_of(&plugin).await;
    assert!(reserved > 0, "admission must reserve tokens");

    // No inspector is attached for a non-2xx; the terminal hook is the only
    // settlement point for a streamed response.
    plugin
        .on_response_stream_terminated(&mut ctx, 502, &BodyOutcome::success(0))
        .await;

    assert_eq!(
        observed_usage_of(&plugin).await,
        0,
        "a streamed non-2xx must release the reservation exactly as a buffered one does"
    );
}

/// The same terminal hook must be inert for unrelated streamed traffic on a
/// shared proxy: nothing reserved, nothing classified, nothing to settle.
#[tokio::test]
async fn stream_termination_is_inert_for_unrelated_traffic() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;

    assert_eq!(
        observed_usage_of(&plugin).await,
        0,
        "non-AI streamed traffic must neither charge nor release anything"
    );
}

// ─── GHSA-rxj9-f483-g53f — provider-native stream formats ───────────────

/// Gemini `streamGenerateContent` SSE reports usage as `usageMetadata` on
/// `GenerateContentResponse` events, with no root `usage` object at all. The
/// pre-fix SSE parser only entered generic extraction for root `usage`, so these
/// streams were unmetered.
#[test]
fn gemini_sse_usage_metadata_is_extracted() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(
        br#"data: {"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}
"#,
    );
    scanner.observe(
        br#"data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":29,"totalTokenCount":40}}
"#,
    );
    scanner.finish();

    let usage = scanner
        .authoritative_usage()
        .expect("Gemini usageMetadata must be an authoritative usage record");
    assert_eq!(usage.prompt_tokens, Some(11));
    assert_eq!(usage.completion_tokens, Some(29));
    assert_eq!(usage.total_for_mode("total_tokens"), Some(40));
    assert!(!scanner.malformed());
}

/// Native TGI reports its authoritative counts on the terminal object only.
/// Every earlier stream event carries `details: null`, which must NOT be read as
/// an authoritative zero.
#[test]
fn tgi_terminal_details_are_extracted_and_interim_events_are_not() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b"data: {\"token\":{\"id\":1,\"text\":\"hi\"},\"details\":null}\n");
    scanner.finish();
    assert!(
        scanner.authoritative_usage().is_none(),
        "an interim TGI event carries no usage"
    );

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(
        br#"data: {"token":{"id":2,"text":"!"},"generated_text":"hi!","details":{"finish_reason":"length","generated_tokens":29}}
"#,
    );
    scanner.finish();
    let usage = scanner
        .authoritative_usage()
        .expect("TGI details.generated_tokens must be authoritative");
    assert_eq!(usage.completion_tokens, Some(29));
    assert_eq!(usage.total_for_mode("completion_tokens"), Some(29));
}

/// The documented Bedrock streaming media type is recognized as a meterable
/// format rather than an unsupported content type.
#[test]
fn bedrock_event_stream_content_type_is_recognized() {
    assert!(is_aws_event_stream_content_type(
        "application/vnd.amazon.eventstream"
    ));
    assert!(is_aws_event_stream_content_type(
        "Application/VND.Amazon.EventStream; charset=utf-8"
    ));
    assert!(!is_aws_event_stream_content_type("application/json"));
    assert_eq!(
        StreamUsageFormat::for_content_type("application/vnd.amazon.eventstream"),
        Some(StreamUsageFormat::AwsEventStream)
    );
    assert_eq!(
        StreamUsageFormat::for_content_type("text/event-stream"),
        Some(StreamUsageFormat::Sse)
    );
    assert_eq!(StreamUsageFormat::for_content_type("application/json"), None);
}

/// CRC-32 (IEEE) — the algorithm the AWS event-stream framing specifies for
/// both its prelude and its whole-message checksum.
fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Encode one AWS event-stream STRING header (value type `7`).
fn string_header(name: &str, value: &str) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(u8::try_from(name.len()).unwrap());
    header.extend_from_slice(name.as_bytes());
    header.push(7);
    header.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    header.extend_from_slice(value.as_bytes());
    header
}

/// The documented Bedrock reserved header block for one modelled event.
fn bedrock_event_headers(event_type: &str) -> Vec<u8> {
    let mut headers = string_header(":event-type", event_type);
    headers.extend_from_slice(&string_header(":content-type", "application/json"));
    headers.extend_from_slice(&string_header(":message-type", "event"));
    headers
}

/// A correctly checksummed 12-byte prelude for an arbitrary declared layout.
///
/// Used by the negative framing tests so they exercise the *length* validation
/// rather than tripping the prelude CRC first.
fn event_stream_prelude(total_length: u32, headers_length: u32) -> Vec<u8> {
    let mut prelude = Vec::with_capacity(12);
    prelude.extend_from_slice(&total_length.to_be_bytes());
    prelude.extend_from_slice(&headers_length.to_be_bytes());
    let checksum = crc32(&prelude);
    prelude.extend_from_slice(&checksum.to_be_bytes());
    prelude
}

/// Build one complete, correctly checksummed AWS event-stream message.
///
/// Layout: total length (u32 BE), headers length (u32 BE), prelude CRC-32 over
/// those eight bytes, the header block, the payload, and a message CRC-32 over
/// everything preceding it. Both checksums are real: the scanner verifies them,
/// because `application/vnd.amazon.eventstream` is application framing that no
/// HTTP transport validates.
fn event_stream_frame(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    let total = 16 + headers.len() + payload.len();
    let mut message = event_stream_prelude(
        u32::try_from(total).unwrap(),
        u32::try_from(headers.len()).unwrap(),
    );
    message.extend_from_slice(headers);
    message.extend_from_slice(payload);
    let checksum = crc32(&message);
    message.extend_from_slice(&checksum.to_be_bytes());
    message
}

/// A message with no header block at all — the shape a provider variant that
/// frames a bare JSON payload emits. Absent reserved headers stay meterable.
fn event_stream_message(payload: &[u8]) -> Vec<u8> {
    event_stream_frame(&[], payload)
}

/// Bedrock `InvokeModelWithResponseStream` wraps each model chunk as a base64
/// `bytes` envelope; the terminal chunk carries
/// `amazon-bedrock-invocationMetrics`.
#[test]
fn bedrock_invocation_metrics_are_extracted_from_the_event_stream() {
    use base64::Engine as _;
    let inner = json!({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {
            "inputTokenCount": 17,
            "outputTokenCount": 83,
            "invocationLatency": 900,
            "firstByteLatency": 100
        }
    });
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner.to_string());
    let envelope = serde_json::to_vec(&json!({ "bytes": encoded })).unwrap();

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_message(&envelope));
    scanner.finish();

    let usage = scanner
        .authoritative_usage()
        .expect("Bedrock invocation metrics must be authoritative");
    assert_eq!(usage.prompt_tokens, Some(17));
    assert_eq!(usage.completion_tokens, Some(83));
    assert_eq!(usage.total_for_mode("total_tokens"), Some(100));
    assert!(!scanner.malformed());
}

/// Bedrock `ConverseStream` reports usage directly on its `metadata` event.
#[test]
fn bedrock_converse_stream_metadata_usage_is_extracted() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 12, "outputTokens": 34, "totalTokens": 46}
    }))
    .unwrap();

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_message(&payload));
    scanner.finish();

    let usage = scanner.authoritative_usage().expect("ConverseStream usage");
    assert_eq!(usage.total_for_mode("total_tokens"), Some(46));
}

/// A message reassembled across arbitrary chunk boundaries yields the same
/// result as one delivered whole.
#[test]
fn event_stream_messages_reassemble_across_chunk_boundaries() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 7, "totalTokens": 12}
    }))
    .unwrap();
    let message = event_stream_message(&payload);

    for split in 1..message.len() {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&message[..split]);
        scanner.observe(&message[split..]);
        scanner.finish();
        assert_eq!(
            scanner
                .authoritative_usage()
                .and_then(|usage| usage.total_for_mode("total_tokens")),
            Some(12),
            "reassembly must be independent of the chunk split at {split}"
        );
        assert!(!scanner.malformed(), "split at {split} must not be malformed");
    }
}

/// A declared message length that cannot be honored is hostile framing: the
/// scanner must stop and report the stream as malformed rather than allocating
/// for it or reporting a clean usage-free stream.
#[test]
fn oversized_or_impossible_event_stream_framing_fails_closed() {
    // Each prelude below carries a VALID prelude CRC, so the rejection proves
    // the length validation and not merely the checksum.

    // Declared total length below the framing overhead.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_prelude(4, 0));
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());

    // Declared total length far above the retained bound.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_prelude(u32::MAX, 0));
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());

    // Headers longer than the message that contains them.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_prelude(32, 1024));
    scanner.finish();
    assert!(scanner.malformed());
}

/// The prelude CRC-32 covers the two declared lengths. A corrupted prelude must
/// be refused BEFORE its declared length is honored, so a forged length can
/// never drive reassembly.
#[test]
fn event_stream_prelude_crc_mismatch_fails_closed() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 7, "totalTokens": 12}
    }))
    .unwrap();
    let mut message = event_stream_frame(&bedrock_event_headers("metadata"), &payload);

    // Flip one bit inside the prelude checksum.
    message[11] ^= 0x01;

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&message);
    scanner.finish();

    assert!(
        scanner.malformed(),
        "a prelude CRC mismatch must mark the scan malformed"
    );
    assert!(
        scanner.authoritative_usage().is_none(),
        "usage behind a corrupted prelude is never authoritative"
    );
}

/// The message CRC-32 covers the complete message except its own checksum.
/// Corruption anywhere in the headers or payload must fail the scan closed even
/// though the prelude still validates.
#[test]
fn event_stream_message_crc_mismatch_fails_closed() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 7, "totalTokens": 12}
    }))
    .unwrap();
    let headers = bedrock_event_headers("metadata");

    // Corrupt a payload byte: the prelude (lengths) is untouched and still
    // checksums correctly, so only the message CRC can catch this.
    let mut corrupted_payload = event_stream_frame(&headers, &payload);
    let payload_start = 12 + headers.len();
    corrupted_payload[payload_start] ^= 0x20;
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&corrupted_payload);
    scanner.finish();
    assert!(
        scanner.malformed(),
        "a payload byte flip must be caught by the message CRC"
    );
    assert!(scanner.authoritative_usage().is_none());

    // Corrupt the trailing checksum itself.
    let mut corrupted_crc = event_stream_frame(&headers, &payload);
    let last = corrupted_crc.len() - 1;
    corrupted_crc[last] ^= 0x01;
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&corrupted_crc);
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());
}

/// The canonical wire headers of both metered Bedrock event kinds are accepted:
/// `InvokeModelWithResponseStream`'s `chunk` and `ConverseStream`'s `metadata`.
#[test]
fn canonical_bedrock_event_headers_are_accepted() {
    use base64::Engine as _;
    let inner = json!({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 17, "outputTokenCount": 83}
    });
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner.to_string());
    let envelope = serde_json::to_vec(&json!({ "bytes": encoded })).unwrap();

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(
        &bedrock_event_headers("chunk"),
        &envelope,
    ));
    scanner.finish();
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(100),
        "an `:event-type: chunk` frame is a usage authority"
    );
    assert!(!scanner.malformed());

    let metadata = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 12, "outputTokens": 34, "totalTokens": 46}
    }))
    .unwrap();
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(
        &bedrock_event_headers("metadata"),
        &metadata,
    ));
    scanner.finish();
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(46),
        "an `:event-type: metadata` frame is a usage authority"
    );
    assert!(!scanner.malformed());
}

/// A frame that is well-framed but is NOT one of the usage-bearing event kinds
/// must not mint usage, even when its payload is usage-shaped. Framing is
/// intact, so the scan itself stays clean.
#[test]
fn non_usage_bedrock_event_types_do_not_mint_usage() {
    let usage_shaped = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 999, "outputTokens": 999, "totalTokens": 1998}
    }))
    .unwrap();

    for event_type in [
        "contentBlockDelta",
        "messageStart",
        "messageStop",
        "totally-unknown",
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(
            &bedrock_event_headers(event_type),
            &usage_shaped,
        ));
        scanner.finish();
        assert!(
            scanner.authoritative_usage().is_none(),
            "`{event_type}` must never mint authoritative usage"
        );
        assert!(
            !scanner.malformed(),
            "`{event_type}` is well-framed, so the scan is not damaged"
        );
    }
}

/// Exception and error frames terminate a Bedrock stream in failure. Their
/// payload is an error document, never a usage authority.
#[test]
fn bedrock_exception_frames_do_not_mint_usage() {
    let usage_shaped = serde_json::to_vec(&json!({
        "message": "throttled",
        "usage": {"inputTokens": 999, "outputTokens": 999, "totalTokens": 1998}
    }))
    .unwrap();

    let mut exception = string_header(":message-type", "exception");
    exception.extend_from_slice(&string_header(":exception-type", "throttlingException"));
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(&exception, &usage_shaped));
    scanner.finish();
    assert!(scanner.authoritative_usage().is_none());

    let error = string_header(":message-type", "error");
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(&error, &usage_shaped));
    scanner.finish();
    assert!(
        scanner.authoritative_usage().is_none(),
        "an `error` message-type is not an event"
    );
}

/// A header block that cannot be walked exactly to its end is damaged framing:
/// the payload boundary the prelude declared is no longer corroborated, so the
/// scan fails closed rather than reading the bytes behind it.
#[test]
fn malformed_event_stream_headers_fail_closed() {
    let usage = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 7, "totalTokens": 12}
    }))
    .unwrap();

    // A declared string length that runs past the end of the header block.
    let mut overrun = string_header(":event-type", "metadata");
    let value_length_at = overrun.len() - 8 - 2;
    overrun[value_length_at] = 0xff;

    // A header value type the framing does not define, so nothing after it can
    // be located.
    let unknown_type = {
        let mut header = Vec::new();
        header.push(11u8);
        header.extend_from_slice(b":event-type");
        header.push(0x5a);
        header
    };

    // A zero-length header name.
    let empty_name = vec![0u8, 7u8, 0u8, 0u8];

    // The same reserved header twice with conflicting values.
    let mut duplicated = string_header(":event-type", "metadata");
    duplicated.extend_from_slice(&string_header(":event-type", "contentBlockDelta"));

    for (label, headers) in [
        ("string length overrun", overrun),
        ("unknown value type", unknown_type),
        ("empty header name", empty_name),
        ("duplicate reserved header", duplicated),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(&headers, &usage));
        scanner.finish();
        assert!(
            scanner.malformed(),
            "{label}: a header block that cannot be walked must fail closed"
        );
        assert!(
            scanner.authoritative_usage().is_none(),
            "{label}: no usage may be minted from a damaged header block"
        );
    }
}

/// A truncated event stream — the terminal usage message never fully arrived —
/// must not be reported as a clean stream that simply had no usage.
#[test]
fn truncated_event_stream_is_malformed_not_usage_free() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 7, "totalTokens": 12}
    }))
    .unwrap();
    let message = event_stream_message(&payload);

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&message[..message.len() - 3]);
    scanner.finish();

    assert!(
        scanner.malformed(),
        "a partially received message must fail closed"
    );
    assert!(scanner.authoritative_usage().is_none());
}

/// Encode one AWS event-stream header with an explicit value type.
///
/// `value` is the raw on-wire value encoding: nothing for the boolean types,
/// the fixed-width bytes for the numeric/timestamp/UUID types, and a
/// [`length_prefixed_value`] blob for `BYTE_ARRAY` (6) and `STRING` (7).
fn typed_header(name: &str, value_type: u8, value: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(u8::try_from(name.len()).unwrap());
    header.extend_from_slice(name.as_bytes());
    header.push(value_type);
    header.extend_from_slice(value);
    header
}

/// The 16-bit big-endian length prefix and bytes of a `BYTE_ARRAY`/`STRING`
/// header value.
fn length_prefixed_value(bytes: &[u8]) -> Vec<u8> {
    let mut value = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    value.extend_from_slice(bytes);
    value
}

/// A canonical `ConverseStream` `metadata` frame reporting one usage record.
fn bedrock_metadata_usage_frame(input: u64, output: u64) -> Vec<u8> {
    let total = input + output;
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": input, "outputTokens": output, "totalTokens": total}
    }))
    .unwrap();
    let headers = bedrock_event_headers("metadata");
    event_stream_frame(&headers, &payload)
}

/// A canonical `InvokeModelWithResponseStream` `chunk` frame wrapping `inner`
/// as the documented base64 `bytes` envelope.
fn bedrock_chunk_frame(inner: &str) -> Vec<u8> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
    let envelope = serde_json::to_vec(&json!({ "bytes": encoded })).unwrap();
    let headers = bedrock_event_headers("chunk");
    event_stream_frame(&headers, &envelope)
}

/// Once a frame declares ANY reserved header it is speaking the Bedrock
/// vocabulary, so a *partial* declaration is ambiguous rather than permissive.
/// Usage is authoritative only for the fully specified documented shape:
/// `:message-type` exactly `event`, `:event-type` exactly `chunk`/`metadata`,
/// and no `:exception-type`. Everything short of that must stay unmetered —
/// while remaining well-framed, so it is not damage either.
#[test]
fn partial_reserved_event_stream_headers_never_mint_usage() {
    let usage_shaped = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 999, "outputTokens": 999, "totalTokens": 1998}
    }))
    .unwrap();

    // `:event-type` with no `:message-type`: nothing asserts this frame is an
    // `event` rather than an exception or an error frame.
    let metadata_only = string_header(":event-type", "metadata");
    let chunk_only = string_header(":event-type", "chunk");

    // `:message-type: event` with no `:event-type`: nothing names a
    // usage-bearing kind.
    let event_only = string_header(":message-type", "event");

    // An `:exception-type` disqualifies the frame however it is framed.
    let exception_only = string_header(":exception-type", "throttling");
    let mut event_and_exception = string_header(":message-type", "event");
    event_and_exception.extend_from_slice(&string_header(":exception-type", "t"));
    let mut full_and_exception = string_header(":message-type", "event");
    full_and_exception.extend_from_slice(&string_header(":event-type", "metadata"));
    full_and_exception.extend_from_slice(&string_header(":exception-type", "t"));

    // A non-`event` message type is never a usage authority, whatever the
    // event type claims.
    let mut exception_kind = string_header(":message-type", "exception");
    exception_kind.extend_from_slice(&string_header(":event-type", "metadata"));
    let mut error_kind = string_header(":message-type", "error");
    error_kind.extend_from_slice(&string_header(":event-type", "chunk"));

    // The comparisons are exact: no case folding, no empty-value fallback, and
    // no unknown-kind fallback.
    let mut folded_message = string_header(":message-type", "Event");
    folded_message.extend_from_slice(&string_header(":event-type", "metadata"));
    let mut folded_event = string_header(":message-type", "event");
    folded_event.extend_from_slice(&string_header(":event-type", "Metadata"));
    let mut empty_message = string_header(":message-type", "");
    empty_message.extend_from_slice(&string_header(":event-type", "metadata"));
    let mut empty_event = string_header(":message-type", "event");
    empty_event.extend_from_slice(&string_header(":event-type", ""));
    let mut unknown_event = string_header(":message-type", "event");
    unknown_event.extend_from_slice(&string_header(":event-type", "usage"));

    for (label, headers) in [
        (":event-type metadata alone", metadata_only),
        (":event-type chunk alone", chunk_only),
        (":message-type event alone", event_only),
        (":exception-type alone", exception_only),
        ("event + exception-type", event_and_exception),
        ("event + metadata + exception", full_and_exception),
        ("exception message-type", exception_kind),
        ("error message-type", error_kind),
        ("case-mismatched message-type", folded_message),
        ("case-mismatched event-type", folded_event),
        ("empty message-type", empty_message),
        ("empty event-type", empty_event),
        ("unknown event-type", unknown_event),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(&headers, &usage_shaped));
        scanner.finish();
        assert!(
            scanner.authoritative_usage().is_none(),
            "{label}: a partial reserved-header declaration must never mint usage"
        );
        assert!(
            !scanner.malformed(),
            "{label}: the framing itself is intact, so the frame is not a damaged candidate"
        );
    }
}

/// A reserved header is documented as a `STRING`. Encoded with any other AWS
/// header value type its meaning is ambiguous, so it must fail the scan closed
/// rather than being walked past as if the header were absent — otherwise a
/// wrong-typed `:message-type`/`:event-type` would fall through to the
/// headerless compatibility path and mint usage.
#[test]
fn wrong_typed_reserved_event_stream_headers_fail_closed() {
    let usage_shaped = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 999, "outputTokens": 999, "totalTokens": 1998}
    }))
    .unwrap();

    let bool_message = typed_header(":message-type", 0, &[]);
    let bool_event = typed_header(":event-type", 1, &[]);
    let byte_event = typed_header(":event-type", 2, &[7]);
    let short_message = typed_header(":message-type", 3, &[0, 1]);
    let int_event = typed_header(":event-type", 4, &[0, 0, 0, 1]);
    let long_event = typed_header(":event-type", 5, &[0; 8]);
    let exception_value = length_prefixed_value(b"throttlingException");
    let bytes_exception = typed_header(":exception-type", 6, &exception_value);
    let timestamp_event = typed_header(":event-type", 8, &[0; 8]);
    let uuid_event = typed_header(":event-type", 9, &[0; 16]);

    // A wrong-typed occurrence followed by a valid duplicate: the ambiguous
    // header is refused before the later well-formed one can be read, so
    // ordering cannot be used to smuggle a usable declaration past it.
    let mut wrong_then_valid = typed_header(":event-type", 4, &[0, 0, 0, 1]);
    wrong_then_valid.extend_from_slice(&string_header(":event-type", "metadata"));
    wrong_then_valid.extend_from_slice(&string_header(":message-type", "event"));

    // And the mirror image: a valid declaration followed by a wrong-typed
    // duplicate is equally ambiguous.
    let mut valid_then_wrong = string_header(":event-type", "metadata");
    let wrong_typed_event = typed_header(":event-type", 4, &[0, 0, 0, 1]);
    valid_then_wrong.extend_from_slice(&wrong_typed_event);
    valid_then_wrong.extend_from_slice(&string_header(":message-type", "event"));

    // A duplicate STRING declaration stays fail-closed as before.
    let mut duplicate_message = string_header(":message-type", "event");
    duplicate_message.extend_from_slice(&string_header(":message-type", "event"));
    duplicate_message.extend_from_slice(&string_header(":event-type", "metadata"));

    for (label, headers) in [
        (":message-type as BOOL_TRUE", bool_message),
        (":event-type as BOOL_FALSE", bool_event),
        (":event-type as BYTE", byte_event),
        (":message-type as SHORT", short_message),
        (":event-type as INTEGER", int_event),
        (":event-type as LONG", long_event),
        (":exception-type as BYTE_ARRAY", bytes_exception),
        (":event-type as TIMESTAMP", timestamp_event),
        (":event-type as UUID", uuid_event),
        ("wrong-typed then valid duplicate", wrong_then_valid),
        ("valid then wrong-typed duplicate", valid_then_wrong),
        ("duplicate STRING :message-type", duplicate_message),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(&headers, &usage_shaped));
        scanner.finish();
        assert!(
            scanner.malformed(),
            "{label}: an ambiguous reserved header must fail the scan closed"
        );
        assert!(
            scanner.authoritative_usage().is_none(),
            "{label}: no usage may be minted from an ambiguous reserved header"
        );
    }
}

/// All ten documented AWS header value encodings (type codes 0 through 9:
/// `BOOL_TRUE`, `BOOL_FALSE`, `BYTE`, `SHORT`, `INTEGER`, `LONG`, `BYTE_ARRAY`,
/// `STRING`, `TIMESTAMP`, `UUID`) are still walked in full for
/// NON-reserved headers, so a frame carrying operator/service metadata beside
/// its reserved headers is metered normally — and an undefined value type on a
/// non-reserved header still fails closed, because its width is unknown.
#[test]
fn every_defined_header_value_type_is_walked_for_non_reserved_headers() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 12, "outputTokens": 34, "totalTokens": 46}
    }))
    .unwrap();

    let mut headers = Vec::new();
    headers.extend(typed_header("x-bool-true", 0, &[]));
    headers.extend(typed_header("x-bool-false", 1, &[]));
    headers.extend(typed_header("x-byte", 2, &[7]));
    headers.extend(typed_header("x-short", 3, &[0, 9]));
    headers.extend(typed_header("x-int", 4, &[0, 0, 0, 9]));
    headers.extend(typed_header("x-long", 5, &[0; 8]));
    let opaque = length_prefixed_value(b"opaque\x00\xff");
    headers.extend(typed_header("x-bytes", 6, &opaque));
    let text = length_prefixed_value(b"text");
    headers.extend(typed_header("x-string", 7, &text));
    headers.extend(typed_header("x-timestamp", 8, &[0; 8]));
    headers.extend(typed_header("x-uuid", 9, &[0; 16]));
    headers.extend(bedrock_event_headers("metadata"));

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(&headers, &payload));
    scanner.finish();
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(46),
        "every defined value type must be walkable without losing the frame"
    );
    assert!(!scanner.malformed());

    // An undefined value type on a non-reserved header has an unknown width, so
    // nothing after it can be located.
    let mut unknown = typed_header("x-mystery", 0x5a, &[]);
    unknown.extend(bedrock_event_headers("metadata"));
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&event_stream_frame(&unknown, &payload));
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());
}

/// A frame that declares NONE of the reserved headers keeps the documented
/// compatibility path, including one that carries only non-reserved headers.
#[test]
fn headerless_event_stream_frames_keep_the_compatibility_path() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 12, "outputTokens": 34, "totalTokens": 46}
    }))
    .unwrap();

    let mut non_reserved = string_header(":content-type", "application/json");
    non_reserved.extend_from_slice(&string_header("x-amzn-requestid", "abc"));

    for (label, headers) in [
        ("no header block at all", Vec::new()),
        ("only non-reserved headers", non_reserved),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(&headers, &payload));
        scanner.finish();
        assert_eq!(
            scanner
                .authoritative_usage()
                .and_then(|usage| usage.total_for_mode("total_tokens")),
            Some(46),
            "{label}: a frame with no reserved headers stays meterable"
        );
        assert!(!scanner.malformed(), "{label}");
    }
}

/// The AWS path applies the same ordering-safe invariant as SSE: an undecodable
/// candidate AFTER the last authoritative usage record invalidates that older
/// snapshot for settlement, so a Bedrock stream whose tail was corrupted can no
/// longer be charged against the counts it reported earlier.
#[test]
fn event_stream_damage_after_usage_fails_closed() {
    const UNREADABLE_USAGE: &[u8] = br#"{"usage":{"inputTokens":"lots"}}"#;
    const NO_USAGE: &[u8] = br#"{"metrics":{"latencyMs":12}}"#;
    const BAD_METRICS: &str = r#"{"amazon-bedrock-invocationMetrics":{"in":"17"}}"#;

    let chunk_headers = bedrock_event_headers("chunk");
    let metadata_headers = bedrock_event_headers("metadata");

    let non_json = event_stream_frame(&chunk_headers, b"not json at all");
    let non_object = event_stream_frame(&chunk_headers, b"[1,2,3]");
    let empty = event_stream_frame(&chunk_headers, b"");
    let truncated_inner = bedrock_chunk_frame(r#"{"type":"content_block_"#);
    let scalar_inner = bedrock_chunk_frame("42");
    let unreadable_usage = event_stream_frame(&metadata_headers, UNREADABLE_USAGE);
    let no_usage = event_stream_frame(&metadata_headers, NO_USAGE);
    let unreadable_metrics = bedrock_chunk_frame(BAD_METRICS);

    for (label, damaging) in [
        ("non-JSON chunk payload", non_json),
        ("non-object chunk payload", non_object),
        ("empty chunk payload", empty),
        ("truncated inner document", truncated_inner),
        ("non-object inner document", scalar_inner),
        ("metadata with unreadable usage", unreadable_usage),
        ("metadata with no usage at all", no_usage),
        ("unreadable invocation metrics", unreadable_metrics),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&bedrock_metadata_usage_frame(12, 34));
        assert!(!scanner.malformed(), "{label}: the stream is clean so far");
        assert_eq!(
            scanner
                .authoritative_usage()
                .and_then(|usage| usage.total_for_mode("total_tokens")),
            Some(46),
            "{label}: the earlier snapshot was recorded"
        );

        scanner.observe(&damaging);
        scanner.finish();
        assert!(
            scanner.malformed(),
            "{label}: a damaged candidate after the last usage record must fail closed"
        );
    }
}

/// The mirror-image ordering DOES recover while the framing itself stayed
/// intact: a later valid authoritative cumulative usage record restates the
/// provider's complete counts, so the earlier undecodable candidate no longer
/// hides anything.
#[test]
fn event_stream_damage_before_usage_recovers() {
    let chunk_headers = bedrock_event_headers("chunk");
    let non_json = event_stream_frame(&chunk_headers, b"not json at all");
    let truncated_inner = bedrock_chunk_frame(r#"{"type":"content_block_"#);
    let empty_inner = bedrock_chunk_frame("");
    let scalar_inner = bedrock_chunk_frame("42");

    for (label, damaging) in [
        ("non-JSON chunk payload", non_json),
        ("truncated inner document", truncated_inner),
        ("empty inner document", empty_inner),
        ("non-object inner document", scalar_inner),
    ] {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&damaging);
        assert!(
            scanner.malformed(),
            "{label}: the undecodable candidate damages the scan immediately"
        );

        scanner.observe(&bedrock_metadata_usage_frame(12, 34));
        scanner.finish();
        assert!(
            !scanner.malformed(),
            "{label}: a later authoritative cumulative record recovers the scan"
        );
        assert_eq!(
            scanner
                .authoritative_usage()
                .and_then(|usage| usage.total_for_mode("total_tokens")),
            Some(46)
        );
    }
}

/// A payload that simply does not declare the base64 `bytes` envelope is the
/// ordinary shape of a `ConverseStream` event and of any provider variant that
/// frames its model document directly. Absence must therefore stay clean
/// content — and a metrics container carried inline is still metered.
#[test]
fn a_chunk_without_a_bytes_field_stays_ordinary_content() {
    let chunk_headers = bedrock_event_headers("chunk");
    let content = event_stream_frame(
        &chunk_headers,
        br#"{"type":"content_block_delta","delta":{"text":"Hi"}}"#,
    );
    let inline_metrics = event_stream_frame(
        &chunk_headers,
        br#"{"amazon-bedrock-invocationMetrics":{"inputTokenCount":17,"outputTokenCount":83}}"#,
    );

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&content);
    scanner.finish();
    assert!(
        !scanner.malformed(),
        "a missing `bytes` field is ordinary content, not an invalid envelope"
    );
    assert!(scanner.authoritative_usage().is_none());

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&content);
    scanner.observe(&inline_metrics);
    scanner.finish();
    assert!(!scanner.malformed());
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(100),
        "a frame with no `bytes` envelope is still metered normally"
    );
}

/// An *explicitly declared* `bytes` field that is not a string is an invalid
/// base64-envelope declaration, never ordinary content: the real payload cannot
/// be reconstructed, so the scan halts as hard malformed and no later frame —
/// including a valid authoritative cumulative record — may recover it.
#[test]
fn an_explicitly_wrong_typed_bytes_envelope_fails_hard() {
    let chunk_headers = bedrock_event_headers("chunk");

    let variants: [(&str, &[u8]); 5] = [
        ("null", br#"{"bytes":null}"#),
        ("number", br#"{"bytes":12345}"#),
        ("boolean", br#"{"bytes":true}"#),
        ("object", br#"{"bytes":{"inner":"eyJhIjoxfQ=="}}"#),
        ("array", br#"{"bytes":["eyJhIjoxfQ=="]}"#),
    ];

    for (label, payload) in variants {
        let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
        scanner.observe(&event_stream_frame(&chunk_headers, payload));
        assert!(
            scanner.malformed(),
            "{label}: an explicit non-string `bytes` is an invalid envelope declaration"
        );

        // The failure is hard, not ordering-sensitive: parsing has stopped.
        scanner.observe(&bedrock_metadata_usage_frame(12, 34));
        scanner.finish();
        assert!(
            scanner.malformed(),
            "{label}: a hard envelope failure is never cleared by a later record"
        );
        assert!(
            scanner.authoritative_usage().is_none(),
            "{label}: no frame after a hard envelope failure may be parsed"
        );
    }
}

/// A `bytes` value that is a string but not decodable base64 could have carried
/// the terminal `amazon-bedrock-invocationMetrics`, and nothing about it can be
/// reconstructed. It halts the scan for the same reason, so a later valid
/// authoritative record behind it can neither be read nor recover the stream.
#[test]
fn an_undecodable_bytes_envelope_halts_and_cannot_be_recovered() {
    let chunk_headers = bedrock_event_headers("chunk");
    let undecodable = event_stream_frame(&chunk_headers, br#"{"bytes":"!!! not base64 !!!"}"#);

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&undecodable);
    assert!(
        scanner.malformed(),
        "an undecodable envelope damages the scan immediately"
    );

    scanner.observe(&bedrock_metadata_usage_frame(12, 34));
    scanner.finish();
    assert!(
        scanner.malformed(),
        "invalid base64 is a hard failure, not ordering-sensitive damage"
    );
    assert!(
        scanner.authoritative_usage().is_none(),
        "a halted scan parses no further frames, so the later record is never read"
    );
}

/// The contrast that pins the boundary: an envelope that DECODED but whose inner
/// document was unreadable stays ordering-sensitive, while an envelope that never
/// decoded at all does not. Same frame headers, same position in the stream, same
/// following authoritative record — only the recoverability differs.
#[test]
fn only_a_decoded_envelope_stays_recoverable() {
    let chunk_headers = bedrock_event_headers("chunk");
    let decoded_but_unreadable = bedrock_chunk_frame("not a json document");
    let never_decoded = event_stream_frame(&chunk_headers, br#"{"bytes":"%%%%"}"#);

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&decoded_but_unreadable);
    assert!(scanner.malformed());
    scanner.observe(&bedrock_metadata_usage_frame(12, 34));
    scanner.finish();
    assert!(
        !scanner.malformed(),
        "a decoded envelope's unreadable inner document is recoverable damage"
    );
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(46)
    );

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&never_decoded);
    scanner.observe(&bedrock_metadata_usage_frame(12, 34));
    scanner.finish();
    assert!(
        scanner.malformed(),
        "an envelope that never decoded is irrecoverable"
    );
    assert!(scanner.authoritative_usage().is_none());
}

/// Ordinary provider content must be told apart from a malformed candidate. A
/// well-framed non-usage event and a `chunk` that simply carries model text —
/// before AND after the usage record — are the normal Bedrock stream shape and
/// must never damage the scan.
#[test]
fn well_framed_non_usage_event_stream_content_is_not_damaging() {
    let start = bedrock_chunk_frame(r#"{"type":"message_start"}"#);
    let delta = bedrock_chunk_frame(r#"{"type":"content_block_delta"}"#);
    let stop = bedrock_chunk_frame(r#"{"type":"content_block_stop"}"#);
    let delta_headers = bedrock_event_headers("contentBlockDelta");
    let content = event_stream_frame(&delta_headers, br#"{"delta":{"t":"Hi"}}"#);
    let stop_headers = bedrock_event_headers("messageStop");
    let message_stop = event_stream_frame(&stop_headers, br#"{"stopReason":"end"}"#);
    let usage = bedrock_metadata_usage_frame(12, 34);

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    scanner.observe(&start);
    scanner.observe(&delta);
    scanner.observe(&content);
    scanner.observe(&usage);
    // Content after the usage record is still content, not tail damage.
    scanner.observe(&stop);
    scanner.observe(&message_stop);
    scanner.finish();

    assert!(
        !scanner.malformed(),
        "ordinary content events are not damaged candidates"
    );
    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(46)
    );
}

/// Malformed JSON inside otherwise well-formed SSE lines is skipped without
/// poisoning the scan: a later valid usage event is still extracted.
#[test]
fn malformed_sse_payloads_do_not_block_a_later_usage_event() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b"data: {not json at all\n");
    scanner.observe(b"data: \n");
    scanner.observe(b"data: [DONE]\n");
    scanner.observe(
        br#"data: {"object":"chat.completion.chunk","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}
"#,
    );
    scanner.finish();

    assert_eq!(
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode("total_tokens")),
        Some(7)
    );
    assert!(
        !scanner.malformed(),
        "a later authoritative cumulative usage record restates the counts an \
         undecodable earlier record could have carried, so the scan recovers"
    );
}

/// The mirror-image ordering must NOT recover. Syntax damage *after* the last
/// authoritative usage record means the provider may have restated its counts in
/// a record the scanner could not read, so the earlier snapshot can no longer be
/// settled as a clean terminal stream.
#[test]
fn sse_damage_after_a_usage_record_fails_closed() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(
        br#"data: {"object":"chat.completion.chunk","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}
"#,
    );
    assert!(!scanner.malformed(), "the stream is clean at this point");

    scanner.observe(b"data: {\"object\":\"chat.completion.chunk\",\"usage\":{\"prompt_\n");
    scanner.finish();

    assert!(
        scanner.malformed(),
        "damaged candidate data after the last usage record must fail closed"
    );
}

/// A `data:` payload that is truncated at end of stream (no terminating newline,
/// no closing brace) is the same fail-closed case: the terminal usage record
/// never fully arrived.
#[test]
fn truncated_trailing_sse_data_fails_closed() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b"data: {\"object\":\"chat.completion.chunk\",\"usage\":{\"total_tok");
    scanner.finish();

    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());
}

/// A `data:` line whose bytes are not valid UTF-8 cannot be decoded as the
/// provider event it claims to be, so it damages the scan. `text/event-stream`
/// is UTF-8 by definition; a non-UTF-8 record is not something to skip quietly.
#[test]
fn non_utf8_sse_candidate_data_fails_closed() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(
        br#"data: {"object":"chat.completion.chunk","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}
"#,
    );
    let mut line = b"data: ".to_vec();
    line.extend_from_slice(&[0xff, 0xfe, 0x80]);
    line.push(b'\n');
    scanner.observe(&line);
    scanner.finish();

    assert!(
        scanner.malformed(),
        "non-UTF-8 candidate data must fail closed"
    );
}

/// A data record that parses as JSON but is not an object is not the provider
/// event shape either.
#[test]
fn non_object_sse_data_fails_closed() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b"data: 12345\n");
    scanner.finish();
    assert!(scanner.malformed());

    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b"data: [1,2,3]\n");
    scanner.finish();
    assert!(scanner.malformed());
}

/// Ordinary SSE syntax must never poison the scan: comments, keep-alives, other
/// field names, blank event separators, empty data records, `[DONE]`, and
/// non-UTF-8 bytes on a line that is not a `data:` candidate.
#[test]
fn ordinary_sse_syntax_does_not_poison_the_scan() {
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::Sse, None);
    scanner.observe(b": keep-alive\n");
    scanner.observe(b"event: message\n");
    scanner.observe(b"id: 42\n");
    scanner.observe(b"retry: 1000\n");
    scanner.observe(b"\n");
    scanner.observe(b"data:\n");
    scanner.observe(b"data: \n");
    scanner.observe(b"data: [DONE]\n");
    scanner.observe(&[b':', b' ', 0xff, 0xfe, b'\n']);
    scanner.finish();

    assert!(
        !scanner.malformed(),
        "well-formed SSE syntax that carries no usage is a clean usage-free stream"
    );
    assert!(scanner.authoritative_usage().is_none());
}

/// End to end: a stream whose tail is damaged after a valid usage snapshot must
/// take the unmetered posture rather than charging the earlier snapshot.
#[tokio::test]
async fn stream_damaged_after_usage_takes_the_unmetered_posture() {
    let plugin: Arc<dyn Plugin> = Arc::new(limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true,
        "on_unmetered_response": "charge_estimate"
    })));
    let mut ctx = ai_request_ctx(200, "damage my tail");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = observed_usage_of(&plugin).await;
    assert!(reserved > 0);
    assert_ne!(
        reserved, 100,
        "the estimate must differ from the snapshot the damaged stream carries"
    );

    let chunks: [&[u8]; 2] = [
        b"data: {\"object\":\"chat.completion.chunk\",\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":60,\"total_tokens\":100}}\n\n",
        b"data: {\"object\":\"chat.completion.chu\n\n",
    ];
    let expected: Vec<u8> = chunks.concat();
    let forwarded = stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &chunks,
        BodyOutcome::success(expected.len() as u64),
    )
    .await;

    assert_eq!(
        forwarded, expected,
        "damage changes accounting, never the bytes the client receives"
    );
    assert_eq!(
        observed_usage_of(&plugin).await,
        reserved,
        "the earlier snapshot must not be charged for a stream damaged after it"
    );
}

/// End to end for the AWS framing: a Bedrock stream is charged against the
/// window through the full plugin lifecycle, and every framing byte reaches the
/// client unchanged.
#[tokio::test]
async fn bedrock_stream_charges_actual_usage_end_to_end() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = ai_request_ctx(200, "bedrock please");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let frame = bedrock_metadata_usage_frame(12, 34);
    let chunks: [&[u8]; 1] = [&frame];
    let forwarded = stream_response(
        &plugin,
        &mut ctx,
        "application/vnd.amazon.eventstream",
        &chunks,
        BodyOutcome::success(frame.len() as u64),
    )
    .await;

    assert_eq!(
        forwarded, frame,
        "the AWS event-stream framing is forwarded byte for byte"
    );
    assert_eq!(
        observed_usage_of(&plugin).await,
        46,
        "the provider's authoritative ConverseStream usage must replace the estimate"
    );
}

/// End to end for the AWS ordering invariant: a Bedrock stream whose tail is a
/// recognized usage-bearing frame the scanner could not decode must take the
/// unmetered posture rather than charging the snapshot the earlier frame
/// reported — and the damaged bytes still reach the client untouched.
#[tokio::test]
async fn bedrock_stream_damaged_after_usage_takes_the_unmetered_posture() {
    let plugin: Arc<dyn Plugin> = Arc::new(limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true,
        "on_unmetered_response": "charge_estimate"
    })));
    let mut ctx = ai_request_ctx(200, "damage my bedrock tail");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = observed_usage_of(&plugin).await;
    assert!(reserved > 0);
    assert_ne!(
        reserved, 46,
        "the estimate must differ from the snapshot the damaged stream carries"
    );

    let usage_frame = bedrock_metadata_usage_frame(12, 34);
    let chunk_headers = bedrock_event_headers("chunk");
    let damaged_frame = event_stream_frame(&chunk_headers, b"not a json document");
    let chunks: [&[u8]; 2] = [&usage_frame, &damaged_frame];
    let expected: Vec<u8> = chunks.concat();
    let forwarded = stream_response(
        &plugin,
        &mut ctx,
        "application/vnd.amazon.eventstream",
        &chunks,
        BodyOutcome::success(expected.len() as u64),
    )
    .await;

    assert_eq!(
        forwarded, expected,
        "damage changes accounting, never the bytes the client receives"
    );
    assert_eq!(
        observed_usage_of(&plugin).await,
        reserved,
        "the earlier Bedrock snapshot must not be charged for a stream damaged after it"
    );
}

/// Settlement implication of the hard envelope failures: a Bedrock stream whose
/// tail declares an invalid `bytes` envelope — explicitly wrong-typed, or a
/// string that is not decodable base64 — must take the unmetered posture instead
/// of settling the snapshot the earlier frame reported, and the bytes must still
/// reach the client untouched.
#[tokio::test]
async fn bedrock_stream_with_an_invalid_bytes_envelope_takes_the_unmetered_posture() {
    let chunk_headers = bedrock_event_headers("chunk");

    let variants: [(&str, &[u8]); 2] = [
        ("wrong-typed `bytes`", br#"{"bytes":null}"#),
        ("undecodable `bytes`", br#"{"bytes":"!!!!"}"#),
    ];

    for (label, payload) in variants {
        let plugin: Arc<dyn Plugin> = Arc::new(limiter(json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
            "on_unmetered_response": "charge_estimate"
        })));
        let mut ctx = ai_request_ctx(200, "damage my bedrock envelope");
        let mut headers = HashMap::new();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        let reserved = observed_usage_of(&plugin).await;
        assert!(reserved > 0, "{label}");
        assert_ne!(
            reserved, 46,
            "{label}: the estimate must differ from the snapshot the stream carries"
        );

        let usage_frame = bedrock_metadata_usage_frame(12, 34);
        let damaged_frame = event_stream_frame(&chunk_headers, payload);
        let chunks: [&[u8]; 2] = [&usage_frame, &damaged_frame];
        let expected: Vec<u8> = chunks.concat();
        let forwarded = stream_response(
            &plugin,
            &mut ctx,
            "application/vnd.amazon.eventstream",
            &chunks,
            BodyOutcome::success(expected.len() as u64),
        )
        .await;

        assert_eq!(
            forwarded, expected,
            "{label}: a fail-closed envelope changes accounting, never the client's bytes"
        );
        assert_eq!(
            observed_usage_of(&plugin).await,
            reserved,
            "{label}: the earlier snapshot must not be settled after an invalid envelope"
        );
    }
}

/// A streamed Gemini response is charged against the window through the full
/// plugin lifecycle, not just the scanner.
#[tokio::test]
async fn gemini_stream_charges_actual_usage_end_to_end() {
    let plugin: Arc<dyn Plugin> = Arc::new(ip_limiter(10_000));
    let mut ctx = ai_request_ctx(200, "gemini please");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let event: &[u8] = br#"data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":29,"totalTokenCount":40}}

"#;
    stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &[event],
        BodyOutcome::success(event.len() as u64),
    )
    .await;

    assert_eq!(
        observed_usage_of(&plugin).await,
        40,
        "the provider's authoritative Gemini usage must replace the estimate"
    );
}

// ─── GHSA-wh4p-pmxm-3784 — independent instances ────────────────────────

/// Two local instances with different `count_mode` values (and therefore
/// different estimates) must each reserve, reconcile, and settle against their
/// OWN window. Previously the second admission pass overwrote the first
/// instance's reservation markers and each reconciled using the other's data.
#[tokio::test]
async fn two_local_instances_keep_separate_reservations() {
    let per_consumer = limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "count_mode": "total_tokens",
        "expose_headers": true
    }));
    let per_ip = limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "count_mode": "completion_tokens",
        "expose_headers": true
    }));

    let mut ctx = ai_request_ctx(200, "a reasonably long prompt for estimation");
    let mut headers = HashMap::new();
    assert_continue(per_consumer.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(per_ip.before_proxy(&mut ctx, &mut headers).await);

    let first_reserved = per_consumer.reserved_tokens_for_test(&ctx);
    let second_reserved = per_ip.reserved_tokens_for_test(&ctx);
    assert!(first_reserved > 0 && second_reserved > 0);
    assert_ne!(
        first_reserved, second_reserved,
        "different count modes must produce different estimates for this fixture"
    );
    assert_eq!(
        second_reserved, 200,
        "completion_tokens mode reserves exactly the requested output cap"
    );

    // Each instance charges the provider's actual usage to its own window using
    // ITS OWN reservation, so neither is corrupted by the other's estimate.
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 40, "completion_tokens": 60, "total_tokens": 100}
    }))
    .unwrap();
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        per_consumer
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );
    assert_continue(
        per_ip
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );

    assert_eq!(
        observed_usage(&per_consumer).await,
        100,
        "total_tokens instance charges the total"
    );
    assert_eq!(
        observed_usage(&per_ip).await,
        60,
        "completion_tokens instance charges only completion tokens"
    );
}

/// Byte-identical configuration is still two independent budgets: one
/// instance's settlement must not suppress the other's.
#[tokio::test]
async fn identical_instances_each_settle_their_own_reservation() {
    let config = json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true
    });
    let first = limiter(config.clone());
    let second = limiter(config);

    let mut ctx = ai_request_ctx(200, "identical config");
    let mut headers = HashMap::new();
    assert_continue(first.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(second.before_proxy(&mut ctx, &mut headers).await);
    let first_reserved = first.reserved_tokens_for_test(&ctx);
    assert!(first_reserved > 0);
    assert_eq!(second.reserved_tokens_for_test(&ctx), first_reserved);

    assert!(!first.reservation_settled_for_test(&ctx));
    assert!(!second.reservation_settled_for_test(&ctx));

    // A non-2xx releases the FIRST instance's reservation only.
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        first
            .on_response_body(&mut ctx, 500, &mut response_headers, b"{}")
            .await,
    );
    assert!(first.reservation_settled_for_test(&ctx));
    assert!(
        !second.reservation_settled_for_test(&ctx),
        "GHSA-wh4p-pmxm-3784: one instance settling must not suppress a sibling"
    );
    assert_eq!(observed_usage(&first).await, 0);
    assert_eq!(
        observed_usage(&second).await,
        first_reserved,
        "the sibling's reservation is still outstanding"
    );

    // The sibling then settles its own.
    assert_continue(
        second
            .on_response_body(&mut ctx, 500, &mut response_headers, b"{}")
            .await,
    );
    assert!(second.reservation_settled_for_test(&ctx));
    assert_eq!(observed_usage(&second).await, 0);
}

/// A mixed local/Redis pair must not make either instance apply backend-switch
/// logic to the other's reservation. The Redis instance is configured against an
/// unreachable endpoint with `local_fallback`, so both settle without either
/// inheriting the other's backend identity.
#[tokio::test]
async fn mixed_backend_instances_do_not_share_backend_identity() {
    let local = limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true
    }));
    let redis = limiter(json!({
        "token_limit": 10_000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        // Long enough that no background recovery dial happens during a test.
        "redis_health_check_interval_seconds": 3600,
        "redis_key_prefix": "ferrum:ai_rate_limiter:ghsa-wh4p-mixed",
        "redis_failure_policy": "local_fallback"
    }));

    let mut ctx = ai_request_ctx(200, "mixed backends");
    let mut headers = HashMap::new();
    assert_continue(local.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(redis.before_proxy(&mut ctx, &mut headers).await);

    assert!(local.reserved_tokens_for_test(&ctx) > 0);
    assert!(redis.reserved_tokens_for_test(&ctx) > 0);
    assert!(local.ai_request_for_test(&ctx));
    assert!(redis.ai_request_for_test(&ctx));

    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 40, "completion_tokens": 60, "total_tokens": 100}
    }))
    .unwrap();
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        local
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );
    assert_continue(
        redis
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );

    assert!(local.reservation_settled_for_test(&ctx));
    assert!(redis.reservation_settled_for_test(&ctx));
    assert_eq!(
        observed_usage(&local).await,
        100,
        "the local instance charges the actual usage to its own window"
    );
}

/// Each instance applies — and records — its own `on_unmetered_response`
/// action, so a sibling's posture never leaks into this one's settlement.
#[tokio::test]
async fn instances_record_their_own_unmetered_action() {
    let charging = limiter(json!({
        "token_limit": 10_000,
        "limit_by": "ip",
        "on_unmetered_response": "charge_estimate"
    }));
    let releasing = limiter(json!({
        "token_limit": 10_000,
        "limit_by": "ip",
        "on_unmetered_response": "warn"
    }));

    let mut ctx = ai_request_ctx(200, "no usage in this response");
    let mut headers = HashMap::new();
    assert_continue(charging.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(releasing.before_proxy(&mut ctx, &mut headers).await);
    let reserved = charging.reserved_tokens_for_test(&ctx);
    assert!(reserved > 0);

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        charging
            .on_response_body(&mut ctx, 200, &mut response_headers, b"{\"ok\":true}")
            .await,
    );
    assert_continue(
        releasing
            .on_response_body(&mut ctx, 200, &mut response_headers, b"{\"ok\":true}")
            .await,
    );

    assert_eq!(
        charging.unmetered_action_for_test(&ctx).as_deref(),
        Some("charge_estimate")
    );
    assert_eq!(
        releasing.unmetered_action_for_test(&ctx).as_deref(),
        Some("warn")
    );
    assert_eq!(
        observed_usage(&charging).await,
        reserved,
        "charge_estimate keeps its own reservation"
    );
    assert_eq!(
        observed_usage(&releasing).await,
        0,
        "warn releases its own reservation"
    );
}

/// A rejection re-running `after_proxy` after a non-2xx release must not
/// release a second time, per instance.
#[tokio::test]
async fn gateway_rejection_rerun_does_not_double_release() {
    let plugin = ip_limiter(10_000);
    let mut ctx = ai_request_ctx(200, "release me once");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = plugin.reserved_tokens_for_test(&ctx);
    assert_eq!(observed_usage(&plugin).await, reserved);

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 502, &mut response_headers, b"{}")
            .await,
    );
    assert_eq!(observed_usage(&plugin).await, 0);

    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 502, &mut response_headers)
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "the second terminal pass must be a clean no-op"
    );
}

/// The plugin must never reject a streamed response after the fact: headers and
/// bytes are already committed, so `reject` degrades to keeping the reservation
/// charged.
#[tokio::test]
async fn reject_posture_on_a_stream_keeps_the_charge_instead_of_rejecting() {
    let plugin: Arc<dyn Plugin> = Arc::new(limiter(json!({
        "token_limit": 10_000,
        "limit_by": "ip",
        "expose_headers": true,
        "on_unmetered_response": "reject"
    })));
    let mut ctx = ai_request_ctx(200, "reject me if you can");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = observed_usage_of(&plugin).await;
    assert!(reserved > 0);

    let body: &[u8] = b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\n";
    let forwarded = stream_response(
        &plugin,
        &mut ctx,
        "text/event-stream",
        &[body],
        BodyOutcome::success(body.len() as u64),
    )
    .await;

    assert_eq!(forwarded, body, "the committed stream is delivered intact");
    assert_eq!(
        observed_usage_of(&plugin).await,
        reserved,
        "a usage-free stream under `reject` keeps the reservation charged"
    );
}

/// `tgi` is an accepted provider value and an unknown one is still refused.
#[test]
fn tgi_is_an_accepted_provider_value() {
    assert!(
        AiRateLimiter::new(
            &json!({"token_limit": 100, "provider": "tgi"}),
            PluginHttpClient::default()
        )
        .is_ok()
    );
    assert!(
        AiRateLimiter::new(
            &json!({"token_limit": 100, "provider": "TGI"}),
            PluginHttpClient::default()
        )
        .is_ok(),
        "provider parsing is case-insensitive"
    );
    let err = AiRateLimiter::new(
        &json!({"token_limit": 100, "provider": "not_a_provider"}),
        PluginHttpClient::default(),
    )
    .unwrap_err();
    assert!(err.contains("unknown 'provider' value"));
    assert!(err.contains("tgi"), "the error must list the accepted values");
}

/// An over-budget admission still refuses with the documented 429 (guards
/// against the per-instance record refactor changing admission behavior).
///
/// The first request may be admitted (an empty window admits before the
/// reservation lands), so the assertion is made on a request issued once the
/// budget is already exhausted.
#[tokio::test]
async fn admission_rejection_is_unchanged_by_the_record_refactor() {
    let plugin = ip_limiter(1);
    let mut headers = HashMap::new();

    let mut first = ai_request_ctx(5_000, "way over budget");
    let _ = plugin.before_proxy(&mut first, &mut headers).await;

    let mut second = ai_request_ctx(5_000, "way over budget");
    match plugin.before_proxy(&mut second, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 429),
        other => panic!("expected a 429 rejection, got {other:?}"),
    }
}

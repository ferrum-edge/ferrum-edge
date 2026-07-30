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
    headers.insert(
        "content-type".to_string(),
        "text/event-stream".to_string(),
    );
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

/// Build one AWS event-stream message with an empty header block.
///
/// Layout: total length (u32 BE), headers length (u32 BE), prelude CRC (u32),
/// headers, payload, message CRC (u32). CRCs are not validated by the scanner
/// (the transport already did), so they are zero-filled here.
fn event_stream_message(payload: &[u8]) -> Vec<u8> {
    let total = 16 + payload.len();
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&(total as u32).to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes()); // headers length
    message.extend_from_slice(&0u32.to_be_bytes()); // prelude CRC
    message.extend_from_slice(payload);
    message.extend_from_slice(&0u32.to_be_bytes()); // message CRC
    message
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
    // Declared total length below the framing overhead.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    let mut bogus = Vec::new();
    bogus.extend_from_slice(&4u32.to_be_bytes());
    bogus.extend_from_slice(&0u32.to_be_bytes());
    bogus.extend_from_slice(&0u32.to_be_bytes());
    scanner.observe(&bogus);
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());

    // Declared total length far above the retained bound.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    let mut huge = Vec::new();
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    huge.extend_from_slice(&0u32.to_be_bytes());
    huge.extend_from_slice(&0u32.to_be_bytes());
    scanner.observe(&huge);
    scanner.finish();
    assert!(scanner.malformed());
    assert!(scanner.authoritative_usage().is_none());

    // Headers longer than the message that contains them.
    let mut scanner = StreamUsageScanner::new(StreamUsageFormat::AwsEventStream, None);
    let mut inconsistent = Vec::new();
    inconsistent.extend_from_slice(&32u32.to_be_bytes());
    inconsistent.extend_from_slice(&1024u32.to_be_bytes());
    inconsistent.extend_from_slice(&0u32.to_be_bytes());
    scanner.observe(&inconsistent);
    scanner.finish();
    assert!(scanner.malformed());
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

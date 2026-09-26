//! Tests for the bounded incremental AI response-usage extractor.
//!
//! Covers GHSA-q2r2-6r7h-f69x (bounded retention instead of full-response
//! buffering) and GHSA-rxj9-f483-g53f (authoritative terminal usage for the
//! provider-native Gemini, Bedrock, and TGI streaming formats), including
//! AWS event-stream CRC integrity before usage is trusted.

use base64::Engine;
use ferrum_edge::_test_support::{
    encode_aws_event_stream_message_for_test, encode_aws_event_stream_prelude_for_test,
};
use ferrum_edge::plugins::utils::ai_providers::AiProvider;
use ferrum_edge::plugins::utils::ai_usage_stream::{
    MAX_EVENT_STREAM_MESSAGE_BYTES, MAX_SSE_EVENT_BYTES, UsageStreamExtractor, UsageStreamFormat,
    is_aws_event_stream_content_type,
};
use serde_json::json;

// ─── helpers ────────────────────────────────────────────────────────────

fn sse(events: &[&str]) -> Vec<u8> {
    let mut out = String::new();
    for event in events {
        out.push_str("data: ");
        out.push_str(event);
        out.push_str("\n\n");
    }
    out.into_bytes()
}

/// One standards-correct `application/vnd.amazon.eventstream` message.
fn event_stream_message(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    encode_aws_event_stream_message_for_test(headers, payload)
}

/// `InvokeModelWithResponseStream` wraps the model-native chunk as base64.
fn bedrock_invoke_chunk(inner: serde_json::Value) -> Vec<u8> {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&inner).unwrap());
    let payload = serde_json::to_vec(&json!({"bytes": encoded})).unwrap();
    event_stream_message(b"", &payload)
}

fn extract(format: UsageStreamFormat, chunks: &[&[u8]], count_mode: &str) -> Option<u64> {
    let mut extractor = UsageStreamExtractor::new(format, None);
    for chunk in chunks {
        extractor.push(chunk);
    }
    extractor.finish();
    extractor.usage().total_for_mode(count_mode)
}

fn mutate_byte(message: &mut [u8], index: usize) {
    message[index] ^= 0xff;
}

// ─── SSE: existing providers stay identical ─────────────────────────────

#[test]
fn openai_stream_options_usage_is_extracted() {
    let body = sse(&[
        &json!({"object": "chat.completion.chunk", "choices": []}).to_string(),
        &json!({
            "object": "chat.completion.chunk",
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        })
        .to_string(),
        "[DONE]",
    ]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(18)
    );
}

#[test]
fn anthropic_split_counters_merge_across_events() {
    let body = sse(&[
        &json!({"type": "message_start", "message": {"usage": {"input_tokens": 25}}}).to_string(),
        &json!({"type": "content_block_delta"}).to_string(),
        &json!({"type": "message_delta", "usage": {"output_tokens": 40}}).to_string(),
    ]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "prompt_tokens"),
        Some(25)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "completion_tokens"),
        Some(40)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(65)
    );
}

#[test]
fn cohere_v2_message_end_usage_is_extracted() {
    let body = sse(&[
        &json!({"type": "content-delta"}).to_string(),
        &json!({
            "type": "message-end",
            "delta": {"usage": {"tokens": {"input_tokens": 23, "output_tokens": 41}}}
        })
        .to_string(),
    ]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(64)
    );
}

// ─── GHSA-rxj9: Gemini native SSE ───────────────────────────────────────

#[test]
fn gemini_stream_generate_content_usage_metadata_is_authoritative() {
    // `streamGenerateContent` emits a sequence of `GenerateContentResponse`
    // values; the usage counters are cumulative and the last one wins.
    let body = sse(&[
        &json!({
            "candidates": [{"content": {"parts": [{"text": "hel"}]}}],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 3,
                "totalTokenCount": 15
            }
        })
        .to_string(),
        &json!({
            "candidates": [{"content": {"parts": [{"text": "lo"}]}}],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 9,
                "totalTokenCount": 21
            }
        })
        .to_string(),
    ]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(21)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "prompt_tokens"),
        Some(12)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "completion_tokens"),
        Some(9)
    );
}

#[test]
fn gemini_stream_without_usage_metadata_is_unmetered() {
    let body =
        sse(&[&json!({"candidates": [{"content": {"parts": [{"text": "hello"}]}}]}).to_string()]);
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(&body);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "a Gemini stream with no usageMetadata must never be charged as zero"
    );
}

// ─── GHSA-rxj9: TGI native SSE ──────────────────────────────────────────

#[test]
fn tgi_generate_stream_final_details_are_extracted() {
    let body = sse(&[
        &json!({"token": {"id": 1, "text": "he"}, "generated_text": null}).to_string(),
        &json!({
            "token": {"id": 2, "text": "llo"},
            "generated_text": "hello",
            "details": {"finish_reason": "length", "generated_tokens": 42}
        })
        .to_string(),
    ]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "completion_tokens"),
        Some(42)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(42)
    );
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, Some(AiProvider::Tgi));
    extractor.push(&body);
    extractor.finish();
    assert!(
        !extractor.usage().is_complete_for_mode("total_tokens"),
        "generated_tokens alone is only a lower bound for total_tokens"
    );
}

#[test]
fn tgi_empty_prefill_is_not_a_prompt_count_of_zero() {
    // TGI omits input details unless asked; an empty `prefill` array must not
    // be read as "0 prompt tokens" or a large prompt would be charged nothing.
    let body = sse(&[&json!({"details": {"generated_tokens": 9, "prefill": []}}).to_string()]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "prompt_tokens"),
        None
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "completion_tokens"),
        Some(9)
    );
}

#[test]
fn tgi_prefill_tokens_supply_the_prompt_count() {
    let body = sse(&[&json!({
        "details": {
            "generated_tokens": 4,
            "prefill": [{"id": 1, "text": "a"}, {"id": 2, "text": "b"}, {"id": 3, "text": "c"}]
        }
    })
    .to_string()]);
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "prompt_tokens"),
        Some(3)
    );
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
        Some(7)
    );
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, Some(AiProvider::Tgi));
    extractor.push(&body);
    extractor.finish();
    assert!(extractor.usage().is_complete_for_mode("total_tokens"));
}

// ─── GHSA-rxj9: Bedrock event-stream framing ────────────────────────────

#[test]
fn is_aws_event_stream_content_type_matches_documented_media_type() {
    assert!(is_aws_event_stream_content_type(
        "application/vnd.amazon.eventstream"
    ));
    assert!(is_aws_event_stream_content_type(
        "Application/VND.Amazon.EventStream; charset=utf-8"
    ));
    assert!(!is_aws_event_stream_content_type("application/json"));
    assert!(!is_aws_event_stream_content_type("text/event-stream"));
}

#[test]
fn bedrock_invoke_model_stream_invocation_metrics_are_extracted() {
    let mut stream = Vec::new();
    stream.extend_from_slice(&bedrock_invoke_chunk(
        json!({"type": "content_block_delta", "delta": {"text": "hi"}}),
    ));
    stream.extend_from_slice(&bedrock_invoke_chunk(json!({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {
            "inputTokenCount": 31,
            "outputTokenCount": 12,
            "invocationLatency": 900,
            "firstByteLatency": 120
        }
    })));

    assert_eq!(
        extract(
            UsageStreamFormat::AwsEventStream,
            &[&stream],
            "total_tokens"
        ),
        Some(43)
    );
    assert_eq!(
        extract(
            UsageStreamFormat::AwsEventStream,
            &[&stream],
            "prompt_tokens"
        ),
        Some(31)
    );
}

#[test]
fn bedrock_converse_stream_metadata_usage_is_extracted() {
    let payload = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 5, "outputTokens": 6, "totalTokens": 11}
    }))
    .unwrap();
    let stream = event_stream_message(b"\x00\x00\x00\x00", &payload);
    assert_eq!(
        extract(
            UsageStreamFormat::AwsEventStream,
            &[&stream],
            "total_tokens"
        ),
        Some(11)
    );
}

#[test]
fn event_stream_messages_split_across_chunk_boundaries_are_reassembled() {
    let stream = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 8, "outputTokenCount": 4}
    }));
    // Feed one byte at a time — the worst case for a length-prefixed parser.
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    for byte in &stream {
        extractor.push(std::slice::from_ref(byte));
    }
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(12));
}

#[test]
fn truncated_event_stream_message_reports_no_usage() {
    let stream = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 8, "outputTokenCount": 4}
    }));
    let truncated = &stream[..stream.len() - 3];
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(truncated);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "an incomplete binary frame carries no trustworthy counters"
    );
}

#[test]
fn truncated_event_stream_crc_reports_no_usage() {
    // Drop only the final CRC bytes after a complete body — still incomplete.
    let stream = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 8, "outputTokenCount": 4}
    }));
    let truncated = &stream[..stream.len() - 4];
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(truncated);
    extractor.finish();
    assert!(!extractor.usage().observed());
}

#[test]
fn malformed_event_stream_framing_stops_parsing_without_panicking() {
    // A declared total length below the structural minimum is not event-stream
    // framing at all. There is no resync point in a length-prefixed format, so
    // the parser must stop cleanly and report nothing.
    let mut stream = Vec::new();
    stream.extend_from_slice(&encode_aws_event_stream_prelude_for_test(3, 0));
    stream.extend_from_slice(b"garbage garbage garbage");
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert!(!extractor.usage().observed());
    assert_eq!(extractor.retained_bytes(), 0);
}

#[test]
fn corrupt_prelude_crc_rejects_declared_length_before_skip_or_parse() {
    let oversized_total = (MAX_EVENT_STREAM_MESSAGE_BYTES + 4096) as u32;
    let mut prelude = encode_aws_event_stream_prelude_for_test(oversized_total, 0);
    mutate_byte(&mut prelude, 9);
    let mut stream = Vec::new();
    stream.extend_from_slice(&prelude);
    // Hostile remainder that would be skipped if the corrupt length were trusted.
    stream.extend_from_slice(&[0x41; 64]);
    stream.extend_from_slice(&bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 2, "outputTokenCount": 3}
    })));

    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "a corrupt prelude CRC must never trust length or admit later frames"
    );
    assert_eq!(extractor.retained_bytes(), 0);
}

#[test]
fn corrupt_message_crc_stops_without_admitting_usage() {
    let mut stream = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 8, "outputTokenCount": 4}
    }));
    let last = stream.len() - 1;
    mutate_byte(&mut stream, last);

    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "a corrupt final message CRC must never admit payload usage"
    );
}

#[test]
fn corrupt_frame_after_valid_usage_preserves_observed_counters() {
    let valid = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 10, "outputTokenCount": 5}
    }));
    let mut corrupt = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 99, "outputTokenCount": 99}
    }));
    let last = corrupt.len() - 1;
    mutate_byte(&mut corrupt, last);

    let mut stream = valid;
    stream.extend_from_slice(&corrupt);
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert_eq!(
        extractor.usage().total_for_mode("total_tokens"),
        Some(15),
        "already-observed usage must survive a later corrupt frame"
    );
}

#[test]
fn malformed_lengths_with_valid_prelude_crc_stop_cleanly() {
    // Prelude CRC matches, but headers_length exceeds the structural maximum.
    let mut stream = Vec::new();
    stream.extend_from_slice(&encode_aws_event_stream_prelude_for_test(16, 8));
    stream.extend_from_slice(&[0u8; 8]);
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert!(!extractor.usage().observed());
    assert_eq!(extractor.retained_bytes(), 0);
}

#[test]
fn malformed_lengths_with_invalid_prelude_crc_never_skip_by_length() {
    let mut prelude = encode_aws_event_stream_prelude_for_test(16, 8);
    mutate_byte(&mut prelude, 10);
    let mut stream = Vec::new();
    stream.extend_from_slice(&prelude);
    stream.extend_from_slice(&[0u8; 64]);
    stream.extend_from_slice(&bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 1, "outputTokenCount": 1}
    })));
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    extractor.push(&stream);
    extractor.finish();
    assert!(!extractor.usage().observed());
}

#[test]
fn oversized_event_stream_message_is_skipped_by_length_not_buffered() {
    let oversized_total = (MAX_EVENT_STREAM_MESSAGE_BYTES + 4096) as u32;
    let mut stream = Vec::new();
    stream.extend_from_slice(&encode_aws_event_stream_prelude_for_test(
        oversized_total,
        0,
    ));
    stream.extend_from_slice(&vec![0x41; MAX_EVENT_STREAM_MESSAGE_BYTES + 4096 - 12]);
    // A well-formed usage message follows the oversized one.
    stream.extend_from_slice(&bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 2, "outputTokenCount": 3}
    })));

    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, None);
    for window in stream.chunks(1024) {
        extractor.push(window);
        assert!(
            extractor.retained_bytes() <= MAX_EVENT_STREAM_MESSAGE_BYTES,
            "retention must stay bounded while skipping an oversized message"
        );
    }
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(5));
}

// ─── Bounded retention ──────────────────────────────────────────────────

#[test]
fn never_ending_sse_stream_retains_a_bounded_carry() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    // 8 MiB of a single unterminated `data:` line: the exact shape that made
    // the old full-buffering limiter accumulate the whole response.
    for _ in 0..(8 * 1024) {
        extractor.push(&vec![b'x'; 1024]);
        assert!(
            extractor.retained_bytes() <= MAX_SSE_EVENT_BYTES,
            "retention must never grow with stream length"
        );
    }
    extractor.finish();
    assert!(!extractor.usage().observed());
}

#[test]
fn oversized_sse_line_resynchronizes_and_still_captures_a_later_usage_event() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(b"data: ");
    for _ in 0..((MAX_SSE_EVENT_BYTES / 1024) + 4) {
        extractor.push(&vec![b'y'; 1024]);
        assert!(extractor.retained_bytes() <= MAX_SSE_EVENT_BYTES);
    }
    extractor.push(b"\n\n");
    extractor.push(&sse(&[
        &json!({"usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}})
            .to_string(),
    ]));
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(5));
}

#[test]
fn complete_oversized_sse_line_in_one_chunk_is_not_parsed() {
    let mut body = br#"data: {"usage":{"total_tokens":999},"padding":""#.to_vec();
    body.extend(std::iter::repeat_n(
        b'x',
        MAX_SSE_EVENT_BYTES.saturating_add(1),
    ));
    body.extend_from_slice(b"\"}\n");

    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(&body);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "a complete SSE line above the cap must not reach JSON parsing"
    );
    assert_eq!(extractor.retained_bytes(), 0);
}

#[test]
fn complete_oversized_sse_line_split_at_the_cap_is_not_merged_or_parsed() {
    let mut body = br#"data: {"usage":{"total_tokens":999},"padding":""#.to_vec();
    body.extend(std::iter::repeat_n(
        b'y',
        MAX_SSE_EVENT_BYTES.saturating_add(1),
    ));
    body.extend_from_slice(b"\"}\n");
    let split = MAX_SSE_EVENT_BYTES.saturating_sub(1);

    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(&body[..split]);
    assert!(extractor.retained_bytes() <= MAX_SSE_EVENT_BYTES);
    extractor.push(&body[split..]);
    extractor.finish();
    assert!(
        !extractor.usage().observed(),
        "a line completed across chunks must still obey the parser cap"
    );
    assert_eq!(extractor.retained_bytes(), 0);
}

#[test]
fn sse_events_split_across_chunk_boundaries_are_reassembled() {
    let body = sse(&[
        &json!({"usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 6}}).to_string(),
    ]);
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    for byte in &body {
        extractor.push(std::slice::from_ref(byte));
    }
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(10));
}

#[test]
fn terminal_event_without_trailing_newline_is_still_applied() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor
        .push(br#"data: {"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#);
    assert!(!extractor.usage().observed(), "not applied before finish");
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(2));
}

// ─── Malformed / hostile content ────────────────────────────────────────

#[test]
fn malformed_sse_frames_never_erase_an_observed_count() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(&sse(&[
        &json!({"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})
            .to_string(),
    ]));
    extractor.push(b"data: {not json at all\n\ndata: \n\n:comment\n\nevent: ping\n\n");
    extractor.push(&sse(&[&json!({"usage": {}}).to_string()]));
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(30));
}

#[test]
fn non_data_lines_and_invalid_utf8_are_ignored() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, None);
    extractor.push(b"id: 1\nretry: 500\n\xff\xfe\n\n");
    extractor.finish();
    assert!(!extractor.usage().observed());
}

#[test]
fn configured_provider_still_sees_the_native_terminal_signal() {
    // An operator pinning `provider: google` must still be charged for a
    // Bedrock-framed stream's authoritative metrics rather than silently
    // metering nothing — every recognized shape is checked independently.
    let stream = bedrock_invoke_chunk(json!({
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 7, "outputTokenCount": 7}
    }));
    let mut extractor =
        UsageStreamExtractor::new(UsageStreamFormat::AwsEventStream, Some(AiProvider::Google));
    extractor.push(&stream);
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(14));
}

#[test]
fn configured_provider_cannot_suppress_an_unambiguous_root_usage_signal() {
    let mut extractor = UsageStreamExtractor::new(UsageStreamFormat::Sse, Some(AiProvider::Google));
    extractor.push(&sse(&[&json!({
        "object": "chat.completion.chunk",
        "usage": {"prompt_tokens": 5, "completion_tokens": 8, "total_tokens": 13}
    })
    .to_string()]));
    extractor.finish();
    assert_eq!(extractor.usage().total_for_mode("total_tokens"), Some(13));
}

// ─── SSE line endings ───────────────────────────────────────────────────

/// Like `sse`, but every line, including each dispatching blank line, ends
/// with `eol`.
fn sse_with_eol(events: &[&str], eol: &str) -> Vec<u8> {
    let mut out = String::new();
    for event in events {
        out.push_str("data: ");
        out.push_str(event);
        out.push_str(eol);
        out.push_str(eol);
    }
    out.into_bytes()
}

fn openai_usage_stream(eol: &str) -> Vec<u8> {
    let chunk = json!({"object": "chat.completion.chunk", "choices": []}).to_string();
    let usage = json!({
        "object": "chat.completion.chunk",
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    })
    .to_string();
    sse_with_eol(&[&chunk, &usage, "[DONE]"], eol)
}

#[test]
fn sse_usage_is_extracted_under_every_line_ending_at_every_chunk_split() {
    for eol in ["\r", "\r\n", "\n"] {
        let body = openai_usage_stream(eol);
        assert_eq!(
            extract(UsageStreamFormat::Sse, &[&body], "total_tokens"),
            Some(18),
            "{eol:?}"
        );
        for split in 0..=body.len() {
            let (head, tail) = body.split_at(split);
            assert_eq!(
                extract(UsageStreamFormat::Sse, &[head, tail], "total_tokens"),
                Some(18),
                "{eol:?} split at {split}"
            );
        }
        let bytes: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(
            extract(UsageStreamFormat::Sse, &bytes, "total_tokens"),
            Some(18),
            "{eol:?} one byte at a time"
        );
    }
}

#[test]
fn mixed_line_endings_in_one_sse_stream_are_all_split() {
    let start =
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 25}}}).to_string();
    let delta = json!({"type": "message_delta", "usage": {"output_tokens": 40}}).to_string();
    // A lone CR ends the first data line and a CRLF its blank line; an LF ends
    // the second data line and a lone CR its blank line.
    let body = format!(
        "event: message_start\rdata: {start}\r\r\nevent: message_delta\r\ndata: {delta}\n\r"
    );
    let body = body.as_bytes();
    for split in 0..=body.len() {
        let (head, tail) = body.split_at(split);
        assert_eq!(
            extract(UsageStreamFormat::Sse, &[head, tail], "total_tokens"),
            Some(65),
            "split at {split}"
        );
    }
}

#[test]
fn crlf_split_across_chunks_does_not_dispatch_an_event_early() {
    // One usage document legally split across two `data` lines. If the LF that
    // completes the chunk-ending CR were read as a blank line, the event would
    // dispatch after its first half and neither half would parse.
    let first = b"data: {\"usage\": {\"prompt_tokens\": 2,\r" as &[u8];
    let second = b"\ndata: \"completion_tokens\": 3, \"total_tokens\": 5}}\r\n\r\n" as &[u8];
    assert_eq!(
        extract(UsageStreamFormat::Sse, &[first, second], "total_tokens"),
        Some(5)
    );
}

#[test]
fn stacked_leading_boms_are_stripped_before_the_first_sse_line() {
    // The usage event is the first event, so a BOM left on its field name
    // would hide it.
    let usage = json!({
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    })
    .to_string();
    for eol in ["\r", "\r\n", "\n"] {
        let mut body = "\u{feff}\u{feff}".as_bytes().to_vec();
        body.extend_from_slice(&sse_with_eol(&[&usage], eol));
        for split in 0..=body.len() {
            let (head, tail) = body.split_at(split);
            assert_eq!(
                extract(UsageStreamFormat::Sse, &[head, tail], "total_tokens"),
                Some(18),
                "{eol:?} split at {split}"
            );
        }
    }
}

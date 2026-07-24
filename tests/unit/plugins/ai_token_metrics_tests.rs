//! Tests for ai_token_metrics plugin

use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext,
    ai_token_metrics::AiTokenMetrics,
    utils::content_encoding::{DecodeLimits, decode_content_encoding},
    validate_plugin_config,
};
use serde_json::json;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;

use super::plugin_utils::create_test_context;

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn brotli(body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut input = body;
    brotli::BrotliCompress(
        &mut input,
        &mut encoded,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    encoded
}

#[test]
fn content_decoding_borrows_when_no_transform_is_required() {
    let body = b"plain provider response";
    let limits = DecodeLimits {
        max_decoded_bytes: 4 * 1024 * 1024,
        max_cumulative_bytes: 8 * 1024 * 1024,
        max_codings: 4,
        max_amplification_ratio: 0,
    };
    for header in [None, Some("identity")] {
        let decoded = decode_content_encoding(header, body, limits).unwrap();
        assert_eq!(decoded.as_ptr(), body.as_ptr());
        assert!(matches!(decoded, Cow::Borrowed(_)));
    }
}

fn ctx_with_content_type(method: &str, content_type: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx
}

fn ctx_without_content_type(method: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    )
}

fn assert_continue(result: PluginResult) {
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue, got {:?}",
        result
    );
}

// ─── Plugin basics ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_plugin_name_and_priority() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ai_token_metrics");
    assert_eq!(plugin.priority(), 4100);
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type(
        "POST",
        "multipart/form-data; boundary=abc"
    )));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
    // Spec change (PR #956 / commit 55a59396): token-metrics buffering is
    // no longer POST-only; otherwise non-POST AI responses skip token
    // accounting entirely.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));
}

#[test]
fn test_response_buffering_is_narrowed_by_response_content_type() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let ctx = ctx_with_content_type("GET", "application/json");

    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; charset=utf-8"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/plain"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new()));
}

#[test]
fn test_streaming_response_buffering_requires_explicit_opt_in() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let ctx = ctx_with_content_type("POST", "application/json");

    assert!(
        !default_plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &HashMap::new()
        )
    );
    assert!(opt_in_plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
}

// The pre-header `should_buffer_response_body` decision drives every backend
// dispatch path — including the retry and HTTP/3-backend paths
// that never consult the header-time content-type refinement. These tests pin
// the request-shape gating that keeps those paths streaming (PR #1751 follow-up).

#[test]
fn test_pre_header_decision_streams_sse_accept_requests() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();

    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    // A client asking for a stream must not be buffered by default, even on the
    // retry / gRPC / H3-backend paths that skip the content-type refinement.
    assert!(!default_plugin.should_buffer_response_body(&ctx));
    // Opt-in restores buffering for operators who want streamed token metrics.
    assert!(opt_in_plugin.should_buffer_response_body(&ctx));
}

#[test]
fn test_pre_header_decision_streams_request_streaming_marker() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();

    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());

    // A `stream: true` request flagged by an earlier AI plugin must not be
    // buffered by default.
    assert!(!default_plugin.should_buffer_response_body(&ctx));
    assert!(opt_in_plugin.should_buffer_response_body(&ctx));
}

#[test]
fn test_native_grpc_is_explicitly_unsupported() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
}

#[test]
fn test_pre_header_decision_buffers_plain_json_requests() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();

    // A normal (non-streaming, non-gRPC) request keeps buffering so JSON token
    // accounting still works on every dispatch path.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
}

// ─── OpenAI format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_openai_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "100");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "50");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "gpt-4o");
}

// ─── Anthropic format ───────────────────────────────────────────────────

#[tokio::test]
async fn test_anthropic_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "claude-sonnet-4-20250514",
        "usage": {
            "input_tokens": 200,
            "output_tokens": 80
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "anthropic");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "280");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "200");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "80");
    assert_eq!(
        ctx.metadata.get("ai_model").unwrap(),
        "claude-sonnet-4-20250514"
    );
}

// ─── Google Gemini format ───────────────────────────────────────────────

#[tokio::test]
async fn test_google_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "modelVersion": "gemini-1.5-pro",
        "usageMetadata": {
            "promptTokenCount": 300,
            "candidatesTokenCount": 120,
            "totalTokenCount": 420
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "google");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "420");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "300");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "120");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "gemini-1.5-pro");
}

// ─── Cohere format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_cohere_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "command-r-plus",
        "meta": {
            "tokens": {
                "input_tokens": 50,
                "output_tokens": 30
            }
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "80");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "50");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "30");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "command-r-plus");
}

#[tokio::test]
async fn test_cohere_v2_buffered_format() {
    // Cohere v2 `/v2/chat` puts counts at `usage.tokens.*` (the v1 layout
    // was `meta.tokens.*`). Auto-detection must distinguish v2 from
    // OpenAI / Bedrock which also key off `usage.*`.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "id": "abc-123",
        "finish_reason": "COMPLETE",
        "usage": {
            "tokens": {
                "input_tokens": 17,
                "output_tokens": 9
            }
        }
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "26");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "17");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "9");
}

#[tokio::test]
async fn test_cohere_v2_streaming_format() {
    // Cohere v2 SSE: the terminal `message-end` event carries counts under
    // `delta.usage.tokens.*`. The previous SSE detector classified all
    // `message*` events as Anthropic and dropped these.
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());

    let sse = concat!(
        "data: {\"type\":\"message-start\",\"id\":\"abc\"}\n\n",
        "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"hi\"}}}}\n\n",
        "data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":23,\"output_tokens\":41}}}}\n\n",
    )
    .as_bytes();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, sse)
        .await;

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "64");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "23");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "41");
}

// ─── Bedrock format ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_bedrock_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {
            "inputTokens": 150,
            "outputTokens": 75,
            "totalTokens": 225
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "bedrock");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "225");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "75");
}

// ─── Explicit provider config ───────────────────────────────────────────

#[tokio::test]
async fn test_explicit_provider_openai() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "openai"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

#[test]
fn explicit_provider_requires_the_documented_lowercase_enum_spelling() {
    for provider in ["OpenAI", " openai", "openai ", "OPENAI"] {
        let err = AiTokenMetrics::new(&json!({"provider": provider}))
            .err()
            .expect("non-canonical provider spelling must be rejected");
        assert!(err.contains("unknown 'provider' value"), "got: {err}");
    }
}

#[tokio::test]
async fn test_explicit_provider_mistral() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "mistral"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "mistral-large",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "mistral");
}

// ─── Custom metadata prefix ─────────────────────────────────────────────

#[tokio::test]
async fn test_custom_prefix() {
    let plugin = AiTokenMetrics::new(&json!({"metadata_prefix": "llm"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("llm_total_tokens").unwrap(), "15");
    assert_eq!(ctx.metadata.get("llm_prompt_tokens").unwrap(), "10");
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

// ─── Cost calculation ───────────────────────────────────────────────────

#[tokio::test]
async fn test_cost_calculation() {
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.00001,
        "cost_per_completion_token": 0.00003
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    // Cost = 1000 * 0.00001 + 500 * 0.00003 = 0.01 + 0.015 = 0.025
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.025000");
}

#[tokio::test]
async fn test_cost_calculation_prompt_only() {
    // Embedding models only have input cost
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.0001
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "total_tokens": 1000}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    // Cost = 1000 * 0.0001 + 0 * 0.0 = 0.1
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.100000");
}

#[tokio::test]
async fn test_cost_not_calculated_when_no_rates() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
}

// ─── include_model = false ──────────────────────────────────────────────

#[tokio::test]
async fn test_include_model_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_model": false})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_model"));
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

// ─── include_token_details = false ──────────────────────────────────────

#[tokio::test]
async fn test_include_token_details_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_token_details": false})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
}

// ─── Edge cases ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_non_json_content_type() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"not json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_empty_body() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_malformed_json() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"not valid json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_missing_usage_fields() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({"id": "chatcmpl-123"})).unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);
    // No provider detected, no metadata written
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_zero_tokens() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "0");
}

#[test]
fn test_unknown_configured_provider_rejected() {
    let err = AiTokenMetrics::new(&json!({"provider": "unknown_provider"}))
        .err()
        .unwrap();
    assert!(err.contains("provider"), "got: {err}");
}

#[tokio::test]
async fn test_bedrock_computed_total() {
    // Bedrock without explicit totalTokens — should compute from input + output
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 100, "outputTokens": 50}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
}

// ─── Response status filtering ────────────────────────────────────────

#[tokio::test]
async fn test_skips_4xx_responses() {
    // Error responses (4xx) often have non-LLM body shapes — they must
    // not be parsed for token counts or pollute observability metrics.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 401, &mut headers, &body)
        .await;
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "4xx response must not record token metrics"
    );
}

#[tokio::test]
async fn test_skips_5xx_responses() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 503, &mut headers, &body)
        .await;
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "5xx response must not record token metrics"
    );
}

#[tokio::test]
async fn test_processes_2xx_responses() {
    // Sanity check that the new filter doesn't accidentally drop happy-path
    // 2xx responses.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "30");
}

// ─── Cost validation ────────────────────────────────────────────────────

#[test]
fn test_negative_prompt_cost_rejected() {
    // Negative cost rates would produce negative cost metrics that pollute
    // observability and chargeback pipelines.
    let err = AiTokenMetrics::new(&json!({"cost_per_prompt_token": -0.0001}))
        .err()
        .unwrap();
    assert!(err.contains("cost_per_prompt_token"), "got: {err}");
    assert!(err.contains("non-negative"), "got: {err}");
}

#[test]
fn test_negative_completion_cost_rejected() {
    let err = AiTokenMetrics::new(&json!({"cost_per_completion_token": -0.001}))
        .err()
        .unwrap();
    assert!(err.contains("cost_per_completion_token"), "got: {err}");
    assert!(err.contains("non-negative"), "got: {err}");
}

#[test]
fn test_nan_cost_handled_safely() {
    // The serde_json::json!() macro coerces non-finite f64 values to
    // Value::Null, so a NaN/Inf field is the same as omitting the field.
    // Verify the constructor accepts that path (treats it as "no cost
    // tracking") rather than panicking on `.as_f64()`.
    assert!(
        AiTokenMetrics::new(&json!({"cost_per_prompt_token": f64::NAN})).is_ok(),
        "NaN serializes to JSON null and should be treated as 'unset'"
    );
    assert!(
        AiTokenMetrics::new(&json!({"cost_per_completion_token": f64::INFINITY})).is_ok(),
        "Infinity serializes to JSON null and should be treated as 'unset'"
    );
}

#[test]
fn test_zero_cost_accepted() {
    // Zero is a valid cost rate (e.g., free-tier accounting).
    assert!(
        AiTokenMetrics::new(&json!({
            "cost_per_prompt_token": 0.0,
            "cost_per_completion_token": 0.0
        }))
        .is_ok()
    );
}

#[test]
fn cost_rate_maximum_matches_the_openapi_contract() {
    assert!(
        AiTokenMetrics::new(&json!({
            "cost_per_prompt_token": 18_446_744_073_709.55,
            "cost_per_completion_token": 18_446_744_073_709.55
        }))
        .is_ok()
    );
    assert!(AiTokenMetrics::new(&json!({"cost_per_prompt_token": 18_446_744_073_710.0})).is_err());
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (json!({"provider": ""}), "provider"),
        (json!({"include_model": "yes"}), "include_model"),
        (
            json!({"include_token_details": "yes"}),
            "include_token_details",
        ),
        (
            json!({"buffer_streaming_responses": "yes"}),
            "buffer_streaming_responses",
        ),
        (json!({"metadata_prefix": ""}), "metadata_prefix"),
        (
            json!({"cost_per_prompt_token": "free"}),
            "cost_per_prompt_token",
        ),
        (
            json!({"cost_per_completion_token": "free"}),
            "cost_per_completion_token",
        ),
    ] {
        let err = AiTokenMetrics::new(&config).err().unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

#[test]
fn test_shared_validation_rejects_invalid_ai_token_metrics_config() {
    let err = validate_plugin_config("ai_token_metrics", &json!({"include_model": "yes"}))
        .expect_err("shared plugin validation must reject a non-boolean include_model");
    assert_eq!(err, "ai_token_metrics: 'include_model' must be a boolean");
}

// ─── Synthetic short-circuit accounting guard ───────────────────────────────

// Regression: a synthetic short-circuit 2xx body (an `ai_semantic_cache` hit, a
// `response_mock` returning a canned chat-completion, a `serverless_function`
// terminate, an `ai_federation` synthetic response, …) never reached the
// upstream model, so its token usage must NOT be recorded. Even if the synthetic
// body carries a provider-shaped `usage` block, charging it would inflate token
// metrics / logging sinks / chargeback with phantom usage. The proxy sets the
// synthetic marker for the duration of the response-body-hook phase.
#[tokio::test]
async fn synthetic_short_circuit_body_is_not_token_accounted() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    // Emulate the proxy marking the context before running the body hooks.
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    // A canned OpenAI-shaped body that WOULD otherwise be accounted.
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    // No token-usage metadata was written for the synthetic body.
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "synthetic short-circuit body must not record token usage"
    );
    assert!(!ctx.metadata.contains_key("ai_provider"));
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
    assert!(!ctx.metadata.contains_key("ai_model"));
}

// Control: a GENUINE backend response (no synthetic marker) with the same
// provider-shaped body IS accounted. Guards against the synthetic skip
// accidentally disabling normal token metrics.
#[tokio::test]
async fn genuine_response_is_token_accounted_without_synthetic_marker() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
}

#[tokio::test]
async fn anthropic_sse_merges_cumulative_terminal_usage_without_double_counting() {
    let plugin = AiTokenMetrics::new(&json!({
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;

    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("25")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("15")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("40")
    );
    assert_eq!(
        ctx.metadata.get("ai_estimated_cost").map(String::as_str),
        Some("0.550000")
    );
}

#[tokio::test]
async fn anthropic_sse_without_message_start_keeps_explicit_partial_usage() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n";

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;

    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("9")
    );
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn partial_sse_component_update_retains_earlier_authoritative_total() {
    let plugin = AiTokenMetrics::new(&json!({
        "provider": "openai",
        "buffer_streaming_responses": true
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"usage\":{\"total_tokens\":100}}\n\n",
        "data: {\"usage\":{\"completion_tokens\":7}}\n\n",
        "data: [DONE]\n\n"
    );

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;

    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("100")
    );
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    let export = ctx
        .authoritative_ai_usage_export()
        .expect("partial SSE usage must retain typed export provenance");
    assert_eq!(export.prompt_tokens, None);
    assert_eq!(export.completion_tokens, Some(7));
    assert_eq!(export.total_tokens, Some(100));
}

#[tokio::test]
async fn openai_responses_buffered_and_completed_sse_are_supported() {
    let buffered = json!({
        "id": "resp_123",
        "object": "response",
        "model": "gpt-4.1",
        "usage": {
            "input_tokens": 36,
            "input_tokens_details": {"cached_tokens": 10},
            "output_tokens": 87,
            "output_tokens_details": {"reasoning_tokens": 12},
            "total_tokens": 123
        }
    });
    for config in [
        json!({"cost_per_prompt_token": 0.01, "cost_per_completion_token": 0.02}),
        json!({"provider": "openai", "cost_per_prompt_token": 0.01, "cost_per_completion_token": 0.02}),
    ] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut json_headers(),
                &serde_json::to_vec(&buffered).unwrap(),
            )
            .await;
        assert_eq!(
            ctx.metadata.get("ai_provider").map(String::as_str),
            Some("openai")
        );
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("36")
        );
        assert_eq!(
            ctx.metadata.get("ai_completion_tokens").map(String::as_str),
            Some("87")
        );
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("123")
        );
        assert_eq!(
            ctx.metadata.get("ai_estimated_cost").map(String::as_str),
            Some("2.100000")
        );
    }

    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);
    let event = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({
            "type": "response.completed",
            "response": buffered
        })
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, event.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("123")
    );
}

#[tokio::test]
async fn incomplete_or_malformed_openai_responses_do_not_invent_usage() {
    let plugin = AiTokenMetrics::new(&json!({
        "provider": "openai",
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 1.0
    }))
    .unwrap();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    for event_type in ["response.incomplete", "response.failed"] {
        let mut ctx = create_test_context();
        let event = format!(
            "data: {}\n\n",
            json!({"type": event_type, "response": {"usage": {"input_tokens": 5}}})
        );
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, event.as_bytes())
            .await;
        assert!(!ctx.metadata.contains_key("ai_provider"));
        assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
    }

    let mut ctx = create_test_context();
    let malformed = serde_json::to_vec(&json!({
        "object": "response",
        "usage": {"input_tokens": 1.5, "output_tokens": "2", "total_tokens": -1}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &malformed)
        .await;
    assert!(ctx.metadata.is_empty());
}

#[tokio::test]
async fn google_sse_merges_repeated_partial_usage_for_auto_and_fixed_provider() {
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}],\"modelVersion\":\"gemini-test\"}\n\n",
        "data: {\"usageMetadata\":{\"promptTokenCount\":11}}\n\n",
        "data: {\"usageMetadata\":{\"candidatesTokenCount\":7,\"totalTokenCount\":18}}\n\n",
        "data: [DONE]\n\n"
    );
    for config in [
        json!({"buffer_streaming_responses": true}),
        json!({"provider": "google", "buffer_streaming_responses": true}),
    ] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await;
        assert_eq!(
            ctx.metadata.get("ai_provider").map(String::as_str),
            Some("google")
        );
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("11")
        );
        assert_eq!(
            ctx.metadata.get("ai_completion_tokens").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("18")
        );
        assert_eq!(
            ctx.metadata.get("ai_model").map(String::as_str),
            Some("gemini-test")
        );
    }
}

#[tokio::test]
async fn bedrock_titan_invoke_model_is_supported_without_ambiguous_result_summing() {
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let body = serde_json::to_vec(&json!({
        "inputTextTokenCount": 21,
        "results": [{"tokenCount": 8, "outputText": "hello", "completionReason": "FINISH"}]
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("bedrock")
    );
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("21")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("8")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("29")
    );
    assert_eq!(
        ctx.metadata.get("ai_estimated_cost").map(String::as_str),
        Some("0.370000")
    );

    for results in [json!([]), json!([{"tokenCount": 2}, {"tokenCount": 3}])] {
        let mut ctx = create_test_context();
        let body = serde_json::to_vec(&json!({
            "inputTextTokenCount": 5,
            "results": results
        }))
        .unwrap();
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("5")
        );
        assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
        assert!(!ctx.metadata.contains_key("ai_total_tokens"));
    }
}

#[tokio::test]
async fn encoded_json_supports_gzip_brotli_and_coding_chains_without_mutation() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let plain = serde_json::to_vec(&json!({
        "model": "gpt-test",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();
    let cases = [
        ("GZip", gzip(&plain)),
        ("br", brotli(&plain)),
        ("gzip, BR", brotli(&gzip(&plain))),
    ];

    for (encoding, encoded) in cases {
        let original = encoded.clone();
        let mut headers = HashMap::from([
            (
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("Content-Encoding".to_string(), encoding.to_string()),
            ("Content-Length".to_string(), encoded.len().to_string()),
            ("ETag".to_string(), "encoded-validator".to_string()),
        ]);
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &encoded)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("15")
        );
        assert_eq!(encoded, original);
        assert_eq!(
            headers.get("Content-Encoding").map(String::as_str),
            Some(encoding)
        );
        assert_eq!(
            headers
                .get("Content-Length")
                .and_then(|value| value.parse::<usize>().ok()),
            Some(encoded.len())
        );
        assert_eq!(
            headers.get("ETag").map(String::as_str),
            Some("encoded-validator")
        );
    }
}

#[tokio::test]
async fn encoded_sse_is_inspected_only_when_stream_buffering_is_enabled() {
    let event = b"data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10}}\n\ndata: [DONE]\n\n";
    let encoded = gzip(event);
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/event-stream".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
    ]);

    for (enabled, expected) in [(false, None), (true, Some("10"))] {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": enabled})).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &encoded)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            expected
        );
    }
}

#[tokio::test]
async fn encoded_json_rejects_malformed_unsupported_concatenated_and_oversized_content() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let plain = br#"{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let mut concatenated = gzip(plain);
    concatenated.extend_from_slice(&gzip(plain));
    let oversized = gzip(&vec![b' '; 4 * 1024 * 1024 + 1]);
    let cases = [
        ("gzip", b"not-gzip".to_vec()),
        ("zstd", plain.to_vec()),
        ("gzip; level=9", gzip(plain)),
        ("gzip", concatenated),
        ("gzip", oversized),
    ];
    for (encoding, body) in cases {
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-encoding".to_string(), encoding.to_string()),
        ]);
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await;
        assert!(
            !ctx.metadata.contains_key("ai_total_tokens"),
            "encoding={encoding}"
        );
    }
}

#[tokio::test]
async fn checked_usage_arithmetic_never_saturates_into_invented_totals() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": u64::MAX, "completion_tokens": 1}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("18446744073709551615")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("1")
    );
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[test]
fn every_unknown_root_config_key_is_rejected_with_allowed_key_list() {
    for key in [
        "providre",
        "include_modle",
        "include_token_detail",
        "metadata_prefx",
        "buffer_streaming_response",
        "cost_per_prompt_tokn",
        "cost_per_completion_tokn",
    ] {
        let err = AiTokenMetrics::new(&json!({(key): true})).err().unwrap();
        assert!(err.contains(key), "got: {err}");
        assert!(err.contains("allowed keys"), "got: {err}");
        assert!(err.contains("metadata_prefix"), "got: {err}");
    }
}

//! Tests for ai_rate_limiter plugin

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
    ai_rate_limiter::AiRateLimiter,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
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

fn openai_response(prompt: u64, completion: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion
        }
    }))
    .unwrap()
}

// ─── Plugin basics ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_plugin_name_and_priority() {
    let plugin =
        AiRateLimiter::new(&json!({"token_limit": 1000}), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "ai_rate_limiter");
    assert_eq!(plugin.priority(), 4200);
    assert_eq!(
        plugin.supported_protocols(),
        &[ProxyProtocol::Http, ProxyProtocol::Grpc]
    );
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type(
        "POST",
        "multipart/form-data; boundary=abc"
    )));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
    // Spec change (PR #956 / commit 55a59396): the POST-only buffering
    // shortcut was a security bypass — non-POST AI responses (e.g. GET
    // chat history endpoints) would skip token-budget accounting. The
    // plugin now buffers every method when it's active.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));
}

// ─── Basic flow ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_first_request_passes() {
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_provider_is_case_insensitive() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip",
            "provider": " OpenAI "
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let body = openai_response(80, 30);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );
}

#[tokio::test]
async fn test_token_accumulation_and_limit() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 200,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // First request passes
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Record 150 tokens
    let resp_headers = json_headers();
    let body = openai_response(100, 50);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Second request passes (150 < 200)
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    // Record another 100 tokens (total now 250)
    let body2 = openai_response(60, 40);
    plugin
        .on_response_body(&mut ctx2, 200, &resp_headers, &body2)
        .await;

    // Third request should be rejected (250 >= 200)
    let mut ctx3 = create_test_context();
    let mut headers3 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx3, &mut headers3).await;
    assert_reject(result, Some(429));
}

// ─── Sliding window eviction ─────────────────────────────────────────────

#[tokio::test]
async fn test_sliding_window_eviction() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 1,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Use up the limit
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let resp_headers = json_headers();
    let body = openai_response(80, 30); // 110 tokens
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Should be rejected now
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );

    // Wait for window to expire
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Should pass now (window expired)
    let mut ctx3 = create_test_context();
    let mut headers3 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx3, &mut headers3).await);
}

// ─── Consumer-based limiting ──────────────────────────────────────────────

#[tokio::test]
async fn test_different_consumers_independent() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "consumer"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    // Consumer A uses 150 tokens
    let mut ctx_a = create_test_context();
    ctx_a.identified_consumer = Some(Arc::new(super::plugin_utils::create_test_consumer()));
    let mut headers_a = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;
    let body = openai_response(100, 50);
    plugin
        .on_response_body(&mut ctx_a, 200, &resp_headers, &body)
        .await;

    // Consumer A should be rejected
    let mut ctx_a2 = create_test_context();
    ctx_a2.identified_consumer = ctx_a.identified_consumer.clone();
    let mut headers_a2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx_a2, &mut headers_a2).await,
        Some(429),
    );

    // Consumer B (different IP) should still pass
    let mut ctx_b = create_test_context();
    ctx_b.client_ip = "10.0.0.2".to_string();
    ctx_b.identified_consumer = None;
    let mut headers_b = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx_b, &mut headers_b).await);
}

// ─── Count modes ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_count_mode_prompt_tokens() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 50 prompt + 500 completion = only 50 counted
    let body = openai_response(50, 500);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Should still pass (50 < 100)
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

#[tokio::test]
async fn test_count_mode_completion_tokens() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "count_mode": "completion_tokens",
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 prompt + 50 completion = only 50 counted
    let body = openai_response(500, 50);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Should still pass (50 < 100)
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

// ─── Provider formats ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_anthropic_format() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = serde_json::to_vec(&json!({
        "usage": {"input_tokens": 80, "output_tokens": 40}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // 120 total > 100 limit
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );
}

#[tokio::test]
async fn test_google_format() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = serde_json::to_vec(&json!({
        "usageMetadata": {
            "promptTokenCount": 60,
            "candidatesTokenCount": 50,
            "totalTokenCount": 110
        }
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // 110 > 100
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );
}

// ─── Edge cases ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_non_json_response_not_counted() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/plain".to_string());
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, b"not json")
        .await;

    // No tokens counted — should still pass
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

#[tokio::test]
async fn test_non_2xx_response_not_counted() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 error with tokens — should NOT count
    let body = openai_response(500, 500);
    plugin
        .on_response_body(&mut ctx, 500, &resp_headers, &body)
        .await;

    // Should still pass
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

#[tokio::test]
async fn test_empty_body_not_counted() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, b"")
        .await;

    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

#[tokio::test]
async fn test_zero_tokens_counted_but_no_usage() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = openai_response(0, 0);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // 0 tokens used — still within limit
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
}

// ─── Expose headers ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_expose_headers() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(ctx.metadata.get("ai_ratelimit_limit").unwrap(), "1000");
    assert_eq!(ctx.metadata.get("ai_ratelimit_remaining").unwrap(), "1000");
    assert_eq!(ctx.metadata.get("ai_ratelimit_window").unwrap(), "60");
    assert_eq!(ctx.metadata.get("ai_ratelimit_usage").unwrap(), "0");

    // after_proxy should inject headers
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("x-ai-ratelimit-limit").unwrap(),
        "1000"
    );
}

#[tokio::test]
async fn test_expose_headers_on_rejection() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 50,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    // Record 100 tokens
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let body = openai_response(60, 40);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Should be rejected with headers
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(headers.get("x-ai-ratelimit-limit").unwrap(), "50");
            assert_eq!(headers.get("x-ai-ratelimit-remaining").unwrap(), "0");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_consumer_fallback_to_ip() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "consumer"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    // No consumer set — should use IP as key
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = None;
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = openai_response(80, 30);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;

    // Same IP should be rejected
    let mut ctx2 = create_test_context();
    ctx2.identified_consumer = None;
    ctx2.authenticated_identity = None;
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );
}

// ─── Metadata optimization ──────────────────────────────────────────────

#[tokio::test]
async fn test_reads_tokens_from_ai_token_metrics_metadata() {
    // When ai_token_metrics runs first (priority 4100), it writes token counts
    // to ctx.metadata. ai_rate_limiter (priority 4200) should read from
    // metadata instead of re-parsing the response body.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // Simulate ai_token_metrics having written metadata
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "150".to_string());
    ctx.metadata
        .insert("ai_prompt_tokens".to_string(), "100".to_string());
    ctx.metadata
        .insert("ai_completion_tokens".to_string(), "50".to_string());

    // Pass an empty body — the plugin should read from metadata, not body
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, b"")
        .await;

    // Should have recorded 150 tokens from metadata → next request rejected
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(429),
    );
}

// ─── Config validation (rejects unknown enum values) ───────────────────

#[test]
fn test_invalid_count_mode_rejected() {
    let err = AiRateLimiter::new(
        &json!({"token_limit": 100, "count_mode": "completion_token"}),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(err.contains("count_mode"), "got: {err}");
}

#[test]
fn test_invalid_limit_by_rejected() {
    let err = AiRateLimiter::new(
        &json!({"token_limit": 100, "limit_by": "consumr"}),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(err.contains("limit_by"), "got: {err}");
}

#[test]
fn test_valid_count_mode_accepted() {
    for mode in ["prompt_tokens", "completion_tokens", "total_tokens"] {
        AiRateLimiter::new(
            &json!({"token_limit": 100, "count_mode": mode}),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|e| panic!("count_mode '{mode}' should be valid: {e}"));
    }
}

#[test]
fn test_valid_limit_by_accepted() {
    for value in ["consumer", "ip"] {
        AiRateLimiter::new(
            &json!({"token_limit": 100, "limit_by": value}),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|e| panic!("limit_by '{value}' should be valid: {e}"));
    }
}

#[test]
fn test_valid_on_unmetered_response_accepted() {
    for value in ["reject", "charge_estimate", "warn"] {
        AiRateLimiter::new(
            &json!({"token_limit": 100, "on_unmetered_response": value}),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|e| panic!("on_unmetered_response '{value}' should be valid: {e}"));
    }
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (json!({}), "token_limit"),
        (json!({"token_limit": "100"}), "token_limit"),
        (
            json!({"token_limit": 100, "window_seconds": "60"}),
            "window_seconds",
        ),
        (
            json!({"token_limit": 100, "expose_headers": "true"}),
            "expose_headers",
        ),
        (json!({"token_limit": 100, "provider": ""}), "provider"),
        (
            json!({"token_limit": 100, "provider": "unknown"}),
            "provider",
        ),
        (
            json!({"token_limit": 100, "on_unmetered_response": "ignore"}),
            "on_unmetered_response",
        ),
        (
            json!({"token_limit": 100, "sync_mode": "database"}),
            "'sync_mode' must be 'local' or 'redis'",
        ),
    ] {
        let err = AiRateLimiter::new(&config, PluginHttpClient::default())
            .err()
            .unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

// ─── Anthropic SSE token merging (partial state) ───────────────────────

#[tokio::test]
async fn test_anthropic_sse_only_message_delta_records_completion_tokens() {
    // SSE stream with ONLY a message_delta event (no message_start). The
    // previous behavior dropped the entire token count because total_tokens
    // remained None. The fix recovers from partial state by treating the
    // available count as the total.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "provider": "anthropic"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(res);

    let sse = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":750}}\n\n";
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, sse)
        .await;

    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    let sse2 = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":300}}\n\n";
    plugin
        .on_response_body(&mut ctx2, 200, &resp_headers, sse2)
        .await;

    // 750 + 300 = 1050 → exceeds 1000 → next request must be rejected.
    let mut ctx3 = create_test_context();
    let mut headers3 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx3, &mut headers3).await,
        Some(429),
    );
}

// ─── Cohere v2 SSE token recording ─────────────────────────────────────

#[tokio::test]
async fn test_cohere_v2_sse_message_end_records_tokens() {
    // Cohere v2 SSE: counts arrive on the terminal `message-end` event
    // under `delta.usage.tokens.*`. Auto-detection must classify the
    // hyphenated event types as Cohere (previously swallowed as Anthropic),
    // and the rate-limiter must read the nested counts so token-based
    // throttling works for Cohere v2 streaming clients.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 100, "window_seconds": 60, "provider": "auto"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let sse = concat!(
        "data: {\"type\":\"message-start\",\"id\":\"abc\"}\n\n",
        "data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":40,\"output_tokens\":35}}}}\n\n",
    )
    .as_bytes();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, sse)
        .await;

    // 75 tokens recorded — second request fits (75 + 25 ≤ 100), a 26-token
    // follow-up would exceed.
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    let sse2 = b"data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":15,\"output_tokens\":15}}}}\n\n";
    plugin
        .on_response_body(&mut ctx2, 200, &resp_headers, sse2)
        .await;

    let mut ctx3 = create_test_context();
    let mut headers3 = HashMap::new();
    assert_reject(
        plugin.before_proxy(&mut ctx3, &mut headers3).await,
        Some(429),
    );
}

// ─── TokenWindow running-sum invariant ─────────────────────────────────

#[tokio::test]
async fn test_window_running_sum_matches_after_eviction() {
    // Record some tokens, sleep past the window, record more, then verify
    // the visible "remaining" budget reflects only the unexpired portion.
    // Verifies the running-sum bookkeeping handles eviction correctly.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 200,
            "window_seconds": 1,
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    let body100 = openai_response(50, 50);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body100)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let body50 = openai_response(20, 30);
    plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body50)
        .await;

    // Next call should see remaining = 200 - 50 = 150.
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
    let remaining = ctx2
        .metadata
        .get("ai_ratelimit_remaining")
        .map(|v| v.parse::<u64>().unwrap_or(0))
        .unwrap_or(0);
    assert_eq!(
        remaining, 150,
        "expected remaining=150 after expired entry evicted, got {remaining}"
    );
}

// ─── tracked_keys_count observability ──────────────────────────────────

#[tokio::test]
async fn test_tracked_keys_count_grows_with_distinct_keys() {
    // tracked_keys_count() exposes the local-mode rate-limit DashMap size
    // for observability (matches rate_limiting and ai_semantic_cache).
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.tracked_keys_count(), Some(0));

    // First IP creates a key.
    let mut ctx_a = create_test_context();
    ctx_a.client_ip = "10.0.0.1".to_string();
    let mut headers_a = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // Second IP creates a second key.
    let mut ctx_b = create_test_context();
    ctx_b.client_ip = "10.0.0.2".to_string();
    let mut headers_b = HashMap::new();
    plugin.before_proxy(&mut ctx_b, &mut headers_b).await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    // Repeated request from the first IP reuses the existing key.
    let mut ctx_a_again = create_test_context();
    ctx_a_again.client_ip = "10.0.0.1".to_string();
    let mut headers_a_again = HashMap::new();
    plugin
        .before_proxy(&mut ctx_a_again, &mut headers_a_again)
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));
}

// ─── SSE token accounting: absent vs zero (#53, #54) ───────────────────

fn sse_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/event-stream".to_string());
    h
}

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

fn reserved_tokens(ctx: &RequestContext) -> u64 {
    ctx.metadata
        .get("ai_ratelimit_reserved_tokens")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Read the current-window usage the limiter would charge, by issuing a
/// follow-up `before_proxy` and reading the exposed `ai_ratelimit_usage`.
async fn observed_usage(plugin: &AiRateLimiter) -> u64 {
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata
        .get("ai_ratelimit_usage")
        .map(|v| v.parse::<u64>().unwrap_or(0))
        .unwrap_or(0)
}

#[tokio::test]
async fn test_sse_with_usage_block_still_recorded() {
    // Non-regression for #54: the saw_usage gating must NOT break extraction
    // when a usage block IS present. A streamed OpenAI-style response that
    // reports prompt_tokens must still be charged in prompt_tokens mode.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
               data: {\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":8,\"total_tokens\":50}}\n\n\
               data: [DONE]\n\n";
    plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), sse.as_bytes())
        .await;

    assert_eq!(
        observed_usage(&plugin).await,
        42,
        "prompt_tokens from the SSE usage block should be charged"
    );
}

#[tokio::test]
async fn streaming_without_usage_charged_or_rejected() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "count_mode": "total_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "hello");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve estimated tokens");

    // Content-only deltas, no usage block anywhere.
    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n\
               data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n\
               data: [DONE]\n\n";
    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), sse.as_bytes())
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "default enforce behavior should keep the reservation for unmetered SSE"
    );
}

#[tokio::test]
async fn unmetered_2xx_is_not_free_in_enforce_mode() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "count this prompt");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve estimated tokens");

    // Valid JSON, but no usage block the extractor understands.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "an unmetered 2xx should keep the estimated reservation by default"
    );
}

#[tokio::test]
async fn concurrent_requests_cannot_oversubscribe_budget() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 150,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx_a = ai_request_ctx(100, "first");
    let mut ctx_b = ai_request_ctx(100, "second");
    let mut headers_a = HashMap::new();
    let mut headers_b = HashMap::new();

    let (result_a, result_b) = tokio::join!(
        plugin.before_proxy(&mut ctx_a, &mut headers_a),
        plugin.before_proxy(&mut ctx_b, &mut headers_b)
    );

    let allowed = u8::from(matches!(&result_a, PluginResult::Continue))
        + u8::from(matches!(&result_b, PluginResult::Continue));
    let rejected = u8::from(matches!(&result_a, PluginResult::Reject { .. }))
        + u8::from(matches!(&result_b, PluginResult::Reject { .. }));
    assert_eq!(allowed, 1, "only one reservation should fit in the budget");
    assert_eq!(rejected, 1, "the oversubscribing reservation should reject");
}

#[tokio::test]
async fn federation_metadata_still_records_actual_usage() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(300, "federated prompt");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 40);

    ctx.metadata
        .insert("ai_federation_provider".to_string(), "primary".to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "40".to_string());
    ctx.metadata
        .insert("ai_prompt_tokens".to_string(), "15".to_string());
    ctx.metadata
        .insert("ai_completion_tokens".to_string(), "25".to_string());

    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        40,
        "federation actual usage should reconcile the pre-request reservation"
    );
}

// ─── Reconciliation of unmetered 2xx by on_unmetered_response mode ──────

#[tokio::test]
async fn unmetered_2xx_warn_mode_releases_reservation() {
    // on_unmetered_response = "warn": a 2xx with no resolvable usage must
    // RELEASE the pre-request reservation (delta = 0 - reserved) so the window
    // returns to zero. This drives the `OnUnmeteredResponse::Warn` arm of
    // `reconcile_usage` plus the negative-delta `adjust_usage` plugin path.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "warn",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "warn-mode prompt");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 0, "request should reserve tokens");

    // Valid JSON 2xx with no usage block the extractor understands.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "warn mode must release the reservation for an unmetered 2xx"
    );
}

#[tokio::test]
async fn unmetered_2xx_reject_mode_returns_502() {
    // on_unmetered_response = "reject": a 2xx with no resolvable usage must be
    // rejected with 502. Drives the `OnUnmeteredResponse::Reject` arm of
    // `reconcile_usage` and the `reject_unmetered()` builder. The reservation
    // is intentionally KEPT (rejection means the budget stays charged until the
    // window/TTL expires).
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "reject-mode prompt");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "reject mode keeps the reservation charged"
    );
}

#[tokio::test]
async fn non_2xx_releases_pre_request_reservation() {
    // A non-2xx response after a reservation must release the full reservation
    // via `reconcile_usage(.., None, ..)` regardless of on_unmetered_response.
    // Drives the non-2xx branch of `on_response_body` -> `reconcile_usage` with
    // a real (non-zero) reservation, exercising the negative-delta release.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(150, "this prompt will 500");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 0, "request should reserve tokens");

    // Backend 500 — even with a usage block present, a non-2xx releases the
    // reservation and charges nothing.
    let body = openai_response(500, 500);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 500, &json_headers(), &body)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a non-2xx must release the reservation"
    );
}

#[tokio::test]
async fn actual_usage_above_reservation_charges_extra() {
    // Reconciliation where actual > reserved must charge the positive delta so
    // the window reflects true consumption. Exercises the `Some(actual_tokens)`
    // arm of `reconcile_usage` with a positive `reservation_delta` flowing into
    // the plugin's `adjust_usage`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(50, "short");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    // Actual response reports far more than the estimate.
    let body = openai_response(400, 600); // 1000 total tokens
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        1000,
        "actual usage above the reservation must be charged in full"
    );
}

#[tokio::test]
async fn gateway_rejection_releases_reservation_in_after_proxy() {
    // When a downstream plugin rejects the request after this plugin reserved
    // tokens, the gateway sets `ferrum:rejection_response=true`. `after_proxy`
    // must then release the reservation via `should_release_gateway_rejection`
    // -> `reconcile_usage(.., 500, None, "gateway_rejection")`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "gateway will reject this");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 0, "request should reserve tokens");

    // Simulate a gateway-side rejection of the proxied request.
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());

    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 500, &mut response_headers)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a gateway rejection must release the reservation"
    );
}

#[tokio::test]
async fn response_body_plugin_reject_keeps_reservation_after_2xx_backend() {
    // codex P2: when the backend returned a successful (2xx) response but a
    // later response-body plugin (e.g. ai_response_guard, priority 4075 < 4200)
    // rejects the body, `ai_rate_limiter`'s `on_response_body` is skipped and its
    // `after_proxy` re-runs inside the rejection. The provider call DID consume
    // tokens, so the reservation must be kept — not released as if it were a
    // gateway rejection.
    //
    // We reproduce the production ordering: a genuine `after_proxy` run with the
    // 2xx backend status (records the backend status), then the rejection re-run
    // with `ferrum:rejection_response=true`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "guard will reject the 2xx body");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    // Genuine after_proxy run: backend served 200, no rejection marker yet.
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );

    // A later response-body plugin rejects: the proxy sets the rejection marker
    // and re-runs after_proxy with the rejection status.
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    let mut reject_headers = HashMap::new();
    assert_continue(plugin.after_proxy(&mut ctx, 403, &mut reject_headers).await);

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "a 2xx backend whose body a later plugin rejected must keep the reservation charged"
    );
}

#[tokio::test]
async fn reject_mode_does_not_release_on_gateway_rejection() {
    // `should_release_gateway_rejection` must NOT fire when the configured
    // unmetered action is `reject` (the reservation deliberately stays charged).
    // Here we record an unmetered-action marker of "reject" and assert the
    // after_proxy gateway-rejection branch is skipped. Covers the negative arm
    // of `should_release_gateway_rejection`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "reject keeps the charge");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    ctx.metadata.insert(
        "ai_ratelimit_unmetered_action".to_string(),
        "reject".to_string(),
    );

    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 500, &mut response_headers)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "reject mode must keep the reservation even on gateway rejection"
    );
}

#[tokio::test]
async fn federation_unmetered_reject_returns_502_from_after_proxy_in_isolation() {
    // DOCUMENTED LIMITATION (codex P1): this asserts only the *isolated* return
    // value of `after_proxy`. It does NOT prove the reject reaches the client on
    // the federation path. In production `ai_federation` delivers the provider
    // response as a `before_proxy` `RejectBinary`, so `ai_rate_limiter`'s
    // `after_proxy` runs via the proxy's `apply_after_proxy_hooks_to_rejection`
    // helper, which intentionally *ignores* after-proxy-on-reject `Reject`
    // results (it is already committed to emitting a rejection response and only
    // logs a warning). Therefore `on_unmetered_response: "reject"` is effectively
    // a no-op for federated 2xx responses missing usage metadata — they are still
    // returned to the client. This is called out in docs/plugins.md; honoring the
    // reject would require restructuring the proxy rejection pipeline so an
    // after-proxy hook can replace an in-flight rejection, which is deferred.
    //
    // The assertion below pins the *plugin-local* contract (reconciliation
    // returns a 502 reject) so the policy decision itself stays covered; the
    // production swallowing is the documented gap, not a bug in this function.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "federated, no usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Federation marker set, but no ai_total_tokens metadata.
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "primary".to_string());

    let mut response_headers = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_reject(result, Some(502));
}

// ─── Pre-request estimation by count_mode and prompt shape ──────────────

#[tokio::test]
async fn completion_count_mode_estimates_from_max_tokens_only() {
    // With count_mode = "completion_tokens" the pre-reservation estimate comes
    // solely from the requested completion budget (max_tokens family), not the
    // prompt text. A large max_tokens that exceeds the limit must deny up front.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100,
            "window_seconds": 60,
            "count_mode": "completion_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Tiny prompt but a max_tokens of 500 > limit 100 → deny on reservation.
    let mut ctx = ai_request_ctx(500, "hi");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn completion_count_mode_uses_max_output_tokens_field() {
    // `requested_completion_tokens` takes the max across max_tokens /
    // max_completion_tokens / max_output_tokens. A request using only
    // max_output_tokens must still produce a non-zero reservation.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "count_mode": "completion_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "input": "anything",
            "max_output_tokens": 250
        }))
        .unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        250,
        "completion_tokens mode reserves max_output_tokens"
    );
}

// Build a POST JSON request whose ONLY recognized prompt field is a single
// `prompt` string, so the estimated prompt-character count is exactly the
// string length (no `messages` key/value recursion to reason about).
fn ai_prompt_field_ctx(prompt: &str, max_tokens: u64) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "prompt": prompt,
            "max_tokens": max_tokens
        }))
        .unwrap(),
    );
    ctx
}

#[tokio::test]
async fn prompt_count_mode_estimates_from_prompt_text() {
    // With count_mode = "prompt_tokens" the estimate is derived from prompt
    // character count (chars / 4, rounded up) from the recognized prompt
    // fields, ignoring the max_tokens completion budget. Exercises
    // `estimate_prompt_tokens` / `prompt_character_count` `prompt` branch.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // 40-char prompt -> ceil(40/4) = 10 prompt tokens. max_tokens is present
    // but must be ignored in prompt_tokens mode.
    let prompt = "0123456789012345678901234567890123456789"; // 40 chars
    let mut ctx = ai_prompt_field_ctx(prompt, 900);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        10,
        "prompt_tokens mode estimates from prompt chars only"
    );
}

#[tokio::test]
async fn total_count_mode_sums_prompt_and_completion() {
    // Default total_tokens mode sums the prompt estimate and the requested
    // completion budget. Covers the `_ =>` arm of
    // `estimate_request_tokens_from_json`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // 40-char prompt -> 10 prompt tokens; max_tokens 64 completion.
    let prompt = "0123456789012345678901234567890123456789"; // 40 chars
    let mut ctx = ai_prompt_field_ctx(prompt, 64);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        74,
        "total mode sums prompt (10) + completion (64)"
    );
}

#[tokio::test]
async fn prompt_estimate_covers_system_prompt_input_and_tools_fields() {
    // `prompt_character_count` accumulates across system / messages / prompt /
    // input / contents / tools fields. Use prompt_tokens mode and a body that
    // exercises the `system`, `prompt`, `input`, `contents`, and `tools`
    // branches together so their character counts sum into the reservation.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // 4 chars in each of system/prompt/input/contents + 4 chars inside tools
    // = 20 chars total -> ceil(20/4) = 5 tokens.
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "system": "0123",
            "prompt": "4567",
            "input": "89ab",
            "contents": "cdef",
            "tools": [{"name": "ghij"}]
        }))
        .unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        5,
        "prompt estimate must sum system+prompt+input+contents+tools chars"
    );
}

#[tokio::test]
async fn prompt_estimate_falls_back_to_whole_body_when_no_known_fields() {
    // When none of the recognized prompt fields are present,
    // `prompt_character_count` falls back to counting the whole JSON body's
    // string values (minus the max_* keys). Covers the fallback branch.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // No system/messages/prompt/input/contents/tools — only an unrelated string
    // field. The fallback counts its 8 chars -> ceil(8/4) = 2 tokens.
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"description": "01234567"})).unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        2,
        "estimate falls back to counting the whole body's string values"
    );
}

#[tokio::test]
async fn large_base64_image_does_not_falsely_deny_vision_request() {
    // claude #1 / codex multimodal finding: a base64 image embedded in an OpenAI
    // vision request (`image_url.url` = data URL) must NOT be counted as prompt
    // characters. Previously a ~1 MB image (~1.37 M base64 chars ≈ 340k "tokens")
    // would deny the request with a 429 *before* it was proxied — and a pre-proxy
    // reject never reconciles, so the bogus estimate would never be corrected.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // ~1.4 MB of base64 payload — vastly larger than the 10k token budget if it
    // were (wrongly) counted as text.
    let huge_b64 = "A".repeat(1_400_000);
    let data_url = format!("data:image/jpeg;base64,{huge_b64}");

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "model": "gpt-4o",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {"type": "image_url", "image_url": {"url": data_url}}
                ]
            }]
        }))
        .unwrap(),
    );

    let mut headers = HashMap::new();
    // Must NOT be denied: the 1.4 MB base64 payload is excluded, so the estimate
    // stays a tiny function of the surrounding text/marker strings — far below
    // the 10k budget. (Asserting a bounded estimate rather than an exact count
    // keeps the test robust to how key/value strings around the image are
    // tallied; the point is that base64 bytes do not enter the estimate.)
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(
        reserved > 0 && reserved < 100,
        "base64 image bytes must be excluded; estimate was {reserved}, expected a small text-only count"
    );
}

#[tokio::test]
async fn anthropic_base64_image_source_excluded_from_estimate() {
    // Anthropic vision shape: a content part `{"type":"image","source":{"type":
    // "base64","data":"..."}}`. The `source` subtree (and the base64 `data`)
    // must be skipped so it can't inflate the estimate.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let huge_b64 = "Z".repeat(900_000);

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "model": "claude-3-5-sonnet",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "abcd"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": huge_b64}}
                ]
            }]
        }))
        .unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(
        reserved > 0 && reserved < 100,
        "Anthropic base64 image source must be excluded; estimate was {reserved}"
    );
}

#[tokio::test]
async fn inline_data_url_in_text_field_excluded_from_estimate() {
    // Defense-in-depth: even a `data:` URL embedded directly in a text-bearing
    // field (not under a known binary key) must count as zero, since it is an
    // inline binary blob rather than prose.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let data_url = format!("data:image/png;base64,{}", "Q".repeat(500_000));

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({ "prompt": data_url })).unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "a bare data: URL in a text field must not be counted as prompt characters"
    );
}

#[tokio::test]
async fn no_request_body_metadata_skips_reservation() {
    // `estimate_request_tokens` returns 0 when there is no buffered
    // `request_body`, so `before_proxy` falls back to the legacy CheckBudget
    // path and records no reservation. Covers the early-return guard.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "no request_body metadata means no pre-reservation"
    );
}

#[tokio::test]
async fn invalid_request_body_json_skips_reservation() {
    // A non-JSON `request_body` makes `estimate_request_tokens` return 0 (the
    // `serde_json::from_str` failure branch), so no reservation is taken.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid json {".to_string());

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "invalid request body JSON means no pre-reservation"
    );
}

#[tokio::test]
async fn buffers_request_body_for_json_post_only() {
    // `should_buffer_request_body` must be true for a JSON POST (so the body is
    // available for estimation) and false otherwise. Covers the predicate.
    let plugin =
        AiRateLimiter::new(&json!({"token_limit": 1000}), PluginHttpClient::default()).unwrap();

    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.should_buffer_request_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_request_body(&ctx_with_content_type(
        "POST",
        "application/json; charset=utf-8"
    )));
    assert!(!plugin.should_buffer_request_body(&ctx_with_content_type("GET", "application/json")));
    assert!(!plugin.should_buffer_request_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(!plugin.should_buffer_request_body(&ctx_without_content_type("POST")));
}

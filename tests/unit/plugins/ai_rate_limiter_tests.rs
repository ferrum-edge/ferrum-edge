//! Tests for ai_rate_limiter plugin

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, ai_rate_limiter::AiRateLimiter,
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
    assert!(plugin.requires_response_body_buffering());
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

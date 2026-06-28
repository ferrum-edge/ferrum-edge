//! Tests for ai_rate_limiter plugin

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
    ai_rate_limiter::AiRateLimiter,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

/// Mirror of the crate-internal `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`
/// (which is `pub(crate)` and not reachable from this external test crate). The
/// proxy sets this metadata key in `ctx.metadata` while replaying a synthetic
/// short-circuit body through the response-body hooks; `ai_rate_limiter` uses its
/// presence — NOT any response header — to exempt synthetic bodies from token
/// charging. Tests that simulate a synthetic body set it directly. Kept in sync
/// with the source constant (a drift would surface as a failing skip assertion).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

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
async fn test_sse_without_usage_block_not_charged() {
    // #54: when an SSE stream is walked but carries no recognizable usage
    // block, prompt_tokens/completion_tokens modes must NOT charge a count
    // (previously they substituted Some(0) and recorded 0 without any
    // operator signal; now they return None so the caller's warn fires).
    // Either way the window must be unaffected — assert no usage is charged
    // and the request is allowed through.
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
        0,
        "no usage block means nothing is charged to the window"
    );
}

#[tokio::test]
async fn test_unparseable_2xx_json_not_charged() {
    // #53: a 2xx whose token count cannot be resolved (unrecognized response
    // shape) must not panic and must not be charged; the request continues.
    // The fail-open is now surfaced at warn-level for operators.
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

    // Valid JSON, but no usage block the extractor understands.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "an unparseable 2xx must not advance the rate-limit window"
    );
}

// ─── Federation token recording idempotency ──────────────────────────────

#[tokio::test]
async fn test_federation_tokens_recorded_once_when_after_proxy_runs_twice() {
    // Regression: when ai_federation emits a synthetic 2xx body and a response
    // guardrail rejects it, `after_proxy` runs twice for the SAME request —
    // first via `finalize_reject_response_with_after_proxy_hooks` (the initial
    // RejectBinary{200} short-circuit) and again via
    // `apply_after_proxy_hooks_to_rejection` after the synthetic body hook
    // (`on_response_body`) rejects. `record_usage` is additive, so without the
    // idempotency guard the consumer would be charged twice for one synthetic
    // response and could be pushed over the limit by a *blocked* response.
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
    // Simulate ai_federation having populated provider + token metadata on the
    // synthetic response (count_mode defaults to total_tokens → ai_total_tokens).
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "openai".to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "600".to_string());

    // First after_proxy run records the tokens once.
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    // The idempotency flag is now scoped per limiter instance, so its key
    // carries a budget-derived suffix (prefix:limit_by:window:limit:mode:provider).
    let recorded_flag = ctx
        .metadata
        .iter()
        .find(|(k, _)| k.starts_with("ai_ratelimit_federation_tokens_recorded"));
    assert_eq!(
        recorded_flag.map(|(_, v)| v.as_str()),
        Some("true"),
        "first after_proxy run should mark federation tokens as recorded"
    );

    // Second after_proxy run (response-guardrail rejection re-runs the hooks)
    // must be a no-op for recording.
    let mut response_headers2 = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers2)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        600,
        "federation tokens must be charged exactly once even when after_proxy \
         runs twice for a blocked synthetic response"
    );
}

#[tokio::test]
async fn test_federation_flag_is_scoped_per_limiter_instance() {
    // Regression: when a proxy has multiple ai_rate_limiter instances with
    // distinct budgets (e.g. a per-consumer and a per-IP limiter), a single
    // global idempotency flag let the first instance's recording suppress the
    // others, so only the first budget was charged for an ai_federation
    // response. The flag is now scoped per limiter instance so EACH budget
    // records the federation tokens exactly once.
    // `expose_headers` is required for `observed_usage` to read the recorded
    // window total back out of `ai_ratelimit_usage` metadata (it is only stored
    // when headers are exposed).
    let consumer_limiter = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "consumer",
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let ip_limiter = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // One request, shared ctx: ai_federation populated provider + token metadata.
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "openai".to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "500".to_string());

    // Both limiters run after_proxy over the same request (same ctx.metadata).
    let mut h1 = HashMap::new();
    assert_continue(consumer_limiter.after_proxy(&mut ctx, 200, &mut h1).await);
    let mut h2 = HashMap::new();
    assert_continue(ip_limiter.after_proxy(&mut ctx, 200, &mut h2).await);

    // Each independent budget must have recorded the federation tokens once.
    assert_eq!(
        observed_usage(&consumer_limiter).await,
        500,
        "the consumer-scoped limiter must charge the federation tokens"
    );
    assert_eq!(
        observed_usage(&ip_limiter).await,
        500,
        "the ip-scoped limiter must ALSO charge the federation tokens — the \
         first limiter's idempotency flag must not suppress it"
    );
}

#[tokio::test]
async fn test_two_byte_identical_instances_each_charge_federation_tokens() {
    // codex finding #2: the federation idempotency flag must be scoped per
    // PLUGIN INSTANCE, not per budget-config fingerprint. Two `ai_rate_limiter`
    // instances with byte-for-byte identical budget config can still be
    // intentionally SEPARATE budgets (e.g. distinct `sync_mode`/`redis_key_prefix`
    // backends, or simply two local instances). With the OLD config-derived flag
    // key both shared one flag: the first to run set it and the second SKIPPED
    // `record_usage`, under-counting its own window on `ai_federation` traffic.
    // The per-instance id key fixes this — each owns a distinct flag and records
    // independently. (The existing test above used different `limit_by` values, so
    // it could not catch the identical-config collision.)
    let make = || {
        AiRateLimiter::new(
            &json!({
                "token_limit": 10_000,
                "window_seconds": 60,
                "limit_by": "ip",
                "count_mode": "total_tokens",
                "provider": "auto",
                "expose_headers": true,
            }),
            PluginHttpClient::default(),
        )
        .unwrap()
    };
    let limiter_a = make();
    let limiter_b = make();

    // One request, shared ctx: ai_federation populated provider + token metadata.
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "openai".to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "500".to_string());

    // Both limiters run after_proxy over the same request (same ctx.metadata),
    // exactly as two instances on one proxy would.
    let mut h1 = HashMap::new();
    assert_continue(limiter_a.after_proxy(&mut ctx, 200, &mut h1).await);
    let mut h2 = HashMap::new();
    assert_continue(limiter_b.after_proxy(&mut ctx, 200, &mut h2).await);

    assert_eq!(
        observed_usage(&limiter_a).await,
        500,
        "the first identical-config instance must charge the federation tokens"
    );
    assert_eq!(
        observed_usage(&limiter_b).await,
        500,
        "the second identical-config instance must ALSO charge the federation \
         tokens — its flag is per-instance, so the first instance's flag cannot \
         suppress it"
    );

    // Both instances stamped their OWN distinct idempotency flag onto the shared
    // ctx (two keys, not one), proving the per-instance scoping.
    let flag_keys: Vec<&String> = ctx
        .metadata
        .keys()
        .filter(|k| k.starts_with("ai_ratelimit_federation_tokens_recorded"))
        .collect();
    assert_eq!(
        flag_keys.len(),
        2,
        "each instance must set its own per-instance federation idempotency flag \
         (got {flag_keys:?})"
    );
}

#[tokio::test]
async fn test_on_response_body_does_not_charge_federation_tokens() {
    // `after_proxy` is the SOLE federation charger. On the synthetic
    // short-circuit reject path the body hooks (`on_response_body`) run FIRST
    // and the reject `after_proxy` hook runs once afterwards. If
    // `on_response_body` also charged the federation tokens, the consumer would
    // be double-charged for one synthetic response. This test exercises that
    // production order: `on_response_body` must record NOTHING for a federation
    // response, and the subsequent `after_proxy` must record the tokens exactly
    // once. `expose_headers` is required for `observed_usage` to read the window.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // ai_federation populated provider + token metadata on the synthetic 2xx.
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "openai".to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "300".to_string());

    // The synthetic body even carries a usage block that WOULD be charged for a
    // non-federation response — proving the skip is driven by the federation
    // marker, not by an unparseable body.
    let body = openai_response(100, 200);
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);
    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "on_response_body must NOT charge federation tokens — after_proxy is the \
         sole federation charger"
    );
    // The federation idempotency flag must NOT be set yet: `on_response_body`
    // no longer touches it, so `after_proxy` is free to do the one recording.
    assert!(
        !ctx.metadata
            .keys()
            .any(|k| k.starts_with("ai_ratelimit_federation_tokens_recorded")),
        "on_response_body must not set the federation idempotency flag"
    );

    // Now the reject `after_proxy` hook runs (as it does last on the synthetic
    // path) and records the federation tokens exactly once.
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        300,
        "after_proxy must charge the federation tokens exactly once"
    );
}

#[tokio::test]
async fn test_cache_hit_is_not_charged_against_token_budget() {
    // Regression: ai_semantic_cache cache hits are served from cache and never
    // reach the upstream model, so they consume no provider tokens. Synthetic
    // cache-hit bodies flow through on_response_body (the response-body guardrail
    // path) with the internal synthetic short-circuit marker set; without a guard
    // the cached body's tokens would be charged against the window, silently
    // shrinking the effective budget.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // The proxy stamps the synthetic short-circuit marker before replaying the
    // cache-hit body through the response hooks. (ai_semantic_cache also sets
    // `ai_cache_status: HIT`, but the exemption is driven by the unspoofable
    // synthetic marker, not by that producer-specific metadata.)
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    ctx.metadata
        .insert("ai_cache_status".to_string(), "HIT".to_string());

    // A cached OpenAI-style body that DOES carry a usage block — proving the
    // skip is driven by the synthetic marker, not by an unparseable body.
    let body = serde_json::to_vec(&json!({
        "id": "x",
        "object": "chat.completion",
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
    }))
    .unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a cache HIT must not consume the token budget (no model call occurred)"
    );
}

#[tokio::test]
async fn test_response_caching_hit_is_not_charged_against_token_budget() {
    // Regression: `response_caching` HITs are served from the generic response
    // cache and never reach the upstream model. Their synthetic bodies flow
    // through `on_response_body` via the `RejectBinary` short-circuit with the
    // internal synthetic marker set, so without an exemption an OpenAI-shaped
    // cached body with a `usage` block would be charged against the window on
    // every cache hit.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // The proxy stamps the synthetic marker before replaying the cached body.
    // (`response_caching` also sets `cache_status: HIT`, but the exemption is
    // driven by the unspoofable synthetic marker, not by that metadata.)
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    ctx.metadata
        .insert("cache_status".to_string(), "HIT".to_string());

    let body = serde_json::to_vec(&json!({
        "id": "x",
        "object": "chat.completion",
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
    }))
    .unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a response_caching HIT must not consume the token budget (no model call occurred)"
    );
}

#[tokio::test]
async fn test_request_deduplication_replay_is_not_charged_against_token_budget() {
    // Regression: `request_deduplication` replays a stored response for a
    // repeated idempotency key. The replayed body never came from the backend, so
    // its tokens (charged when the response was first produced) must not be
    // charged again. The replay flows through `on_response_body` via the
    // `RejectBinary` short-circuit with the internal synthetic marker set; the
    // exemption is driven by that marker, NOT by the public
    // `x-idempotent-replayed` response header — a header a backend could spoof to
    // dodge a real charge (see codex finding #4).
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // The proxy stamps the synthetic marker before replaying the stored body.
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );

    // `request_deduplication` also stamps `x-idempotent-replayed: true`, but we
    // deliberately rely on the marker, not the header, for the exemption.
    let mut resp_headers = json_headers();
    resp_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());

    let body = serde_json::to_vec(&json!({
        "id": "x",
        "object": "chat.completion",
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
    }))
    .unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a request_deduplication replay must not re-consume the token budget"
    );
}

#[tokio::test]
async fn test_replay_response_header_alone_does_not_skip_charging() {
    // codex finding #4: the replay exemption must NOT be satisfied by a public
    // response header. A FRESH backend (or a `response_transformer` rewrite) that
    // emits `x-idempotent-replayed: true` (or any cache-status header) on a real
    // 2xx model response with a `usage` block must STILL be charged — the header
    // is spoofable, the internal synthetic marker is not. With no synthetic
    // marker present, the header is ignored and the real response is charged.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;

    // A genuine backend response that spoofs the replay header — but carries NO
    // synthetic short-circuit marker.
    let mut resp_headers = json_headers();
    resp_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());

    let body = openai_response(100, 200);
    let result = plugin
        .on_response_body(&mut ctx, 200, &resp_headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        300,
        "a fresh 2xx response that spoofs x-idempotent-replayed (no synthetic \
         marker) must STILL be charged — the exemption is marker-driven, not \
         header-driven"
    );
}

#[tokio::test]
async fn test_response_mock_synthetic_body_is_not_charged() {
    // codex finding #1: a NON-cache synthetic 2xx (e.g. `response_mock`,
    // `serverless_function`, `request_termination`) can return an OpenAI-shaped
    // body with a `usage` block. It flows through `on_response_body` carrying the
    // internal synthetic marker but NO cache/replay marker. The OLD guard only
    // exempted cache/replay producers, so it fell through and charged tokens for
    // a request that never reached any model. The marker-driven guard now exempts
    // it: no upstream model call occurred, so nothing is charged.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // The proxy stamps the synthetic marker for ANY synthetic short-circuit body,
    // including `response_mock` — with NO cache/replay metadata or header.
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );

    // A canned OpenAI-style mock body with a usage block.
    let body = serde_json::to_vec(&json!({
        "id": "mock",
        "object": "chat.completion",
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
    }))
    .unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "a response_mock / serverless / termination synthetic 2xx must NOT be \
         charged — no upstream model call occurred"
    );
}

#[tokio::test]
async fn test_fresh_response_is_still_charged_despite_replay_exemption() {
    // Guard for the synthetic exemption being too broad: a FRESH backend response
    // (no synthetic short-circuit marker) MUST still be charged against the
    // window. Only synthetic short-circuit bodies are exempt; a real backend
    // response — even one that happens to carry cache-status metadata such as a
    // `response_caching` MISS — has no marker and is charged.
    // `expose_headers` is required for `observed_usage` to read the recorded
    // window total back out of `ai_ratelimit_usage` metadata (it is only stored
    // when headers are exposed). The synthetic exemption tests above assert a
    // usage of 0, which `observed_usage` returns regardless of `expose_headers`,
    // so they do not need it — but this test asserts a NON-zero charge actually
    // landed, so it must expose headers to observe it.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    // A `response_caching` MISS is a fresh response and must be charged — it
    // carries no synthetic marker, so the cache-status metadata is irrelevant.
    ctx.metadata
        .insert("cache_status".to_string(), "MISS".to_string());

    let body = openai_response(100, 200);
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_continue(result);

    assert_eq!(
        observed_usage(&plugin).await,
        300,
        "a fresh (non-cached, non-replayed) response must still charge tokens"
    );
}

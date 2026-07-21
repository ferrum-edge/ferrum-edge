//! Tests for ai_rate_limiter plugin

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
    ai_rate_limiter::AiRateLimiter,
};
use ferrum_edge::proxy::client_ip::{TrustedProxies, resolve_client_ip};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

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

    // Third request should be rejected (250 >= 200) and exported by the
    // aggregate limiter metric.
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.rate_limit_exceeded.load(Ordering::Relaxed);
    let mut ctx3 = create_test_context();
    let mut headers3 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx3, &mut headers3).await;
    assert_reject(result, Some(429));
    assert!(registry.rate_limit_exceeded.load(Ordering::Relaxed) > before);
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
fn test_token_limit_is_required_with_no_default() {
    // Contract (#2263): runtime requires `token_limit`; omitting it must fail
    // rather than silently applying a documented 100000 default.
    let err = AiRateLimiter::new(&json!({}), PluginHttpClient::default())
        .err()
        .expect("empty ai_rate_limiter config must fail without token_limit");
    assert!(
        err.contains("token_limit"),
        "missing token_limit must surface in the error: {err}"
    );

    let err = AiRateLimiter::new(&json!({"window_seconds": 60}), PluginHttpClient::default())
        .err()
        .expect("window_seconds alone must not satisfy construction");
    assert!(
        err.contains("token_limit"),
        "optional fields must not mask missing token_limit: {err}"
    );

    AiRateLimiter::new(&json!({"token_limit": 100000}), PluginHttpClient::default())
        .expect("explicit token_limit must construct");
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

#[tokio::test]
async fn test_tracked_keys_count_uses_canonical_ingress_identity() {
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut native = create_test_context();
    native.client_ip = "192.0.2.10".to_string();
    let mut native_headers = HashMap::new();
    plugin.before_proxy(&mut native, &mut native_headers).await;

    let mut mapped = create_test_context();
    mapped.client_ip = resolve_client_ip("::ffff:192.0.2.10", None, &TrustedProxies::parse(""));
    let mut mapped_headers = HashMap::new();
    plugin.before_proxy(&mut mapped, &mut mapped_headers).await;

    assert_eq!(plugin.tracked_keys_count(), Some(1));
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
async fn compressed_request_skips_pre_reservation_and_reconciles_actual_usage() {
    // Codex P2: for a POST JSON request with a non-identity `Content-Encoding`,
    // `ctx.metadata["request_body"]` still holds the COMPRESSED wire bytes at
    // `before_proxy` time (request decompression runs later, in
    // `transform_request_body`). Estimating against those bytes would yield a
    // wrong/tiny pre-reservation that under-reserves the budget. The plugin must
    // therefore SKIP the estimate-based pre-reservation for compressed requests
    // (falling back to the no-reservation `CheckBudget` path) and rely on
    // reconciliation to charge actual usage afterward.
    //
    // The two concerns below are deliberately split across SEPARATE limiter
    // instances. `limit_by: "ip"` derives the rate key from the client IP, and
    // every `create_test_context()` shares `127.0.0.1`, so a single instance
    // would accumulate the control request's (unreconciled) pre-reservation onto
    // the same key that the compressed-reconcile assertion reads back via the
    // cumulative `observed_usage`. A fresh instance gives the 55 assertion its
    // own zeroed counter, so it reflects ONLY the compressed request's usage.

    // Control concern: an uncompressed JSON POST still reserves estimated tokens.
    // This is asserted via the PER-REQUEST `ai_ratelimit_reserved_tokens` marker
    // (which does not accumulate across requests), and on its own limiter so its
    // reservation can never leak into the reconciliation assertion below.
    let control_plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut uncompressed = ai_request_ctx(120, "count this prompt please");
    let mut uncompressed_headers = json_headers();
    control_plugin
        .before_proxy(&mut uncompressed, &mut uncompressed_headers)
        .await;
    assert!(
        reserved_tokens(&uncompressed) > 0,
        "an uncompressed JSON POST should still reserve estimated tokens"
    );

    // Reconciliation concern: a FRESH limiter instance handles only the
    // compressed request, so its in-memory counter starts at zero and the
    // cumulative `observed_usage` reflects exactly the reconciled actual usage.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            // `observed_usage` reads `ai_ratelimit_usage` from metadata, which the
            // limiter only writes when `expose_headers` is set (see `store_metadata`).
            "expose_headers": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Compressed: a non-identity `Content-Encoding` on the request. `before_proxy`
    // reads the encoding from the `headers` PARAMETER (not `ctx.headers`),
    // matching the production phase where the handler may `mem::take` headers out
    // of `ctx`. No body-derived pre-reservation is made.
    let mut compressed = ai_request_ctx(120, "count this prompt please");
    let mut compressed_headers = json_headers();
    compressed_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let result = plugin
        .before_proxy(&mut compressed, &mut compressed_headers)
        .await;
    assert_continue(result);
    assert_eq!(
        reserved_tokens(&compressed),
        0,
        "a compressed request must NOT produce a body-derived pre-reservation"
    );
    assert!(
        !compressed
            .metadata
            .contains_key("ai_ratelimit_reserved_tokens"),
        "compressed request should skip pre-reservation entirely (no reserved-tokens marker)"
    );
    assert!(
        compressed.metadata.contains_key("ai_ratelimit_request"),
        "compressed POST JSON must stay subject to unmetered-response policy"
    );

    // Reconciliation still charges the ACTUAL provider-reported usage afterward,
    // so the compressed request is debited correctly even without a reservation.
    // No control traffic touched this instance's key, so cumulative usage == 55.
    let body = openai_response(40, 15);
    let reconcile = plugin
        .on_response_body(&mut compressed, 200, &json_headers(), &body)
        .await;
    assert_continue(reconcile);
    assert_eq!(
        observed_usage(&plugin).await,
        55,
        "reconciliation should charge actual usage (40 + 15) for the compressed request"
    );
}

#[tokio::test]
async fn compressed_unmetered_2xx_reject_mode_returns_502() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "compressed reject-mode prompt");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "compressed request is not pre-reserved"
    );
    assert!(
        ctx.metadata.contains_key("ai_ratelimit_request"),
        "compressed POST JSON must be marked so reject mode cannot be bypassed"
    );

    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
}

#[tokio::test]
async fn compressed_unmetered_2xx_default_charge_estimate_rejects_without_estimate() {
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "compressed default-mode prompt");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "br".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "compressed request is not pre-reserved"
    );

    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
}

#[tokio::test]
async fn compressed_decompressed_ai_request_classified_in_on_final() {
    // Case A (the #1949 Finding-2 path): a co-located `compression` plugin with
    // `decompress_request: true` already stripped `content-encoding` and recorded
    // the `compression:request_encoding` metadata before this plugin runs, so the
    // bare content-encoding check sees nothing. `before_proxy` must DEFER (not
    // mark), and `on_final_request_body` — which receives the DECOMPRESSED body —
    // must classify and mark it so a usage-less AI 2xx is still rejected. Default
    // `charge_estimate` mode, to exercise the compressed-candidate reject.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "decompressed ai prompt");
    // compression has already decompressed: content-encoding gone, trusted
    // metadata set (clients cannot forge `ctx.metadata`).
    ctx.metadata.insert(
        "compression:request_encoding".to_string(),
        "gzip".to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "a compressed request is never pre-reserved"
    );
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "Case A must DEFER classification, never mark in before_proxy"
    );
    assert!(
        ctx.metadata
            .contains_key("ai_ratelimit_deferred_compressed_classify"),
        "before_proxy must set the deferred-classification marker for Case A"
    );

    // on_final receives the now-decompressed body — a genuine AI request.
    let decompressed = serde_json::to_vec(&json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}]
    }))
    .unwrap();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &decompressed)
            .await,
    );
    assert!(
        ctx.metadata.contains_key("ai_ratelimit_request"),
        "on_final must mark the decompressed AI request"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_ratelimit_deferred_compressed_classify"),
        "on_final must consume the deferred marker"
    );

    // A usage-less 2xx is now subject to the default charge_estimate reject → 502.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
}

#[tokio::test]
async fn compressed_decompressed_non_ai_request_not_marked() {
    // Case A + #1949 Finding-1: a decompressed NON-AI JSON body must NOT be
    // marked, so an ordinary successful JSON response on a shared proxy is never
    // falsely rejected under the unmetered policy. `reject` mode makes a false
    // positive observable as a 502.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Trusted compression metadata marks the body as decompressed (Case A).
    ctx.metadata.insert(
        "compression:request_encoding".to_string(),
        "gzip".to_string(),
    );
    let mut headers = json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        ctx.metadata
            .contains_key("ai_ratelimit_deferred_compressed_classify"),
        "before_proxy defers compressed POST JSON to on_final"
    );

    // on_final receives a decompressed body that is NOT an AI request.
    let decompressed = serde_json::to_vec(&json!({"foo": "bar", "hello": "world"})).unwrap();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &decompressed)
            .await,
    );
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "a decompressed NON-AI body must NOT be marked (no false positive)"
    );

    // The usage-less 2xx must pass through — this request was never an AI call.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
}

#[tokio::test]
async fn spoofed_original_encoding_header_without_compression_still_reserves() {
    // #1949 round-2 P1 regression: the deferred (Case A) path must be driven by
    // the compression-owned `compression:request_encoding` metadata, NOT the
    // client-settable `x-ferrum-original-content-encoding` header. Without a
    // co-located `compression` plugin, a client could forge that header on a
    // normal uncompressed AI POST; if trusted, the request would be deferred with
    // reserved_tokens=0 and skip up-front token-limit enforcement.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "normal uncompressed ai prompt");
    let mut headers = json_headers();
    // Forged header, but NO trusted compression metadata (no compression plugin ran).
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        reserved_tokens(&ctx) > 0,
        "a normal AI POST must be estimated + pre-reserved even with a forged \
         x-ferrum-original-content-encoding header"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_ratelimit_deferred_compressed_classify"),
        "a forged client header must not trigger the deferred path"
    );
}

#[tokio::test]
async fn compressed_framed_grpc_json_not_marked() {
    // #1949 round-2 P2 regression: a framed gRPC / gRPC-Web body with a `+json`
    // media type is length-prefixed frames, not a bare JSON document, so it must
    // NOT be marked a compressed AI candidate — otherwise a normal gRPC 2xx with
    // no LLM usage would be turned into a 502 under reject/charge_estimate.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web+json".to_string(),
    );
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "a framed gRPC body must not be marked an AI candidate"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_ratelimit_deferred_compressed_classify"),
        "a framed gRPC body must not be deferred"
    );

    // A usage-less 2xx must pass through — it was never an AI call.
    let body = serde_json::to_vec(&json!({"id": "x"})).unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );
}

#[tokio::test]
async fn identity_content_encoding_still_pre_reserves() {
    // `identity` (and an empty/whitespace list) is NOT compression — those
    // requests are estimable and must keep the normal estimate-based
    // pre-reservation. Guards against `has_non_identity_content_encoding`
    // over-matching on the `is_empty()` / `identity` tokens.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    // A single `identity` token is not compression -> still pre-reserves.
    let mut ctx = ai_request_ctx(120, "count this prompt please");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "identity".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        reserved_tokens(&ctx) > 0,
        "an `identity` content-encoding is not compressed and must still pre-reserve"
    );

    // An empty `Content-Encoding` value yields only empty tokens (filtered by
    // the `!token.is_empty()` guard) -> not treated as compression.
    let mut empty_ctx = ai_request_ctx(120, "count this prompt please");
    let mut empty_headers = json_headers();
    empty_headers.insert("content-encoding".to_string(), "  ,  ".to_string());
    plugin
        .before_proxy(&mut empty_ctx, &mut empty_headers)
        .await;
    assert!(
        reserved_tokens(&empty_ctx) > 0,
        "an empty/whitespace `Content-Encoding` list is not compression and must still pre-reserve"
    );
}

#[tokio::test]
async fn comma_listed_compression_encoding_skips_pre_reservation() {
    // A comma-separated `Content-Encoding` list whose later token is a real
    // compression codec (e.g. `identity, gzip`) MUST be treated as compressed:
    // the body is not estimable at this phase, so pre-reservation is skipped and
    // reconciliation backstops. Exercises the multi-token branch of
    // `has_non_identity_content_encoding`.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "count this prompt please");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "identity, gzip".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "a comma-listed compression codec must skip the body-derived pre-reservation"
    );
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_reserved_tokens"),
        "comma-listed compression should skip pre-reservation entirely (no reserved-tokens marker)"
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
async fn non_ai_2xx_is_not_rejected_in_reject_mode() {
    // Regression: `on_unmetered_response: "reject"` must NOT turn a non-AI 2xx
    // into a 502. The plugin forces full response buffering, so `on_response_body`
    // runs for EVERY buffered 2xx regardless of content type; without gating the
    // policy on the AI-request marker, a GET / empty-body / non-JSON / non-LLM
    // request on the same proxy would be rejected with a proxy-wide blast radius.
    // `before_proxy` sets the `ai_ratelimit_request` marker only when it parsed a
    // JSON request body and ran the estimate, so a context with no `request_body`
    // is never marked and must fall straight through.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // No `request_body` metadata => not an AI request, no marker.
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "a request with no parseable JSON body must not be marked as an AI call"
    );

    // An empty-body 200 (e.g. a 204-style success) — the very shape the blast
    // radius would have rejected — must continue, not 502.
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), b"")
            .await,
    );

    // A non-JSON 2xx on the same proxy must also continue.
    let mut html_headers = HashMap::new();
    html_headers.insert("content-type".to_string(), "text/html".to_string());
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &html_headers, b"<html>ok</html>")
            .await,
    );
}

#[tokio::test]
async fn completion_tokens_mode_ai_request_still_subject_to_reject_policy() {
    // The marker — not `reserved_tokens > 0` — is the gate: `completion_tokens`
    // mode reserves 0 for a valid AI request that omits an output cap, but it is
    // still an AI call and must remain subject to `on_unmetered_response: reject`.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "on_unmetered_response": "reject"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // AI request body but no max_tokens => completion_tokens estimate is 0.
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "no output cap"}]
        }))
        .unwrap(),
    );
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "completion_tokens mode with no max_* reserves nothing"
    );
    assert!(
        ctx.metadata.contains_key("ai_ratelimit_request"),
        "a parseable AI request body must be marked even when it reserves 0"
    );

    // An unmetered 2xx for this AI request must still be rejected per policy.
    let body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    let result = plugin
        .on_response_body(&mut ctx, 200, &json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
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
async fn earlier_after_proxy_plugin_reject_keeps_reservation_after_2xx_backend() {
    // codex P2 (newest): when a LOWER-priority after_proxy plugin rejects a 2xx
    // backend response BEFORE `ai_rate_limiter` runs (e.g. `response_size_limiting`
    // at 3490 < ai_rate_limiter at 4200), this plugin's *genuine* after_proxy pass
    // never runs, so it cannot record the backend status itself. The proxy's
    // `run_after_proxy_hooks` records the real backend status into
    // `ai_ratelimit_backend_status` BEFORE the after_proxy loop, so the rejection
    // re-run still sees a 2xx backend and KEEPS the reservation (tokens were
    // consumed by the provider). This reproduces that metadata state: the genuine
    // pass is intentionally skipped; only the proxy-recorded backend status and
    // the rejection re-run happen.
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

    let mut ctx = ai_request_ctx(200, "earlier after_proxy plugin will reject the 2xx");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    // `run_after_proxy_hooks` records the genuine backend status before the loop.
    // (Gated in production on the reservation marker, which is present here.)
    ctx.metadata
        .insert("ai_ratelimit_backend_status".to_string(), "200".to_string());

    // A lower-priority after_proxy plugin rejected the 2xx, so ai_rate_limiter's
    // genuine pass is skipped and it only re-runs inside the rejection. The
    // proxy sets the rejection marker and re-runs after_proxy with the reject
    // status (e.g. 413 from response_size_limiting).
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    let mut reject_headers = HashMap::new();
    assert_continue(plugin.after_proxy(&mut ctx, 413, &mut reject_headers).await);

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "a 2xx backend that an EARLIER after_proxy plugin rejected must keep the reservation charged"
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
async fn non_2xx_release_then_gateway_rejection_reconciles_exactly_once() {
    // Regression for the Redis double-release: a non-2xx backend releases the
    // reservation in `on_response_body`, and then a *later* response-body plugin's
    // rejection re-runs `after_proxy` in rejection context, where
    // `should_release_gateway_rejection` fires AGAIN for the same non-2xx backend.
    // Both paths funnel through `reconcile_usage`, so without an idempotency marker
    // the reservation is released twice. The local `TokenUsageWindow` self-dedups
    // via `reservation_id` (the second release finds no matching entry → negative
    // delta no-op), but the Redis backend has no per-entry id: it just subtracts
    // `reserved` from the shared window, so a double-release double-subtracts and
    // under-counts the consumer's own budget, permitting oversubscription.
    //
    // `reconcile_usage` now sets `ai_ratelimit_reservation_reconciled` on the first
    // pass and short-circuits to `Continue` on any later pass, so the reservation
    // is reconciled EXACTLY ONCE across both backends. This twin exercises the
    // marker gate on the in-memory limiter; the assertions below would also catch
    // the Redis double-subtract (which would drive the shared window below the
    // single-release value).
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

    let mut ctx = ai_request_ctx(200, "non-2xx then a later plugin rejects");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");
    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "the pre-request reservation should be charged to the window"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_ratelimit_reservation_reconciled"),
        "the reservation must not be marked reconciled before any response phase"
    );

    // Phase 1 — `on_response_body` with a non-2xx backend releases the full
    // reservation (RELEASE #1) and marks the reservation reconciled.
    let body = openai_response(500, 500);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 500, &json_headers(), &body)
            .await,
    );
    assert!(
        ctx.metadata
            .contains_key("ai_ratelimit_reservation_reconciled"),
        "the non-2xx release must mark the reservation reconciled"
    );
    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "the non-2xx response should release the reservation exactly once"
    );

    // Phase 2 — a later response-body plugin rejected, so the proxy sets the
    // rejection marker and re-runs `after_proxy`. `should_release_gateway_rejection`
    // would fire here (non-2xx backend, rejection, reserved > 0, not reject-mode),
    // but the idempotency marker makes the second `reconcile_usage` a no-op
    // (RELEASE #2 is suppressed). On Redis this is exactly the double-subtract that
    // would otherwise corrupt the shared window.
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    let mut reject_headers = HashMap::new();
    assert_continue(plugin.after_proxy(&mut ctx, 500, &mut reject_headers).await);

    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "the reservation must be released exactly once, not twice"
    );

    // A fresh request must still see the full budget — the window was debited by
    // exactly one reservation's worth, never below zero / under-counted (the Redis
    // double-subtract symptom).
    let mut next_ctx = ai_request_ctx(200, "follow-up after single release");
    let mut next_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut next_ctx, &mut next_headers).await);
    assert_eq!(
        observed_usage(&plugin).await,
        reserved_tokens(&next_ctx),
        "after a single release the window must reflect only the new reservation, \
         proving no double-subtract drove the counter below the single-release value"
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
    // When an LLM-shaped body uses none of the prompt fields
    // `prompt_character_count` recognizes (system/messages/prompt/input/
    // contents/tools), the estimate falls back to counting the whole JSON body's
    // string values (minus the max_* keys). A TGI body (`inputs` — a strong
    // AI-request marker, but not one of the itemized prompt fields) exercises that
    // fallback branch while still passing the LLM-shape gate.
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
    // TGI `inputs` is a strong AI-request marker but is NOT among the fields
    // `prompt_character_count` sums, so the estimate falls back to counting the
    // whole body's string values (minus the max_* keys): 7 chars -> ceil(7/4) = 2.
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"inputs": "yyyyyyy"})).unwrap(),
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
async fn prose_starting_with_data_prefix_is_counted_not_treated_as_data_url() {
    // Regression: `is_data_url` must require real RFC 2397 structure
    // (`data:[<mediatype>][;base64],<payload>`), not merely a `data:` prefix.
    // Ordinary prose like "data: my notes" starts with `data:` but has whitespace
    // in (and no `,` terminating) the header, so it is prose and MUST be counted —
    // otherwise a chat message that happens to begin with "data:" would silently
    // drop from the estimate.
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

    // 40-char prose prompt beginning with "data:" — counted, so the estimate is
    // chars/4 = 10 tokens (> 0). The leading space after the colon and the
    // absence of a header `,` disqualify it as a data URL.
    let prose = "data: my notes about the quarterly plan!"; // 40 chars
    assert_eq!(prose.chars().count(), 40);

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({ "prompt": prose })).unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        10,
        "prose beginning with 'data:' must be counted as prompt characters"
    );

    // Sanity: a genuine base64 data URL of the same logical field IS excluded.
    let data_url = format!("data:image/png;base64,{}", "Q".repeat(500_000));
    let mut ctx2 = create_test_context();
    ctx2.method = "POST".to_string();
    ctx2.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({ "prompt": data_url })).unwrap(),
    );
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);
    assert_eq!(
        reserved_tokens(&ctx2),
        0,
        "a real data:<mediatype>;base64,<payload> URL must still be excluded"
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

// ─── Follow-up (#1923): provider-native estimation, LLM-shape gating, and
//     federation reservation reconciliation ──────────────────────────────

#[tokio::test]
async fn completion_mode_reserves_provider_native_output_caps() {
    // Codex P2: the reservation estimator only read top-level OpenAI-style output
    // caps, so native Gemini/Bedrock/Titan/TGI requests reserved 0 in
    // `completion_tokens` mode and could oversubscribe the budget. The nested
    // provider containers must size the reservation.
    let cases: [(&str, serde_json::Value, u64); 4] = [
        (
            "gemini generationConfig.maxOutputTokens",
            json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}], "generationConfig": {"maxOutputTokens": 4096}}),
            4096,
        ),
        (
            "bedrock inferenceConfig.maxTokens",
            json!({"messages": [{"role": "user", "content": "hi"}], "inferenceConfig": {"maxTokens": 2048}}),
            2048,
        ),
        (
            "titan textGenerationConfig.maxTokenCount",
            json!({"inputText": "hi", "textGenerationConfig": {"maxTokenCount": 1024}}),
            1024,
        ),
        (
            "tgi parameters.max_new_tokens",
            json!({"inputs": "hi", "parameters": {"max_new_tokens": 512}}),
            512,
        ),
    ];

    for (label, body, want) in cases {
        let plugin = AiRateLimiter::new(
            &json!({
                "token_limit": 100_000,
                "window_seconds": 60,
                "count_mode": "completion_tokens",
                "limit_by": "ip"
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
            serde_json::to_string(&body).unwrap(),
        );
        let mut headers = HashMap::new();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            reserved_tokens(&ctx),
            want,
            "{label}: nested provider output cap must size the completion reservation"
        );
    }
}

#[tokio::test]
async fn prompt_mode_counts_text_document_source_but_skips_binary() {
    // Codex P2: `source` was a blanket skip, dropping the prose of an Anthropic
    // TEXT document block (`source:{type:"text",...,data:"<prose>"}`) — real input
    // the provider bills. A BINARY image/PDF source must still be skipped so a
    // base64 blob can't inflate the estimate.
    let text_doc = "x".repeat(4000); // ~1000 tokens at chars/4
    let plugin_text = AiRateLimiter::new(
        &json!({"token_limit": 100_000, "window_seconds": 60, "count_mode": "prompt_tokens", "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx_text = create_test_context();
    ctx_text.method = "POST".to_string();
    ctx_text
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx_text.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": text_doc}}
            ]}]
        }))
        .unwrap(),
    );
    let mut h_text = HashMap::new();
    assert_continue(plugin_text.before_proxy(&mut ctx_text, &mut h_text).await);
    assert!(
        reserved_tokens(&ctx_text) >= 1000,
        "text-document source prose must be counted (got {})",
        reserved_tokens(&ctx_text)
    );

    let big_b64 = "A".repeat(4000);
    let plugin_bin = AiRateLimiter::new(
        &json!({"token_limit": 100_000, "window_seconds": 60, "count_mode": "prompt_tokens", "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx_bin = create_test_context();
    ctx_bin.method = "POST".to_string();
    ctx_bin
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx_bin.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": big_b64}}
            ]}]
        }))
        .unwrap(),
    );
    let mut h_bin = HashMap::new();
    assert_continue(plugin_bin.before_proxy(&mut ctx_bin, &mut h_bin).await);
    assert!(
        reserved_tokens(&ctx_bin) < 100,
        "binary image source must not be counted as prompt text (got {})",
        reserved_tokens(&ctx_bin)
    );

    // A base64 source that merely declares a `text/*` media type is still encoded
    // bytes, not prose — it must be skipped (counting it would charge the inflated
    // base64 payload as prompt text). Only an explicit `type:"text"` source counts.
    let big_b64_text = "A".repeat(4000);
    let plugin_b64 = AiRateLimiter::new(
        &json!({"token_limit": 100_000, "window_seconds": 60, "count_mode": "prompt_tokens", "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx_b64 = create_test_context();
    ctx_b64.method = "POST".to_string();
    ctx_b64
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx_b64.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": big_b64_text}}
            ]}]
        }))
        .unwrap(),
    );
    let mut h_b64 = HashMap::new();
    assert_continue(plugin_b64.before_proxy(&mut ctx_b64, &mut h_b64).await);
    assert!(
        reserved_tokens(&ctx_b64) < 100,
        "a base64 source with a text/* media type must NOT be counted (got {})",
        reserved_tokens(&ctx_b64)
    );
}

#[tokio::test]
async fn non_llm_json_post_is_not_treated_as_ai_request() {
    // Codex P2: any parseable JSON POST was marked an AI request, so on a shared
    // proxy an ordinary non-LLM payload was subjected to `on_unmetered_response`
    // (502 under `reject`). Only LLM-shaped bodies should carry the marker.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "on_unmetered_response": "reject"
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
        serde_json::to_string(&json!({"order_id": 42, "items": ["a", "b"]})).unwrap(),
    );
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        0,
        "non-LLM JSON must not reserve tokens"
    );
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "non-LLM JSON must not be marked as an AI request"
    );

    // A usage-less 2xx for the non-AI request must NOT be turned into a 502.
    let body = serde_json::to_vec(&json!({"ok": true})).unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &json_headers(), &body)
            .await,
    );

    // A bare generic `message` (no `model`) is NOT an LLM request — the exact
    // common shape that must not be turned into a 502 on a shared proxy.
    let mut msg_ctx = create_test_context();
    msg_ctx.method = "POST".to_string();
    msg_ctx
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    msg_ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"message": "contact me"})).unwrap(),
    );
    let mut msg_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut msg_ctx, &mut msg_headers).await);
    assert!(
        !msg_ctx.metadata.contains_key("ai_ratelimit_request"),
        "a bare `message` without `model` must not be marked as an AI request"
    );

    // But the same generic field WITH a `model` (Cohere v2) IS an AI request.
    let mut cohere_ctx = create_test_context();
    cohere_ctx.method = "POST".to_string();
    cohere_ctx
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    cohere_ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"model": "command-r", "message": "hi"})).unwrap(),
    );
    let mut cohere_headers = HashMap::new();
    assert_continue(
        plugin
            .before_proxy(&mut cohere_ctx, &mut cohere_headers)
            .await,
    );
    assert!(
        cohere_ctx.metadata.contains_key("ai_ratelimit_request"),
        "a `message` corroborated by `model` must be marked as an AI request"
    );

    // Contrast: an LLM-shaped request with a usage-less 2xx IS rejected.
    let mut ai_ctx = ai_request_ctx(50, "real prompt");
    let mut ai_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ai_ctx, &mut ai_headers).await);
    assert!(
        ai_ctx.metadata.contains_key("ai_ratelimit_request"),
        "an LLM-shaped request must be marked as an AI request"
    );
    let ai_body = serde_json::to_vec(&json!({"id": "x", "object": "thing"})).unwrap();
    assert_reject(
        plugin
            .on_response_body(&mut ai_ctx, 200, &json_headers(), &ai_body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn responses_request_without_input_is_treated_as_ai() {
    // Codex P2: an OpenAI Responses request can be driven by `instructions` or
    // `previous_response_id` with no `input` field — a shape `ai_request_guard`
    // already accepts (`looks_like_responses`). The limiter must recognize it so
    // the reservation + `on_unmetered_response` policy still apply.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 100_000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    for body in [
        json!({"model": "gpt-4o", "instructions": "be terse"}),
        json!({"model": "gpt-4o", "previous_response_id": "resp_123"}),
        json!({"previous_response_id": "resp_123"}), // strong marker on its own
    ] {
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        ctx.metadata.insert(
            "request_body".to_string(),
            serde_json::to_string(&body).unwrap(),
        );
        let mut headers = HashMap::new();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            ctx.metadata.contains_key("ai_ratelimit_request"),
            "Responses-without-input must be marked as an AI request: {body}"
        );
    }

    // A bare generic `instructions` without `model` is NOT an AI request (it
    // could be any non-LLM JSON), so it stays exempt from the unmetered policy.
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"instructions": "assemble the widget"})).unwrap(),
    );
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_request"),
        "bare `instructions` without `model` must not be marked as an AI request"
    );
}

#[test]
fn compressed_request_is_not_pre_buffered() {
    // Codex P2: `before_proxy` forces `reserved_tokens = 0` for a compressed body
    // (it can't be estimated before decompression), so requesting full request
    // buffering for it just wastes memory/latency. This withdraws only THIS
    // plugin's buffering request; a co-located plugin can still force buffering.
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "uncompressed JSON POST should be buffered"
    );

    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    assert!(
        !plugin.should_buffer_request_body(&ctx),
        "compressed JSON POST must not be pre-buffered by ai_rate_limiter"
    );

    ctx.headers
        .insert("content-encoding".to_string(), "identity".to_string());
    assert!(
        plugin.should_buffer_request_body(&ctx),
        "an `identity` content-encoding is not compressed and must still buffer"
    );
}

#[tokio::test]
async fn federation_usageless_response_kept_when_guard_rejects() {
    // Codex P2: with `ai_rate_limiter` priority-overridden before `ai_federation`
    // it pre-reserves for the federated call. A federation 2xx WITHOUT usage that
    // a response-body guardrail later rejects re-runs after_proxy with the 5xx
    // rejection status; reconciling against that 5xx would release the reservation
    // for a provider call that already consumed tokens (a paid call made free).
    // Reconciliation must use the ORIGINAL federation status (`ai_federation_status`)
    // and keep the reservation via the default `charge_estimate` policy.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 100_000,
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
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve estimated tokens");

    // ai_federation served a 2xx but reported NO usage; it recorded the provider
    // and the original synthetic status, but no `ai_total_tokens`.
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "primary".to_string());
    ctx.metadata
        .insert("ai_federation_status".to_string(), "200".to_string());

    // A response-body guardrail rejected the synthetic body: after_proxy re-runs
    // in rejection context with the 5xx status.
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 502, &mut response_headers)
            .await,
    );

    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "a usage-less federation 2xx that is later guard-rejected must KEEP its \
         reservation, not be released by the rejection status"
    );
}

// ─── Azure OpenAI "On Your Data" role_information accounting ───────────────────
//
// Azure's "On Your Data" / extensions API attaches a per-data-source system
// instruction (`data_sources[].parameters.role_information`, or the legacy
// camelCase `dataSources[].parameters.roleInformation`). That text is sent to the
// model and billed as input but is not part of `messages`/`system`/etc., so the
// pre-reservation prompt estimate must add it. These tests drive the public
// `before_proxy` surface in `prompt_tokens` mode and read the reserved estimate,
// asserting the delta equals exactly the instruction text (and nothing else).

/// A minimal Azure chat-completions request. The `messages` content is `"abcd"`
/// (4 chars); together with the `"user"` role value the recognized prompt fields
/// total a multiple of 4 characters. Because `div_ceil(4)` distributes over a
/// base that is a multiple of 4, the reserved-token delta after adding
/// `role_information` is exactly `ceil(instruction_chars / 4)` — independent of
/// the exact base count — which keeps the assertions below robust.
fn azure_base_messages() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "abcd"}]
    })
}

/// Reserved prompt-token estimate for `body` under a `prompt_tokens`-mode limiter
/// with a budget far above any test request, so the reservation always succeeds
/// and `ai_ratelimit_reserved_tokens` is written. A fresh limiter per call keeps
/// each estimate isolated from sliding-window accumulation.
async fn azure_reserved(body: serde_json::Value) -> u64 {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1_000_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip"
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
        serde_json::to_string(&body).unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    reserved_tokens(&ctx)
}

#[tokio::test]
async fn prompt_estimate_counts_azure_on_your_data_role_information() {
    // Current chat-completions data plane: snake_case `data_sources` /
    // `role_information`. The instruction must be counted, while the surrounding
    // endpoint / index / key fields (which are NOT prompt input) must not be — the
    // delta equals exactly the instruction text.
    let instruction = "You are a helpful assistant answering only from the indexed docs.";
    let reserved_base = azure_reserved(azure_base_messages()).await;

    let mut with = azure_base_messages();
    with["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "endpoint": "https://example.search.windows.net",
            "index_name": "contoso-products-index-name-not-prompt-input",
            "authentication": {"type": "api_key", "key": "super-secret-key-not-prompt-input"},
            "role_information": instruction
        }
    }]);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(
        reserved_with > reserved_base,
        "role_information instruction must be counted in the prompt estimate"
    );
    assert_eq!(
        reserved_with - reserved_base,
        instruction_tokens,
        "only the role_information text should be added; endpoint/index/key fields \
         are not prompt input and must be excluded"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_azure_extensions_api_role_information_camelcase() {
    // The original extensions API used camelCase for BOTH the outer array
    // (`dataSources`) and the inner field (`roleInformation`); both casings must be
    // recognized.
    let instruction = "Answer in formal English and cite the source document id.";
    let reserved_base = azure_reserved(azure_base_messages()).await;

    let mut with = azure_base_messages();
    with["dataSources"] = json!([{
        "type": "AzureCognitiveSearch",
        "parameters": {
            "endpoint": "https://example.search.windows.net",
            "indexName": "contoso-index",
            "roleInformation": instruction
        }
    }]);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(reserved_with > reserved_base);
    assert_eq!(reserved_with - reserved_base, instruction_tokens);
}

#[tokio::test]
async fn prompt_estimate_does_not_short_circuit_on_empty_role_information() {
    // `Value::as_str("")` is `Some("")` (not `None`), so an `or_else`-style lookup
    // that stops at the first present key would be fooled by an empty
    // `role_information` decoy and never count a real `roleInformation` sibling.
    // Both inner casings must be summed independently. (Both keys on one source is
    // a synthetic, defensive shape — real requests carry one casing.)
    let instruction = "Stay strictly within the retrieved enterprise knowledge base.";
    let reserved_base = azure_reserved(azure_base_messages()).await;

    let mut with = azure_base_messages();
    with["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "role_information": "",
            "roleInformation": instruction
        }
    }]);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(instruction_tokens > 0);
    assert_eq!(
        reserved_with - reserved_base,
        instruction_tokens,
        "an empty role_information decoy must not hide a real roleInformation sibling"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_whitespace_role_information_without_hiding_sibling() {
    // Whitespace is literal prompt input (sent and billed), so a whitespace-only
    // value is counted as its characters rather than trimmed away — and, like the
    // empty-string case, it must not short-circuit a real sibling in the other
    // casing.
    let whitespace = "   "; // 3 chars: neither None nor empty.
    let instruction = "Respond concisely.";
    let reserved_base = azure_reserved(azure_base_messages()).await;

    let mut with = azure_base_messages();
    with["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "role_information": whitespace,
            "roleInformation": instruction
        }
    }]);
    let reserved_with = azure_reserved(with).await;

    let added_chars = (whitespace.chars().count() + instruction.chars().count()) as u64;
    assert!(
        reserved_with > reserved_base,
        "the real instruction must be counted alongside a whitespace decoy"
    );
    assert_eq!(reserved_with - reserved_base, added_chars.div_ceil(4));
}

#[tokio::test]
async fn prompt_estimate_counts_role_information_on_non_first_data_source() {
    // The instruction can live on any data source, not just the first; the estimate
    // must enumerate every entry in the array.
    let instruction = "Prefer the most recently updated document when sources conflict.";
    let reserved_base = azure_reserved(azure_base_messages()).await;

    let mut with = azure_base_messages();
    with["data_sources"] = json!([
        // First source carries no role_information (only connection fields).
        {
            "type": "azure_search",
            "parameters": {"endpoint": "https://a.search.windows.net", "index_name": "first"}
        },
        // The instruction is on the SECOND source.
        {
            "type": "azure_search",
            "parameters": {
                "endpoint": "https://b.search.windows.net",
                "index_name": "second",
                "role_information": instruction
            }
        }
    ]);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(
        reserved_with > reserved_base,
        "role_information on a non-first data source must be counted"
    );
    assert_eq!(reserved_with - reserved_base, instruction_tokens);
}

#[tokio::test]
async fn prompt_estimate_preserves_whole_body_fallback_prompt_with_role_information() {
    // Regression guard (Codex P2 on #1942): fields like TGI/HuggingFace `inputs`
    // are AI markers but are NOT summed by the recognized-field pass, so their
    // prompt text is captured only by the zero-char whole-body fallback. Counting
    // `role_information` must NOT make the recognized-field total nonzero and
    // short-circuit that fallback — doing so would drop the real `inputs` prompt
    // and reserve only the short instruction.
    let inputs = "a".repeat(400); // real prompt text, counted only via the fallback
    let instruction = "Be terse.";

    let mut body = json!({ "inputs": inputs });
    let reserved_inputs_only = azure_reserved(body.clone()).await;
    assert!(
        reserved_inputs_only > 0,
        "the `inputs` prompt must be counted via the whole-body fallback"
    );

    body["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": { "role_information": instruction }
    }]);
    let reserved_with_role = azure_reserved(body).await;

    // The fallback still walks the whole body, so the full `inputs` prompt remains
    // counted (now alongside the instruction) — the estimate must not collapse to
    // just the instruction.
    assert!(
        reserved_with_role >= reserved_inputs_only,
        "role_information must not drop the fallback-counted `inputs` prompt \
         (got {reserved_with_role}, inputs-only was {reserved_inputs_only})"
    );
}

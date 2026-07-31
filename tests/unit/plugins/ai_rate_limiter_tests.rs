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
    // GHSA-8f27-23x9-f825: the accounting lifecycle is HTTP JSON/SSE only, so
    // the plugin must not advertise (and must not be attachable to) native gRPC.
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let body = openai_response(80, 30);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();
    let body = openai_response(100, 50);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
        .await;

    // Second request passes (150 < 200)
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    // Record another 100 tokens (total now 250)
    let body2 = openai_response(60, 40);
    plugin
        .on_response_body(&mut ctx2, 200, &mut resp_headers, &body2)
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

    let mut resp_headers = json_headers();
    let body = openai_response(80, 30); // 110 tokens
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    // Consumer A uses 150 tokens
    let mut ctx_a = create_test_context();
    ctx_a.identified_consumer = Some(Arc::new(super::plugin_utils::create_test_consumer()));
    let mut headers_a = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;
    let body = openai_response(100, 50);
    plugin
        .on_response_body(&mut ctx_a, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 50 prompt + 500 completion = only 50 counted
    let body = openai_response(50, 500);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 prompt + 50 completion = only 50 counted
    let body = openai_response(500, 50);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = serde_json::to_vec(&json!({
        "usage": {"input_tokens": 80, "output_tokens": 40}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

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
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, b"not json")
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 error with tokens — should NOT count
    let body = openai_response(500, 500);
    plugin
        .on_response_body(&mut ctx, 500, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, b"")
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
    let mut resp_headers = json_headers();

    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = openai_response(0, 0);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    // Record 100 tokens
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let body = openai_response(60, 40);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

    // No consumer set — should use IP as key
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = None;
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let body = openai_response(80, 30);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
    let mut resp_headers = json_headers();

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
        .on_response_body(&mut ctx, 200, &mut resp_headers, b"")
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
            "'sync_mode' must be exactly 'local' or 'redis'",
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, sse)
        .await;

    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    let sse2 = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":300}}\n\n";
    plugin
        .on_response_body(&mut ctx2, 200, &mut resp_headers, sse2)
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, sse)
        .await;

    // 75 tokens recorded — second request fits (75 + 25 ≤ 100), a 26-token
    // follow-up would exceed.
    let mut ctx2 = create_test_context();
    let mut headers2 = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx2, &mut headers2).await);

    let sse2 = b"data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":15,\"output_tokens\":15}}}}\n\n";
    plugin
        .on_response_body(&mut ctx2, 200, &mut resp_headers, sse2)
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body100)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let body50 = openai_response(20, 30);
    plugin
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body50)
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
    let no_trust = TrustedProxies::parse_strict("", "test").expect("empty trust list is valid");
    mapped.client_ip = resolve_client_ip("::ffff:192.0.2.10", None, &no_trust);
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
    // Non-regression for #54: absent selected counters must not be coerced to
    // zero when a usage block IS present. A streamed OpenAI-style response that
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
        .on_response_body(&mut ctx, 200, &mut sse_headers(), sse.as_bytes())
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
        .on_response_body(&mut ctx, 200, &mut sse_headers(), sse.as_bytes())
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut compressed, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), b"")
            .await,
    );

    // A non-JSON 2xx on the same proxy must also continue.
    let mut html_headers = HashMap::new();
    html_headers.insert("content-type".to_string(), "text/html".to_string());
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut html_headers, b"<html>ok</html>")
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 500, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
    // The applied unmetered action is part of this instance's own reservation
    // record, not a shared metadata key, so seed it through the instance.
    plugin.seed_unmetered_action_for_test(&mut ctx, "reject");

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
    // `reconcile_usage` now marks THIS INSTANCE's reservation record settled on
    // the first pass and short-circuits to `Continue` on any later pass, so the
    // reservation is settled EXACTLY ONCE across both backends. The marker is
    // per instance, so a sibling limiter's settlement can no longer suppress
    // this one's (GHSA-wh4p-pmxm-3784). This twin exercises the
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
        !plugin.reservation_settled_for_test(&ctx),
        "the reservation must not be marked settled before any response phase"
    );

    // Phase 1 — `on_response_body` with a non-2xx backend releases the full
    // reservation (RELEASE #1) and marks the reservation reconciled.
    let body = openai_response(500, 500);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 500, &mut json_headers(), &body)
            .await,
    );
    assert!(
        plugin.reservation_settled_for_test(&ctx),
        "the non-2xx release must mark the reservation settled"
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

// ─── Absent-vs-zero usage contract (GHSA-h8m9-8vrh-m626) ───────────────

fn openai_response_without_usage() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{"message": {"content": "hello"}}]
    }))
    .unwrap()
}

async fn assert_fixed_provider_unmetered_rejects(count_mode: &str, body: Vec<u8>, provider: &str) {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": count_mode,
            "provider": provider,
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "fixed-provider absent usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 0, "request should reserve tokens");

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_reject(result, Some(502));
}

#[tokio::test]
async fn fixed_openai_completion_mode_rejects_absent_usage() {
    assert_fixed_provider_unmetered_rejects(
        "completion_tokens",
        openai_response_without_usage(),
        "openai",
    )
    .await;
}

#[tokio::test]
async fn fixed_openai_prompt_mode_rejects_absent_usage() {
    assert_fixed_provider_unmetered_rejects(
        "prompt_tokens",
        openai_response_without_usage(),
        "openai",
    )
    .await;
}

#[tokio::test]
async fn fixed_openai_completion_mode_rejects_empty_usage_object() {
    let body = serde_json::to_vec(&json!({
        "usage": {},
        "choices": [{"message": {"content": "hello"}}]
    }))
    .unwrap();
    assert_fixed_provider_unmetered_rejects("completion_tokens", body, "openai").await;
}

#[tokio::test]
async fn fixed_openai_completion_mode_rejects_missing_selected_counter() {
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 40},
        "choices": [{"message": {"content": "hello"}}]
    }))
    .unwrap();
    assert_fixed_provider_unmetered_rejects("completion_tokens", body, "openai").await;
}

#[tokio::test]
async fn fixed_openai_completion_mode_honors_explicit_zero() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "provider": "openai",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "explicit zero completion");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "request should reserve tokens");

    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 40, "completion_tokens": 0}
    }))
    .unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "explicit zero completion must be treated as metered usage, not unmetered"
    );
}

#[tokio::test]
async fn auto_provider_completion_mode_rejects_absent_usage() {
    assert_fixed_provider_unmetered_rejects(
        "completion_tokens",
        openai_response_without_usage(),
        "auto",
    )
    .await;
}

#[tokio::test]
async fn auto_provider_rejects_missing_selected_counter_after_detection() {
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 40},
        "choices": [{"message": {"content": "hello"}}]
    }))
    .unwrap();
    assert_fixed_provider_unmetered_rejects("completion_tokens", body, "auto").await;
}

#[tokio::test]
async fn fixed_provider_warn_mode_releases_absent_usage() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "provider": "openai",
            "on_unmetered_response": "warn",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "warn absent usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(reserved_tokens(&ctx) > 0);

    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut json_headers(),
                &openai_response_without_usage(),
            )
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        0,
        "warn mode must release the reservation when the selected counter is absent"
    );
}

#[tokio::test]
async fn fixed_provider_charge_estimate_keeps_absent_usage_reservation() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "provider": "openai",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "charge estimate absent usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0);

    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut json_headers(),
                &openai_response_without_usage(),
            )
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        reserved,
        "charge_estimate must keep the reservation when the selected counter is absent"
    );
}

#[tokio::test]
async fn fixed_provider_total_mode_still_charges_explicit_total_usage() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "total_tokens",
            "provider": "openai",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "explicit total usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let body = serde_json::to_vec(&json!({
        "usage": {"total_tokens": 88}
    }))
    .unwrap();
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await,
    );
    assert_eq!(
        observed_usage(&plugin).await,
        88,
        "total_tokens mode must still charge an explicit provider total"
    );
}

#[tokio::test]
async fn fixed_provider_sse_completion_mode_rejects_absent_usage() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "provider": "openai",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(120, "sse absent usage");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
               data: [DONE]\n\n";
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), sse.as_bytes())
        .await;
    assert_reject(result, Some(502));
}

#[tokio::test]
async fn federation_metadata_missing_selected_counter_is_unmetered() {
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "count_mode": "completion_tokens",
            "on_unmetered_response": "reject",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = ai_request_ctx(200, "federated missing completion");
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "primary".to_string());
    ctx.metadata
        .insert("ai_prompt_tokens".to_string(), "30".to_string());

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
// `prompt` string (plus a token-cap field that must stay excluded).
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
    // character count (chars / 4, rounded up) over the prompt value and its
    // member name, ignoring the max_tokens completion budget.
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

    // Member name `prompt` (6) + 40-char value = 46 -> ceil(46/4) = 12.
    // max_tokens is present but must be ignored in prompt_tokens mode.
    let prompt = "0123456789012345678901234567890123456789"; // 40 chars
    let mut ctx = ai_prompt_field_ctx(prompt, 900);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        12,
        "prompt_tokens mode estimates from prompt value + member name"
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

    // Member name `prompt` (6) + 40-char value = 46 -> 12 prompt tokens; max_tokens 64.
    let prompt = "0123456789012345678901234567890123456789"; // 40 chars
    let mut ctx = ai_prompt_field_ctx(prompt, 64);
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        76,
        "total mode sums prompt (12) + completion (64)"
    );
}

#[tokio::test]
async fn prompt_estimate_covers_system_prompt_input_and_tools_fields() {
    // Whole-body prompt walk accumulates string values and object member names
    // under system/prompt/input/contents/tools together into the reservation.
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
    // String values: 4 chars × 5 fields = 20.
    // Member names: system(6)+prompt(6)+input(5)+contents(8)+tools(5)+name(4) = 34.
    // Total 54 chars -> ceil(54/4) = 14 tokens.
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
        14,
        "prompt estimate must sum system+prompt+input+contents+tools values and keys"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_ai_marker_outside_common_prompt_containers() {
    // An LLM-shaped body whose only string text sits under an AI marker that is
    // not a common prompt container (Responses continuation `previous_response_id`)
    // must still reserve via the whole-body walk (value + member name).
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
    // Member name `previous_response_id` (20) + value (7) = 27 -> ceil(27/4) = 7.
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({"previous_response_id": "yyyyyyy"})).unwrap(),
    );

    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        reserved_tokens(&ctx),
        7,
        "estimate must count AI-marker values and their member names"
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
async fn inline_data_url_in_text_field_is_counted() {
    // Path-context fix: a well-formed `data:` URL in an ordinary text-bearing
    // field (not a recognized multimodal leaf) is billed prompt text and must
    // reserve. The pre-09514f4b / shape-only walk counted it as zero.
    // Length 48 (= 0 mod 4) keeps the chars/4 token delta exact vs empty.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 10_000_000,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let data_url = format!("data:text/plain,{}", "X".repeat(32)); // 16+32=48
    assert_eq!(data_url.chars().count(), 48);

    let mut empty_ctx = create_test_context();
    empty_ctx.method = "POST".to_string();
    empty_ctx
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    empty_ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&json!({ "prompt": "" })).unwrap(),
    );
    let mut empty_headers = HashMap::new();
    assert_continue(
        plugin
            .before_proxy(&mut empty_ctx, &mut empty_headers)
            .await,
    );
    let empty_reserved = reserved_tokens(&empty_ctx);

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
    let reserved = reserved_tokens(&ctx);
    assert_eq!(
        reserved - empty_reserved,
        12,
        "48-char data:text/plain literal in prompt must reserve ceil(48/4)=12"
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

    // Member name `prompt` (6) + 40-char prose = 46 -> ceil(46/4) = 12 tokens.
    // The leading space after the colon and the absence of a header `,`
    // disqualify it as a data URL.
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
        12,
        "prose beginning with 'data:' must be counted as prompt characters"
    );
}

// ─── Fail-closed whole-body prompt reservation (GHSA-2r5g-438w-85hr) ──────────
//
// Pre-dispatch estimation walks billable string values, visited object member
// names, and JSON scalar literals once so a present recognized field cannot
// suppress unknown (or known) billed siblings, tool/function schema property
// names cannot be omitted, and coincidental reserved spellings (`max_tokens`,
// `image_url`, `source`, …) cannot hide schema prose. Exclusions are
// path/context aware (exact token-cap paths; multimodal leaves inside
// recognized content blocks only). Exact token deltas isolate value or
// member-name text by keeping the compared key structure identical in the
// baseline (empty string / empty property name). These tests drive the public
// `before_proxy` surface in `prompt_tokens` mode.

/// Reserved prompt-token estimate for `body` under an isolated
/// `prompt_tokens`-mode limiter with a budget far above any test request.
async fn prompt_tokens_reserved(body: serde_json::Value) -> u64 {
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

/// 32-character billed text keeps `div_ceil(4)` deltas exact regardless of the
/// baseline remainder when only that text (or a same-length member name) changes.
const PROMPT_DELTA_32: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn prompt_estimate_sums_responses_instructions_with_input() {
    // OpenAI Responses: a tiny `input` must not suppress a large `instructions`
    // sibling — both are billed prompt text and both must reserve. Baseline keeps
    // the `instructions` key so the delta isolates the 32-char value (member name
    // already counted on both sides).
    let input_only = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": "abcd",
        "instructions": ""
    }))
    .await;
    let with_instructions = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": "abcd",
        "instructions": PROMPT_DELTA_32
    }))
    .await;

    assert!(
        with_instructions > input_only,
        "Responses instructions must be reserved alongside input"
    );
    assert_eq!(
        with_instructions - input_only,
        8,
        "instructions delta must be exactly ceil(32/4)=8 tokens"
    );
}

#[tokio::test]
async fn prompt_estimate_sums_gemini_system_instruction_with_contents() {
    // Gemini: tiny `contents` must not suppress `systemInstruction`.
    let contents_only = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {"parts": [{"text": ""}]}
    }))
    .await;
    let with_system = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {"parts": [{"text": PROMPT_DELTA_32}]}
    }))
    .await;

    assert!(with_system > contents_only);
    assert_eq!(with_system - contents_only, 8);
}

#[tokio::test]
async fn prompt_estimate_sums_gemini_system_instruction_snake_alias() {
    // Both Gemini casings are billed siblings; snake_case must reserve too.
    let contents_only = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "system_instruction": {"parts": [{"text": ""}]}
    }))
    .await;
    let with_system = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "system_instruction": {"parts": [{"text": PROMPT_DELTA_32}]}
    }))
    .await;

    assert_eq!(with_system - contents_only, 8);
}

#[tokio::test]
async fn prompt_estimate_sums_cohere_preamble_and_documents_with_message() {
    // Cohere v1: `message` must not suppress `preamble` or `documents`.
    let message_only = prompt_tokens_reserved(json!({
        "model": "command-r",
        "message": "abcd",
        "preamble": "",
        "documents": [{"text": ""}]
    }))
    .await;
    let with_siblings = prompt_tokens_reserved(json!({
        "model": "command-r",
        "message": "abcd",
        "preamble": "0123456789abcdef", // 16 chars
        "documents": [{"text": "0123456789abcdef"}] // 16 chars
    }))
    .await;

    assert_eq!(
        with_siblings - message_only,
        8,
        "preamble+documents (32 chars) must add ceil(32/4)=8 tokens"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_titan_input_text_and_bedrock_system() {
    // Titan `inputText` value delta is isolated against an empty same-key baseline.
    assert_eq!(
        prompt_tokens_reserved(json!({ "inputText": PROMPT_DELTA_32 })).await
            - prompt_tokens_reserved(json!({ "inputText": "" })).await,
        8
    );

    // TGI `inputs` likewise reserves alongside another textual sibling (`tools`)
    // — the recognized tools field must not hide the inputs prompt.
    let tools_only = prompt_tokens_reserved(json!({
        "inputs": "",
        "tools": [{"name": "abcd"}]
    }))
    .await;
    let with_inputs = prompt_tokens_reserved(json!({
        "inputs": PROMPT_DELTA_32,
        "tools": [{"name": "abcd"}]
    }))
    .await;
    assert_eq!(with_inputs - tools_only, 8);

    // Bedrock Converse-style: top-level `system` alongside `messages`.
    let messages_only = prompt_tokens_reserved(json!({
        "model": "anthropic.claude-3-sonnet",
        "system": [{"text": ""}],
        "messages": [{"role": "user", "content": [{"text": "abcd"}]}]
    }))
    .await;
    let with_system = prompt_tokens_reserved(json!({
        "model": "anthropic.claude-3-sonnet",
        "system": [{"text": PROMPT_DELTA_32}],
        "messages": [{"role": "user", "content": [{"text": "abcd"}]}]
    }))
    .await;
    assert_eq!(with_system - messages_only, 8);
}

#[tokio::test]
async fn prompt_estimate_counts_tools_alongside_messages_without_dropping_siblings() {
    let messages_only = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "description": ""
            }
        }]
    }))
    .await;
    let with_tools = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "description": PROMPT_DELTA_32
            }
        }]
    }))
    .await;

    assert_eq!(
        with_tools - messages_only,
        8,
        "tool schema description must reserve exactly ceil(32/4)=8 alongside messages"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_nested_tool_schema_property_names() {
    // Root review: string-value-only walks omit JSON Schema property names that
    // providers bill. Identical string values with an empty vs 32-char property
    // name under `parameters.properties` must differ by exactly 8 tokens — the
    // old omission yields delta 0.
    let empty_prop = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "": {
                            "type": "string",
                            "description": "x"
                        }
                    }
                }
            }
        }]
    }))
    .await;
    let named_prop = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "0123456789abcdef0123456789abcdef": {
                            "type": "string",
                            "description": "x"
                        }
                    }
                }
            }
        }]
    }))
    .await;

    assert!(
        named_prop > empty_prop,
        "schema property names must increase the reservation (got named={named_prop}, empty={empty_prop})"
    );
    assert_eq!(
        named_prop - empty_prop,
        8,
        "nested schema property-name delta must be exactly ceil(32/4)=8 tokens"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_nested_schema_keys_under_provider_siblings() {
    // Nested `properties` / `$defs`-style keys under a Gemini systemInstruction
    // sibling must reserve; baseline keeps the same object shape with an empty
    // property name so only the 32-char member name contributes to the delta.
    let empty_name = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {
            "parts": [{
                "text": "use schema",
                "tool_schema": {
                    "type": "object",
                    "properties": {
                        "": {"type": "number"}
                    }
                }
            }]
        }
    }))
    .await;
    let named = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {
            "parts": [{
                "text": "use schema",
                "tool_schema": {
                    "type": "object",
                    "properties": {
                        "0123456789abcdef0123456789abcdef": {"type": "number"}
                    }
                }
            }]
        }
    }))
    .await;

    assert_eq!(
        named - empty_name,
        8,
        "nested provider-sibling schema property names must reserve ceil(32/4)=8"
    );
}

#[tokio::test]
async fn prompt_estimate_does_not_double_count_alias_pair_as_nested_duplicate() {
    // When both Gemini casings carry DISTINCT text, both contribute (conservative).
    // Baseline already carries an empty snake_case sibling so the delta isolates
    // the 32-char value (member names cancel).
    let single = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {"parts": [{"text": PROMPT_DELTA_32}]},
        "system_instruction": {"parts": [{"text": ""}]}
    }))
    .await;
    let both_same = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "abcd"}]}],
        "systemInstruction": {"parts": [{"text": PROMPT_DELTA_32}]},
        "system_instruction": {"parts": [{"text": PROMPT_DELTA_32}]}
    }))
    .await;

    // Both aliases present ⇒ both counted (over-reserve), never under-count.
    assert!(
        both_same > single,
        "distinct alias keys must each contribute when both are present"
    );
    assert_eq!(both_same - single, 8);
}

#[tokio::test]
async fn prompt_estimate_excludes_multimodal_bytes_while_counting_text_siblings() {
    // Vision request with Responses instructions: image bytes stay excluded,
    // but instructions + input text still reserve.
    let huge_b64 = "A".repeat(800_000);
    let reserved = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "instructions": PROMPT_DELTA_32,
        "input": [{
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "abcd"},
                {"type": "input_image", "image_url": format!("data:image/jpeg;base64,{huge_b64}")}
            ]
        }]
    }))
    .await;

    assert!(
        reserved > 0 && reserved < 100,
        "multimodal binary must be excluded while text siblings still reserve; got {reserved}"
    );
}

#[tokio::test]
async fn prompt_estimate_excludes_binary_payload_leaves_but_counts_siblings() {
    // Recognized multimodal leaves exclude only the URL/base64 payload; member
    // names and unexpected textual siblings still reserve. A top-level `prompt`
    // data URL (not a multimodal leaf) also counts — the old path-independent
    // skip would hide both.
    let huge_b64 = "A".repeat(200_000);
    let empty_siblings = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd"},
            {"type": "image_url", "image_url": {
                "url": format!("data:image/png;base64,{huge_b64}"),
                "description": ""
            }},
            {"type": "input_audio", "input_audio": {
                "data": huge_b64.clone(),
                "transcript": ""
            }}
        ]}]
    }))
    .await;
    let with_siblings = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd"},
            {"type": "image_url", "image_url": {
                "url": format!("data:image/png;base64,{huge_b64}"),
                "description": PROMPT_DELTA_32
            }},
            {"type": "input_audio", "input_audio": {
                "data": huge_b64.clone(),
                "transcript": PROMPT_DELTA_32
            }}
        ]}]
    }))
    .await;

    assert_eq!(
        with_siblings - empty_siblings,
        16,
        "description+transcript siblings must reserve ceil(64/4)=16; \
         whole-object binary skips yield delta 0"
    );
    assert!(
        empty_siblings < 120,
        "binary payloads must stay excluded; got {empty_siblings}"
    );

    // Collision-shaped / text-field data URL must count (old walk → delta 0).
    let empty_prompt = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "prompt": "data:text/plain,"
    }))
    .await;
    let data_prompt = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "prompt": format!("data:text/plain,{PROMPT_DELTA_32}")
    }))
    .await;
    assert_eq!(
        data_prompt - empty_prompt,
        8,
        "data: URL outside a multimodal leaf must count at full width"
    );
}

#[tokio::test]
async fn prompt_estimate_excludes_binary_source_but_counts_text_document_source() {
    let huge_b64 = "C".repeat(100_000);
    let messages = json!([{"role": "user", "content": [{"type": "text", "text": "abcd"}]}]);
    let binary_no_sibling = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": huge_b64.clone(),
                    "description": ""
                }
            }]
        }]
    }))
    .await;
    let binary_with_sibling = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": huge_b64,
                    "description": PROMPT_DELTA_32
                }
            }]
        }]
    }))
    .await;
    assert!(
        binary_no_sibling < 80,
        "binary Anthropic source payload must stay excluded; got {binary_no_sibling}"
    );
    assert_eq!(
        binary_with_sibling - binary_no_sibling,
        8,
        "unexpected textual sibling under a real Anthropic binary source must \
         reserve ceil(32/4)=8; whole-subtree skips yield delta 0"
    );

    let text_source_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": messages.clone(),
        "document": {
            "source": {
                "type": "text",
                "media_type": "text/plain",
                "data": ""
            }
        }
    }))
    .await;
    let text_source = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": messages,
        "document": {
            "source": {
                "type": "text",
                "media_type": "text/plain",
                "data": PROMPT_DELTA_32
            }
        }
    }))
    .await;

    assert_eq!(
        text_source - text_source_empty,
        8,
        "text document source prose must reserve ceil(32/4)=8"
    );
}

#[tokio::test]
async fn prompt_estimate_excludes_token_cap_member_names() {
    // Exact-path token-cap keys are control fields: neither their names nor
    // numeric values enter the prompt estimate. Baselines keep the same
    // container keys so only the excluded numeric fields differ.
    let base = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "generationConfig": {"temperature": 0},
        "parameters": {"temperature": 0},
        "textGenerationConfig": {"temperature": 0}
    }))
    .await;
    let with_caps = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "max_completion_tokens": 999999,
        "max_output_tokens": 999999,
        "max_new_tokens": 999999,
        "maxOutputTokens": 999999,
        "maxTokens": 999999,
        "max_tokens_to_sample": 999999,
        "generationConfig": {"temperature": 0, "maxOutputTokens": 999999},
        "parameters": {"temperature": 0, "max_new_tokens": 999999},
        "textGenerationConfig": {"temperature": 0, "maxTokenCount": 999999}
    }))
    .await;

    assert_eq!(
        with_caps, base,
        "exact-path token-cap member names must not change the prompt reservation"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_tool_schema_property_named_max_tokens() {
    // Root review: name-only TOKEN_CAP_KEYS skips hid billed schema subtrees
    // under `parameters.properties.max_tokens`. A schema-shaped object must
    // reserve its description; a numeric top-level cap must still be excluded.
    let empty_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "max_tokens": {
                            "type": "integer",
                            "description": ""
                        }
                    }
                }
            }
        }]
    }))
    .await;
    let with_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "max_tokens": {
                            "type": "integer",
                            "description": PROMPT_DELTA_32
                        }
                    }
                }
            }
        }]
    }))
    .await;

    assert_eq!(
        with_desc - empty_desc,
        8,
        "schema property max_tokens description must reserve ceil(32/4)=8; \
         name-only skips yield delta 0"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_tool_schema_properties_named_binary_reserved_keys() {
    // Root review: name-only BINARY_CONTENT_KEYS skips hid schema properties
    // named `image_url` / `input_audio`. Schema-shaped objects must reserve
    // their descriptions; real multimodal payloads must stay excluded.
    let empty_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_url": {
                            "type": "string",
                            "description": ""
                        },
                        "input_audio": {
                            "type": "string",
                            "description": ""
                        }
                    }
                }
            }
        }]
    }))
    .await;
    let with_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_url": {
                            "type": "string",
                            "description": PROMPT_DELTA_32
                        },
                        "input_audio": {
                            "type": "string",
                            "description": PROMPT_DELTA_32
                        }
                    }
                }
            }
        }]
    }))
    .await;

    assert_eq!(
        with_desc - empty_desc,
        16,
        "schema properties image_url+input_audio descriptions must reserve \
         ceil(64/4)=16; name-only skips yield delta 0"
    );

    // Real vision payload under the same spelling must remain excluded.
    let huge_b64 = "A".repeat(200_000);
    let with_real_image = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd"},
            {"type": "image_url", "image_url": {
                "url": format!("data:image/png;base64,{huge_b64}")
            }}
        ]}]
    }))
    .await;
    assert!(
        with_real_image < 80,
        "real image_url data-URL payload must stay excluded; got {with_real_image}"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_schema_shaped_source_with_type_string() {
    // Root review: treating every non-`type:"text"` `source` as binary discarded
    // ordinary schema objects such as `{"type":"string","description":"..."}`.
    let empty_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": ""
                        }
                    }
                }
            }
        }]
    }))
    .await;
    let with_desc = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": PROMPT_DELTA_32
                        }
                    }
                }
            }
        }]
    }))
    .await;

    assert_eq!(
        with_desc - empty_desc,
        8,
        "schema source type:string description must reserve ceil(32/4)=8; \
         blanket non-text source skips yield delta 0"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_data_url_instructions_literal() {
    // Reproduction: OpenAI Responses `instructions` holding a valid
    // `data:text/plain,<literal>` is billed prompt text. Path-independent
    // `is_data_url` exclusion (09514f4) counted it as zero.
    // Keep the `data:text/plain,` prefix on both sides so only the 32-char
    // payload contributes → exact ceil(32/4)=8 token delta.
    let empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": "abcd",
        "instructions": "data:text/plain,"
    }))
    .await;
    let with = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": "abcd",
        "instructions": format!("data:text/plain,{PROMPT_DELTA_32}")
    }))
    .await;

    assert_eq!(
        with - empty,
        8,
        "data:text/plain instructions literal must produce exact ceil(32/4)=8 delta"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_nested_numeric_caps_outside_exact_paths() {
    // Direct numeric members with reserved spellings at an unrelated nested path
    // are billed; recognized root / provider-container caps stay symmetrically
    // present and excluded. Path-independent TOKEN_CAP_KEYS (09514f4) skipped
    // any-depth Numbers under those names → delta 0. Changing a nested object
    // property's `default` does not exercise the collision (09514f4 already
    // counted object-shaped values under those keys).
    let empty_nested = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "generationConfig": {"maxOutputTokens": 999999},
        "metadata": {
            "max_tokens": 0,
            "maxOutputTokens": 0
        }
    }))
    .await;
    let nested_caps = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "generationConfig": {"maxOutputTokens": 999999},
        "metadata": {
            "max_tokens": 10000,
            "maxOutputTokens": 10000
        }
    }))
    .await;

    // Two nested numbers: `0` (1 digit) → `10000` (5 digits) = +4 chars each →
    // +8 chars → ceil(8/4)=2 tokens. Any-depth numeric skips yield delta 0.
    assert_eq!(
        nested_caps - empty_nested,
        2,
        "nested metadata numeric max_tokens/maxOutputTokens must contribute; \
         exact-path caps remain excluded"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_collision_shaped_source_outside_content_block() {
    // `source:{type:"url", description:<long>}` outside a real Anthropic content
    // block must count. Old any-depth binary-source skip hid the description.
    let empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "metadata": {
            "source": {
                "type": "url",
                "description": ""
            }
        }
    }))
    .await;
    let with = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "metadata": {
            "source": {
                "type": "url",
                "description": PROMPT_DELTA_32
            }
        }
    }))
    .await;

    assert_eq!(
        with - empty,
        8,
        "collision-shaped source outside a content block must reserve ceil(32/4)=8"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_collision_shaped_binary_keys_outside_content_parts() {
    // Long alphanumeric / prose values placed *directly* under reserved
    // multimodal spellings outside content parts must count. Old any-depth
    // BINARY_CONTENT_KEYS + base64 heuristic (09514f4) skipped those members
    // entirely → delta 0. Nested schema `default` changes do not exercise the
    // collision (09514f4 already counted object-shaped schema properties).
    let long_alnum = "A".repeat(64); // above MIN_BASE64_PAYLOAD_LEN, alphabet-only
    let empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "metadata": {
            "image_url": "",
            "inline_data": ""
        }
    }))
    .await;
    let with = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "metadata": {
            "image_url": long_alnum.clone(),
            "inline_data": long_alnum
        }
    }))
    .await;

    assert_eq!(
        with - empty,
        (64u64 * 2).div_ceil(4),
        "collision-shaped image_url/inline_data strings outside content parts must count"
    );

    // Real Gemini inline_data leaf stays excluded; unexpected sibling counts.
    let huge = "B".repeat(100_000);
    let gemini_empty = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [
            {"text": "abcd"},
            {"inline_data": {"mime_type": "image/png", "data": huge.clone(), "note": ""}}
        ]}]
    }))
    .await;
    let gemini_sibling = prompt_tokens_reserved(json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [
            {"text": "abcd"},
            {"inline_data": {
                "mime_type": "image/png",
                "data": huge,
                "note": PROMPT_DELTA_32
            }}
        ]}]
    }))
    .await;
    assert!(
        gemini_empty < 120,
        "real Gemini inline_data payload must stay excluded; got {gemini_empty}"
    );
    assert_eq!(
        gemini_sibling - gemini_empty,
        8,
        "textual sibling under real Gemini inline_data must reserve ceil(32/4)=8"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_wrong_family_content_part_binary_collisions() {
    // Provider-agnostic ContentPart exclusion (179d) skipped reserved binary
    // keys without checking part `type` / family. Wrong-family collisions must
    // count fail-closed; legitimate shapes stay leaf-only excluded.
    let long_alnum = "A".repeat(64);
    let huge = "B".repeat(100_000);

    // OpenAI/Anthropic text part + image_url long alnum / URL must count.
    let text_img_empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd", "image_url": ""}
        ]}]
    }))
    .await;
    let text_img = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd", "image_url": long_alnum.clone()}
        ]}]
    }))
    .await;
    assert_eq!(
        text_img - text_img_empty,
        16,
        "text part image_url alphanumeric collision must reserve ceil(64/4)=16"
    );

    let text_url_empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd", "image_url": "https://example.com/"}
        ]}]
    }))
    .await;
    let text_url = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd",
             "image_url": format!("https://example.com/{PROMPT_DELTA_32}")}
        ]}]
    }))
    .await;
    assert_eq!(
        text_url - text_url_empty,
        8,
        "text part image_url URL collision must reserve ceil(32/4)=8"
    );

    // Text part with Anthropic-shaped binary source must count the data leaf.
    let text_src_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "text",
            "text": "abcd",
            "source": {"type": "base64", "media_type": "image/png", "data": ""}
        }]}]
    }))
    .await;
    let text_src = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "text",
            "text": "abcd",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": PROMPT_DELTA_32
            }
        }]}]
    }))
    .await;
    assert_eq!(
        text_src - text_src_empty,
        8,
        "text part source.data must count; only image/document blocks exclude"
    );

    // inline_data on an OpenAI message part (wrong family) must count.
    let oa_inline_empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [{
            "type": "text",
            "text": "abcd",
            "inline_data": {"mime_type": "image/png", "data": ""}
        }]}]
    }))
    .await;
    let oa_inline = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [{
            "type": "text",
            "text": "abcd",
            "inline_data": {"mime_type": "image/png", "data": long_alnum.clone()}
        }]}]
    }))
    .await;
    assert_eq!(
        oa_inline - oa_inline_empty,
        16,
        "OpenAI message-part inline_data must count (Gemini contents.parts only)"
    );

    // Legitimate OpenAI Chat image_url part stays bounded; sibling counts.
    let real_img_empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd"},
            {"type": "image_url", "image_url": {
                "url": format!("data:image/png;base64,{huge}"),
                "caption": ""
            }}
        ]}]
    }))
    .await;
    let real_img = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "abcd"},
            {"type": "image_url", "image_url": {
                "url": format!("data:image/png;base64,{huge}"),
                "caption": PROMPT_DELTA_32
            }}
        ]}]
    }))
    .await;
    assert!(
        real_img_empty < 120,
        "real OpenAI image_url payload must stay excluded; got {real_img_empty}"
    );
    assert_eq!(real_img - real_img_empty, 8);

    // Legitimate Responses input_image stays bounded.
    let resp_empty = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "abcd"},
                {"type": "input_image", "image_url": format!("data:image/png;base64,{huge}"),
                 "detail": ""}
            ]
        }]
    }))
    .await;
    let resp = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "abcd"},
                {"type": "input_image", "image_url": format!("data:image/png;base64,{huge}"),
                 "detail": PROMPT_DELTA_32}
            ]
        }]
    }))
    .await;
    assert!(
        resp_empty < 120,
        "real Responses input_image payload must stay excluded; got {resp_empty}"
    );
    assert_eq!(resp - resp_empty, 8);

    // Legitimate Anthropic image source stays bounded; sibling counts.
    let anth_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": huge.clone(),
                "note": ""
            }
        }]}]
    }))
    .await;
    let anth = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": huge,
                "note": PROMPT_DELTA_32
            }
        }]}]
    }))
    .await;
    assert!(
        anth_empty < 120,
        "real Anthropic image source payload must stay excluded; got {anth_empty}"
    );
    assert_eq!(anth - anth_empty, 8);
}

#[tokio::test]
async fn prompt_estimate_counts_malformed_anthropic_source_payload_leaves() {
    // Anthropic `source` leaves share the OpenAI/Responses/Gemini payload-shape
    // gate: a block that declares a binary `source.type` but whose leaf carries
    // prose (no `data:` / `http(s)` prefix, not base64-shaped) is MALFORMED and
    // must count fail-closed, so a reserved spelling alone cannot drop unbounded
    // billed text. Baselines keep the same keys so each delta isolates the value.
    let prose = "not a payload just ordinary text"; // 32 chars; spaces => not base64
    assert_eq!(prose.chars().count(), 32);

    // `type: "base64"` with prose at `data` must count at full width.
    let b64_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": ""}
        }]}]
    }))
    .await;
    let b64_prose = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": prose}
        }]}]
    }))
    .await;
    assert_eq!(
        b64_prose - b64_empty,
        8,
        "prose under a base64-declared Anthropic source must reserve ceil(32/4)=8"
    );

    // `type: "url"` with prose at `url` must count at full width.
    let url_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "url", "url": ""}
        }]}]
    }))
    .await;
    let url_prose = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "url", "url": prose}
        }]}]
    }))
    .await;
    assert_eq!(
        url_prose - url_empty,
        8,
        "prose under a url-declared Anthropic source must reserve ceil(32/4)=8"
    );

    // `type: "file"` with prose at `file_id` / `data` / `url` must count.
    let file_empty = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "document",
            "source": {"type": "file", "file_id": "", "data": "", "url": ""}
        }]}]
    }))
    .await;
    let file_prose = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "document",
            "source": {"type": "file", "file_id": prose, "data": prose, "url": prose}
        }]}]
    }))
    .await;
    assert_eq!(
        file_prose - file_empty,
        24,
        "prose under a file-declared Anthropic source must reserve ceil(96/4)=24"
    );

    // Genuine binary payloads at the same leaves stay excluded: growing them by
    // 32 chars must not move the reservation at all.
    let real_b64_short = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "A".repeat(100_000)}
        }]}]
    }))
    .await;
    let real_b64_long = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "A".repeat(100_032)}
        }]}]
    }))
    .await;
    assert_eq!(
        real_b64_long, real_b64_short,
        "real base64 Anthropic source payloads must stay excluded"
    );
    assert!(
        real_b64_short < 80,
        "real base64 Anthropic source payload must stay excluded; got {real_b64_short}"
    );

    let real_url_short = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "url", "url": "https://e.test/"}
        }]}]
    }))
    .await;
    let real_url_long = prompt_tokens_reserved(json!({
        "model": "claude-3",
        "messages": [{"role": "user", "content": [{
            "type": "image",
            "source": {"type": "url", "url": format!("https://e.test/{PROMPT_DELTA_32}")}
        }]}]
    }))
    .await;
    assert_eq!(
        real_url_long, real_url_short,
        "real https Anthropic source URLs must stay excluded"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_non_u64_token_caps_at_exact_paths() {
    // Exclusion shares requested_completion_tokens' as_u64 contract: negative and
    // fractional numbers at exact cap paths are not recognized controls and must
    // count fail-closed (name + literal). Unsigned caps remain excluded.
    let short = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": -1,
        "max_completion_tokens": -1
    }))
    .await;
    let long = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": -10001,
        "max_completion_tokens": -10001
    }))
    .await;
    // Two literals: "-1" (2) → "-10001" (6) = +4 chars each → +8 → 2 tokens.
    // Any-Number exclusion (179d) yielded delta 0.
    assert_eq!(
        long - short,
        2,
        "negative exact-path caps must count at literal width"
    );

    let frac_short = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "generationConfig": {"maxOutputTokens": -1.5},
        "parameters": {"max_new_tokens": -1.5}
    }))
    .await;
    let frac_long = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "generationConfig": {"maxOutputTokens": -10001.5},
        "parameters": {"max_new_tokens": -10001.5}
    }))
    .await;
    // "-1.5" (4) → "-10001.5" (8) = +4 chars each → +8 → 2 tokens.
    assert_eq!(
        frac_long - frac_short,
        2,
        "fractional exact-path caps must count at literal width"
    );

    // Unsigned controls at the same paths stay fully excluded (name + value).
    let base = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "generationConfig": {"temperature": 0},
        "parameters": {"temperature": 0}
    }))
    .await;
    let with_u64 = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "generationConfig": {"temperature": 0, "maxOutputTokens": 999999},
        "parameters": {"temperature": 0, "max_new_tokens": 999999}
    }))
    .await;
    assert_eq!(
        with_u64, base,
        "unsigned exact-path caps must remain excluded from the prompt estimate"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_schema_scalar_literals_without_token_cap_overcharge() {
    // Schema numbers/bools/`null` appear in the serialized prompt; omitting them
    // at scale under-reserves. Count JSON literal widths, but keep numeric
    // token-cap controls excluded.
    //
    // Eight enum integers: `0` (1 digit) vs `10000` (5 digits) → +4 chars each
    // → +32 chars total → exactly ceil(32/4)=8 tokens regardless of baseline
    // remainder. Name-only / scalar-ignoring walks yield delta 0.
    let short_enum = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "n": {
                            "type": "integer",
                            "enum": [0, 0, 0, 0, 0, 0, 0, 0]
                        }
                    },
                    "additionalProperties": false
                }
            }
        }]
    }))
    .await;
    let long_enum = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 999999,
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "n": {
                            "type": "integer",
                            "enum": [10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000]
                        }
                    },
                    "additionalProperties": false
                }
            }
        }]
    }))
    .await;

    assert_eq!(
        long_enum - short_enum,
        8,
        "schema numeric enum literal width must reserve ceil(32/4)=8; \
         ignored scalars yield delta 0"
    );

    // Bool literals: `false` (5) vs `true` (4) across eight defaults → +8 chars
    // → exactly 2 tokens.
    let all_true = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 42,
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "boolean", "default": true},
                        "b": {"type": "boolean", "default": true},
                        "c": {"type": "boolean", "default": true},
                        "d": {"type": "boolean", "default": true},
                        "e": {"type": "boolean", "default": true},
                        "f": {"type": "boolean", "default": true},
                        "g": {"type": "boolean", "default": true},
                        "h": {"type": "boolean", "default": true}
                    }
                }
            }
        }]
    }))
    .await;
    let all_false = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "max_tokens": 42,
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "boolean", "default": false},
                        "b": {"type": "boolean", "default": false},
                        "c": {"type": "boolean", "default": false},
                        "d": {"type": "boolean", "default": false},
                        "e": {"type": "boolean", "default": false},
                        "f": {"type": "boolean", "default": false},
                        "g": {"type": "boolean", "default": false},
                        "h": {"type": "boolean", "default": false}
                    }
                }
            }
        }]
    }))
    .await;

    assert_eq!(
        all_false - all_true,
        2,
        "eight false vs true defaults must reserve ceil(8/4)=2 from literal width"
    );

    // Numeric top-level caps in the bodies above must stay excluded (finite
    // estimates; unbounded cap digits would dominate if counted).
    assert!(
        long_enum < 200,
        "scalar counting must not reintroduce token-cap overcharge; got {long_enum}"
    );
}

#[tokio::test]
async fn concurrent_reserved_name_schema_requests_cannot_oversubscribe() {
    // Long descriptions under schema properties that reuse reserved spellings
    // (`max_tokens`, `image_url`, `source`) must reserve enough that concurrent
    // twins cannot both fit — name-only exclusion would admit both.
    let desc = "D".repeat(600); // 600 chars -> 150 tokens from one description alone
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 200,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 999999,
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "max_tokens": {
                            "type": "integer",
                            "description": desc.clone()
                        },
                        "image_url": {
                            "type": "string",
                            "description": "x"
                        },
                        "source": {
                            "type": "string",
                            "description": "y"
                        }
                    }
                }
            }
        }]
    });

    let make_ctx = || {
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        ctx.metadata.insert(
            "request_body".to_string(),
            serde_json::to_string(&body).unwrap(),
        );
        ctx
    };

    let mut ctx_a = make_ctx();
    let mut ctx_b = make_ctx();
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

    assert_eq!(
        allowed, 1,
        "only one reserved-name schema-heavy reservation should fit"
    );
    assert_eq!(
        rejected, 1,
        "the second reserved-name schema-heavy request must be rejected"
    );
}

#[tokio::test]
async fn concurrent_sibling_heavy_requests_cannot_oversubscribe_on_omitted_instructions() {
    // Reproduction-shaped: tiny input + large instructions must reserve enough
    // that a second concurrent twin cannot also fit in a tight budget.
    let instructions = "X".repeat(400); // 400 chars -> 100 prompt tokens
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 120,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let body = json!({
        "model": "gpt-4o",
        "input": "hi",
        "instructions": instructions
    });

    let make_ctx = || {
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        ctx.metadata.insert(
            "request_body".to_string(),
            serde_json::to_string(&body).unwrap(),
        );
        ctx
    };

    let mut ctx_a = make_ctx();
    let mut ctx_b = make_ctx();
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

    // If instructions were omitted, each request would reserve ~1 token and both
    // would fit. Fail-closed whole-body counting makes only one fit.
    assert_eq!(allowed, 1, "only one sibling-heavy reservation should fit");
    assert_eq!(
        rejected, 1,
        "the second sibling-heavy request must be rejected"
    );
}

#[tokio::test]
async fn concurrent_schema_property_heavy_requests_cannot_oversubscribe() {
    // Long nested schema property names alone must reserve enough that two
    // concurrent twins cannot both fit — proves member-name accounting is live
    // on the admission path (string-value-only walks would admit both).
    let prop = "P".repeat(600); // 600-char property name -> 150 tokens from the name alone
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 200,
            "window_seconds": 60,
            "count_mode": "prompt_tokens",
            "limit_by": "ip",
            "expose_headers": true
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        prop: {"type": "string"}
                    }
                }
            }
        }]
    });

    let make_ctx = || {
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        ctx.metadata.insert(
            "request_body".to_string(),
            serde_json::to_string(&body).unwrap(),
        );
        ctx
    };

    let mut ctx_a = make_ctx();
    let mut ctx_b = make_ctx();
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

    assert_eq!(allowed, 1, "only one schema-heavy reservation should fit");
    assert_eq!(
        rejected, 1,
        "the second schema-heavy request must be rejected"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_unknown_textual_sibling_alongside_recognized_field() {
    // GHSA-2r5g-438w-85hr root finding: a non-empty recognized prompt field must
    // not hide provider-native billed text under an unknown top-level sibling.
    // Baseline keeps the sibling key so the delta isolates the 32-char value.
    let recognized_only = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "provider_native_prompt_extension": ""
    }))
    .await;
    let with_unknown = prompt_tokens_reserved(json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "abcd"}],
        "provider_native_prompt_extension": PROMPT_DELTA_32
    }))
    .await;

    assert!(
        with_unknown > recognized_only,
        "unknown textual sibling must increase the reservation when a recognized \
         field is already non-empty (got {with_unknown}, recognized-only {recognized_only})"
    );
    assert_eq!(
        with_unknown - recognized_only,
        8,
        "unknown sibling delta must be exactly ceil(32/4)=8 tokens"
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut resp_headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
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
            .on_response_body(&mut ai_ctx, 200, &mut json_headers(), &ai_body)
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
// model and billed as input. The whole-body walk counts string values and member
// names once alongside `messages` (no separate add path — that would double-count).
// These tests drive the public `before_proxy` surface in `prompt_tokens` mode and
// compare a same-shape baseline (empty instruction key) against the filled
// instruction so the reserved delta equals the instruction text.

/// A minimal Azure chat-completions request used by the delta comparisons below.
fn azure_base_messages() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "abcd"}]
    })
}

/// A 32-character instruction keeps token deltas exact under `div_ceil(4)`
/// regardless of the baseline's remainder.
const AZURE_INSTRUCTION_32: &str = "0123456789abcdef0123456789abcdef";

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
    // `role_information`. Baseline already carries an empty instruction key so
    // the delta isolates the instruction text (endpoint/index/key strings and
    // the member name cancel out).
    let instruction = AZURE_INSTRUCTION_32;
    let mut baseline = azure_base_messages();
    baseline["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "endpoint": "https://example.search.windows.net",
            "index_name": "contoso-products-index-name-not-prompt-input",
            "authentication": {"type": "api_key", "key": "super-secret-key-not-prompt-input"},
            "role_information": ""
        }
    }]);
    let reserved_base = azure_reserved(baseline.clone()).await;

    let mut with = baseline;
    with["data_sources"][0]["parameters"]["role_information"] = json!(instruction);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(
        reserved_with > reserved_base,
        "role_information instruction must be counted in the prompt estimate"
    );
    assert_eq!(
        reserved_with - reserved_base,
        instruction_tokens,
        "role_information must be counted once; delta isolates the instruction text"
    );
}

#[tokio::test]
async fn prompt_estimate_counts_azure_extensions_api_role_information_camelcase() {
    // The original extensions API used camelCase for BOTH the outer array
    // (`dataSources`) and the inner field (`roleInformation`); both casings must be
    // recognized by the whole-body walk.
    let instruction = AZURE_INSTRUCTION_32;
    let mut baseline = azure_base_messages();
    baseline["dataSources"] = json!([{
        "type": "AzureCognitiveSearch",
        "parameters": {
            "endpoint": "https://example.search.windows.net",
            "indexName": "contoso-index",
            "roleInformation": ""
        }
    }]);
    let reserved_base = azure_reserved(baseline.clone()).await;

    let mut with = baseline;
    with["dataSources"][0]["parameters"]["roleInformation"] = json!(instruction);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(reserved_with > reserved_base);
    assert_eq!(reserved_with - reserved_base, instruction_tokens);
}

#[tokio::test]
async fn prompt_estimate_does_not_short_circuit_on_empty_role_information() {
    // Distinct Azure role-information casings are distinct JSON keys, so an empty
    // `role_information` decoy cannot hide a real `roleInformation` sibling under
    // the whole-body walk (each string value / member name is visited independently).
    let instruction = AZURE_INSTRUCTION_32;
    let mut baseline = azure_base_messages();
    baseline["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "role_information": "",
            "roleInformation": ""
        }
    }]);
    let reserved_base = azure_reserved(baseline.clone()).await;

    let mut with = baseline;
    with["data_sources"][0]["parameters"]["roleInformation"] = json!(instruction);
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
    // empty-string case, it must not hide a real sibling in the other casing.
    let whitespace = "   "; // 3 chars: neither None nor empty.
    let instruction = AZURE_INSTRUCTION_32;
    let mut baseline = azure_base_messages();
    baseline["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": {
            "role_information": whitespace,
            "roleInformation": ""
        }
    }]);
    let reserved_base = azure_reserved(baseline.clone()).await;

    let mut with = baseline;
    with["data_sources"][0]["parameters"]["roleInformation"] = json!(instruction);
    let reserved_with = azure_reserved(with).await;

    let added_chars = instruction.chars().count() as u64;
    assert!(
        reserved_with > reserved_base,
        "the real instruction must be counted alongside a whitespace decoy"
    );
    assert_eq!(reserved_with - reserved_base, added_chars.div_ceil(4));
}

#[tokio::test]
async fn prompt_estimate_counts_role_information_on_non_first_data_source() {
    // The instruction can live on any data source, not just the first; the
    // whole-body walk enumerates every entry in the array.
    let instruction = AZURE_INSTRUCTION_32;
    let mut baseline = azure_base_messages();
    baseline["data_sources"] = json!([
        {
            "type": "azure_search",
            "parameters": {"endpoint": "https://a.search.windows.net", "index_name": "first"}
        },
        {
            "type": "azure_search",
            "parameters": {
                "endpoint": "https://b.search.windows.net",
                "index_name": "second",
                "role_information": ""
            }
        }
    ]);
    let reserved_base = azure_reserved(baseline.clone()).await;

    let mut with = baseline;
    with["data_sources"][1]["parameters"]["role_information"] = json!(instruction);
    let reserved_with = azure_reserved(with).await;

    let instruction_tokens = (instruction.chars().count() as u64).div_ceil(4);
    assert!(
        reserved_with > reserved_base,
        "role_information on a non-first data source must be counted"
    );
    assert_eq!(reserved_with - reserved_base, instruction_tokens);
}

#[tokio::test]
async fn prompt_estimate_counts_inputs_prompt_with_role_information() {
    // TGI/HuggingFace `inputs` and Azure `role_information` are both string values
    // under the whole-body walk. Adding role_information must not drop or replace
    // the `inputs` prompt — both contribute, and neither is double-counted.
    let inputs = "a".repeat(400);
    let instruction = "Be terse.";

    let mut body = json!({ "inputs": inputs });
    let reserved_inputs_only = azure_reserved(body.clone()).await;
    assert!(
        reserved_inputs_only > 0,
        "the `inputs` prompt must be counted by the whole-body walk"
    );

    body["data_sources"] = json!([{
        "type": "azure_search",
        "parameters": { "role_information": instruction }
    }]);
    let reserved_with_role = azure_reserved(body).await;

    assert!(
        reserved_with_role >= reserved_inputs_only,
        "role_information must not drop the `inputs` prompt \
         (got {reserved_with_role}, inputs-only was {reserved_inputs_only})"
    );
}

// ─── #2261: exposed headers reflect post-reconcile bucket state ─────────

/// Drive the real production ordering for a successful buffered metered response:
/// `before_proxy` (reserve + admission metadata) → `after_proxy` (copy headers) →
/// `on_response_body` (reconcile actual usage + refresh client-visible headers).
async fn run_expose_header_lifecycle(
    plugin: &AiRateLimiter,
    max_tokens: u64,
    prompt: &str,
    actual_prompt: u64,
    actual_completion: u64,
) -> (RequestContext, HashMap<String, String>, u64) {
    let mut ctx = ai_request_ctx(max_tokens, prompt);
    let mut request_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut request_headers).await);

    let reserved = reserved_tokens(&ctx);
    assert!(
        reserved > 0,
        "lifecycle fixture must take a pre-request reservation"
    );
    let admission_usage = ctx
        .metadata
        .get("ai_ratelimit_usage")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert_eq!(
        admission_usage, reserved,
        "admission metadata usage must equal the reservation estimate"
    );

    // The production hook only parses buffered JSON responses when the upstream
    // response declares a JSON-compatible media type. Keep this lifecycle fixture
    // faithful to a real OpenAI-style response so reconciliation sees `usage`.
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    let reserved_str = reserved.to_string();
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some(reserved_str.as_str()),
        "after_proxy must initially expose the admission estimate"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-remaining")
            .map(String::as_str),
        Some(ctx.metadata.get("ai_ratelimit_remaining").unwrap().as_str())
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-limit")
            .map(String::as_str),
        Some("1000")
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-window")
            .map(String::as_str),
        Some("60")
    );

    let body = openai_response(actual_prompt, actual_completion);
    let actual_total = actual_prompt.saturating_add(actual_completion);
    assert_ne!(
        actual_total, reserved,
        "fixture must use actual usage different from the reservation estimate"
    );
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );

    (ctx, response_headers, actual_total)
}

#[tokio::test]
async fn expose_headers_lifecycle_reflects_reconciled_usage_local() {
    // #2261: after_proxy copies admission estimate headers before on_response_body
    // reconciles. The final client-visible usage/remaining must describe the
    // bucket after actual provider usage lands — not the reservation snapshot.
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

    let (ctx, response_headers, actual) =
        run_expose_header_lifecycle(&plugin, 200, "hello world", 4, 6).await;

    let actual_str = actual.to_string();
    let remaining_str = (1000 - actual).to_string();
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some(actual_str.as_str()),
        "final headers must expose reconciled usage, not the admission estimate"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-remaining")
            .map(String::as_str),
        Some(remaining_str.as_str()),
        "final remaining must match the post-reconcile bucket"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-limit")
            .map(String::as_str),
        Some("1000"),
        "limit stays coherent across reconcile"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-window")
            .map(String::as_str),
        Some("60"),
        "window stays coherent across reconcile"
    );
    assert_eq!(
        ctx.metadata.get("ai_ratelimit_usage").map(String::as_str),
        Some(actual_str.as_str()),
        "metadata must refresh with the reconciled outcome"
    );
    assert_eq!(
        observed_usage(&plugin).await,
        actual,
        "internal window must charge actual usage after the lifecycle"
    );
}

#[tokio::test]
async fn expose_headers_lifecycle_reflects_reconciled_usage_redis_fallback() {
    // Redis-compatible path: sync_mode=redis with an unreachable broker falls
    // back to the local window. AdjustUsage still returns post-reconcile
    // usage/remaining, and the same before_proxy → after_proxy → on_response_body
    // ordering must refresh client-visible headers.
    //
    // GHSA-87rq-v4hx-8rcq: per-process fallback is now an explicit opt-in
    // (`redis_failure_policy: "local_fallback"`); the default refuses instead.
    let plugin = AiRateLimiter::new(
        &json!({
            "token_limit": 1000,
            "window_seconds": 60,
            "limit_by": "ip",
            "expose_headers": true,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1/0",
            "redis_failure_policy": "local_fallback",
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 60,
            "redis_key_prefix": "ferrum:ai_rate_limiter:issue2261"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let (_ctx, response_headers, actual) =
        run_expose_header_lifecycle(&plugin, 180, "redis fallback prompt", 5, 5).await;

    let actual_str = actual.to_string();
    let remaining_str = (1000 - actual).to_string();
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some(actual_str.as_str()),
        "Redis-fallback lifecycle must expose reconciled usage on the final headers"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-remaining")
            .map(String::as_str),
        Some(remaining_str.as_str())
    );
    assert_eq!(observed_usage(&plugin).await, actual);
}

#[tokio::test]
async fn expose_headers_lifecycle_positive_delta_charges_extra() {
    // Actual usage ABOVE the reservation (positive delta) must raise both the
    // internal window and the final exposed usage/remaining.
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

    // completion_tokens mode reserves only max_tokens (50). Actual completion=80.
    let (ctx, response_headers, _actual) =
        run_expose_header_lifecycle(&plugin, 50, "short", 10, 80).await;
    assert_eq!(reserved_tokens(&ctx), 50);
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some("80")
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-remaining")
            .map(String::as_str),
        Some("920")
    );
    assert_eq!(observed_usage(&plugin).await, 80);
}

#[tokio::test]
async fn expose_headers_non_2xx_release_refreshes_remaining() {
    // Non-2xx releases the reservation in on_response_body after after_proxy
    // already copied admission headers. Final usage/remaining must show the
    // released bucket (zero charged for this request).
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

    let mut ctx = ai_request_ctx(100, "will fail");
    let mut request_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut request_headers).await);
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0);
    let reserved_str = reserved.to_string();

    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 500, &mut response_headers)
            .await,
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some(reserved_str.as_str())
    );

    assert_continue(
        plugin
            .on_response_body(
                &mut ctx,
                500,
                &mut response_headers,
                br#"{"error":"upstream"}"#,
            )
            .await,
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some("0"),
        "non-2xx release must refresh usage to the post-release bucket"
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-remaining")
            .map(String::as_str),
        Some("1000")
    );
    assert_eq!(observed_usage(&plugin).await, 0);
}

// ── Fail-closed usage reconciliation (GHSA-87rq-v4hx-8rcq) ────────────────
//
// Admission reserves an *estimate*; the authoritative charge is the actual
// provider token count applied after the response. If centralized enforcement
// disappears between the two, that charge cannot be recorded — and delivering
// the upstream 2xx anyway hands the client a completion whose tokens nothing
// debited. Under the default `redis_failure_policy: "fail_closed"` that is
// exactly the per-process budget bypass the policy exists to prevent, so the
// reconciliation path refuses with the same generic 503 admission uses.
//
// These drive the production failover seam — a real Redis-backed limiter
// pointed at an endpoint that is never listening — not a hand-built
// `RateLimitOutcome`.

/// Redis-mode config whose endpoint is never listening, so every centralized
/// operation fails and the configured `redis_failure_policy` decides.
fn unreachable_redis_ai_config(failure_policy: Option<&str>) -> serde_json::Value {
    let mut config = json!({
        "token_limit": 1000,
        "window_seconds": 60,
        "limit_by": "ip",
        "expose_headers": true,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1/0",
        "redis_connect_timeout_seconds": 1,
        // Long enough that no background recovery dial happens during a test.
        "redis_health_check_interval_seconds": 3600,
        "redis_key_prefix": "ferrum:ai_rate_limiter:ghsa87rq"
    });
    if let (Some(object), Some(policy)) = (config.as_object_mut(), failure_policy) {
        object.insert("redis_failure_policy".to_string(), json!(policy));
    }
    config
}

/// A context shaped like one admitted while the centralized store was still
/// healthy: a Redis-mode reservation (window index, no local reservation id) of
/// `reserved` tokens on a request `before_proxy` identified as an AI call.
///
/// Seeded rather than produced by `before_proxy` because the scenario under test
/// is Redis dying *after* admission — a `fail_closed` plugin whose store is
/// already unreachable refuses at admission and never reaches reconciliation at
/// all (see `fail_closed_admission_refuses_when_enforcement_is_unavailable`).
fn reconcilable_ai_ctx(plugin: &AiRateLimiter, reserved: u64) -> RequestContext {
    let mut ctx = ai_request_ctx(200, "hello reconcile");
    // The reservation lifecycle is scoped to the limiter INSTANCE, so seed it
    // through that instance rather than through shared metadata keys.
    plugin.seed_reservation_for_test(&mut ctx, reserved, None, Some(42), true);
    ctx.metadata.insert(
        "ai_ratelimit_reserved_tokens".to_string(),
        reserved.to_string(),
    );
    ctx.metadata
        .insert("ai_ratelimit_request".to_string(), "true".to_string());
    ctx
}

/// Mark a context as carrying a federated provider response of `status` that
/// reported `tokens` total tokens.
fn mark_federated(ctx: &mut RequestContext, status: &str, tokens: &str) {
    ctx.metadata
        .insert("ai_federation_provider".to_string(), "openai".to_string());
    ctx.metadata
        .insert("ai_federation_status".to_string(), status.to_string());
    ctx.metadata
        .insert("ai_total_tokens".to_string(), tokens.to_string());
}

/// Assert a refusal is the generic enforcement-unavailable 503: no rate-limit
/// headers (this gateway has no authoritative counter to advertise) and no
/// endpoint, key, or credential disclosure in the body.
fn assert_generic_enforcement_unavailable(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            // A 503, not a 429: the caller is not over budget — the budget
            // cannot be evaluated at all.
            assert_eq!(status_code, 503);
            assert!(
                body.contains("temporarily unavailable"),
                "unexpected refusal body: {body}"
            );
            let lowered = body.to_ascii_lowercase();
            for secret in ["redis", "127.0.0.1", "ghsa87rq", "ferrum", "cluster"] {
                assert!(
                    !lowered.contains(secret),
                    "refusal must not disclose enforcement internals ({secret}): {body}"
                );
            }
            assert!(
                headers.is_empty(),
                "a fail-closed refusal must advertise no rate-limit headers: {headers:?}"
            );
        }
        other => panic!("expected a fail-closed refusal, got {other:?}"),
    }
}

/// The premise of the reconciliation tests: while centralized enforcement is
/// unavailable, admission itself refuses under the default policy.
#[tokio::test]
async fn fail_closed_admission_refuses_when_enforcement_is_unavailable() {
    let config = unreachable_redis_ai_config(None);
    let plugin = AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap();

    let mut ctx = ai_request_ctx(200, "hello admission");
    let mut request_headers = HashMap::new();
    let admission = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert_generic_enforcement_unavailable(admission);
}

/// Ordinary buffered response path: a 2xx whose actual token usage could not be
/// charged must not be delivered.
#[tokio::test]
async fn fail_closed_reconcile_refuses_uncharged_successful_response() {
    let config = unreachable_redis_ai_config(None);
    let plugin = AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap();

    let mut ctx = reconcilable_ai_ctx(&plugin, 120);
    let mut response_headers = json_headers();
    let body = openai_response(40, 60);
    let reconciled = plugin
        .on_response_body(&mut ctx, 200, &mut response_headers, &body)
        .await;
    assert_generic_enforcement_unavailable(reconciled);
    assert!(
        !response_headers.contains_key("x-ai-ratelimit-usage"),
        "no telemetry may be published for a budget nothing could evaluate"
    );
}

/// Federation/after-proxy reconciliation observes actual usage too (its provider
/// response is delivered as a synthetic short-circuit), so it must fail closed
/// on the same terms.
#[tokio::test]
async fn fail_closed_reconcile_refuses_uncharged_federated_response() {
    let config = unreachable_redis_ai_config(None);
    let plugin = AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap();

    let mut ctx = reconcilable_ai_ctx(&plugin, 120);
    mark_federated(&mut ctx, "200", "100");

    let mut response_headers = json_headers();
    let reconciled = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_generic_enforcement_unavailable(reconciled);
}

/// Safe-release semantics are preserved: when the response is already non-2xx,
/// a failed charge or release can only over-count this consumer's own budget, so
/// the error response stands rather than being swapped for a 503.
#[tokio::test]
async fn fail_closed_reconcile_keeps_an_already_failed_response() {
    let config = unreachable_redis_ai_config(None);
    let plugin = AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap();

    let mut ctx = reconcilable_ai_ctx(&plugin, 120);
    mark_federated(&mut ctx, "500", "100");

    let mut response_headers = json_headers();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 500, &mut response_headers)
            .await,
    );
}

/// The documented escape hatch still works — and only when asked for:
/// `local_fallback` reconciles the actual usage on per-process state instead of
/// refusing. The reservation lived on Redis, so the now-active local window is
/// charged the FULL actual usage rather than the relative delta.
#[tokio::test]
async fn local_fallback_reconcile_charges_local_state_instead_of_refusing() {
    let config = unreachable_redis_ai_config(Some("local_fallback"));
    let plugin = AiRateLimiter::new(&config, PluginHttpClient::default()).unwrap();

    let mut ctx = reconcilable_ai_ctx(&plugin, 120);
    let mut response_headers = json_headers();
    let body = openai_response(40, 60);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );
    assert_eq!(
        response_headers
            .get("x-ai-ratelimit-usage")
            .map(String::as_str),
        Some("100"),
        "local_fallback must reconcile actual usage on per-process state"
    );
}

// ─── GHSA-8f27-23x9-f825: HTTP-only protocol contract ────────────────────

/// Framed native-gRPC and gRPC-Web request bodies must never be buffered,
/// classified as a JSON AI request, or given a token reservation. Native gRPC
/// cannot reach these hooks at all under the HTTP-only protocol view; gRPC-Web
/// does ride the HTTP view, so the request-side screen is what keeps a
/// length-prefixed frame from being mistaken for a bare JSON AI document.
#[tokio::test]
async fn framed_grpc_requests_are_never_ai_candidates_or_reserved() {
    let plugin = AiRateLimiter::new(
        &json!({"token_limit": 1000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Unary, client/server/bidi-streaming (multiple concatenated frames),
    // compressed-message flag, and malformed/truncated framing — none of them
    // may produce a protected state.
    let cases: &[(&str, &str)] = &[
        // Unary frame whose payload happens to be an OpenAI-shaped AI request.
        (
            "application/grpc",
            "\u{0}\u{0}\u{0}\u{0}\u{2a}{\"model\":\"gpt-4o\",\"messages\":[],\"max_tokens\":500}",
        ),
        (
            "application/grpc+proto",
            "\u{0}\u{0}\u{0}\u{0}\u{6}\u{a}\u{4}chat",
        ),
        // `+json` variants satisfy the ordinary JSON content-type screen.
        (
            "application/grpc+json",
            "\u{0}\u{0}\u{0}\u{0}\u{2a}{\"model\":\"gpt-4o\",\"messages\":[],\"max_tokens\":500}",
        ),
        (
            "application/grpc-web+json",
            "\u{0}\u{0}\u{0}\u{0}\u{2a}{\"model\":\"gpt-4o\",\"messages\":[],\"max_tokens\":500}",
        ),
        ("application/grpc-web-text", "AAAAACp7Im1vZGVsIjoiZ3B0In0="),
        // Two concatenated frames (client-streaming shape).
        (
            "application/grpc+json",
            "\u{0}\u{0}\u{0}\u{0}\u{7}{\"a\":1}\u{0}\u{0}\u{0}\u{0}\u{7}{\"b\":1}",
        ),
        // Compressed-message flag set: payload is opaque to this plugin.
        ("application/grpc", "\u{1}\u{0}\u{0}\u{0}\u{8}\u{1f}\u{8b}"),
        // Malformed / truncated length prefix.
        ("application/grpc", "\u{0}\u{0}\u{0}"),
    ];

    for (content_type, body) in cases {
        let mut ctx = create_test_context();
        ctx.method = "POST".to_string();
        ctx.headers
            .insert("content-type".to_string(), (*content_type).to_string());
        ctx.metadata
            .insert("request_body".to_string(), (*body).to_string());

        assert!(
            !plugin.should_buffer_request_body(&ctx),
            "framed body must not be buffered for {content_type}"
        );

        let mut headers = ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            !ctx.metadata.contains_key("ai_ratelimit_request"),
            "framed body must not be classified as an AI request for {content_type}"
        );
        assert_eq!(
            reserved_tokens(&ctx),
            0,
            "framed body must not reserve tokens for {content_type}"
        );
        assert_eq!(
            plugin.reserved_tokens_for_test(&ctx),
            0,
            "framed body must not hold a reservation for {content_type}"
        );

        // The final-body hook is likewise inert: nothing was deferred, so it
        // must not retro-classify a framed body as an AI call.
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
        );
        assert!(!ctx.metadata.contains_key("ai_ratelimit_request"));
    }
}

/// A gRPC-Web framed response must not be parsed as a JSON usage document,
/// even when its media type ends in `+json` and its bytes happen to contain a
/// valid provider usage object. It is routed through the explicit
/// `on_unmetered_response` policy instead of being reconciled as if the
/// provider had reported usage.
#[tokio::test]
async fn framed_grpc_web_response_is_not_charged_as_json_usage() {
    // `observed_usage` reads `ai_ratelimit_usage` from metadata, which
    // `store_metadata` only writes when headers are exposed.
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

    let mut ctx = ai_request_ctx(120, "hello");
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(ctx.metadata.contains_key("ai_ratelimit_request"));
    let reserved = reserved_tokens(&ctx);
    assert!(reserved > 0, "an ordinary JSON AI POST must still reserve");

    // Body is byte-for-byte a valid OpenAI usage document; only the framed
    // content-type distinguishes it.
    let body = openai_response(400, 300);
    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web+json".to_string(),
    );
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &body)
            .await,
    );
    assert!(
        !ctx.metadata.contains_key("ai_ratelimit_actual_tokens"),
        "a framed gRPC-Web body must never be reconciled as provider-reported usage"
    );
    assert_eq!(
        plugin.unmetered_action_for_test(&ctx).as_deref(),
        Some("charge_estimate"),
        "framed gRPC-Web must take the unmetered policy path, not JSON usage extract"
    );
    // Default `charge_estimate` keeps the reservation rather than charging 0
    // or the embedded OpenAI usage total (700).
    assert_eq!(observed_usage(&plugin).await, reserved);
}

/// The framed-response screen is content-type scoped: ordinary HTTP JSON and
/// SSE AI responses keep their existing reconciliation behavior.
#[tokio::test]
async fn ordinary_json_and_sse_responses_remain_eligible() {
    let json_plugin = AiRateLimiter::new(
        &json!({"token_limit": 10_000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = ai_request_ctx(120, "hello");
    assert!(
        json_plugin.should_buffer_request_body(&ctx),
        "bare JSON AI POSTs must still be buffered"
    );
    let mut headers = ctx.headers.clone();
    assert_continue(json_plugin.before_proxy(&mut ctx, &mut headers).await);
    let mut response_headers = json_headers();
    let json_body = openai_response(400, 300);
    assert_continue(
        json_plugin
            .on_response_body(&mut ctx, 200, &mut response_headers, &json_body)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("ai_ratelimit_actual_tokens")
            .map(String::as_str),
        Some("700"),
        "an ordinary JSON usage block must still be charged"
    );

    let sse_plugin = AiRateLimiter::new(
        &json!({"token_limit": 10_000, "window_seconds": 60, "limit_by": "ip"}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut sse_ctx = ai_request_ctx(120, "hello");
    let mut sse_request_headers = sse_ctx.headers.clone();
    assert_continue(
        sse_plugin
            .before_proxy(&mut sse_ctx, &mut sse_request_headers)
            .await,
    );
    let sse_body =
        b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\ndata: [DONE]\n\n";
    let mut sse_response_headers = sse_headers();
    assert_continue(
        sse_plugin
            .on_response_body(&mut sse_ctx, 200, &mut sse_response_headers, sse_body)
            .await,
    );
    assert_eq!(
        sse_ctx
            .metadata
            .get("ai_ratelimit_actual_tokens")
            .map(String::as_str),
        Some("15"),
        "SSE usage extraction must be unchanged"
    );
}

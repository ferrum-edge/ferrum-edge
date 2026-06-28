//! Tests for ai_request_guard plugin

use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, ai_request_guard::AiRequestGuard, priority,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn make_post_ctx(body: &serde_json::Value) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(body).unwrap(),
    );
    ctx
}

fn make_post_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

// ─── Plugin basics ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_plugin_name_and_priority() {
    // Empty config is now rejected (would be a no-op); pass at least one
    // policy so we can still verify name/priority/buffering metadata.
    let plugin = AiRequestGuard::new(&json!({"max_messages": 1})).unwrap();
    assert_eq!(plugin.name(), "ai_request_guard");
    assert_eq!(plugin.priority(), priority::AI_REQUEST_GUARD);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.requires_response_body_buffering());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_empty_config_rejected() {
    // No policies configured → plugin would be a no-op → constructor errors.
    let err = AiRequestGuard::new(&json!({})).err().unwrap();
    assert!(
        err.contains("at least one policy must be configured"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for config in [
        json!("bad"),
        json!({"max_tokens_limit": "1000"}),
        json!({"enforce_max_tokens": "truncate"}),
        json!({"default_max_tokens": "4096"}),
        json!({"allowed_models": "gpt-4"}),
        json!({"allowed_models": ["gpt-4", 123]}),
        json!({"blocked_models": ["gpt-4", false]}),
        json!({"require_user_field": "true"}),
        json!({"max_messages": "10"}),
        json!({"max_prompt_characters": "1000"}),
        json!({"block_system_prompts": "false"}),
        json!({"required_metadata_fields": ["stream", 123]}),
        json!({"max_messages": 10, "fail_on_uninspectable_body": "false"}),
    ] {
        let result = AiRequestGuard::new(&config);
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_request_buffering_only_for_matching_json_requests() {
    let plugin = AiRequestGuard::new(&json!({"max_messages": 2})).unwrap();
    assert!(plugin.requires_request_body_buffering());

    let post_ctx = make_post_ctx(&json!({"messages": []}));
    assert!(plugin.should_buffer_request_body(&post_ctx));

    let mut get_ctx = make_post_ctx(&json!({"messages": []}));
    get_ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&get_ctx));

    let mut text_ctx = make_post_ctx(&json!({"messages": []}));
    text_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!plugin.should_buffer_request_body(&text_ctx));
}

// ─── Model blocking ────────────────────────────────────────────────────

#[tokio::test]
async fn test_blocked_model_rejected() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["o3", "gpt-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "o3", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_non_blocked_model_passes() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["o3"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4o-mini", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Model allowlist ───────────────────────────────────────────────────

#[tokio::test]
async fn test_allowed_model_passes() {
    let plugin =
        AiRequestGuard::new(&json!({"allowed_models": ["gpt-4o-mini", "gpt-4o"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4o-mini", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_unlisted_model_rejected() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4o-mini"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_blocked_takes_precedence_over_allowed() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4"],
        "blocked_models": ["gpt-4"]
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_case_insensitive_model_matching() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["GPT-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Max tokens ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_tokens_reject_over_limit() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 1000})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "max_tokens": 5000}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_max_tokens_reject_under_limit() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 1000})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "max_tokens": 500}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_max_tokens_clamp_mode() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 1000,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();
    assert!(plugin.modifies_request_body());

    // In clamp mode, before_proxy should NOT reject
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "max_tokens": 5000}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // transform_request_body should clamp the value
    let body = serde_json::to_vec(&json!({"model": "gpt-4", "max_tokens": 5000})).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["max_tokens"], 1000);
}

#[tokio::test]
async fn test_before_proxy_writes_clamped_max_tokens_to_metadata() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 1000,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "max_tokens": 5000}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // The metadata body should now contain the clamped value
    let updated_body: serde_json::Value =
        serde_json::from_str(ctx.metadata.get("request_body").unwrap()).unwrap();
    assert_eq!(
        updated_body["max_tokens"], 1000,
        "before_proxy must eagerly write clamped max_tokens back to metadata"
    );
}

#[tokio::test]
async fn test_before_proxy_writes_default_max_tokens_to_metadata() {
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 4096})).unwrap();

    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let updated_body: serde_json::Value =
        serde_json::from_str(ctx.metadata.get("request_body").unwrap()).unwrap();
    assert_eq!(
        updated_body["max_tokens"], 4096,
        "before_proxy must eagerly inject default_max_tokens into metadata"
    );
}

#[tokio::test]
async fn test_before_proxy_does_not_inject_default_for_non_object_json() {
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 4096})).unwrap();

    let mut ctx = make_post_ctx(&json!(["hello"]));
    let original_body = ctx.metadata.get("request_body").cloned().unwrap();
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("request_body").unwrap(),
        &original_body,
        "non-object JSON must remain unchanged"
    );
}

#[tokio::test]
async fn test_before_proxy_clamps_max_output_tokens_in_metadata() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 500,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({"model": "claude-3", "max_output_tokens": 2000}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let updated_body: serde_json::Value =
        serde_json::from_str(ctx.metadata.get("request_body").unwrap()).unwrap();
    assert_eq!(
        updated_body["max_output_tokens"], 500,
        "before_proxy must eagerly clamp max_output_tokens in metadata"
    );
}

#[tokio::test]
async fn test_before_proxy_no_metadata_write_when_under_limit() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 5000,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();

    let original_body = json!({"model": "gpt-4", "max_tokens": 1000});
    let mut ctx = make_post_ctx(&original_body);
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Body should be unchanged since max_tokens is within the limit
    let body_after: serde_json::Value =
        serde_json::from_str(ctx.metadata.get("request_body").unwrap()).unwrap();
    assert_eq!(
        body_after["max_tokens"], 1000,
        "max_tokens within limit should remain unchanged"
    );
}

#[tokio::test]
async fn test_max_output_tokens_clamped() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 500,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();
    let body =
        serde_json::to_vec(&json!({"model": "claude-3", "max_output_tokens": 2000})).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["max_output_tokens"], 500);
}

#[tokio::test]
async fn test_default_max_tokens_injected() {
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 4096})).unwrap();
    assert!(plugin.modifies_request_body());

    let body = serde_json::to_vec(&json!({"model": "gpt-4", "messages": []})).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["max_tokens"], 4096);
}

#[tokio::test]
async fn test_default_max_tokens_not_injected_when_present() {
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 4096})).unwrap();
    let body = serde_json::to_vec(&json!({"model": "gpt-4", "max_tokens": 100})).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    // No modification needed
    assert!(result.is_none());
}

// ─── Message limits ────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_messages_exceeded() {
    let plugin = AiRequestGuard::new(&json!({"max_messages": 2})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": "b"},
            {"role": "user", "content": "c"}
        ]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_max_messages_within_limit() {
    let plugin = AiRequestGuard::new(&json!({"max_messages": 5})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Prompt character limit ─────────────────────────────────────────────

#[tokio::test]
async fn test_max_prompt_characters_exceeded() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "this is a long prompt that exceeds the limit"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_multimodal_content_character_counting() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}},
                {"type": "text", "text": "world!"}
            ]
        }]
    }));
    let mut headers = make_post_headers();
    // "hello" (5) + "world!" (6) = 11 > 10
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_max_prompt_characters_counts_unicode_scalars_not_bytes() {
    // Regression for #41: the limit must count Unicode scalar values, not
    // UTF-8 bytes. Each CJK char is 3 bytes, so this 5-character prompt is
    // 15 bytes. Under a 10-character budget it must PASS (5 <= 10); a
    // byte-based count (15 > 10) would wrongly reject it.
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "你好世界!"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // And the same prompt exceeding the character budget is still rejected,
    // confirming the cap is enforced on character count (6 chars > 5).
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 5})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "你好世界!!"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Temperature range ──────────────────────────────────────────────────

#[tokio::test]
async fn test_temperature_out_of_range() {
    let plugin = AiRequestGuard::new(&json!({"temperature_range": [0.0, 1.0]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "temperature": 1.5}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_temperature_in_range() {
    let plugin = AiRequestGuard::new(&json!({"temperature_range": [0.0, 2.0]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "temperature": 0.7}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[test]
fn test_temperature_range_rejects_inverted_bounds() {
    // [max, min] would silently reject every request because the check is
    // `temp < min || temp > max`. Reject at construction time so the
    // misconfiguration cannot reach traffic.
    let err = AiRequestGuard::new(&json!({"temperature_range": [1.0, 0.0]}))
        .err()
        .unwrap();
    assert!(err.contains("min must be <= max"), "got: {err}");
}

#[test]
fn test_default_max_tokens_exceeding_limit_rejected() {
    // Regression for #42: a default_max_tokens above max_tokens_limit is a
    // contradictory cost-control config — the gateway would inject a value
    // that violates its own cap. Reject at construction time.
    let err = AiRequestGuard::new(&json!({
        "max_tokens_limit": 1000,
        "default_max_tokens": 4000
    }))
    .err()
    .unwrap();
    assert!(
        err.contains("'default_max_tokens'") && err.contains("max_tokens_limit"),
        "got: {err}"
    );
}

#[test]
fn test_default_max_tokens_within_limit_accepted() {
    // A default at or below the limit is a valid config and must construct.
    assert!(
        AiRequestGuard::new(&json!({
            "max_tokens_limit": 1000,
            "default_max_tokens": 1000
        }))
        .is_ok()
    );
    // default with no limit is also fine (nothing to contradict).
    assert!(AiRequestGuard::new(&json!({"default_max_tokens": 4000})).is_ok());
}

#[test]
fn test_temperature_range_rejects_wrong_arity() {
    let err = AiRequestGuard::new(&json!({"temperature_range": [0.0]}))
        .err()
        .unwrap();
    assert!(err.contains("exactly 2 elements"), "got: {err}");

    let err = AiRequestGuard::new(&json!({"temperature_range": [0.0, 1.0, 2.0]}))
        .err()
        .unwrap();
    assert!(err.contains("exactly 2 elements"), "got: {err}");
}

#[test]
fn test_temperature_range_rejects_non_array() {
    let err = AiRequestGuard::new(&json!({"temperature_range": "0,1"}))
        .err()
        .unwrap();
    assert!(err.contains("must be an array"), "got: {err}");
}

#[test]
fn test_temperature_range_rejects_non_numeric_bounds() {
    let err = AiRequestGuard::new(&json!({"temperature_range": ["low", "high"]}))
        .err()
        .unwrap();
    assert!(err.contains("must be a number"), "got: {err}");
}

// ─── System prompt blocking ─────────────────────────────────────────────

#[tokio::test]
async fn test_block_system_prompts() {
    let plugin = AiRequestGuard::new(&json!({"block_system_prompts": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": "Hello"}
        ]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_no_system_prompts_passes() {
    let plugin = AiRequestGuard::new(&json!({"block_system_prompts": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Require user field ─────────────────────────────────────────────────

#[tokio::test]
async fn test_require_user_field_missing() {
    let plugin = AiRequestGuard::new(&json!({"require_user_field": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_require_user_field_present() {
    let plugin = AiRequestGuard::new(&json!({"require_user_field": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": [], "user": "user-123"}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Non-AI request passthrough ─────────────────────────────────────────

#[tokio::test]
async fn test_non_post_passes() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "GET".to_string();
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_non_json_content_type_passes() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn missing_buffered_body_rejected_when_policy_requires_body() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(500));
    assert_eq!(
        ctx.metadata.get("ai_request_guard.uninspectable_body"),
        Some(&"true".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"missing_buffered_body".to_string())
    );
}

#[tokio::test]
async fn empty_buffered_body_rejected_when_policy_requires_body() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), String::new());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "0".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"empty_body".to_string())
    );
}

#[tokio::test]
async fn non_utf8_buffered_body_rejected_when_policy_requires_body() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "12".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"non_utf8_body".to_string())
    );
}

#[tokio::test]
async fn malformed_json_rejected_when_fail_on_uninspectable_body() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 1000})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid json{{{".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("Malformed JSON request body"));
            assert!(!body.contains("ai_request_guard"));
            assert!(!body.contains("expected ident"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata.get("ai_request_guard.uninspectable_body"),
        Some(&"true".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"malformed_json".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"reject".to_string())
    );
}

#[tokio::test]
async fn compatibility_mode_allows_backend_to_handle_malformed_json() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 1000,
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid json{{{".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

#[tokio::test]
async fn compatibility_mode_allows_empty_buffered_body() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4"],
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), String::new());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "0".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"empty_body".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

#[tokio::test]
async fn compatibility_mode_allows_non_utf8_buffered_body() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4"],
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Body was buffered (size recorded) but no UTF-8 `request_body` is present.
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "12".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"non_utf8_body".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

#[tokio::test]
async fn compatibility_mode_allows_missing_buffered_body() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4"],
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Neither `request_body` nor `request_body_size_bytes` is present: this is
    // the internal plugin-runner inconsistency path. Compatibility mode still
    // passes the request through (the error is logged at `error!`).
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"missing_buffered_body".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

// ─── Required metadata fields ───────────────────────────────────────────

#[tokio::test]
async fn test_required_metadata_fields_present() {
    let plugin = AiRequestGuard::new(&json!({"required_metadata_fields": ["stream"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": [], "stream": true}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_required_metadata_fields_missing() {
    let plugin = AiRequestGuard::new(&json!({"required_metadata_fields": ["stream"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Framed gRPC bodies are skipped, not rejected ───────────────────────

/// `application/grpc+json` matches `is_json_content_type` via its `+json`
/// suffix, but the buffered body is gRPC wire framing (5-byte header + message),
/// not a bare JSON document. The guard must Continue, not 400 it as malformed.
#[tokio::test]
async fn grpc_plus_json_framed_body_skipped() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    // 5-byte gRPC frame prefix (compression flag + 4-byte BE length) followed by
    // a tiny JSON message. As a whole this is not parseable as a JSON document.
    let mut framed = vec![0u8, 0, 0, 0, 2];
    framed.extend_from_slice(b"{}");
    // The frame happens to be valid UTF-8 here, so it would land in
    // `request_body`; the old code would have parse-error 400'd it.
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8_lossy(&framed).into_owned(),
    );
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "7".to_string());

    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    // No uninspectable-body bookkeeping should be recorded for skipped gRPC.
    assert!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body")
            .is_none()
    );
}

#[tokio::test]
async fn bare_grpc_content_type_skipped() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 10})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    // `application/grpc` (no `+json`) isn't even JSON, so it Continues at the
    // first content-type gate, but assert the behavior explicitly.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn grpc_web_text_is_not_treated_as_native_grpc() {
    // `application/grpc-web-text+json` is NOT native gRPC; the native-gRPC
    // classifier rejects the `-web` suffix. It still isn't a plain JSON document
    // the guard should inspect — but here we just assert the JSON gate still
    // applies (it ends in `+json`) and the guard inspects normally. The body is
    // valid JSON to avoid a false uninspectable reject.
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text+json".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({"model": "evil"}).to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text+json".to_string(),
    );
    // Because it is inspected as JSON and the model is blocked, it rejects.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn grpc_content_type_not_buffered() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ─── Compressed bodies are skipped, not rejected ────────────────────────

/// A gzipped JSON body is still compressed when `before_proxy` runs (the
/// `compression` plugin decompresses in the later `transform_request_body`
/// phase). The compressed bytes are not UTF-8, so the buffer path stores only
/// `request_body_size_bytes`. The guard must Continue, not 400 as `non_utf8_body`.
#[tokio::test]
async fn gzip_encoded_body_skipped_not_rejected() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    // Simulate the buffered-but-non-UTF-8 (still-compressed) body state.
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "42".to_string());

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body")
            .is_none(),
        "compressed bodies should be skipped before the uninspectable-body path"
    );
}

#[tokio::test]
async fn brotli_encoded_body_skipped() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 5})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "br".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "16".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "br".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn identity_content_encoding_still_inspected() {
    // `identity` is a no-op encoding: the body is plaintext JSON and must still
    // be inspected and rejected on a blocked model.
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4"}));
    ctx.headers
        .insert("content-encoding".to_string(), "identity".to_string());
    let mut headers = make_post_headers();
    headers.insert("content-encoding".to_string(), "identity".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn compressed_body_not_buffered() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));
}

#[tokio::test]
async fn plain_json_still_buffered_and_inspected() {
    // Guard against over-skipping: an ordinary plain JSON POST must still buffer
    // and still be inspected/rejected.
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4"}));
    assert!(plugin.should_buffer_request_body(&ctx));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

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

fn assert_reject_error(result: PluginResult, expected_status: u16, expected_error: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, expected_status);
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["error"], expected_error);
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
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
        json!({"require_model_for_model_policy": "true"}),
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

#[tokio::test]
async fn blocked_models_requires_model_or_documented_behavior() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();

    let mut missing_ctx = make_post_ctx(&json!({"messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut missing_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Missing required model field");

    let mut non_string_ctx = make_post_ctx(&json!({"model": 4, "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut non_string_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");
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
async fn allowed_models_requires_model() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4o"]})).unwrap();

    let mut missing_ctx = make_post_ctx(&json!({"messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut missing_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Missing required model field");

    let mut non_string_ctx = make_post_ctx(&json!({"model": true, "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut non_string_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");

    // A present-but-empty/whitespace string is "present but invalid", so it
    // reports the "Invalid model field" title (shared with the non-string arm),
    // not "Missing required model field".
    let mut empty_ctx = make_post_ctx(&json!({"model": "", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut empty_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");

    let mut whitespace_ctx = make_post_ctx(&json!({"model": "   ", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut whitespace_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");
}

#[tokio::test]
async fn default_config_rejects_empty_and_whitespace_model() {
    // Regression guard for the `trim().is_empty()` branch: an empty or
    // whitespace-only string `model` is present but unusable. With the default
    // config (require_model_for_model_policy defaults to true) both must fail
    // closed with the "Invalid model field" title — the same title the
    // non-string arm uses — not "Missing required model field".
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4o"]})).unwrap();

    let mut empty_ctx = make_post_ctx(&json!({"model": "", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut empty_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");

    let mut whitespace_ctx = make_post_ctx(&json!({"model": "   ", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut whitespace_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");

    // A tab/newline-only string is also whitespace and must be rejected.
    let mut ws_ctx = make_post_ctx(&json!({"model": "\t\n ", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ws_ctx, &mut headers).await;
    assert_reject_error(result, 400, "Invalid model field");
}

#[tokio::test]
async fn require_model_false_still_enforces_block_on_present_model() {
    // The opt-out only relaxes the *presence* requirement. A present, valid
    // string model that is explicitly blocked must STILL be rejected — the
    // false path previously only had coverage for a missing model.
    let plugin = AiRequestGuard::new(&json!({
        "blocked_models": ["gpt-4"],
        "require_model_for_model_policy": false
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject_error(result, 400, "Model not allowed");
}

#[tokio::test]
async fn require_model_false_still_enforces_allowlist_on_present_model() {
    // Same as above for an allowlist: a present model not on the allowed list
    // is rejected even with the presence requirement opted out.
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4o"],
        "require_model_for_model_policy": false
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4", "messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject_error(result, 400, "Model not allowed");
}

#[tokio::test]
async fn explicit_require_model_for_model_policy_true_rejects_missing_model() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4o"],
        "require_model_for_model_policy": true
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject_error(result, 400, "Missing required model field");
}

#[tokio::test]
async fn explicit_require_model_for_model_policy_false_allows_missing_model() {
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4o"],
        "require_model_for_model_policy": false
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"messages": []}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// The `require_model_for_model_policy: false` + present-but-blocked/unlisted
// model cases are covered by `require_model_false_still_enforces_block_on_present_model`
// and `require_model_false_still_enforces_allowlist_on_present_model` above,
// which assert the exact "Model not allowed" rejection title.

#[tokio::test]
async fn require_model_false_still_rejects_present_non_string_model() {
    // The opt-out only tolerates a *genuinely absent* model. A present but
    // non-string `model` (number/bool/array/object/null) must STILL be rejected
    // even with `require_model_for_model_policy: false` — otherwise a malformed
    // model value silently bypasses both the allowlist and the blocklist.
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4o"],
        "require_model_for_model_policy": false
    }))
    .unwrap();

    for bad_model in [
        json!(123),
        json!(true),
        json!(["gpt-4o"]),
        json!({"name": "gpt-4o"}),
        json!(null),
    ] {
        let mut ctx = make_post_ctx(&json!({"model": bad_model, "messages": []}));
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject_error(result, 400, "Invalid model field");
    }
}

#[tokio::test]
async fn require_model_false_still_rejects_present_empty_model() {
    // A present-but-empty/whitespace string is the same "present but invalid"
    // shape as a non-string value: it cannot satisfy the configured policy, so
    // it is rejected even under the presence opt-out. Also locks the shared
    // `details` message against drift.
    let plugin = AiRequestGuard::new(&json!({
        "allowed_models": ["gpt-4o"],
        "require_model_for_model_policy": false
    }))
    .unwrap();

    for empty_model in ["", "   ", "\t\n "] {
        let mut ctx = make_post_ctx(&json!({"model": empty_model, "messages": []}));
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 400);
                let body: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(body["error"], "Invalid model field");
                assert_eq!(
                    body["details"],
                    "The 'model' field must be a non-empty string when model policy is configured"
                );
            }
            other => panic!("Expected Reject, got {other:?}"),
        }
    }
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
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body")
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
async fn grpc_web_text_framed_body_skipped() {
    // `application/grpc-web-text+json` matches `is_json_content_type` via its
    // `+json` suffix, but a real gRPC-Web-text body is base64-encoded,
    // length-prefixed gRPC framing — not a bare JSON document. Parsing it as JSON
    // would 400 valid gRPC-Web traffic on a proxy that has `ai_request_guard` but
    // no `grpc_web` plugin (normally `grpc_web` rewrites the content-type to
    // native gRPC first). The guard must skip it, not reject it.
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text+json".to_string(),
    );
    // Even bare JSON content here must be skipped: the guard cannot tell framed
    // gRPC-Web from JSON by parsing, so it skips on content-type alone.
    ctx.metadata.insert(
        "request_body".to_string(),
        json!({"model": "evil"}).to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text+json".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body"),
        "framed gRPC-Web bodies are skipped before the uninspectable-body path"
    );
}

#[tokio::test]
async fn grpc_web_binary_content_type_skipped() {
    // Bare `application/grpc-web` (no `+json`) isn't JSON, so it Continues at the
    // first content-type gate; assert it explicitly.
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 10})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
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

// ─── Compressed bodies are deferred in before_proxy, then fail closed ────

/// A gzipped JSON body is still compressed when `before_proxy` runs (the
/// `compression` plugin decompresses in the later `transform_request_body`
/// phase). `before_proxy` cannot inspect it, so it DEFERS to
/// `on_final_request_body` by setting the deferred-compressed marker and
/// Continuing — it must not 400 as `non_utf8_body` here, and must not yet record
/// uninspectable-body bookkeeping.
#[tokio::test]
async fn gzip_encoded_body_deferred_in_before_proxy() {
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
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body"),
        "before_proxy defers compressed bodies; the uninspectable decision is made in on_final_request_body"
    );
    assert_eq!(
        ctx.metadata.get(plugin.deferred_compressed_marker_key()),
        Some(&"true".to_string()),
        "before_proxy must mark the compressed body for deferred inspection"
    );
}

#[tokio::test]
async fn brotli_encoded_body_deferred_in_before_proxy() {
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
    assert_eq!(
        ctx.metadata.get(plugin.deferred_compressed_marker_key()),
        Some(&"true".to_string())
    );
}

/// THE BYPASS GUARD: a caller gzips a blocked-model request on a proxy that has
/// `ai_request_guard` but no `compression`/`decompress_request`. `before_proxy`
/// defers; `on_final_request_body` sees the body is STILL `Content-Encoding:
/// gzip` (nothing decompressed it) and fails closed — the blocked model is NOT
/// bypassed.
#[tokio::test]
async fn compressed_body_still_encoded_fails_closed_in_final_hook() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    // before_proxy already ran and marked the deferral.
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    // Final backend headers still carry the encoding (no compression plugin
    // stripped it), so the still-compressed bytes are uninspectable.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    // Body is the raw (still-compressed) bytes — never parsed because the
    // encoding check fires first.
    let body = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata.get("ai_request_guard.uninspectable_body"),
        Some(&"true".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"compressed_body".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"reject".to_string())
    );
}

/// Compatibility mode (`fail_on_uninspectable_body: false`) forwards a
/// still-compressed body rather than rejecting it.
#[tokio::test]
async fn compressed_body_still_encoded_passes_in_compatibility_mode() {
    let plugin = AiRequestGuard::new(&json!({
        "blocked_models": ["evil"],
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "br".to_string());
    let body = vec![0x1b, 0x00, 0x00, 0x00];
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"compressed_body".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

/// When a `compression` plugin decompressed the body, `on_final_request_body`
/// sees plaintext JSON (no `Content-Encoding`) and enforces the full reject
/// policy — a blocked model in a previously-gzipped request is now rejected.
#[tokio::test]
async fn decompressed_body_validated_and_rejected_in_final_hook() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    // compression's before_proxy stripped Content-Encoding; transform_request_body
    // produced plaintext JSON, which is what the final hook receives.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = json!({"model": "evil"}).to_string().into_bytes();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_reject(result, Some(400));
    // A real policy reject, not an uninspectable-body reject.
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body"),
        "a decompressed-and-inspected body that violates policy is a normal reject, not uninspectable"
    );
}

/// A previously-gzipped request whose decompressed body is allowed Continues
/// through the final hook.
#[tokio::test]
async fn decompressed_allowed_body_continues_in_final_hook() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = json!({"model": "gpt-4"}).to_string().into_bytes();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
}

/// The final hook is a no-op for the common uncompressed path: without the
/// deferred marker (set only for compressed bodies), it must Continue without
/// re-validating, so plain bodies pay no second parse.
#[tokio::test]
async fn final_hook_noop_without_deferred_marker() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    // Even a blocked-model body Continues here — before_proxy already handled it
    // on the uncompressed path, and the final hook must not double-validate.
    let body = json!({"model": "evil"}).to_string().into_bytes();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body")
    );
}

/// A decompressed body that turns out to be empty or malformed still fails
/// closed in the final hook.
#[tokio::test]
async fn final_hook_empty_decompressed_body_fails_closed() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"")
        .await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"empty_body".to_string())
    );
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
async fn compressed_body_buffered_for_final_inspection() {
    // Compressed JSON bodies are now buffered (not skipped) so the
    // `on_final_request_body` hook can inspect them after decompression and fail
    // closed when they are still encoded. This is the fail-closed counterpart to
    // the old skip-and-pass behavior.
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[tokio::test]
async fn grpc_web_content_type_not_buffered() {
    // gRPC-Web framed bodies (length-prefixed / base64) are never bare JSON, so
    // they are skipped from buffering exactly like native gRPC.
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text+json".to_string(),
    );
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

/// Final-hook defensive content-type re-check: a deferred request whose
/// content-type was relabeled to a non-JSON type by an earlier-phase plugin must
/// Continue (the JSON policies do not apply), and must NOT record
/// uninspectable-body bookkeeping. The deferred marker is still consumed.
#[tokio::test]
async fn final_hook_non_json_content_type_skips_after_deferral() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    // Content-type is no longer JSON (relabeled), so the guard skips inspection.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let body = json!({"model": "evil"}).to_string().into_bytes();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body"),
        "a non-JSON content-type is out of scope, not uninspectable"
    );
    // The deferred marker must have been consumed by the hook.
    assert!(
        !ctx.metadata
            .contains_key(plugin.deferred_compressed_marker_key())
    );
}

/// Final-hook defensive content-type re-check: a deferred request relabeled to
/// framed gRPC (`application/grpc`) must Continue — framed gRPC wire bytes are
/// never bare JSON, so they are skipped, not rejected.
#[tokio::test]
async fn final_hook_framed_grpc_content_type_skips_after_deferral() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    );
    // Even a blocked-model JSON payload Continues — the content-type marks this
    // as framed gRPC, which is out of scope for JSON policy.
    let body = json!({"model": "evil"}).to_string().into_bytes();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body")
    );
}

/// Final-hook malformed JSON: a deferred body that was decompressed (no
/// `Content-Encoding`, non-empty) but is not valid JSON fails closed with reason
/// `malformed_json`, and the serde error detail never leaks to the client body.
#[tokio::test]
async fn final_hook_malformed_decompressed_body_fails_closed() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    // Decompression "succeeded" (no Content-Encoding) but produced garbage.
    let body = b"not valid json{{{".to_vec();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("Malformed JSON request body"));
            // The serde parse error detail is for logs only, never the client.
            assert!(!body.contains("expected"));
            assert!(!body.contains("ai_request_guard"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
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

/// Final-hook malformed JSON in compatibility mode
/// (`fail_on_uninspectable_body: false`): a decompressed-but-malformed body is
/// forwarded for the backend to handle, recording `action = allow`.
#[tokio::test]
async fn final_hook_malformed_decompressed_body_passes_in_compatibility_mode() {
    let plugin = AiRequestGuard::new(&json!({
        "blocked_models": ["evil"],
        "fail_on_uninspectable_body": false
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = b"}{ not json".to_vec();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"malformed_json".to_string())
    );
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_action"),
        Some(&"allow".to_string())
    );
}

/// `content-encoding` is tolerant of comma-separated lists: a list containing a
/// non-identity token (`identity, gzip`) marks the body compressed, so
/// `before_proxy` defers rather than parsing the compressed bytes.
#[tokio::test]
async fn comma_separated_content_encoding_with_compression_deferred() {
    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "identity, gzip".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "32".to_string());
    let mut headers = make_post_headers();
    headers.insert("content-encoding".to_string(), "identity, gzip".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get(plugin.deferred_compressed_marker_key()),
        Some(&"true".to_string()),
        "a comma-separated encoding list containing gzip must defer"
    );
    assert!(
        !ctx.metadata
            .contains_key("ai_request_guard.uninspectable_body")
    );
}

/// Comma-separated `content-encoding` in the final hook: a list with a
/// non-identity token (`gzip, br`) still means the body was never decompressed,
/// so the final hook fails closed with `compressed_body`.
#[tokio::test]
async fn comma_separated_content_encoding_still_encoded_fails_closed_in_final_hook() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "gzip, br".to_string());
    let body = vec![0x1f, 0x8b, 0x08, 0x00];
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata
            .get("ai_request_guard.uninspectable_body_reason"),
        Some(&"compressed_body".to_string())
    );
}

/// A `content-encoding` list whose every token is `identity` is a no-op: the
/// body is plaintext JSON and `before_proxy` must inspect it (not defer), so a
/// blocked model is still rejected inline.
#[tokio::test]
async fn all_identity_content_encoding_list_is_inspected() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4"}));
    ctx.headers.insert(
        "content-encoding".to_string(),
        "identity, identity".to_string(),
    );
    let mut headers = make_post_headers();
    headers.insert(
        "content-encoding".to_string(),
        "identity, identity".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert!(
        !ctx.metadata
            .contains_key(plugin.deferred_compressed_marker_key()),
        "an all-identity encoding list must not defer"
    );
}

// ─── Multi-instance deferral markers are instance-specific ───────────────

/// Two `ai_request_guard` instances configured differently on the same proxy
/// must use DISTINCT deferral marker keys, and `before_proxy` on a compressed
/// body must leave both markers set on the shared `ctx` — neither instance may
/// clobber or consume the other's marker.
#[tokio::test]
async fn two_instances_use_distinct_deferral_markers() {
    let guard_a = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let guard_b = AiRequestGuard::new(&json!({"allowed_models": ["claude"]})).unwrap();
    assert_ne!(
        guard_a.deferred_compressed_marker_key(),
        guard_b.deferred_compressed_marker_key(),
        "co-located instances must have distinct deferral marker keys"
    );

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "42".to_string());

    let mut headers = make_post_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    // Both instances run before_proxy on the SAME ctx (the plugin chain order).
    assert_continue(guard_a.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(guard_b.before_proxy(&mut ctx, &mut headers).await);

    // Both markers must be present simultaneously — each deferred its own.
    assert_eq!(
        ctx.metadata.get(guard_a.deferred_compressed_marker_key()),
        Some(&"true".to_string())
    );
    assert_eq!(
        ctx.metadata.get(guard_b.deferred_compressed_marker_key()),
        Some(&"true".to_string())
    );
}

/// REGRESSION (instance-specific markers): with two instances on the same proxy,
/// the first instance's `on_final_request_body` must NOT cause the second to skip
/// inspection. The decompressed body passes instance A's policy (so A Continues
/// and clears A's marker), but violates instance B's policy. B must still find
/// its own marker and reject — proving B's compressed-body policy is not silently
/// skipped after A consumed its marker.
#[tokio::test]
async fn second_instance_still_inspects_after_first_clears_its_marker() {
    // A allows everything except "evil"; B only allows "claude".
    let guard_a = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let guard_b = AiRequestGuard::new(&json!({"allowed_models": ["claude"]})).unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    // Both instances deferred this compressed request in before_proxy.
    ctx.metadata.insert(
        guard_a.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    ctx.metadata.insert(
        guard_b.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );

    // A `compression` plugin decompressed the body (Content-Encoding stripped);
    // the now-plaintext body names a model A allows but B does not.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = json!({"model": "gpt-4"}).to_string().into_bytes();

    // A inspects, allows, and clears ONLY its own marker.
    let result_a = guard_a
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_continue(result_a);
    assert!(
        !ctx.metadata
            .contains_key(guard_a.deferred_compressed_marker_key()),
        "A must clear its own marker"
    );
    // B's marker must survive A's run.
    assert!(
        ctx.metadata
            .contains_key(guard_b.deferred_compressed_marker_key()),
        "A must not consume B's marker"
    );

    // B still inspects the same decompressed body and rejects it (not skipped).
    let result_b = guard_b
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    assert_reject(result_b, Some(400));
    assert!(
        !ctx.metadata
            .contains_key(guard_b.deferred_compressed_marker_key()),
        "B must clear its own marker after inspecting"
    );
}

/// A long, non-gRPC JSON content-type carrying a `;charset` parameter
/// (`application/json; charset=utf-8`) is normal JSON: it is neither native gRPC
/// nor gRPC-Web, so it must be inspected and a blocked model rejected. Exercises
/// the gRPC-Web prefix-mismatch branch for a content-type at least as long as the
/// `application/grpc-web` prefix.
#[tokio::test]
async fn parameterized_json_content_type_is_inspected() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "gpt-4"}));
    ctx.headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
    let mut headers = make_post_headers();
    headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Uninspectable-body debug logging (lazy detail materialization) ──────
//
// `handle_uninspectable_body` builds its log-only `details` string lazily: for
// client-caused reasons (`empty_body` / `non_utf8_body` / `malformed_json` /
// `compressed_body`) the `details()` closure is invoked only when
// `tracing::enabled!(DEBUG)` is true, so it never allocates on a busy proxy with
// DEBUG disabled. The tests above all run with no subscriber installed, so that
// branch — and the per-call-site `format!` / `.to_string()` closures, plus the
// `debug!` reject arm — is never exercised. The tests below install a
// DEBUG-level subscriber so `tracing::enabled!(DEBUG)` returns true, forcing the
// lazy detail string (and the closures that build it) to run, and assert the
// log-only detail never leaks to the client body.

#[derive(Clone, Default)]
struct DebugLogCapture {
    buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl DebugLogCapture {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct DebugLogWriter {
    buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for DebugLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DebugLogCapture {
    type Writer = DebugLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DebugLogWriter {
            buffer: std::sync::Arc::clone(&self.buffer),
        }
    }
}

/// Install a DEBUG-level `fmt` subscriber as the thread-local default and return
/// the capture buffer + drop guard. `set_default` is thread-local, so callers
/// must run on a single-thread runtime (`flavor = "current_thread"`) so the
/// `debug!` calls land on the same thread the subscriber is bound to.
fn debug_capture() -> (DebugLogCapture, tracing::subscriber::DefaultGuard) {
    let capture = DebugLogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(capture.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}

/// With DEBUG enabled, a `malformed_json` reject in `before_proxy` materializes
/// the lazy detail string (the `format!("...: {err}")` closure runs), logs at
/// DEBUG, and rejects 400 — without leaking the serde parse detail to the client
/// body. Exercises the `Some(details())` branch + the `before_proxy`
/// `malformed_json` closure + the `debug!` reject arm.
#[tokio::test(flavor = "current_thread")]
async fn malformed_json_reject_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 1000})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid json{{{".to_string());
    let mut headers = make_post_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    drop(guard);

    // Client body carries only the generic message, never the serde detail.
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("Malformed JSON request body"));
            assert!(!body.contains("expected ident"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }

    // The lazily-built detail (with the serde error) reaches the DEBUG log.
    let captured = logs.contents();
    assert!(
        captured.contains("ai_request_guard: rejecting uninspectable request body"),
        "expected debug reject log, got: {captured:?}"
    );
    assert!(
        captured.contains("Malformed JSON request body cannot be inspected:"),
        "expected lazily-materialized detail in log, got: {captured:?}"
    );
}

/// With DEBUG enabled, an `empty_body` reject in `before_proxy` runs its
/// (different) detail closure and logs at DEBUG. Exercises the `before_proxy`
/// `empty_body` closure body under the `Some(details())` branch.
#[tokio::test(flavor = "current_thread")]
async fn empty_body_reject_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

    let plugin = AiRequestGuard::new(&json!({"allowed_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Present-but-empty buffered body → `empty_body` (not `missing_buffered_body`).
    ctx.metadata
        .insert("request_body".to_string(), String::new());
    let mut headers = make_post_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    drop(guard);

    assert_reject(result, Some(400));
    let captured = logs.contents();
    assert!(
        captured.contains("JSON request body is empty and cannot be inspected"),
        "expected empty-body detail in log, got: {captured:?}"
    );
}

/// With DEBUG enabled and compatibility mode on, a `malformed_json` body
/// Continues but still logs the lazily-built detail at DEBUG. Exercises the
/// `debug!` compatibility-mode arm together with `Some(details())`.
#[tokio::test(flavor = "current_thread")]
async fn malformed_json_compatibility_mode_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

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
    drop(guard);

    assert_continue(result);
    let captured = logs.contents();
    assert!(
        captured
            .contains("ai_request_guard: uninspectable request body allowed by compatibility mode"),
        "expected debug compatibility-mode log, got: {captured:?}"
    );
    assert!(
        captured.contains("Malformed JSON request body cannot be inspected:"),
        "expected lazily-materialized detail in compatibility-mode log, got: {captured:?}"
    );
}

/// With DEBUG enabled, the final-hook `compressed_body` reject runs its detail
/// closure (the still-encoded-after-transforms message) and logs at DEBUG.
/// Exercises the final-hook `compressed_body` closure under `Some(details())`.
#[tokio::test(flavor = "current_thread")]
async fn final_hook_compressed_body_reject_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let body = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    drop(guard);

    assert_reject(result, Some(400));
    let captured = logs.contents();
    assert!(
        captured.contains("Request body is still compressed after request transforms"),
        "expected compressed-body detail in log, got: {captured:?}"
    );
}

/// With DEBUG enabled, the final-hook `empty_body` reject (body decompressed to
/// empty) runs its detail closure and logs at DEBUG. Exercises the final-hook
/// `empty_body` closure under `Some(details())`.
#[tokio::test(flavor = "current_thread")]
async fn final_hook_empty_body_reject_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    // Decompressed (Content-Encoding stripped) but empty body.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body: Vec<u8> = Vec::new();

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    drop(guard);

    assert_reject(result, Some(400));
    let captured = logs.contents();
    assert!(
        captured.contains("Request body is empty after request transforms"),
        "expected final-hook empty-body detail in log, got: {captured:?}"
    );
}

/// With DEBUG enabled, the final-hook `malformed_json` reject runs its
/// `format!`-based detail closure and logs at DEBUG. Exercises the final-hook
/// `malformed_json` closure under `Some(details())`.
#[tokio::test(flavor = "current_thread")]
async fn final_hook_malformed_json_reject_logs_detail_at_debug() {
    let (logs, guard) = debug_capture();

    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["evil"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.metadata.insert(
        plugin.deferred_compressed_marker_key().to_string(),
        "true".to_string(),
    );
    // Decompressed but not valid JSON.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let body = b"not json{{{".to_vec();

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    drop(guard);

    assert_reject(result, Some(400));
    let captured = logs.contents();
    assert!(
        captured.contains("Malformed JSON request body cannot be inspected:"),
        "expected final-hook malformed-json detail in log, got: {captured:?}"
    );
}

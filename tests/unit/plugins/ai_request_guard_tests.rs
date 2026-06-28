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
        other => panic!("expected reject, got {other:?}"),
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
        json!({"supported_schema": 123}),
        json!({"supported_schema": "unsupported"}),
        json!({"strict_schema": "true"}),
        json!({"allowed_models": "gpt-4"}),
        json!({"allowed_models": ["gpt-4", 123]}),
        json!({"blocked_models": ["gpt-4", false]}),
        json!({"require_user_field": "true"}),
        json!({"max_messages": "10"}),
        json!({"max_prompt_characters": "1000"}),
        json!({"block_system_prompts": "false"}),
        json!({"system_prompt_aliases": "policy"}),
        json!({"system_prompt_aliases": ["policy", 123]}),
        json!({"required_metadata_fields": ["stream", 123]}),
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
async fn provider_native_token_fields_are_rejected_over_limit() {
    let plugin = AiRequestGuard::new(&json!({"max_tokens_limit": 1000})).unwrap();

    for body in [
        json!({
            "model": "gemini-2.0-flash",
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
            "generationConfig": {"maxOutputTokens": 2000}
        }),
        json!({
            "model": "anthropic.claude-3-sonnet",
            "messages": [{"role": "user", "content": [{"text": "hello"}]}],
            "inferenceConfig": {"maxTokens": 2000}
        }),
        json!({
            "model": "legacy-anthropic",
            "prompt": "Human: hello\n\nAssistant:",
            "max_tokens_to_sample": 2000
        }),
        json!({
            "model": "hf-model",
            "inputs": "hello",
            "max_new_tokens": 2000
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn provider_native_token_fields_are_clamped_in_metadata_and_transform() {
    let plugin = AiRequestGuard::new(&json!({
        "max_tokens_limit": 500,
        "enforce_max_tokens": "clamp"
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
        "generationConfig": {"maxOutputTokens": 2000}
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    let updated_body: serde_json::Value =
        serde_json::from_str(ctx.metadata.get("request_body").unwrap()).unwrap();
    assert_eq!(updated_body["generationConfig"]["maxOutputTokens"], 500);

    let body = serde_json::to_vec(&json!({
        "model": "anthropic.claude-3-sonnet",
        "messages": [{"role": "user", "content": [{"text": "hello"}]}],
        "inferenceConfig": {"maxTokens": 2000}
    }))
    .unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["inferenceConfig"]["maxTokens"], 500);
}

#[tokio::test]
async fn default_max_tokens_uses_provider_native_containers_when_detected() {
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 256})).unwrap();

    let gemini = serde_json::to_vec(&json!({
        "model": "gemini-2.0-flash",
        "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
    }))
    .unwrap();
    let result = plugin
        .transform_request_body(&gemini, Some("application/json"), &HashMap::new())
        .await;
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["generationConfig"]["maxOutputTokens"], 256);

    let bedrock = serde_json::to_vec(&json!({
        "model": "anthropic.claude-3-sonnet",
        "messages": [{"role": "user", "content": [{"text": "hello"}]}],
        "inferenceConfig": {}
    }))
    .unwrap();
    let result = plugin
        .transform_request_body(&bedrock, Some("application/json"), &HashMap::new())
        .await;
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["inferenceConfig"]["maxTokens"], 256);
}

#[tokio::test]
async fn default_max_tokens_routes_tgi_bodies_to_max_new_tokens() {
    // TGI / HuggingFace text-generation bodies cap output via `max_new_tokens`;
    // injecting a top-level `max_tokens` (which the backend ignores) would
    // silently drop the configured default cap.
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 256})).unwrap();

    let tgi = serde_json::to_vec(&json!({"inputs": "hello"})).unwrap();
    let result = plugin
        .transform_request_body(&tgi, Some("application/json"), &HashMap::new())
        .await;
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(modified["max_new_tokens"], 256);
    assert!(
        modified.get("max_tokens").is_none(),
        "TGI bodies must not receive an ignored top-level max_tokens"
    );
}

#[tokio::test]
async fn default_max_tokens_not_injected_when_tgi_already_caps_output() {
    // `max_new_tokens` already present means the client set its own cap, so the
    // guard must leave the body untouched.
    let plugin = AiRequestGuard::new(&json!({"default_max_tokens": 256})).unwrap();
    let tgi = serde_json::to_vec(&json!({"inputs": "hello", "max_new_tokens": 16})).unwrap();
    let result = plugin
        .transform_request_body(&tgi, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_none());
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

#[tokio::test]
async fn max_messages_counts_responses_input_and_provider_native_message_arrays() {
    let plugin = AiRequestGuard::new(&json!({"max_messages": 1})).unwrap();

    for body in [
        json!({
            "model": "gpt-4.1",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "first"}]},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "second"}]}
            ]
        }),
        json!({
            "model": "gemini-2.0-flash",
            "contents": [
                {"role": "user", "parts": [{"text": "first"}]},
                {"role": "user", "parts": [{"text": "second"}]}
            ]
        }),
        json!({
            "model": "command-r",
            "chat_history": [
                {"role": "USER", "message": "first"},
                {"role": "CHATBOT", "message": "second"}
            ],
            "message": "third"
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn max_messages_counts_cohere_top_level_message() {
    // Cohere-native requests carry the current user turn in a top-level
    // `message` string. With two prior `chat_history` entries it forms a
    // 3-message conversation, so a `max_messages: 2` cap must reject it; if the
    // top-level `message` were ignored the body would count as 2 and slip past.
    let plugin = AiRequestGuard::new(&json!({"max_messages": 2})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "command-r",
        "chat_history": [
            {"role": "USER", "message": "first"},
            {"role": "CHATBOT", "message": "second"}
        ],
        "message": "third"
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn max_messages_cohere_message_within_limit_passes() {
    // The same shape under a cap that accommodates the current turn must pass,
    // confirming the top-level `message` is counted as exactly one entry.
    let plugin = AiRequestGuard::new(&json!({"max_messages": 3})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "command-r",
        "chat_history": [
            {"role": "USER", "message": "first"},
            {"role": "CHATBOT", "message": "second"}
        ],
        "message": "third"
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

#[tokio::test]
async fn max_prompt_characters_counts_responses_instructions_and_input_without_messages() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();

    for body in [
        json!({
            "model": "gpt-4.1",
            "instructions": "Follow this very long policy instruction",
            "input": "short"
        }),
        json!({
            "model": "gpt-4.1",
            "input": [{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "this input text is too long"}]
            }]
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn max_prompt_characters_counts_provider_native_prompt_shapes() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 12})).unwrap();

    for body in [
        json!({
            "model": "claude-3",
            "system": "long top-level anthropic system",
            "messages": [{"role": "user", "content": "hi"}]
        }),
        json!({
            "model": "gemini-2.0-flash",
            "systemInstruction": {"parts": [{"text": "long gemini system"}]},
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        }),
        json!({
            "model": "anthropic.claude-3-sonnet",
            "system": [{"text": "long bedrock system"}],
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        }),
        json!({
            "model": "command-r",
            "preamble": "long cohere preamble",
            "message": "hi"
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn max_prompt_characters_counts_tools_arguments_and_rag_document_fields() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 20})).unwrap();

    for body in [
        json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "short"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "this tool description is intentionally long",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "very long query guidance"}
                        }
                    }
                }
            }]
        }),
        json!({
            "model": "gpt-4",
            "messages": [{
                "role": "assistant",
                "content": "short",
                "tool_calls": [{
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": "{\"query\":\"this tool argument is far too long\"}"
                    }
                }]
            }]
        }),
        json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "short"}],
            "context": "this retrieved context is too long"
        }),
        json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "short"}],
            "documents": [{"text": "this document text is too long"}]
        }),
        json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "short"}],
            "retrieved_context": [{"content": "this retrieved chunk is too long"}]
        }),
        json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "short"}],
            "tool_results": [{"content": "this tool result is too long"}]
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn max_prompt_characters_counts_tgi_inputs_field() {
    // TGI / HuggingFace text-generation prompts live in the plural `inputs`
    // field; the prompt-character cap must count them so a large prompt cannot
    // bypass the limit.
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "inputs": "this TGI prompt is well over ten characters",
        "max_new_tokens": 16
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));

    // A short `inputs` prompt under the cap still passes.
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({"inputs": "hi"}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn max_prompt_characters_counts_responses_function_call_output() {
    // Responses API follow-up requests feed tool results back as
    // `function_call_output` items whose `output` carries model-visible text.
    // That text must count toward the prompt budget.
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 10})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4.1",
        "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]},
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "this tool output is far longer than the ten character budget"
            }
        ]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn max_prompt_characters_ignores_non_text_multimodal_parts() {
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 8})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "short"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,THIS_IS_A_VERY_LONG_IMAGE_PAYLOAD"}},
                {"type": "input_audio", "input_audio": {"data": "THIS_IS_A_VERY_LONG_AUDIO_PAYLOAD"}}
            ]
        }]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
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
async fn block_system_prompts_rejects_developer_role_and_responses_instructions() {
    let plugin = AiRequestGuard::new(&json!({"block_system_prompts": true})).unwrap();

    for body in [
        json!({
            "model": "gpt-4.1",
            "messages": [
                {"role": "developer", "content": "You must follow this policy"},
                {"role": "user", "content": "Hello"}
            ]
        }),
        json!({
            "model": "gpt-4.1",
            "instructions": "You must follow this policy",
            "input": "Hello"
        }),
        json!({
            "model": "gpt-4.1",
            "input": [{
                "type": "message",
                "role": "developer",
                "content": [{"type": "input_text", "text": "You must follow this policy"}]
            }]
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn block_system_prompts_rejects_provider_native_system_fields() {
    let plugin = AiRequestGuard::new(&json!({"block_system_prompts": true})).unwrap();

    for body in [
        json!({
            "model": "claude-3",
            "system": "You must follow this policy",
            "messages": [{"role": "user", "content": "Hello"}]
        }),
        json!({
            "model": "gemini-2.0-flash",
            "systemInstruction": {"parts": [{"text": "You must follow this policy"}]},
            "contents": [{"role": "user", "parts": [{"text": "Hello"}]}]
        }),
        json!({
            "model": "command-r",
            "preamble": "You must follow this policy",
            "message": "Hello"
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn block_system_prompts_rejects_configured_alias_roles_and_fields() {
    let plugin = AiRequestGuard::new(&json!({
        "block_system_prompts": true,
        "system_prompt_aliases": ["policy"]
    }))
    .unwrap();

    for body in [
        json!({
            "model": "gpt-4",
            "messages": [{"role": "policy", "content": "internal policy"}]
        }),
        json!({
            "model": "gpt-4",
            "policy": "internal policy",
            "messages": [{"role": "user", "content": "Hello"}]
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
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

// ─── Schema admission ──────────────────────────────────────────────────

#[tokio::test]
async fn strict_schema_rejects_payloads_outside_configured_schema_family() {
    let plugin = AiRequestGuard::new(&json!({
        "strict_schema": true,
        "supported_schema": "responses"
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject_error(result, 400, "Unsupported AI request schema");
}

#[tokio::test]
async fn strict_chat_schema_rejects_provider_native_marker_bodies() {
    // A body carrying both a `messages` array and a provider-native top-level
    // marker (Anthropic `system`, Cohere `preamble`/`message`/`chat_history`,
    // RAG `documents`/`tool_results`) is NOT OpenAI Chat Completions and must be
    // rejected under strict `chat_completions`.
    let plugin = AiRequestGuard::new(&json!({
        "strict_schema": true,
        "supported_schema": "chat_completions"
    }))
    .unwrap();

    for body in [
        json!({"system": "you are helpful", "messages": [{"role": "user", "content": "hi"}]}),
        json!({"preamble": "be terse", "messages": [{"role": "user", "content": "hi"}]}),
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "chat_history": [{"role": "USER", "message": "prior"}]
        }),
        json!({
            "messages": [{"role": "user", "content": "hi"}],
            "documents": [{"text": "rag doc"}]
        }),
    ] {
        let mut ctx = make_post_ctx(&body);
        let mut headers = make_post_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject_error(result, 400, "Unsupported AI request schema");
    }
}

#[tokio::test]
async fn strict_chat_schema_admits_plain_chat_completions_body() {
    // A clean OpenAI Chat Completions body (no provider-native markers) must
    // still be admitted under strict `chat_completions`.
    let plugin = AiRequestGuard::new(&json!({
        "strict_schema": true,
        "supported_schema": "chat_completions"
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn strict_auto_schema_rejects_unknown_json_shapes() {
    let plugin = AiRequestGuard::new(&json!({"strict_schema": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({"not_an_ai_request": true}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject_error(result, 400, "Unsupported AI request schema");
}

#[tokio::test]
async fn non_strict_schema_keeps_compatibility_for_unknown_json_shapes() {
    let plugin = AiRequestGuard::new(&json!({
        "supported_schema": "responses",
        "max_prompt_characters": 10
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({"not_an_ai_request": true}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn strict_auto_schema_admits_legacy_completions_body() {
    // Default `supported_schema` is `auto`; strict mode must still admit a
    // legacy text-completion body (`{"model", "prompt"}`) rather than reject it
    // as an unsupported schema.
    let plugin = AiRequestGuard::new(&json!({"strict_schema": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({"model": "x", "prompt": "hi"}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn strict_auto_schema_admits_tgi_text_generation_body() {
    // TGI / HuggingFace text-generation shape (`{"inputs", "max_new_tokens"}`)
    // must also be admitted under strict + auto.
    let plugin = AiRequestGuard::new(&json!({"strict_schema": true})).unwrap();
    let mut ctx = make_post_ctx(&json!({"inputs": "hi", "max_new_tokens": 10}));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn count_tool_arguments_ignores_non_tool_call_arguments_keys() {
    // Regression guard for the arbitrary-nesting false positive: an `arguments`
    // key outside a legitimate tool-call location (here under `metadata`) must
    // NOT be counted toward `max_prompt_characters`, so a tiny request stays
    // admitted even though the nested blob is far over the limit.
    let plugin = AiRequestGuard::new(&json!({"max_prompt_characters": 20})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {
            "arguments": "this nested arguments blob is far longer than twenty chars"
        }
    }));
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
async fn test_empty_body_passes() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_malformed_json_passes() {
    let plugin = AiRequestGuard::new(&json!({"blocked_models": ["gpt-4"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not valid json{{{".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
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

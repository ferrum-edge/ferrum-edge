//! Tests for ai_token_metrics plugin

use ferrum_gateway::plugins::{Plugin, PluginResult, ai_token_metrics::AiTokenMetrics};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::create_test_context;

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
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
    let plugin = AiTokenMetrics::new(&json!({}));
    assert_eq!(plugin.name(), "ai_token_metrics");
    assert_eq!(plugin.priority(), 4100);
    assert!(plugin.requires_response_body_buffering());
}

// ─── OpenAI format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_openai_format() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
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
        .on_response_body(&mut ctx, 200, &headers, &body)
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
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "claude-sonnet-4-20250514",
        "usage": {
            "input_tokens": 200,
            "output_tokens": 80
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
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
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
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
        .on_response_body(&mut ctx, 200, &headers, &body)
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
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
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
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "80");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "50");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "30");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "command-r-plus");
}

// ─── Bedrock format ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_bedrock_format() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {
            "inputTokens": 150,
            "outputTokens": 75,
            "totalTokens": 225
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
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
    let plugin = AiTokenMetrics::new(&json!({"provider": "openai"}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

#[tokio::test]
async fn test_explicit_provider_mistral() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "mistral"}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "mistral-large",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "mistral");
}

// ─── Custom metadata prefix ─────────────────────────────────────────────

#[tokio::test]
async fn test_custom_prefix() {
    let plugin = AiTokenMetrics::new(&json!({"metadata_prefix": "llm"}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
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
    }));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    // Cost = 1000 * 0.00001 + 500 * 0.00003 = 0.01 + 0.015 = 0.025
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.025000");
}

#[tokio::test]
async fn test_cost_calculation_prompt_only() {
    // Embedding models only have input cost
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.0001
    }));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "total_tokens": 1000}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    // Cost = 1000 * 0.0001 + 0 * 0.0 = 0.1
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.100000");
}

#[tokio::test]
async fn test_cost_not_calculated_when_no_rates() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
}

// ─── include_model = false ──────────────────────────────────────────────

#[tokio::test]
async fn test_include_model_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_model": false}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_model"));
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

// ─── include_token_details = false ──────────────────────────────────────

#[tokio::test]
async fn test_include_token_details_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_token_details": false}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
}

// ─── Edge cases ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_non_json_content_type() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, b"not json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_empty_body() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();

    let result = plugin.on_response_body(&mut ctx, 200, &headers, b"").await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_malformed_json() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, b"not valid json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_missing_usage_fields() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({"id": "chatcmpl-123"})).unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_continue(result);
    // No provider detected, no metadata written
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_zero_tokens() {
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "0");
}

#[tokio::test]
async fn test_unknown_configured_provider() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "unknown_provider"}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_bedrock_computed_total() {
    // Bedrock without explicit totalTokens — should compute from input + output
    let plugin = AiTokenMetrics::new(&json!({}));
    let mut ctx = create_test_context();
    let headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 100, "outputTokens": 50}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
}

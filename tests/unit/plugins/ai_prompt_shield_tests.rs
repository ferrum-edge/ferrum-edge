//! Tests for ai_prompt_shield plugin

use ferrum_edge::plugins::{Plugin, PluginResult, ai_prompt_shield::AiPromptShield};
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

fn ai_request(content: &str) -> serde_json::Value {
    json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": content}]
    })
}

// ─── Plugin basics ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_plugin_name_and_priority() {
    let plugin = AiPromptShield::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ai_prompt_shield");
    assert_eq!(plugin.priority(), 2925);
    assert!(!plugin.requires_response_body_buffering());
    assert!(plugin.requires_request_body_buffering());
}

#[test]
fn test_request_buffering_only_for_matching_json_requests() {
    let plugin = AiPromptShield::new(&json!({
        "action": "warn",
        "patterns": ["ssn"]
    }))
    .unwrap();
    assert!(plugin.requires_request_body_buffering());

    let post_ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    assert!(plugin.should_buffer_request_body(&post_ctx));

    let mut get_ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    get_ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&get_ctx));

    let mut text_ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    text_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!plugin.should_buffer_request_body(&text_ctx));
}

#[test]
fn test_invalid_custom_regex_returns_error() {
    let result = AiPromptShield::new(&json!({
        "patterns": [],
        "custom_patterns": [
            {"name": "bad", "regex": "[invalid("}
        ]
    }));
    assert!(result.is_err());
}

// ─── SSN detection ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_ssn_detected_rejected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_ssn_no_separators() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("SSN: 123456789"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Credit card detection ──────────────────────────────────────────────

#[tokio::test]
async fn test_credit_card_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["credit_card"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("My card is 4111-1111-1111-1111"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Email detection ────────────────────────────────────────────────────

#[tokio::test]
async fn test_email_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["email"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Contact me at john@example.com"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── AWS key detection ──────────────────────────────────────────────────

#[tokio::test]
async fn test_aws_key_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["aws_key"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Key: AKIAIOSFODNN7EXAMPLE"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── API key detection ──────────────────────────────────────────────────

#[tokio::test]
async fn test_api_key_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["api_key"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Use sk_liveabcdefghijklmnopqrstuvwxyz"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── IBAN detection ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_iban_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["iban"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("My IBAN is GB29NWBK60161331926819"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── IP address detection ───────────────────────────────────────────────

#[tokio::test]
async fn test_ip_address_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ip_address"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Connect to server 10.20.30.40 now"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── No PII passes ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_no_pii_passes() {
    let plugin =
        AiPromptShield::new(&json!({"patterns": ["ssn", "credit_card", "email"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Hello, how are you doing today?"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Only configured patterns checked ───────────────────────────────────

#[tokio::test]
async fn test_only_configured_patterns_checked() {
    // Only SSN enabled — email should pass
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("Contact john@example.com for details"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Redact mode ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_redact_mode_ssn() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"]
    }))
    .unwrap();
    assert!(plugin.modifies_request_body());

    // before_proxy should continue (not reject)
    let mut ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(ctx.metadata.contains_key("ai_shield_redacted"));

    // transform_request_body should redact
    let body = serde_json::to_vec(&ai_request("My SSN is 123-45-6789")).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    let content = modified["messages"][0]["content"].as_str().unwrap();
    assert!(content.contains("[REDACTED:ssn]"));
    assert!(!content.contains("123-45-6789"));
}

#[tokio::test]
async fn test_redact_multiple_types() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn", "email"]
    }))
    .unwrap();

    let body =
        serde_json::to_vec(&ai_request("SSN: 123-45-6789, email: test@example.com")).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    let content = modified["messages"][0]["content"].as_str().unwrap();
    assert!(content.contains("[REDACTED:ssn]"));
    assert!(content.contains("[REDACTED:email]"));
}

// ─── Warn mode ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_warn_mode() {
    let plugin = AiPromptShield::new(&json!({
        "action": "warn",
        "patterns": ["ssn"]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_body());

    let mut ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("ai_shield_warnings").unwrap(), "ssn");
}

// ─── Custom patterns ────────────────────────────────────────────────────

#[tokio::test]
async fn test_custom_pattern() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": [],
        "custom_patterns": [
            {"name": "internal_id", "regex": "ACCT-\\d{8}"}
        ]
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&ai_request("Account ACCT-12345678 is active"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[test]
fn test_invalid_custom_regex_rejected_at_construction() {
    // Invalid regex should cause new() to return an error
    let result = AiPromptShield::new(&json!({
        "patterns": [],
        "custom_patterns": [
            {"name": "bad", "regex": "[invalid("}
        ]
    }));
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("failed to compile custom pattern"));
}

// ─── Exclude roles ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_exclude_roles() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "exclude_roles": ["system"]
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "SSN example: 123-45-6789"},
            {"role": "user", "content": "What is a SSN?"}
        ]
    }));
    let mut headers = make_post_headers();
    // System message has SSN but is excluded from scanning
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Scan modes ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_scan_all_mode() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "scan_fields": "all"
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "system_instruction": "SSN: 123-45-6789",
        "messages": [{"role": "user", "content": "Hello"}]
    }));
    let mut headers = make_post_headers();
    // SSN is in system_instruction, not in message content.
    // With "all" mode, the entire body is scanned.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_scan_content_only_mode() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "scan_fields": "content"
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "system_instruction": "SSN: 123-45-6789",
        "messages": [{"role": "user", "content": "Hello"}]
    }));
    let mut headers = make_post_headers();
    // SSN is in system_instruction, not in message content.
    // With "content" mode, only message content is scanned.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Max scan bytes ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_scan_bytes_exceeded() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "max_scan_bytes": 10
    }))
    .unwrap();
    let mut ctx = make_post_ctx(&ai_request("My SSN is 123-45-6789"));
    let mut headers = make_post_headers();
    // Body is larger than 10 bytes — should skip scanning
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Multimodal content ─────────────────────────────────────────────────

#[tokio::test]
async fn test_multimodal_content_scanned() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Look at this: 123-45-6789"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}}
            ]
        }]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Custom redaction placeholder ───────────────────────────────────────

#[tokio::test]
async fn test_custom_redaction_placeholder() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"],
        "redaction_placeholder": "***{type}***"
    }))
    .unwrap();

    let body = serde_json::to_vec(&ai_request("SSN: 123-45-6789")).unwrap();
    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    let content = modified["messages"][0]["content"].as_str().unwrap();
    assert!(content.contains("***ssn***"));
}

// ─── Non-POST / non-JSON passthrough ────────────────────────────────────

#[tokio::test]
async fn test_non_post_passes() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "GET".to_string();
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_non_json_content_type_passes() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "SSN: 123-45-6789".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_empty_body_passes() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Mixed clean and PII messages ───────────────────────────────────────

#[tokio::test]
async fn test_pii_in_any_message_detected() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hello, how are you?"},
            {"role": "assistant", "content": "I'm fine"},
            {"role": "user", "content": "My SSN is 123-45-6789"}
        ]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Redaction preserves JSON structure ─────────────────────────────────

#[tokio::test]
async fn test_redaction_preserves_json_structure() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"]
    }))
    .unwrap();

    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You help with forms"},
            {"role": "user", "content": "My SSN is 123-45-6789"}
        ],
        "max_tokens": 100,
        "temperature": 0.7
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_some());
    let modified: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();

    // Structure preserved
    assert_eq!(modified["model"], "gpt-4");
    assert_eq!(modified["max_tokens"], 100);
    assert_eq!(modified["temperature"], 0.7);
    assert_eq!(modified["messages"].as_array().unwrap().len(), 2);
    assert_eq!(modified["messages"][0]["role"], "system");
    assert_eq!(modified["messages"][0]["content"], "You help with forms");

    // Only user message content redacted
    let user_content = modified["messages"][1]["content"].as_str().unwrap();
    assert!(user_content.contains("[REDACTED:ssn]"));
    assert!(!user_content.contains("123-45-6789"));
}

// ─── Rejection body format ──────────────────────────────────────────────

#[tokio::test]
async fn test_rejection_body_format() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn", "email"]})).unwrap();
    let mut ctx = make_post_ctx(&ai_request("SSN: 123-45-6789, email: a@b.com"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "PII detected in request");
            let types = parsed["detected_types"].as_array().unwrap();
            assert!(!types.is_empty());
        }
        _ => panic!("Expected Reject"),
    }
}

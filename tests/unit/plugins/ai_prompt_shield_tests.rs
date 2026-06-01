//! Tests for ai_prompt_shield plugin

use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, ai_prompt_shield::AiPromptShield, priority,
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
    assert_eq!(plugin.priority(), priority::AI_PROMPT_SHIELD);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.requires_response_body_buffering());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.is_auth_plugin());
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

#[test]
fn test_invalid_config_shapes_rejected() {
    for config in [
        json!("bad"),
        json!({"action": "drop"}),
        json!({"action": 123}),
        json!({"scan_fields": "everything"}),
        json!({"exclude_roles": "system"}),
        json!({"patterns": ["ssn", 123]}),
        json!({"custom_patterns": "bad"}),
        json!({"patterns": [], "custom_patterns": [{"regex": "x"}]}),
        json!({"patterns": [], "custom_patterns": [{"name": "x"}]}),
        json!({"max_scan_bytes": 0}),
        json!({"max_scan_bytes": "1024"}),
    ] {
        let result = AiPromptShield::new(&config);
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
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
async fn test_redact_mode_updates_request_body_metadata_for_downstream_before_proxy() {
    // Regression test: ai_federation (and any other before_proxy plugin
    // that consumes the buffered body) reads `ctx.metadata["request_body"]`
    // directly and short-circuits the backend dispatch path via
    // RejectBinary. transform_request_body never runs on that path, so
    // unless before_proxy itself redacts the buffered body the original
    // un-redacted PII flows through to the AI provider.
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn", "email"]
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&ai_request("SSN 123-45-6789 email a@b.com"));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let stored = ctx
        .metadata
        .get("request_body")
        .expect("before_proxy must leave a request_body entry in metadata");
    assert!(
        !stored.contains("123-45-6789"),
        "original SSN must not survive in metadata: {stored}"
    );
    assert!(
        !stored.contains("a@b.com"),
        "original email must not survive in metadata: {stored}"
    );
    assert!(
        stored.contains("[REDACTED:ssn]"),
        "metadata must contain the SSN placeholder: {stored}"
    );
    assert!(
        stored.contains("[REDACTED:email]"),
        "metadata must contain the email placeholder: {stored}"
    );
}

#[tokio::test]
async fn test_redact_mode_no_pii_leaves_metadata_unchanged() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"]
    }))
    .unwrap();

    let request = ai_request("nothing sensitive here");
    let original = serde_json::to_string(&request).unwrap();
    let mut ctx = make_post_ctx(&request);
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("request_body").map(String::as_str),
        Some(original.as_str()),
        "without PII, metadata body must not be rewritten"
    );
    assert!(!ctx.metadata.contains_key("ai_shield_redacted"));
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

// ─── Built-in pattern errors ───────────────────────────────────────────

#[test]
fn test_unknown_builtin_pattern_is_fatal() {
    // Unknown built-in names previously logged a warning and silently
    // dropped detection coverage. They are now fatal so misconfiguration
    // cannot quietly disable PII protection.
    let err = AiPromptShield::new(&json!({"patterns": ["this_is_not_real"]}))
        .err()
        .unwrap();
    assert!(err.contains("unknown built-in pattern"), "got: {err}");
}

// ─── RegexSet single-pass detection ────────────────────────────────────

#[tokio::test]
async fn test_regex_set_detects_multiple_pattern_types_in_one_pass() {
    // RegexSet must report ALL matching patterns, not just the first.
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn", "email", "credit_card"],
        "action": "reject"
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&ai_request(
        "ssn 123-45-6789, email a@b.com, card 4111-1111-1111-1111",
    ));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            let types = parsed["detected_types"].as_array().unwrap();
            assert_eq!(types.len(), 3, "got types: {types:?}");
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

// ─── ScanMode::All — structural keys are protected ─────────────────────

#[tokio::test]
async fn test_all_mode_redacts_nonstructural_and_sensitive_fields() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap();

    // No `messages` key → recursive walker is exercised.
    let body = json!({
        "model": "10.0.0.1",
        "user": "192.168.1.1",
        "notes": "client at 8.8.8.8"
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let transformed = plugin
        .transform_request_body(&body_bytes, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["model"], "10.0.0.1", "structural model preserved");
    assert!(
        v["user"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "user should be redacted in all-mode: {}",
        v["user"]
    );
    assert!(
        v["notes"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "non-structural strings still redacted: {}",
        v["notes"]
    );
}

#[tokio::test]
async fn test_all_mode_uses_structured_redaction_when_messages_present() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap();

    let body = json!({
        "model": "10.0.0.1",
        "messages": [
            {"role": "user", "content": "ping 1.2.3.4"}
        ]
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let transformed = plugin
        .transform_request_body(&body_bytes, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["model"], "10.0.0.1");
    assert!(
        v["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "got: {}",
        v["messages"][0]["content"]
    );
}

#[tokio::test]
async fn test_all_mode_redacts_sibling_fields_when_messages_present() {
    // Regression test: when `scan_mode == All` and `messages` contains
    // PII, the plugin must still redact PII in sibling fields
    // (metadata, tool arguments, custom top-level strings). Previously
    // the either-or split meant the structured redactor ran and the
    // recursive walker was skipped, leaving sibling PII untouched even
    // though it was reported as "detected".
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap();

    let body = json!({
        "model": "10.0.0.1",
        "messages": [
            {"role": "user", "content": "ping 1.2.3.4"}
        ],
        "metadata": {"note": "client 8.8.8.8"},
        "custom_field": "also see 172.16.0.5"
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let transformed = plugin
        .transform_request_body(&body_bytes, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    // Structural key preserved
    assert_eq!(v["model"], "10.0.0.1", "structural model preserved");

    // Messages content redacted (structured redactor path)
    assert!(
        v["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "messages content should be redacted: {}",
        v["messages"][0]["content"]
    );

    // Sibling fields redacted (recursive walker path)
    assert!(
        v["metadata"]["note"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "metadata.note sibling should be redacted: {}",
        v["metadata"]["note"]
    );
    assert!(
        v["custom_field"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ip_address]"),
        "custom_field sibling should be redacted: {}",
        v["custom_field"]
    );
}

// ─── #8: PII nested under a structural key is still redacted ────────────

#[tokio::test]
async fn test_all_mode_redacts_pii_nested_under_structural_key() {
    // Finding #8 regression: redact_json_strings previously skipped the
    // ENTIRE subtree under any STRUCTURAL_KEYS name, so PII hidden under a
    // common key (e.g. "metadata"->"type", or "id"->"note") was reported as
    // detected but forwarded unredacted (a fail-open bypass driven by
    // attacker-controlled JSON structure). The fix preserves only TOP-LEVEL
    // structural scalar values (model name, IDs, request params) and redacts
    // everything nested below the top level, including nested occurrences of
    // structural key names and any container hiding PII.
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["credit_card", "ssn"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap();

    let body = json!({
        // Scalar structural keys must stay intact even though their values
        // could look like PII.
        "model": "gpt-4",
        "type": "chat.completion",
        // PII hidden under structural keys at depth — must be redacted.
        "metadata": {"type": "4111 1111 1111 1111"},
        "id": {"note": "123-45-6789"},
        // PII under a structural key inside an array — must be redacted.
        "object": [{"role": "card 4111-1111-1111-1111"}]
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let transformed = plugin
        .transform_request_body(&body_bytes, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body when nested PII present");
    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    // Scalar structural values preserved.
    assert_eq!(v["model"], "gpt-4", "scalar structural model preserved");
    assert_eq!(
        v["type"], "chat.completion",
        "scalar structural type preserved"
    );

    // PII nested under structural keys is redacted.
    let nested_cc = v["metadata"]["type"].as_str().unwrap();
    assert!(
        nested_cc.contains("[REDACTED:credit_card]") && !nested_cc.contains("4111"),
        "PII under metadata.type must be redacted, got: {nested_cc}"
    );
    let nested_ssn = v["id"]["note"].as_str().unwrap();
    assert!(
        nested_ssn.contains("[REDACTED:ssn]") && !nested_ssn.contains("123-45-6789"),
        "PII under id.note must be redacted, got: {nested_ssn}"
    );
    let nested_arr = v["object"][0]["role"].as_str().unwrap();
    assert!(
        nested_arr.contains("[REDACTED:credit_card]") && !nested_arr.contains("4111"),
        "PII under object[].role must be redacted, got: {nested_arr}"
    );
}

#[tokio::test]
async fn test_all_mode_redacts_deeply_nested_pii_under_structural_key() {
    // The whole serialized body must not retain the raw PII anywhere even
    // when it is buried several levels under a structural key name.
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap();

    let body = json!({
        "id": {"deep": {"value": "ssn 123-45-6789"}}
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let transformed = plugin
        .transform_request_body(&body_bytes, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let serialized = String::from_utf8(transformed).unwrap();
    assert!(
        !serialized.contains("123-45-6789"),
        "deeply nested PII under a structural key must not survive: {serialized}"
    );
    assert!(serialized.contains("[REDACTED:ssn]"));
}

// ─── #9: Content mode covers prompt / input / system shapes ─────────────

#[tokio::test]
async fn test_content_mode_scans_prompt_field() {
    // OpenAI legacy /v1/completions uses a top-level `prompt` string and no
    // `messages` array. Content mode (the default) must still detect PII.
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-3.5-turbo-instruct",
        "prompt": "My SSN is 123-45-6789"
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_content_mode_scans_input_field() {
    // Responses API / embeddings use a top-level `input` field.
    let plugin = AiPromptShield::new(&json!({"patterns": ["email"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "text-embedding-3-small",
        "input": "Contact me at john@example.com"
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_content_mode_scans_system_field() {
    // Anthropic carries a top-level `system` string alongside messages.
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "claude-3-5-sonnet",
        "system": "The patient SSN is 123-45-6789",
        "messages": [{"role": "user", "content": "Summarize."}]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_content_mode_scans_responses_instructions_field() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "instructions": "Use SSN 123-45-6789 as the sample identifier",
        "input": "Summarize this request"
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_content_mode_scans_input_array_and_text_parts() {
    // `input` may be an array of strings or of {type:"text", text} parts.
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();

    let mut ctx = make_post_ctx(&json!({
        "model": "text-embedding-3-small",
        "input": ["benign", "leak 123-45-6789"]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [{"type": "text", "text": "ssn 123-45-6789"}]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_content_mode_scans_structured_responses_input() {
    // The OpenAI Responses API uses `input_text`/`output_text` content-part
    // types (not `text`) and a structured `input` array of message objects
    // `{role, content: [parts]}`. Content mode must scan both shapes, else PII
    // passes through on the default scan mode for the default Responses payload.
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();

    // `input_text` content-part type.
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [{"type": "input_text", "text": "ssn 123-45-6789"}]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    // Structured message-object input with nested content parts.
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "leak 123-45-6789"}]}
        ]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    // Message-object input whose content is a plain string.
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [{"role": "user", "content": "leak 123-45-6789"}]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_content_mode_responses_input_honors_exclude_roles() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "exclude_roles": ["system"]
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": "ignore 123-45-6789"}]},
            {"role": "user", "content": [{"type": "input_text", "text": "clean request"}]}
        ]
    }));
    let mut headers = make_post_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-4o",
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": "ignore 123-45-6789"}]},
            {"role": "user", "content": [{"type": "input_text", "text": "block 987-65-4321"}]}
        ]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_content_mode_top_level_system_is_not_role_excluded() {
    let plugin = AiPromptShield::new(&json!({
        "patterns": ["ssn"],
        "exclude_roles": ["system"]
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({
        "model": "claude-3-5-sonnet",
        "system": "operator sample 123-45-6789",
        "messages": [{"role": "user", "content": "clean request"}]
    }));
    let mut headers = make_post_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_content_mode_top_level_system_redaction_is_not_role_excluded() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"],
        "exclude_roles": ["system"]
    }))
    .unwrap();

    let body = serde_json::to_vec(&json!({
        "model": "claude-3-5-sonnet",
        "system": "operator sample 123-45-6789",
        "messages": [{"role": "user", "content": "clean request"}]
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let v: serde_json::Value = serde_json::from_slice(&result).unwrap();
    let system = v["system"].as_str().unwrap();
    assert!(
        system.contains("[REDACTED:ssn]") && !system.contains("123-45-6789"),
        "top-level system field must be redacted: {system}"
    );
}

#[tokio::test]
async fn test_content_mode_no_pii_in_prompt_passes() {
    // Negative case: clean prompt/input/system payloads still pass through.
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn", "email"]})).unwrap();
    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-3.5-turbo-instruct",
        "prompt": "Write a haiku about spring",
        "system": "You are a helpful assistant",
        "input": ["nothing", "sensitive"]
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_content_mode_redacts_prompt_input_system_fields() {
    // Detection and redaction must stay symmetric: PII in prompt/input/system
    // is not just detected but actually rewritten in redact mode.
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn", "email"]
    }))
    .unwrap();

    let body = serde_json::to_vec(&json!({
        "model": "gpt-3.5-turbo-instruct",
        "prompt": "ssn 123-45-6789",
        "system": "email a@b.com",
        "instructions": "email c@d.com",
        "input": ["card holder", "ssn 987-65-4321"]
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let v: serde_json::Value = serde_json::from_slice(&result).unwrap();

    let prompt = v["prompt"].as_str().unwrap();
    assert!(
        prompt.contains("[REDACTED:ssn]") && !prompt.contains("123-45-6789"),
        "prompt must be redacted: {prompt}"
    );
    let system = v["system"].as_str().unwrap();
    assert!(
        system.contains("[REDACTED:email]") && !system.contains("a@b.com"),
        "system must be redacted: {system}"
    );
    let instructions = v["instructions"].as_str().unwrap();
    assert!(
        instructions.contains("[REDACTED:email]") && !instructions.contains("c@d.com"),
        "instructions must be redacted: {instructions}"
    );
    let input1 = v["input"][1].as_str().unwrap();
    assert!(
        input1.contains("[REDACTED:ssn]") && !input1.contains("987-65-4321"),
        "input array element must be redacted: {input1}"
    );
}

#[tokio::test]
async fn test_content_mode_responses_input_redaction_honors_exclude_roles() {
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"],
        "exclude_roles": ["system"]
    }))
    .unwrap();

    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": "keep 123-45-6789"}]},
            {"role": "user", "content": [{"type": "input_text", "text": "redact 987-65-4321"}]}
        ]
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(&body, Some("application/json"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let v: serde_json::Value = serde_json::from_slice(&result).unwrap();

    let system_text = v["input"][0]["content"][0]["text"].as_str().unwrap();
    assert_eq!(system_text, "keep 123-45-6789");
    let user_text = v["input"][1]["content"][0]["text"].as_str().unwrap();
    assert!(
        user_text.contains("[REDACTED:ssn]") && !user_text.contains("987-65-4321"),
        "user Responses input must be redacted: {user_text}"
    );
}

#[tokio::test]
async fn test_content_mode_prompt_field_metadata_no_passthrough() {
    // before_proxy must scrub the PII it reports as redacted from the
    // buffered request_body metadata (consumed by downstream before_proxy
    // plugins), not just rely on transform_request_body.
    let plugin = AiPromptShield::new(&json!({
        "action": "redact",
        "patterns": ["ssn"]
    }))
    .unwrap();

    let mut ctx = make_post_ctx(&json!({
        "model": "gpt-3.5-turbo-instruct",
        "prompt": "My SSN is 123-45-6789"
    }));
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(ctx.metadata.contains_key("ai_shield_redacted"));

    let stored = ctx.metadata.get("request_body").unwrap();
    assert!(
        !stored.contains("123-45-6789"),
        "PII must not survive in metadata body: {stored}"
    );
    assert!(stored.contains("[REDACTED:ssn]"));
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

// ─── Streaming awareness ───────────────────────────────────────────────

#[tokio::test]
async fn test_streaming_metadata_set_when_stream_true() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let body = json!({
        "model": "gpt-4",
        "stream": true,
        "messages": [{"role": "user", "content": "Hello, how are you?"}]
    });
    let mut ctx = make_post_ctx(&body);
    let mut headers = make_post_headers();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(|s| s.as_str()),
        Some("true"),
        "stream:true should set metadata"
    );
}

#[tokio::test]
async fn test_streaming_metadata_not_set_when_stream_false() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let body = json!({
        "model": "gpt-4",
        "stream": false,
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let mut ctx = make_post_ctx(&body);
    let mut headers = make_post_headers();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !ctx.metadata.contains_key("ai_request_streaming"),
        "stream:false should not set metadata"
    );
}

#[tokio::test]
async fn test_streaming_metadata_not_set_when_absent() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"]})).unwrap();
    let body = json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let mut ctx = make_post_ctx(&body);
    let mut headers = make_post_headers();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!ctx.metadata.contains_key("ai_request_streaming"));
}

#[tokio::test]
async fn test_pii_detection_still_works_with_stream_true() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"], "action": "reject"})).unwrap();
    let body = json!({
        "model": "gpt-4",
        "stream": true,
        "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]
    });
    let mut ctx = make_post_ctx(&body);
    let mut headers = make_post_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Streaming metadata should be set
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(|s| s.as_str()),
        Some("true")
    );
    // PII should still be detected
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_streaming_metadata_with_scan_all_mode() {
    let plugin = AiPromptShield::new(&json!({"patterns": ["ssn"], "scan_fields": "all"})).unwrap();
    let body = json!({
        "model": "gpt-4",
        "stream": true,
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let mut ctx = make_post_ctx(&body);
    let mut headers = make_post_headers();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(|s| s.as_str()),
        Some("true"),
        "scan_all mode should still detect streaming intent"
    );
}

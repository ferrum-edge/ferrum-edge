use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> AiResponseGuard {
    AiResponseGuard::new(&config).unwrap()
}

#[test]
fn test_new_with_pii_patterns() {
    let config = json!({
        "pii_patterns": ["ssn", "credit_card", "email"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_blocked_phrases() {
    let config = json!({
        "blocked_phrases": ["kill yourself", "illegal activity"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_blocked_patterns() {
    let config = json!({
        "blocked_patterns": [
            {"name": "profanity", "regex": "\\b(?:damn|hell)\\b"}
        ],
        "action": "warn"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_required_fields() {
    let config = json!({
        "required_fields": ["choices", "model"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_max_completion_length() {
    let config = json!({
        "max_completion_length": 1000,
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_no_patterns_fails() {
    let config = json!({});
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no patterns, phrases, or validation rules")
    );
}

#[test]
fn test_new_invalid_custom_regex_fails() {
    let config = json!({
        "blocked_patterns": [
            {"name": "bad", "regex": "[invalid"}
        ]
    });
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
}

#[test]
fn test_new_invalid_custom_pii_regex_fails() {
    let config = json!({
        "custom_pii_patterns": [
            {"name": "bad", "regex": "(unclosed"}
        ]
    });
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_pii_detection_reject() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Your SSN is 123-45-6789"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("content guard"));
            assert!(body.contains("pii:ssn"));
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

#[tokio::test]
async fn test_pii_detection_warn() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "warn"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Contact us at user@example.com"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_detected"));
}

#[tokio::test]
async fn test_pii_detection_redact() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "redact"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Contact us at user@example.com"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    // on_response_body marks for redaction
    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    // transform_response_body actually redacts
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await;
    assert!(transformed.is_some());
    let transformed_str = String::from_utf8(transformed.unwrap()).unwrap();
    assert!(!transformed_str.contains("user@example.com"));
    assert!(transformed_str.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_blocked_phrase_detection() {
    let config = json!({
        "blocked_phrases": ["harmful content"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "This contains harmful content that should be blocked"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_clean_response_passes() {
    let config = json!({
        "pii_patterns": ["ssn", "credit_card"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "The weather is nice today"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_non_json_skipped() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, b"Your SSN is 123-45-6789")
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_error_status_skipped() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "SSN: 123-45-6789"}}]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    // 4xx/5xx responses are not scanned
    let result = plugin
        .on_response_body(&mut ctx, 400, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_required_fields_missing() {
    let config = json!({
        "required_fields": ["choices", "model"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "hi"}}]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("model"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_max_completion_length() {
    let config = json!({
        "max_completion_length": 10,
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "This is a very long completion that exceeds the limit"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_anthropic_response_format() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "content": [{
            "type": "text",
            "text": "Please email admin@secret.com for help"
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[test]
fn test_require_json_config() {
    let config = json!({
        "require_json": true
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_redact_action_with_no_patterns_still_works_with_other_rules() {
    let config = json!({
        "max_completion_length": 100,
        "action": "redact"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_unknown_builtin_pii_pattern_is_fatal() {
    // Unknown built-in names previously logged a warning and silently
    // dropped detection coverage. They are now fatal so misconfiguration
    // cannot quietly disable PII protection.
    let err = AiResponseGuard::new(&json!({
        "pii_patterns": ["this_is_not_a_real_pii_type"],
        "action": "reject"
    }))
    .err()
    .unwrap();
    assert!(err.contains("unknown built-in PII pattern"), "got: {err}");
}

// ─── ScanMode::All — structural keys are protected from redaction ─────

fn ipv4_redact_plugin() -> AiResponseGuard {
    // ip_address pattern is broad and will match strings that look like
    // dotted quads — including timestamps in the form "2024.01.15.10".
    AiResponseGuard::new(&json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap()
}

#[tokio::test]
async fn test_all_mode_does_not_redact_structural_keys() {
    // The previous implementation walked every string in the response and
    // would happily rewrite values under structural keys like `id`,
    // `model`, `created`, etc. Verify those are now protected even when
    // the value matches a PII pattern.
    let plugin = ipv4_redact_plugin();

    // Body has no recognized AI shape (no "choices", "content",
    // "candidates"), so the recursive walker is exercised.
    let body = serde_json::to_vec(&json!({
        "id": "127.0.0.1",        // looks like an IP — must be preserved
        "model": "10.20.30.40",   // also IP-shaped — must be preserved
        "details": "user IP was 192.168.1.99 last seen"
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();

    // First trigger detection; then call transform_response_body to apply.
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected redacted body when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["id"], "127.0.0.1", "structural id must be preserved");
    assert_eq!(
        v["model"], "10.20.30.40",
        "structural model must be preserved"
    );
    assert!(
        v["details"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "non-structural strings should still be redacted: {}",
        v["details"]
    );
}

#[tokio::test]
async fn test_all_mode_uses_structured_redaction_when_choices_present() {
    // When the body looks like a recognized AI response (has `choices`),
    // even ScanMode::All should prefer the structured redactor that only
    // touches choices[].message.content rather than the recursive walker.
    let plugin = ipv4_redact_plugin();

    let body = serde_json::to_vec(&json!({
        "id": "10.0.0.1",
        "model": "127.0.0.1",
        "choices": [{
            "message": {"role": "assistant", "content": "Server lives at 8.8.8.8"}
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected transformation when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["id"], "10.0.0.1");
    assert_eq!(v["model"], "127.0.0.1");
    assert!(
        v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "completion content should be redacted: {}",
        v["choices"][0]["message"]["content"]
    );
}

#[tokio::test]
async fn test_all_mode_redacts_sibling_fields_when_choices_present() {
    // Regression test: when `scan_mode == All` and `choices` contains
    // PII, the plugin must still redact PII in sibling fields outside
    // the recognized completion shape. Previously the either-or split
    // meant the structured redactor ran and the recursive walker was
    // skipped, leaving sibling PII untouched even though detection
    // reported it.
    let plugin = ipv4_redact_plugin();

    let body = serde_json::to_vec(&json!({
        "id": "10.0.0.1",                 // structural — must be preserved
        "model": "127.0.0.1",             // structural — must be preserved
        "choices": [{
            "message": {"role": "assistant", "content": "Server lives at 8.8.8.8"}
        }],
        "metadata": {"trace": "upstream 192.168.1.1 responded"},
        "extra": "see also 172.16.0.5"
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected transformation when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    // Structural keys preserved
    assert_eq!(v["id"], "10.0.0.1", "structural id must be preserved");
    assert_eq!(
        v["model"], "127.0.0.1",
        "structural model must be preserved"
    );

    // Known completion content redacted (structured redactor path)
    assert!(
        v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "completion content should be redacted: {}",
        v["choices"][0]["message"]["content"]
    );

    // Sibling fields redacted (recursive walker path)
    assert!(
        v["metadata"]["trace"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "metadata.trace sibling should be redacted: {}",
        v["metadata"]["trace"]
    );
    assert!(
        v["extra"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "extra sibling should be redacted: {}",
        v["extra"]
    );
}

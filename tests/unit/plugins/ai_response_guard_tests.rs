use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> AiResponseGuard {
    AiResponseGuard::new(&config).unwrap()
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
    assert!(
        ctx.metadata
            .get("ai_response_guard_rejected")
            .is_some_and(|value| value.contains("pii:ssn")),
        "reject marker missing or wrong: {:?}",
        ctx.metadata.get("ai_response_guard_rejected")
    );
}

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

// Feature regression guard: the WHOLE POINT of funnelling synthetic
// short-circuit bodies through the response-body hooks is that response GUARDS
// finally inspect them. So even when the synthetic marker is set (a cache hit /
// `response_mock` / federation body), `ai_response_guard` MUST still scan the
// body and reject a malicious one. This is the counterpart to the
// storage/accounting plugins (`ai_semantic_cache`, `ai_token_metrics`) that skip
// synthetic bodies: guards must NOT skip — they must keep inspecting.
#[tokio::test]
async fn guard_still_rejects_bad_synthetic_short_circuit_body() {
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
    // The body arrived via a synthetic short-circuit (e.g. a poisoned cache
    // entry or a `response_mock` leaking PII). The proxy marks the context.
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("pii:ssn"));
        }
        _ => panic!(
            "guard must still reject a malicious synthetic short-circuit body, got {result:?}"
        ),
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
async fn test_all_mode_decodes_json_escaped_pii_for_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"content":"Contact user\u0040example.com"}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    let transformed = plugin
        .transform_response_body(body, Some("application/json"), &headers)
        .await
        .expect("expected escaped email to be redacted");
    let value: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(
        value["choices"][0]["message"]["content"],
        "Contact [REDACTED:pii:email]"
    );
}

#[tokio::test]
async fn test_all_mode_detects_blocked_phrase_in_object_key() {
    // codex: ScanMode::All must scan object KEYS, not just string values — the
    // previous raw-body scan covered the whole serialized body (field names
    // included), so a blocked phrase hidden in a JSON key must still be caught.
    let plugin = make_plugin(json!({
        "blocked_phrases": ["harmful content"],
        "scan_fields": "all",
        "action": "reject"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"harmful content":"ok"}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a blocked phrase in a JSON object key must be detected in scan-all mode"
    );
}

#[tokio::test]
async fn test_all_mode_detects_pii_in_numeric_scalar() {
    // codex: ScanMode::All previously scanned the raw serialized body, which
    // matched a numeric SSN like {"ssn":123456789}. The decoded walker must
    // include numeric scalars (stringified) or this content fails open.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "scan_fields": "all",
        "action": "reject"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"ssn":123456789}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a numeric SSN scalar must be detected in scan-all mode"
    );
}

#[tokio::test]
async fn test_all_mode_detects_cross_token_custom_pattern() {
    // codex: a custom blocked_patterns regex written for the documented
    // whole-body scan (e.g. matching JSON field/value context) must keep
    // matching in scan-all mode. The decoded walker feeds the key and value as
    // separate fragments, so only a raw-body union pass reconstructs the
    // `"role":"tool"` context.
    let plugin = make_plugin(json!({
        "blocked_patterns": [
            {"name": "tool_role", "regex": "\"role\"\\s*:\\s*\"tool\""}
        ],
        "scan_fields": "all",
        "action": "reject"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"role":"tool","content":"ok"}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a cross-token custom pattern must still match the serialized JSON in scan-all mode"
    );
}

#[tokio::test]
async fn test_all_mode_detects_pii_in_duplicate_key() {
    // codex: a duplicate object member's overwritten value is dropped from the
    // parsed Value but is still delivered to the client. The raw-body union
    // pass must still catch PII in {"x":"user@example.com","x":"ok"}.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "reject"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    // serde_json keeps only the last "x"; the email survives only in the raw bytes.
    let body = br#"{"x":"user@example.com","x":"ok"}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "PII in an overwritten duplicate key must be detected via the raw-body union pass"
    );
}

#[tokio::test]
async fn test_all_mode_redact_fails_closed_on_unredactable_residual() {
    // The scan-all redactor rewrites string values but cannot rewrite a numeric
    // scalar. Detection now flags it (union), so forwarding the body while
    // reporting it "redacted" would leak PII — redact mode must fail closed
    // (reject) on residual unredactable detections.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "scan_fields": "all",
        "action": "redact"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"ssn":123456789}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "redact mode must reject when a detected numeric PII scalar cannot be redacted"
    );
}

#[tokio::test]
async fn test_all_mode_redact_passes_when_residual_is_redactable() {
    // Counterpart to the fail-closed test: when the detected PII lives in a
    // string value the redactor CAN rewrite, redact mode proceeds normally
    // (Continue + redacted telemetry) instead of over-rejecting.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));

    let mut ctx = ctx_with_content_type("POST", "application/json");
    let body = br#"{"choices":[{"message":{"content":"reach me at user@example.com"}}]}"#;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "redact mode must not reject when the PII is fully redactable"
    );
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    let transformed = plugin
        .transform_response_body(body, Some("application/json"), &headers)
        .await
        .expect("expected redacted body");
    let value: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(
        value["choices"][0]["message"]["content"],
        "reach me at [REDACTED:pii:email]"
    );
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_mode_non_json_fails_closed() {
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
        .on_response_body(&mut ctx, 200, &mut headers, b"Your SSN is 123-45-6789")
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"unsupported_response_content_type".to_string())
    );
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
        .on_response_body(&mut ctx, 400, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
    assert_eq!(plugin.priority(), 4075);
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type(
        "POST",
        "multipart/form-data; boundary=abc"
    )));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
    // Spec change (PR #956 / commit 55a59396): non-POST AI responses must
    // also be buffered for guard validation; previously the POST-only
    // shortcut let GET-style chat history endpoints bypass the guard.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));

    let mut sse_accept = ctx_with_content_type("POST", "application/json");
    sse_accept
        .headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(
        plugin.should_buffer_response_body(&sse_accept),
        "client Accept must not release an ordinary backend response"
    );

    let mut stream_true = ctx_with_content_type("POST", "application/json");
    stream_true
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(
        plugin.should_buffer_response_body(&stream_true),
        "request-side stream metadata must not release an ordinary backend response"
    );

    let sse_headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);
    assert!(plugin.may_release_response_body_under_retries(&sse_accept));
    assert!(plugin.should_release_response_body_under_retries(&sse_accept, 200, &sse_headers));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(
            &sse_accept,
            200,
            &sse_headers,
        )
    );
    let json_profile_headers = HashMap::from([(
        "content-type".to_string(),
        "application/json; profile=event-stream".to_string(),
    )]);
    assert!(!plugin.should_release_response_body_under_retries(
        &sse_accept,
        200,
        &json_profile_headers,
    ));
    assert!(
        !plugin.should_release_response_body_before_content_type_rewrite(
            &sse_accept,
            200,
            &json_profile_headers,
        )
    );
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &sse_accept,
        Some("text/event-stream; charset=utf-8"),
        200,
        &sse_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &sse_accept,
        None,
        200,
        &HashMap::new(),
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &sse_accept,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
}

#[tokio::test]
async fn test_event_stream_fails_closed_before_ai_guard_delivery() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_response_guard_rejected")
            .map(String::as_str),
        Some("streaming_response_requires_bounded_inspection")
    );
}

#[tokio::test]
async fn test_json_event_stream_profile_stays_on_json_guard_path() {
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/json; profile=event-stream".to_string(),
    )]);
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "alice@example.com"}}]
    }))
    .unwrap();

    let reject = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "reject"
    }));
    let mut reject_ctx = ctx_with_content_type("GET", "application/json");
    assert!(matches!(
        reject
            .on_response_body(&mut reject_ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));

    let redact = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut redact_ctx = ctx_with_content_type("GET", "application/json");
    assert!(matches!(
        redact
            .on_response_body(&mut redact_ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    let transformed = redact
        .transform_response_body(
            &body,
            Some("application/json; profile=event-stream"),
            &headers,
        )
        .await
        .expect("profile parameter must not bypass JSON redaction");
    let transformed = String::from_utf8(transformed).unwrap();
    assert!(!transformed.contains("alice@example.com"));
    assert!(transformed.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_warn_only_event_stream_records_uninspectable_and_continues() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "warn"
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_response_guard_warning")
            .map(String::as_str),
        Some("streaming_response_requires_bounded_inspection")
    );
}

#[tokio::test]
async fn test_pristine_event_stream_relabel_still_fails_closed() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.metadata.insert(
        "ferrum:original_response_metadata_stamped".to_string(),
        "true".to_string(),
    );
    ctx.metadata.insert(
        "ferrum:original_response_content_type".to_string(),
        "text/event-stream".to_string(),
    );
    let mut relabeled_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut relabeled_headers)
            .await,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
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

#[test]
fn test_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (json!({"pii_patterns": ["ssn"], "action": "drop"}), "action"),
        (
            json!({"pii_patterns": ["ssn"], "scan_fields": "everything"}),
            "scan_fields",
        ),
        (
            json!({"pii_patterns": ["ssn"], "max_scan_bytes": 0}),
            "max_scan_bytes",
        ),
        (
            json!({"pii_patterns": ["ssn"], "require_json": "yes"}),
            "require_json",
        ),
        (
            json!({"required_fields": ["choices", 42]}),
            "required_fields[1]",
        ),
        (json!({"blocked_phrases": [""]}), "blocked_phrases[0]"),
        (
            json!({"custom_pii_patterns": [{"name": "secret"}]}),
            "custom_pii_patterns[0].regex",
        ),
        (json!({"blocked_patterns": [42]}), "blocked_patterns[0]"),
    ] {
        let err = AiResponseGuard::new(&config).err().unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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
        .on_response_body(&mut ctx, 200, &mut headers, &body)
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

// ─── SSE / streaming response support ────────────────────────────────

fn sse_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/event-stream".to_string());
    h
}

fn openai_sse_body(chunks: &[&str]) -> Vec<u8> {
    let mut body = String::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let frame = json!({
            "id": format!("chatcmpl-{}", i),
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": serde_json::Value::Null}]
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    body.push_str("data: [DONE]\n\n");
    body.into_bytes()
}

#[tokio::test]
async fn test_sse_pii_detection_reject() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Your SSN is ", "123-45-6789", " ok?"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("pii:ssn"));
        }
        _ => panic!("Expected Reject for SSE with SSN, got {:?}", result),
    }
    assert!(
        ctx.metadata
            .get("ai_response_guard_rejected")
            .is_some_and(|value| value.contains("pii:ssn")),
        "reject marker missing or wrong: {:?}",
        ctx.metadata.get("ai_response_guard_rejected")
    );
}

#[tokio::test]
async fn test_sse_pii_detection_warn() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "warn"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Contact ", "admin@secret.com", " now"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        ctx.metadata.contains_key("ai_response_guard_detected"),
        "warn mode should set detected metadata"
    );
}

#[tokio::test]
async fn test_sse_pii_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Email: user@example.com please"]);

    // on_response_body marks for redaction
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    // transform_response_body actually redacts
    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await;
    let transformed = transformed.expect("expected redacted SSE body");
    let transformed_str = String::from_utf8(transformed).unwrap();
    assert!(
        !transformed_str.contains("user@example.com"),
        "email should be removed"
    );
    assert!(
        transformed_str.contains("[REDACTED:pii:email]"),
        "should contain redaction placeholder"
    );
    assert!(
        transformed_str.contains("data: "),
        "SSE framing must be preserved"
    );
    assert!(
        transformed_str.contains("[DONE]"),
        "[DONE] sentinel must be preserved"
    );
}

#[tokio::test]
async fn test_sse_scan_all_decodes_escaped_pii_for_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"Contact user\\u0040example.com\"}}]}\n\ndata: [DONE]\n\n";

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    let transformed = plugin
        .transform_response_body(body, Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected escaped email to be redacted");
    let transformed_str = String::from_utf8(transformed).unwrap();
    assert!(transformed_str.contains("[REDACTED:pii:email]"));
    assert!(!transformed_str.contains("\\u0040"));
    assert!(transformed_str.contains("[DONE]"));
}

#[tokio::test]
async fn test_sse_clean_response_passes() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn", "credit_card"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["The weather ", "is nice today"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_max_completion_length_across_deltas() {
    let plugin = make_plugin(json!({
        "max_completion_length": 10,
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    // Each chunk is short, but concatenated they exceed 10 chars
    let body = openai_sse_body(&["Hello ", "wonderful ", "world!"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "accumulated text exceeds max_completion_length"
    );
}

#[tokio::test]
async fn test_sse_anthropic_streaming_format() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let mut body = String::new();
    // Anthropic content_block_delta frames
    for text in &["Your SSN is ", "123-45-6789"] {
        let frame = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text}
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    body.push_str("data: {\"type\":\"message_stop\"}\n\n");

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "Anthropic SSE with SSN should be rejected"
    );
}

#[tokio::test]
async fn test_sse_anthropic_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let frame = json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "email me at bob@corp.io"}
    });
    let body_str = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );
    let body = body_str.as_bytes();

    let _ = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
        .await;
    let transformed = plugin
        .transform_response_body(body, Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();
    assert!(!out.contains("bob@corp.io"));
    assert!(out.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_sse_gemini_streaming_format() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["credit_card"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let mut body = String::new();
    for text in &["Card number: ", "4111-1111-1111-1111"] {
        let frame = json!({
            "candidates": [{"content": {"parts": [{"text": text}]}}]
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "Gemini SSE with credit card should be rejected"
    );
}

#[tokio::test]
async fn test_sse_scan_all_mode() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    // IP address appears in a non-content field within the SSE body
    let frame = json!({"metadata": {"source_ip": "192.168.1.1"}, "choices": [{"delta": {"content": "hi"}}]});
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "scan_all mode should detect PII anywhere in SSE body"
    );
}

#[tokio::test]
async fn test_sse_scan_all_detects_pii_in_unparseable_frame() {
    // codex: parse_sse_data_frames silently drops non-JSON `data:` payloads, so
    // scanning only the parsed frames lets PII in a plain/malformed frame slip
    // past scan-all. The raw-body union pass must still catch it even when one
    // clean JSON frame precedes the unparseable one.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    // First frame is valid JSON (no PII); the second `data:` payload is plain
    // text carrying an email and is dropped by the JSON frame parser.
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n\
data: contact user@example.com\n\ndata: [DONE]\n\n";

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "PII in an unparseable SSE data frame must be detected via the raw-body union pass"
    );
}

#[tokio::test]
async fn test_sse_scan_all_detects_pii_when_no_frame_parses() {
    // Extreme of the previous case: the only `data:` payload is plain text PII
    // (no JSON frame at all). The early `frames.is_empty()` short-circuit must
    // not skip scan-all detection.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = "data: contact user@example.com\n\ndata: [DONE]\n\n";

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "plain-text PII in an SSE stream with no JSON frames must be detected in scan-all mode"
    );
}

#[tokio::test]
async fn test_sse_scan_all_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let frame =
        json!({"extra": "see 10.0.0.1", "choices": [{"delta": {"content": "IP: 8.8.8.8"}}]});
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let _ = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();
    assert!(!out.contains("10.0.0.1"));
    assert!(!out.contains("8.8.8.8"));
    assert!(out.contains("[REDACTED:pii:ip_address]"));
}

#[tokio::test]
async fn test_sse_blocked_phrase_detection() {
    let plugin = make_plugin(json!({
        "blocked_phrases": ["harmful content"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["This has ", "harmful content", " in it"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_sse_error_status_skipped() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["SSN: 123-45-6789"]);

    let result = plugin
        .on_response_body(&mut ctx, 500, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_empty_frames_pass() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = b"data: [DONE]\n\n";

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_redaction_preserves_non_content_frames() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));

    // Frame 1 has no content, frame 2 has PII
    let frame1 = json!({"choices": [{"index": 0, "delta": {"role": "assistant"}}]});
    let frame2 = json!({"choices": [{"index": 0, "delta": {"content": "hi user@test.io"}}]});
    let body = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame1).unwrap(),
        serde_json::to_string(&frame2).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    // First frame (role-only) should still be present
    assert!(out.contains("\"role\":\"assistant\""));
    // Second frame should be redacted
    assert!(!out.contains("user@test.io"));
    assert!(out.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_sse_no_redaction_returns_none() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "redact"
    }));
    let body = openai_sse_body(&["The weather is nice"]);

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(
        transformed.is_none(),
        "no modification expected when no PII present"
    );
}

#[tokio::test]
async fn test_sse_scan_all_no_match_returns_none() {
    // Fast-skip: scan-all mode with no pattern anywhere in the body must
    // return None without paying per-frame parse/serialize cost.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn", "credit_card"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let body = openai_sse_body(&["nothing sensitive here"]);

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(transformed.is_none());
}

#[tokio::test]
async fn test_sse_redaction_preserves_crlf_line_endings() {
    // Real-world SSE servers often emit CRLF terminators. The redactor must
    // preserve them on rewritten `data:` lines instead of mixing CR/LF.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "ping admin@example.com"}}]});
    let body = format!(
        "data: {}\r\n\r\ndata: [DONE]\r\n\r\n",
        serde_json::to_string(&frame).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    // Every `data:` line we emitted must end with CRLF, not bare LF.
    for line in out.split('\n') {
        if line.starts_with("data:") {
            assert!(
                line.ends_with('\r'),
                "data line lost CR terminator: {:?}",
                line
            );
        }
    }
    // Content was actually redacted.
    assert!(!out.contains("admin@example.com"));
    assert!(out.contains("[REDACTED:pii:email]"));
    // [DONE] sentinel passed through unchanged (still CRLF).
    assert!(out.contains("data: [DONE]\r"));
}

#[tokio::test]
async fn test_sse_preserves_non_data_event_lines() {
    // SSE comments (`:`), `event:`, `id:`, and `retry:` lines must round-trip
    // unchanged. Only `data:` frames carry JSON we touch.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "hi user@test.io"}}]});
    let body = format!(
        ": keep-alive comment\nevent: message\nid: 42\nretry: 5000\ndata: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    assert!(out.contains(": keep-alive comment"));
    assert!(out.contains("event: message"));
    assert!(out.contains("id: 42"));
    assert!(out.contains("retry: 5000"));
    assert!(out.contains("[REDACTED:pii:email]"));
    assert!(!out.contains("user@test.io"));
}

#[tokio::test]
async fn test_sse_oversize_body_is_not_transformed_after_rejection() {
    // The `max_scan_bytes` guard must block redaction of oversize SSE bodies
    // even when content-type is text/event-stream.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact",
        "max_scan_bytes": 64
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "user@example.com"}}]});
    let mut body = String::new();
    // Inflate well past 64 bytes.
    for _ in 0..16 {
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    assert!(body.len() > 64);

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(
        transformed.is_none(),
        "oversize body must skip redaction (returned Some)"
    );
}

#[tokio::test]
async fn test_sse_oversize_body_fails_closed_in_detection() {
    // The body transform cannot inspect beyond the configured ceiling, so an
    // enforcing action must reject rather than forwarding an unredacted body.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject",
        "max_scan_bytes": 64
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let filler = "filler ".repeat(20);
    let body = openai_sse_body(&["SSN: 123-45-6789 ", filler.as_str()]);
    assert!(body.len() > 64);

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"body_exceeds_max_scan_bytes".to_string())
    );
}

#[tokio::test]
async fn test_sse_cross_frame_pii_redact_fails_closed() {
    // PII split across events cannot be removed by rewriting either event.
    // Detection uses the reassembled content, and enforcing redaction must
    // reject instead of forwarding the original stream with false telemetry.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    // The SSN "123-45-6789" is split across two delta chunks.
    let body = openai_sse_body(&["my ssn is 123-", "45-6789 ok"]);

    let detect = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
        .await;
    assert!(matches!(detect, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata.contains_key("ai_response_guard_rejected"),
        "residual cross-event content must be rejected"
    );

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await;
    assert!(
        transformed.is_none(),
        "a rejected cross-event response must not be transformed afterward"
    );
}

#[tokio::test]
async fn test_sse_accumulated_text_order_is_deterministic() {
    // Multiple choice indices arriving out of order must accumulate in a
    // stable, index-sorted order so detection results don't flap between
    // runs. We assert that a `max_completion_length` check on a high-index
    // choice fires the same way regardless of frame arrival order.
    let plugin = make_plugin(json!({
        "max_completion_length": 5,
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    // Emit choice index=2 first, then index=0, then index=1. Each choice's
    // content alone is short, but index=2's exceeds the limit.
    let frames = [
        json!({"choices": [{"index": 2, "delta": {"content": "longer content"}}]}),
        json!({"choices": [{"index": 0, "delta": {"content": "hi"}}]}),
        json!({"choices": [{"index": 1, "delta": {"content": "ok"}}]}),
    ];
    let mut body = String::new();
    for frame in &frames {
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(frame).unwrap()
        ));
    }

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "max_completion_length must be enforced regardless of frame order"
    );
}

// ─── #43: redaction placeholder must not undergo $-capture expansion ──

#[tokio::test]
async fn test_redaction_placeholder_dollar_sequence_emitted_literally() {
    // Literal blocked phrases use non-sensitive positional identifiers. The
    // `$5` in the configured phrase must neither trigger capture expansion nor
    // be copied into the public placeholder.
    let plugin = make_plugin(json!({
        "blocked_phrases": ["cost $5"],
        "action": "redact"
    }));

    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {"content": "the total cost $5 today"}
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("body should be redacted");
    let s = String::from_utf8(transformed).unwrap();
    assert!(
        s.contains("[REDACTED:blocked_phrase:0]"),
        "placeholder must be emitted literally, got: {s}"
    );
    assert!(
        !s.contains("cost $5"),
        "the configured phrase must not be copied into the response: {s}"
    );
}

#[tokio::test]
async fn test_redaction_placeholder_dollar_one_not_reinjected() {
    // A `redaction_placeholder` containing `$1` must NOT re-inject a captured
    // substring of the matched (sensitive) content. With NoExpand, `$1` is
    // literal text in the output.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "redaction_placeholder": "[REDACTED:{type}:$1]",
        "action": "redact"
    }));

    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {"content": "reach me at user@example.com please"}
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("body should be redacted");
    let s = String::from_utf8(transformed).unwrap();
    assert!(
        s.contains("[REDACTED:pii:email:$1]"),
        "$1 must be emitted literally, got: {s}"
    );
    // The original PII must be gone (detection/removal still works).
    assert!(
        !s.contains("user@example.com"),
        "matched PII must still be removed: {s}"
    );
}

#[tokio::test]
async fn test_redaction_placeholder_dollar_literal_in_scan_all_walker() {
    // The recursive scan-all walker (redact_json_strings) is a separate
    // replace_all call site; verify it is also NoExpand-safe. Body has no
    // recognized AI shape so the recursive walker runs.
    let plugin = make_plugin(json!({
        "blocked_phrases": ["cost $5"],
        "scan_fields": "all",
        "action": "redact"
    }));

    let body = serde_json::to_vec(&json!({
        "note": "the cost $5 was billed"
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();

    let _ = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("body should be redacted");
    let s = String::from_utf8(transformed).unwrap();
    assert!(
        s.contains("[REDACTED:blocked_phrase:0]"),
        "scan-all walker must emit placeholder literally, got: {s}"
    );
    assert!(!s.contains("cost $5"));
}

// ─── twin of finding #8: structural-key nesting must not hide PII ─────

#[tokio::test]
async fn test_all_mode_redacts_pii_nested_under_structural_key() {
    // The structural-key skip must apply ONLY to a top-level scalar value.
    // PII nested under a structural key name (`type`, `id`, ...) at any depth
    // below the root must still be redacted. Previously the walker skipped the
    // entire subtree under such keys, letting PII reach the client in redact
    // mode even though detection (ai_response_guard_redacted) fired.
    let plugin = ipv4_redact_plugin();

    // No recognized AI shape (no choices/content/candidates) so the recursive
    // walker is exercised. `id` and `object` here are CONTAINERS (objects),
    // and `metadata` nests a scalar under the structural key `type`.
    let body = serde_json::to_vec(&json!({
        "id": "10.0.0.1",                          // top-level scalar — preserved
        "model": "127.0.0.1",                      // top-level scalar — preserved
        "metadata": {"type": "leak at 8.8.8.8"},   // scalar under structural key — redact
        "id_block": {"note": "see 1.2.3.4"},        // nested under non-top-level
        "object": {"role": "host 172.16.0.9 here"}  // nested structural keys — redact
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();

    let _ = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected redaction when match present");
    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    // Top-level scalar structural values are still preserved.
    assert_eq!(v["id"], "10.0.0.1", "top-level scalar id preserved");
    assert_eq!(v["model"], "127.0.0.1", "top-level scalar model preserved");

    // PII nested under structural key names must be redacted.
    assert!(
        v["metadata"]["type"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "PII under nested structural key `type` must be redacted: {}",
        v["metadata"]["type"]
    );
    assert!(
        v["id_block"]["note"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "PII nested below root must be redacted: {}",
        v["id_block"]["note"]
    );
    assert!(
        v["object"]["role"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "PII under nested structural keys (object.role) must be redacted: {}",
        v["object"]["role"]
    );
}

#[tokio::test]
async fn test_all_mode_redacts_deeply_nested_pii_under_structural_key() {
    // PII cannot be hidden by wrapping it deep inside arrays/objects under a
    // top-level structural key.
    let plugin = ipv4_redact_plugin();

    let body = serde_json::to_vec(&json!({
        "model": "10.0.0.1", // top-level scalar — preserved
        // `usage` is a structural key, but it is an OBJECT here, so the walker
        // must recurse into it and redact the nested PII.
        "usage": {
            "details": [
                {"type": {"inner": "host 192.168.1.50 logged"}}
            ]
        }
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();

    let _ = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected redaction when match present");
    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    assert_eq!(v["model"], "10.0.0.1", "top-level scalar model preserved");
    assert!(
        v["usage"]["details"][0]["type"]["inner"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "deeply nested PII under structural keys must be redacted: {}",
        v["usage"]["details"][0]["type"]["inner"]
    );
}

#[tokio::test]
async fn test_sse_scan_all_redacts_pii_nested_under_structural_key() {
    // The SSE scan-all path also routes through redact_json_strings; verify
    // the depth-aware fix applies there too. The frame's top-level `id` scalar
    // is preserved while PII nested under a structural key is redacted.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }));

    // One self-contained frame: top-level `id` is IP-shaped (preserved),
    // `metadata.type` nests PII under a structural key (must be redacted).
    let frame = json!({
        "id": "10.0.0.1",
        "object": "chat.completion.chunk",
        "metadata": {"type": "host 8.8.8.8 saw it"}
    });
    let body = format!("data: {}\n\n", serde_json::to_string(&frame).unwrap()).into_bytes();

    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected redaction when nested PII present");
    let s = String::from_utf8(transformed).unwrap();
    let data = s
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("data frame present");
    let v: serde_json::Value = serde_json::from_str(data).unwrap();

    assert_eq!(
        v["id"], "10.0.0.1",
        "top-level scalar id preserved in SSE frame"
    );
    assert!(
        v["metadata"]["type"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "nested PII under structural key in SSE frame must be redacted: {}",
        v["metadata"]["type"]
    );
}

#[tokio::test]
async fn test_sse_scan_all_preserves_structural_only_match_without_rewrite() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }));
    // Keep deliberately noncanonical JSON spacing: preserving an exempt field
    // must not canonicalize or otherwise mutate a clean protocol frame.
    let body = br#"data: { "id" : "10.0.0.1", "object" : "chat.completion.chunk", "choices" : [{"index":0,"delta":{"content":"clean"}}] }

"#;

    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body(body, Some("text/event-stream"), &sse_headers())
            .await
            .is_none(),
        "a match confined to a preserved structural scalar must not rewrite the frame"
    );
}

#[tokio::test]
async fn test_sse_scan_all_unredactable_raw_bytes_fail_closed() {
    let cases = [
        (
            "email",
            "data: {\"secret\":\"duplicate@example.com\",\"secret\":\"clean\"}\n\n",
        ),
        ("email", "data: {\"user@example.com\":\"clean\"}\n\n"),
        ("ssn", "data: {\"count\":123456789}\n\n"),
        (
            "email",
            "event: outside@example.com\ndata: {\"content\":\"clean\"}\n\n",
        ),
    ];

    for (pii_pattern, body) in cases {
        let plugin = make_plugin(json!({
            "pii_patterns": [pii_pattern],
            "scan_fields": "all",
            "action": "redact"
        }));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(
            matches!(
                plugin
                    .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
                    .await,
                PluginResult::Reject { .. }
            ),
            "unredactable SSE bytes did not fail closed: {body}"
        );
        assert!(
            plugin
                .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
                .await
                .is_none(),
            "unsafe SSE bytes must not produce a purportedly safe transform"
        );
    }
}

#[tokio::test]
async fn test_sse_scan_all_duplicate_structural_members_fail_closed() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let cases = [
        (
            "last scalar with LF",
            "data: {\"id\":\"victim@example.com\",\"id\":\"chunk_1\",\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}\n\n",
        ),
        (
            "escaped-equivalent last key with CRLF",
            ": preserve this comment\r\nevent: completion\r\ndata: { \"id\" : \"victim@example.com\", \"\\u0069d\" : \"chunk_1\", \"unrelated\" : \"first\", \"unrelated\" : \"second\" }\r\n\r\n",
        ),
        (
            "last semantic value is non-scalar",
            "data: {\"id\":\"victim@example.com\",\"id\":null,\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}\n\n",
        ),
    ];

    for (case, body) in cases {
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(
            matches!(
                plugin
                    .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
                    .await,
                PluginResult::Reject { .. }
            ),
            "duplicate structural member did not fail closed ({case}): {body}"
        );
        assert!(
            plugin
                .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
                .await
                .is_none(),
            "unsafe duplicate structural member produced a transform ({case})"
        );
    }
}

#[tokio::test]
async fn test_sse_scan_all_masks_only_last_duplicate_structural_scalar() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }));
    // The only match is the semantic last `id`, expressed with an equivalent
    // escaped key. It is preserved structurally, so the caller must retain the
    // original CRLF framing, comment, whitespace, and unrelated duplicates.
    let body = b": preserve this comment\r\nevent: completion\r\ndata: { \"id\" : \"chunk_0\", \"\\u0069d\" : \"10.0.0.1\", \"unrelated\" : \"first\", \"unrelated\" : \"second\" }\r\n\r\n";

    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
            .await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_response_body(body, Some("text/event-stream"), &sse_headers())
            .await
            .is_none(),
        "a preserved last structural scalar must leave the exact SSE bytes untouched"
    );
}

// ─── #44: max_completion_length is measured in characters, not bytes ──

#[tokio::test]
async fn test_max_completion_length_counts_characters_not_bytes() {
    // A multibyte completion whose CHARACTER count is within the limit but
    // whose BYTE length exceeds it must NOT be rejected. Each `あ` is 3 UTF-8
    // bytes: 5 chars = 15 bytes. With a limit of 10 characters, a 5-char
    // string is allowed (the old byte-based check, 15 > 10, wrongly rejected).
    let plugin = make_plugin(json!({
        "max_completion_length": 10,
        "action": "reject"
    }));

    let content = "あいうえお"; // 5 chars, 15 bytes
    assert_eq!(content.chars().count(), 5);
    assert!(content.len() > 10, "byte length exceeds the limit");

    let body = serde_json::to_vec(&json!({
        "choices": [{ "message": { "content": content } }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = ctx_with_content_type("POST", "application/json");

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "multibyte completion within the character limit must pass"
    );
}

#[tokio::test]
async fn test_max_completion_length_rejects_when_chars_exceed() {
    // Conversely, a multibyte completion whose character count exceeds the
    // limit must be rejected, and the reported figure is the character count.
    let plugin = make_plugin(json!({
        "max_completion_length": 4,
        "action": "reject"
    }));

    let content = "あいうえお"; // 5 chars > 4
    let body = serde_json::to_vec(&json!({
        "choices": [{ "message": { "content": content } }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = ctx_with_content_type("POST", "application/json");

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            // The message must report the CHARACTER count (5), not bytes (15).
            assert!(
                body.contains("Completion length 5 exceeds maximum 4"),
                "error must report character count, got: {body}"
            );
        }
        other => panic!("expected reject for over-limit char count, got {other:?}"),
    }
}

#[tokio::test]
async fn test_max_completion_length_applies_in_scan_all_json() {
    let plugin = make_plugin(json!({
        "max_completion_length": 4,
        "scan_fields": "all",
        "action": "reject"
    }));
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "12345"}}]
    }))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let mut ctx = ctx_with_content_type("POST", "application/json");

    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"Completion length 5 exceeds maximum 4".to_string())
    );
}

// ─── Plugin-audit regression coverage ───────────────────────────────

#[test]
fn test_unknown_root_and_nested_config_keys_are_rejected() {
    for (config, path) in [
        (
            json!({"required_fields": ["id"], "pii_pattern": ["email"]}),
            "config.pii_pattern",
        ),
        (
            json!({
                "custom_pii_patterns": [{
                    "name": "secret",
                    "regex": "secret",
                    "case_sensitive": false
                }]
            }),
            "custom_pii_patterns[0].case_sensitive",
        ),
        (
            json!({
                "blocked_patterns": [{
                    "name": "secret",
                    "regex": "secret",
                    "enabled": true
                }]
            }),
            "blocked_patterns[0].enabled",
        ),
    ] {
        let error = AiResponseGuard::new(&config).err().unwrap();
        assert!(error.contains(path), "missing path {path:?} in {error:?}");
    }
}

#[tokio::test]
async fn test_blocked_phrase_value_is_not_exposed_by_any_action() {
    let secret_phrase = "internal instruction omega-7391";
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": format!("prefix {secret_phrase} suffix")}}]
    }))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for action in ["reject", "warn"] {
        let plugin = make_plugin(json!({
            "blocked_phrases": [secret_phrase],
            "action": action
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        let result = plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await;

        match (action, result) {
            (
                "reject",
                PluginResult::Reject {
                    status_code, body, ..
                },
            ) => {
                assert_eq!(status_code, 502);
                assert!(!body.contains(secret_phrase));
                assert!(body.contains("blocked_phrase:0"));
            }
            ("warn", PluginResult::Continue) => {}
            (_, other) => panic!("unexpected {action} result: {other:?}"),
        }
        assert!(
            ctx.metadata
                .values()
                .all(|value| !value.contains(secret_phrase))
        );
        assert!(
            ctx.metadata
                .values()
                .any(|value| value.contains("blocked_phrase:0"))
        );
    }

    let plugin = make_plugin(json!({
        "blocked_phrases": [secret_phrase],
        "action": "redact"
    }));
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("blocked phrase should be redacted");
    let transformed = String::from_utf8(transformed).unwrap();
    assert!(!transformed.contains(secret_phrase));
    assert!(transformed.contains("[REDACTED:blocked_phrase:0]"));
}

#[tokio::test]
async fn test_max_scan_boundary_and_oversize_dispositions() {
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "contact boundary@example.com"}}]
    }))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let at_limit = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "reject",
        "max_scan_bytes": body.len()
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    let result = at_limit
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"pii:email".to_string()),
        "a body exactly at the limit must still be inspected"
    );

    for action in ["reject", "redact"] {
        let plugin = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": action,
            "max_scan_bytes": body.len() - 1
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        let result = plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "{action} must fail closed above max_scan_bytes"
        );
        assert_eq!(
            ctx.metadata.get("ai_response_guard_rejected"),
            Some(&"body_exceeds_max_scan_bytes".to_string())
        );
    }

    let warn = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "warn",
        "max_scan_bytes": body.len() - 1
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    let result = warn
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_warning"),
        Some(&"body_exceeds_max_scan_bytes".to_string())
    );
    assert!(
        ctx.metadata
            .values()
            .all(|value| !value.contains("boundary@example.com"))
    );

    let structural = make_plugin(json!({
        "require_json": true,
        "action": "warn",
        "max_scan_bytes": body.len() - 1
    }));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        structural
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_oversized_non_json_error_body_is_bounded_for_every_action() {
    let body = format!("{} oversized-error@example.com", "x".repeat(128)).into_bytes();
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

    for action in ["reject", "redact", "warn"] {
        let plugin = make_plugin(json!({
            "pii_patterns": ["email"],
            "scan_fields": "all",
            "action": action,
            "max_scan_bytes": 32
        }));
        let mut ctx = ctx_with_content_type("GET", "text/plain");
        let result = plugin
            .on_response_body(&mut ctx, 503, &mut headers, &body)
            .await;

        if action == "warn" {
            assert!(matches!(result, PluginResult::Continue));
            assert_eq!(
                ctx.metadata.get("ai_response_guard_warning"),
                Some(&"body_exceeds_max_scan_bytes".to_string())
            );
        } else {
            assert!(
                matches!(result, PluginResult::Reject { .. }),
                "{action} must fail closed for an oversized non-2xx text body"
            );
            assert_eq!(
                ctx.metadata.get("ai_response_guard_rejected"),
                Some(&"body_exceeds_max_scan_bytes".to_string())
            );
        }

        assert!(
            plugin
                .transform_response_body(&body, Some("text/plain"), &headers)
                .await
                .is_none(),
            "{action} must not scan or rewrite raw text above max_scan_bytes"
        );
    }
}

#[tokio::test]
async fn test_require_json_checks_actual_representation() {
    let plugin = make_plugin(json!({"require_json": true}));
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

    let mut valid_ctx = ctx_with_content_type("GET", "text/plain");
    let valid = plugin
        .on_response_body(&mut valid_ctx, 200, &mut headers, br#"{"id":"ok"}"#)
        .await;
    assert!(matches!(valid, PluginResult::Continue));

    let mut invalid_ctx = ctx_with_content_type("GET", "text/plain");
    let invalid = plugin
        .on_response_body(&mut invalid_ctx, 200, &mut headers, b"not json")
        .await;
    assert!(matches!(invalid, PluginResult::Reject { .. }));
    assert_eq!(
        invalid_ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"invalid_json".to_string())
    );
}

#[tokio::test]
async fn test_non_json_scan_all_is_governed_and_redactable() {
    let mut headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    let body = b"contact raw@example.com";

    let reject = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("GET", "text/plain");
    assert!(matches!(
        reject
            .on_response_body(&mut ctx, 200, &mut headers, body)
            .await,
        PluginResult::Reject { .. }
    ));

    let redact = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("GET", "text/plain");
    assert!(matches!(
        redact
            .on_response_body(&mut ctx, 200, &mut headers, body)
            .await,
        PluginResult::Continue
    ));
    let transformed = redact
        .transform_response_body(body, Some("text/plain"), &headers)
        .await
        .expect("raw UTF-8 response should be redacted in scan-all mode");
    let transformed = String::from_utf8(transformed).unwrap();
    assert!(!transformed.contains("raw@example.com"));
    assert!(transformed.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn redaction_findings_on_range_and_delta_responses_fail_closed() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let governed = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "contact secret@example.com"}}]
    }))
    .unwrap();
    let clean = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "safe response"}}]
    }))
    .unwrap();

    for status in [206, 226] {
        let mut governed_ctx = ctx_with_content_type("GET", "application/json");
        let result = plugin
            .on_response_body(&mut governed_ctx, status, &mut headers, &governed)
            .await;
        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 502,
                    ..
                }
            ),
            "status {status} forwarded governed bytes without an available redaction transform: {result:?}"
        );
        assert!(
            governed_ctx
                .metadata
                .contains_key("ai_response_guard_rejected")
        );
        assert!(
            !governed_ctx
                .metadata
                .contains_key("ai_response_guard_redacted")
        );

        let mut clean_ctx = ctx_with_content_type("GET", "application/json");
        assert!(matches!(
            plugin
                .on_response_body(&mut clean_ctx, status, &mut headers, &clean)
                .await,
            PluginResult::Continue
        ));
    }
}

#[tokio::test]
async fn test_uninspectable_sse_fails_closed_except_warn_mode() {
    let malformed = b"data: {\"choices\":[\n\n";
    let non_utf8 = b"data: \xff\xfe\n\n";
    let mut headers = sse_headers();

    for body in [malformed.as_slice(), non_utf8.as_slice()] {
        for action in ["reject", "redact"] {
            let plugin = make_plugin(json!({
                "pii_patterns": ["email"],
                "action": action
            }));
            let mut ctx = ctx_with_content_type("POST", "text/event-stream");
            assert!(matches!(
                plugin
                    .on_response_body(&mut ctx, 200, &mut headers, body)
                    .await,
                PluginResult::Reject { .. }
            ));
            assert_eq!(
                ctx.metadata.get("ai_response_guard_rejected"),
                Some(&"uninspectable_sse".to_string())
            );
        }

        let warn = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": "warn"
        }));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(matches!(
            warn.on_response_body(&mut ctx, 200, &mut headers, body)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.metadata.get("ai_response_guard_warning"),
            Some(&"uninspectable_sse".to_string())
        );
    }
}

#[tokio::test]
async fn test_multiline_sse_event_redaction_uses_complete_event() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));

    for ending in ["\n", "\r\n"] {
        let body = format!(
            ": keep-alive{ending}event: message{ending}data: {{\"choices\":[{ending}data: {{\"index\":0,\"delta\":{{\"content\":\"multi@example.com\"}}}}]}}{ending}{ending}data: [DONE]{ending}{ending}"
        );
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        let result = plugin
            .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
            .await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

        let transformed = plugin
            .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
            .await
            .expect("complete multiline SSE event should be rewritten");
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(!transformed.contains("multi@example.com"));
        assert!(transformed.contains("[REDACTED:pii:email]"));
        assert!(transformed.contains(": keep-alive"));
        assert!(transformed.contains("event: message"));
        assert!(transformed.contains("data: [DONE]"));
        if ending == "\r\n" {
            // `str::lines()` strips a CRLF terminator entirely, so inspect the
            // raw terminators instead: every data line must keep its CRLF.
            assert!(
                transformed
                    .split_inclusive('\n')
                    .filter(|line| line.starts_with("data:"))
                    .all(|line| line.ends_with("\r\n"))
            );
        }
    }
}

#[tokio::test]
async fn test_common_buffered_output_shapes_are_detected_and_redacted() {
    let secret = "shape@example.com";
    let shapes = [
        json!({"choices": [{"text": secret}]}),
        json!({"choices": [{"message": {"content": [{"type": "text", "text": secret}]}}]}),
        json!({"choices": [{"message": {"function_call": {"name": "lookup", "arguments": secret}}}]}),
        json!({"choices": [{"message": {"tool_calls": [{"function": {"name": "lookup", "arguments": secret}}]}}]}),
        json!({"output_text": secret}),
        json!({"output": [{"type": "message", "content": [{"type": "output_text", "text": secret}]}]}),
        json!({"output": [{"type": "function_call", "name": "lookup", "arguments": secret}]}),
    ];
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for (index, value) in shapes.into_iter().enumerate() {
        let body = serde_json::to_vec(&value).unwrap();
        let reject = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": "reject"
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(
            matches!(
                reject
                    .on_response_body(&mut ctx, 200, &mut headers, &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "shape {index} was not detected"
        );

        let redact = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": "redact"
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));
        let transformed = redact
            .transform_response_body(&body, Some("application/json"), &headers)
            .await
            .unwrap_or_else(|| panic!("shape {index} was not redacted"));
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(
            !transformed.contains(secret),
            "shape {index} leaked after redaction: {transformed}"
        );
        assert!(transformed.contains("[REDACTED:pii:email]"));
    }
}

#[tokio::test]
async fn test_tool_arguments_participate_in_completion_length_enforcement() {
    let plugin = make_plugin(json!({
        "max_completion_length": 4,
        "action": "redact"
    }));
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "tool_calls": [{"function": {"name": "lookup", "arguments": "12345"}}]
            }
        }]
    }))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_streaming_tool_and_responses_deltas_are_governed() {
    let bodies = [
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"tool@example.com\"}}]}}]}\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{\"arguments\":\"tool@example.com\"}}}]}\n\ndata: [DONE]\n\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"tool@example.com\"}\n\ndata: [DONE]\n\n",
    ];

    for body in bodies {
        let reject = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": "reject"
        }));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(matches!(
            reject
                .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
                .await,
            PluginResult::Reject { .. }
        ));

        let redact = make_plugin(json!({
            "pii_patterns": ["email"],
            "action": "redact"
        }));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut sse_headers(), body.as_bytes())
                .await,
            PluginResult::Continue
        ));
        let transformed = redact
            .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
            .await
            .expect("streamed output shape should be redacted");
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(!transformed.contains("tool@example.com"));
        assert!(transformed.contains("[REDACTED:pii:email]"));
    }
}

#[tokio::test]
async fn test_sse_scan_all_decodes_responses_arguments_and_preserves_json_scalars() {
    let arguments = r#"{"email":"stream\u0040example.com","count":7,"enabled":true,"note":null}"#;
    let frame = json!({
        "type": "response.function_call_arguments.delta",
        "output_index": 0,
        "delta": arguments
    });
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    )
    .into_bytes();

    let reject = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    assert!(matches!(
        reject
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));

    let redact = make_plugin(json!({
        "pii_patterns": ["email"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    assert!(matches!(
        redact
            .on_response_body(&mut ctx, 200, &mut sse_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    let transformed = redact
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await
        .expect("Responses arguments delta should be redacted");
    let transformed = String::from_utf8(transformed).unwrap();
    let data = transformed
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .expect("data frame present");
    let rewritten_frame: serde_json::Value = serde_json::from_str(data).unwrap();
    let rewritten_arguments: serde_json::Value =
        serde_json::from_str(rewritten_frame["delta"].as_str().unwrap()).unwrap();
    assert_eq!(rewritten_arguments["email"], "[REDACTED:pii:email]");
    assert_eq!(rewritten_arguments["count"], 7);
    assert_eq!(rewritten_arguments["enabled"], true);
    assert!(rewritten_arguments["note"].is_null());
}

#[tokio::test]
async fn test_representation_validators_removed_only_after_rewrite() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let validators = [
        "ETag",
        "LAST-Modified",
        "Content-DIGEST",
        "RePr-DiGeSt",
        "dIgEsT",
        "CONTENT-md5",
    ];
    let mut original_headers =
        HashMap::from([("cache-control".to_string(), "private".to_string())]);
    for validator in validators {
        original_headers.insert(validator.to_string(), "upstream-value".to_string());
    }

    let clean = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "clean"}}]
    }))
    .unwrap();
    let clean_headers = original_headers.clone();
    assert!(
        plugin
            .transform_response_body(&clean, Some("application/json"), &clean_headers)
            .await
            .is_none()
    );
    assert_eq!(clean_headers, original_headers);

    let json_body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "validator@example.com"}}]
    }))
    .unwrap();
    let sse_body = openai_sse_body(&["validator@example.com"]);
    for (content_type, body) in [
        ("application/json", json_body.as_slice()),
        ("text/event-stream", sse_body.as_slice()),
    ] {
        assert!(
            plugin
                .transform_response_body(body, Some(content_type), &original_headers)
                .await
                .is_some()
        );
        let mut rewritten_headers = original_headers.clone();
        let mut ctx = ctx_with_content_type("POST", content_type);
        plugin.on_response_body_transformed(&mut ctx, &mut rewritten_headers);
        for validator in validators {
            assert!(
                rewritten_headers
                    .keys()
                    .all(|key| !key.eq_ignore_ascii_case(validator)),
                "mixed-case {validator} survived a body rewrite"
            );
        }
        assert_eq!(
            rewritten_headers.get("cache-control").map(String::as_str),
            Some("private")
        );
    }
}

#[tokio::test]
async fn test_cross_part_content_matches_are_joined_and_fail_closed() {
    let shapes = [
        json!({"choices": [{"message": {"content": [
            {"type": "text", "text": "admin@"},
            {"type": "text", "text": "example.com"}
        ]}}]}),
        json!({"output": [{"type": "message", "content": [
            {"type": "output_text", "text": "admin@"},
            {"type": "output_text", "text": "example.com"}
        ]}]}),
        json!({"content": [
            {"type": "text", "text": "admin@"},
            {"type": "text", "text": "example.com"}
        ]}),
        json!({"candidates": [{"content": {"parts": [
            {"text": "admin@"},
            {"text": "example.com"}
        ]}}]}),
    ];
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for (index, value) in shapes.into_iter().enumerate() {
        let body = serde_json::to_vec(&value).unwrap();

        let reject = make_plugin(json!({"pii_patterns": ["email"], "action": "reject"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(
            matches!(
                reject
                    .on_response_body(&mut ctx, 200, &mut headers, &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "cross-part email in shape {index} was not rejected"
        );

        let warn = make_plugin(json!({"pii_patterns": ["email"], "action": "warn"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            warn.on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.metadata.get("ai_response_guard_detected"),
            Some(&"pii:email".to_string())
        );

        // A match that only exists across part boundaries cannot be rewritten
        // by per-part redaction; redact mode must fail closed, not report
        // `redacted` while forwarding the joined match.
        let redact = make_plugin(json!({"pii_patterns": ["email"], "action": "redact"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(
            matches!(
                redact
                    .on_response_body(&mut ctx, 200, &mut headers, &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "unrewritable cross-part email in shape {index} did not fail closed"
        );
        assert!(ctx.metadata.contains_key("ai_response_guard_rejected"));
    }
}

#[tokio::test]
async fn test_non_adjacent_text_parts_are_not_joined() {
    let body = serde_json::to_vec(&json!({"choices": [{"message": {"content": [
        {"type": "text", "text": "admin@"},
        {"type": "image_url", "image_url": {"url": "https://images.example.net/x.png"}},
        {"type": "text", "text": "example.com"}
    ]}}]}))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let plugin = make_plugin(json!({"pii_patterns": ["email"], "action": "reject"}));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_completion_length_enforced_across_adjacent_parts() {
    let body = serde_json::to_vec(&json!({"choices": [{"message": {"content": [
        {"type": "text", "text": "12345"},
        {"type": "text", "text": "67890"}
    ]}}]}))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let reject = make_plugin(json!({"max_completion_length": 8, "action": "reject"}));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        reject
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));

    let warn = make_plugin(json!({"max_completion_length": 8, "action": "warn"}));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        warn.on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    assert!(ctx.metadata.contains_key("ai_response_guard_warning"));

    // The joined completion is exactly 10 characters; each part alone is 5.
    let under_limit = make_plugin(json!({"max_completion_length": 10, "action": "reject"}));
    let mut ctx = ctx_with_content_type("POST", "application/json");
    assert!(matches!(
        under_limit
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_refusal_content_is_scanned_and_redacted() {
    let secret = "refuse@example.com";
    let shapes = [
        json!({"output": [{"type": "message", "content": [
            {"type": "refusal", "refusal": format!("cannot help {secret}")}
        ]}]}),
        json!({"choices": [{"message": {"refusal": format!("cannot help {secret}")}}]}),
        json!({"choices": [{"delta": {"refusal": format!("cannot help {secret}")}}]}),
    ];
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for (index, value) in shapes.into_iter().enumerate() {
        let body = serde_json::to_vec(&value).unwrap();

        let reject = make_plugin(json!({"pii_patterns": ["email"], "action": "reject"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(
            matches!(
                reject
                    .on_response_body(&mut ctx, 200, &mut headers, &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "refusal shape {index} was not detected"
        );

        let redact = make_plugin(json!({"pii_patterns": ["email"], "action": "redact"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));
        let transformed = redact
            .transform_response_body(&body, Some("application/json"), &headers)
            .await
            .unwrap_or_else(|| panic!("refusal shape {index} was not redacted"));
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(
            !transformed.contains(secret),
            "refusal shape {index} leaked after redaction: {transformed}"
        );
        assert!(transformed.contains("[REDACTED:pii:email]"));
    }
}

#[tokio::test]
async fn test_escaped_tool_arguments_are_decoded_before_scanning() {
    // The arguments string decodes to {"email":"user@example.com"}; the raw
    // bytes only ever contain the literal characters `\u0040`.
    let escaped_args = r#"{"email":"user\u0040example.com"}"#;
    let shapes = [
        json!({"choices": [{"message": {"tool_calls": [
            {"function": {"name": "send", "arguments": escaped_args}}
        ]}}]}),
        json!({"choices": [{"message": {"function_call": {"name": "send", "arguments": escaped_args}}}]}),
        json!({"output": [{"type": "function_call", "name": "send", "arguments": escaped_args}]}),
    ];
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for (index, value) in shapes.into_iter().enumerate() {
        let body = serde_json::to_vec(&value).unwrap();

        for scan_fields in ["content", "all"] {
            let reject = make_plugin(json!({
                "pii_patterns": ["email"],
                "scan_fields": scan_fields,
                "action": "reject"
            }));
            let mut ctx = ctx_with_content_type("POST", "application/json");
            assert!(
                matches!(
                    reject
                        .on_response_body(&mut ctx, 200, &mut headers, &body)
                        .await,
                    PluginResult::Reject { .. }
                ),
                "escaped argument email in shape {index} bypassed {scan_fields} mode"
            );
        }

        let warn = make_plugin(json!({"pii_patterns": ["email"], "action": "warn"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            warn.on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.metadata.get("ai_response_guard_detected"),
            Some(&"pii:email".to_string())
        );

        // Redact mode rewrites the decoded argument document and re-serializes
        // it, so the escape cannot carry the address past redaction.
        let redact = make_plugin(json!({"pii_patterns": ["email"], "action": "redact"}));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));
        let transformed = redact
            .transform_response_body(&body, Some("application/json"), &headers)
            .await
            .unwrap_or_else(|| panic!("escaped argument shape {index} was not redacted"));
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(transformed.contains("[REDACTED:pii:email]"));
        assert!(
            !transformed.contains("u0040"),
            "escape survived redaction in shape {index}: {transformed}"
        );
        assert!(!transformed.contains("user@example.com"));
    }
}

#[tokio::test]
async fn test_unrewritable_escaped_argument_key_fails_closed_in_redact_mode() {
    // The decoded argument document carries the address in an object KEY,
    // which the argument redactor cannot rewrite.
    let escaped_key_args = r#"{"user\u0040example.com":true}"#;
    let body = serde_json::to_vec(&json!({"choices": [{"message": {"tool_calls": [
        {"function": {"name": "send", "arguments": escaped_key_args}}
    ]}}]}))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for scan_fields in ["content", "all"] {
        let redact = make_plugin(json!({
            "pii_patterns": ["email"],
            "scan_fields": scan_fields,
            "action": "redact"
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(
            matches!(
                redact
                    .on_response_body(&mut ctx, 200, &mut headers, &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "unrewritable escaped argument key did not fail closed in {scan_fields} mode"
        );
        assert!(ctx.metadata.contains_key("ai_response_guard_rejected"));
    }
}

#[tokio::test]
async fn test_unrewritable_argument_keys_and_numeric_scalars_fail_closed() {
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let cases = [
        ("email", r#"{"user@example.com":true}"#),
        ("ssn", "123456789"),
    ];

    for (pii_pattern, arguments) in cases {
        let body = serde_json::to_vec(&json!({"choices": [{"message": {"tool_calls": [
            {"function": {"name": "send", "arguments": arguments}}
        ]}}]}))
        .unwrap();

        for scan_fields in ["content", "all"] {
            let redact = make_plugin(json!({
                "pii_patterns": [pii_pattern],
                "scan_fields": scan_fields,
                "action": "redact"
            }));
            let mut ctx = ctx_with_content_type("POST", "application/json");
            assert!(
                matches!(
                    redact
                        .on_response_body(&mut ctx, 200, &mut headers, &body)
                        .await,
                    PluginResult::Reject { .. }
                ),
                "{scan_fields} mode did not fail closed for unrewritable {arguments}"
            );
            assert_eq!(
                ctx.metadata.get("ai_response_guard_rejected"),
                Some(&format!("pii:{pii_pattern}"))
            );
            assert!(
                redact
                    .transform_response_body(&body, Some("application/json"), &headers)
                    .await
                    .is_none(),
                "the transform must not rename a decoded key or rewrite a numeric JSON scalar"
            );
        }
    }
}

#[tokio::test]
async fn test_nested_argument_string_values_redact_with_valid_json_semantics() {
    let arguments = r#"{"outer":[{"email":"nested\u0040example.com","count":7}],"enabled":true}"#;
    let body = serde_json::to_vec(&json!({"choices": [{"message": {"tool_calls": [
        {"function": {"name": "send", "arguments": arguments}}
    ]}}]}))
    .unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for scan_fields in ["content", "all"] {
        let redact = make_plugin(json!({
            "pii_patterns": ["email"],
            "scan_fields": scan_fields,
            "action": "redact"
        }));
        let mut ctx = ctx_with_content_type("POST", "application/json");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Continue
        ));

        let transformed = redact
            .transform_response_body(&body, Some("application/json"), &headers)
            .await
            .unwrap_or_else(|| panic!("nested argument value was not redacted in {scan_fields}"));
        let response: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
        let rewritten_arguments =
            response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap();
        let decoded: serde_json::Value = serde_json::from_str(rewritten_arguments).unwrap();

        assert_eq!(decoded["outer"][0]["email"], "[REDACTED:pii:email]");
        assert_eq!(decoded["outer"][0]["count"], 7);
        assert_eq!(decoded["enabled"], true);
        assert!(
            !rewritten_arguments.contains("nested@example.com")
                && !rewritten_arguments.contains("u0040")
        );
    }
}

#[tokio::test]
async fn test_sse_refusal_deltas_are_scanned_and_fail_closed_when_split() {
    let chat_split = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"refusal\":\"no: sse-refuse@\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"refusal\":\"example.com\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let responses_split = concat!(
        "data: {\"type\":\"response.refusal.delta\",\"output_index\":0,\"delta\":\"no: sse-refuse@\"}\n\n",
        "data: {\"type\":\"response.refusal.delta\",\"output_index\":0,\"delta\":\"example.com\"}\n\n",
        "data: [DONE]\n\n"
    );
    for body in [chat_split.as_bytes(), responses_split.as_bytes()] {
        let reject = make_plugin(json!({"pii_patterns": ["email"], "action": "reject"}));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(matches!(
            reject
                .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
                .await,
            PluginResult::Reject { .. }
        ));

        // The match spans frames, so per-frame redaction cannot rewrite it.
        let redact = make_plugin(json!({"pii_patterns": ["email"], "action": "redact"}));
        let mut ctx = ctx_with_content_type("POST", "text/event-stream");
        assert!(matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
                .await,
            PluginResult::Reject { .. }
        ));
    }

    // A refusal contained in one frame is rewritable.
    let chat_single = "data: {\"choices\":[{\"index\":0,\"delta\":{\"refusal\":\"no: sse-refuse@example.com\"}}]}\n\ndata: [DONE]\n\n";
    let responses_single = "data: {\"type\":\"response.refusal.delta\",\"output_index\":0,\"delta\":\"no: sse-refuse@example.com\"}\n\ndata: [DONE]\n\n";
    for body in [chat_single.as_bytes(), responses_single.as_bytes()] {
        let redact = make_plugin(json!({"pii_patterns": ["email"], "action": "redact"}));
        let transformed = redact
            .transform_response_body(body, Some("text/event-stream"), &sse_headers())
            .await
            .expect("single-frame refusal should be redacted");
        let transformed = String::from_utf8(transformed).unwrap();
        assert!(!transformed.contains("sse-refuse@example.com"));
        assert!(transformed.contains("[REDACTED:pii:email]"));
        assert!(transformed.contains("data: [DONE]"));
    }
}

#[tokio::test]
async fn test_sse_escaped_tool_arguments_are_decoded_after_reassembly() {
    // Accumulated across frames, the arguments string decodes to
    // {"email":"user@example.com"}; no single frame or raw byte ever contains
    // the literal address.
    let chat_body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"send\",\"arguments\":\"{\\\"email\\\":\\\"user\\\\u00\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"40example.com\\\"}\"}}]}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let responses_body = concat!(
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"{\\\"email\\\":\\\"user\\\\u00\"}\n\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"40example.com\\\"}\"}\n\n",
        "data: [DONE]\n\n"
    );

    for (shape, body) in [
        ("chat", chat_body.as_bytes()),
        ("responses", responses_body.as_bytes()),
    ] {
        for scan_fields in ["content", "all"] {
            let reject = make_plugin(json!({
                "pii_patterns": ["email"],
                "scan_fields": scan_fields,
                "action": "reject"
            }));
            let mut ctx = ctx_with_content_type("POST", "text/event-stream");
            assert!(
                matches!(
                    reject
                        .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
                        .await,
                    PluginResult::Reject { .. }
                ),
                "escaped {shape} arguments bypassed {scan_fields} mode"
            );

            // The escape spans frames, so per-frame argument redaction cannot
            // rewrite it and redact mode must fail closed.
            let redact = make_plugin(json!({
                "pii_patterns": ["email"],
                "scan_fields": scan_fields,
                "action": "redact"
            }));
            let mut ctx = ctx_with_content_type("POST", "text/event-stream");
            assert!(
                matches!(
                    redact
                        .on_response_body(&mut ctx, 200, &mut sse_headers(), body)
                        .await,
                    PluginResult::Reject { .. }
                ),
                "unrewritable {shape} arguments did not fail closed in {scan_fields} mode"
            );
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Native gRPC inspection (issue #3305)
// ══════════════════════════════════════════════════════════════════════

/// Path to the checked-in descriptor compiled from `test_validator.proto`
/// (`test.HelloRequest`, `test.HelloResponse`, `test.Greeter/SayHello`).
fn grpc_descriptor_path() -> String {
    format!(
        "{}/tests/fixtures/test_validator.bin",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn hello_response_bytes(message: &str) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let bytes = std::fs::read(grpc_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(bytes.as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("test.HelloResponse").unwrap();
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("message", Value::String(message.to_string()));
    msg.set_field_by_name("success", Value::Bool(true));
    msg.encode_to_vec()
}

fn hello_response_text(frame_payload: &[u8]) -> String {
    use prost_reflect::{DescriptorPool, DynamicMessage};

    let bytes = std::fs::read(grpc_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(bytes.as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("test.HelloResponse").unwrap();
    let msg = DynamicMessage::decode(descriptor, frame_payload).unwrap();
    msg.get_field_by_name("message")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn gzip_grpc_frame(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame
}

/// Split a buffered gRPC body back into its frame payloads (identity only).
fn grpc_frame_payloads(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;
        offset += 5;
        out.push(body[offset..offset + length].to_vec());
        offset += length;
    }
    out
}

fn grpc_ctx(method: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        method.to_string(),
    );
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::HttpFlavor::Grpc,
    );
    ctx
}

fn grpc_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers
}

fn grpc_guard(action: &str) -> AiResponseGuard {
    make_plugin(json!({
        "action": action,
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {
                "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        }
    }))
}

#[test]
fn grpc_block_extends_supported_protocols_and_admission() {
    let plugin = grpc_guard("reject");
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ProxyProtocol::Http));
    assert!(protocols.contains(&ProxyProtocol::Grpc));

    // Without a `grpc` block the plugin stays HTTP-only.
    let http_only = make_plugin(json!({"pii_patterns": ["email"]}));
    assert_eq!(http_only.supported_protocols(), &[ProxyProtocol::Http]);
}

#[test]
fn grpc_buffering_vote_is_limited_to_enrolled_methods() {
    let plugin = grpc_guard("reject");
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&grpc_ctx("/test.Greeter/SayHello")));
    assert!(!plugin.should_buffer_response_body(&grpc_ctx("/test.Greeter/Other")));
    // Plain HTTP traffic on the same instance keeps its ordinary vote.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
}

#[tokio::test]
async fn grpc_enrolled_method_never_releases_on_sse_content_type() {
    let plugin = grpc_guard("reject");
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    assert!(
        !plugin.may_release_response_body_under_retries(&ctx),
        "native gRPC enrollment must remain buffered while retries are active"
    );
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &headers));
    assert!(!plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &headers));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers,
    ));
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));

    let body = grpc_frame(&hello_response_bytes("contact mislabeled@example.com"));
    assert!(
        matches!(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
            PluginResult::Reject { .. }
        ),
        "the descriptor guard must inspect framed bytes regardless of a misleading SSE label"
    );
}

#[test]
fn grpc_config_requires_descriptor_and_methods() {
    for invalid in [
        json!({"pii_patterns": ["email"], "grpc": {}}),
        json!({"pii_patterns": ["email"], "grpc": {"methods": {}}}),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {}}
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "unknown": 1, "methods": {
                "/a.B/C": {"response_type": "x"}
            }}
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {
                "/a.B/C": {"response_type": "x", "unknown": 1}
            }}
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {"not-a-path": {
                "response_type": "x"
            }}}
        }),
        json!({
            "pii_patterns": ["email"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {"/a.B/C": {}}}
        }),
        // JSON-only structural rules cannot be satisfied by protobuf.
        json!({
            "require_json": true,
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {
                "/a.B/C": {"response_type": "x"}
            }}
        }),
        json!({
            "required_fields": ["choices"],
            "grpc": {"descriptor_path": "/tmp/x.bin", "methods": {
                "/a.B/C": {"response_type": "x"}
            }}
        }),
    ] {
        assert!(
            AiResponseGuard::new(&invalid).is_err(),
            "config must be rejected: {invalid}"
        );
    }
}

#[test]
fn grpc_config_rejects_unresolvable_descriptor_targets() {
    let unknown_type = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {"response_type": "test.NoSuchType"}}
        }
    });
    assert!(AiResponseGuard::new(&unknown_type).is_err());

    let non_string_field = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {
                "response_type": "test.HelloResponse",
                "text_fields": ["success"]
            }}
        }
    });
    assert!(AiResponseGuard::new(&non_string_field).is_err());

    let unknown_field = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {
                "response_type": "test.HelloResponse",
                "text_fields": ["nope"]
            }}
        }
    });
    assert!(AiResponseGuard::new(&unknown_field).is_err());

    let duplicate_text_fields = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {
                "response_type": "test.HelloResponse",
                "text_fields": ["message", " message "]
            }}
        }
    });
    let duplicate_err = AiResponseGuard::new(&duplicate_text_fields)
        .err()
        .expect("duplicate normalized text_fields paths must fail closed");
    assert!(
        duplicate_err.contains("text_fields") && duplicate_err.contains("more than once"),
        "diagnostic must name the field without echoing the path value: {duplicate_err}"
    );
    assert!(
        !duplicate_err.contains("message"),
        "diagnostic must stay value-redacted: {duplicate_err}"
    );

    // Shape-only admission must not need the node-local descriptor at all.
    assert!(
        AiResponseGuard::validate_config(&json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/nonexistent/descriptor.bin",
                "methods": {"/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}}
            }
        }))
        .is_ok()
    );
}

#[tokio::test]
async fn grpc_unary_clean_response_passes_through() {
    let plugin = grpc_guard("reject");
    let body = grpc_frame(&hello_response_bytes("all clear"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn grpc_unary_detection_rejects() {
    let plugin = grpc_guard("reject");
    let body = grpc_frame(&hello_response_bytes("write to agent@example.com"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(ctx.metadata.contains_key("ai_response_guard_rejected"));
}

#[tokio::test]
async fn grpc_unknown_method_is_never_inspected() {
    let plugin = grpc_guard("reject");
    let body = grpc_frame(&hello_response_bytes("write to agent@example.com"));
    let mut ctx = grpc_ctx("/test.Greeter/Unenrolled");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "an un-enrolled method must never be decoded opportunistically"
    );
    assert!(!ctx.metadata.contains_key("ai_response_guard_rejected"));
    assert!(!ctx.metadata.contains_key("ai_response_guard_detected"));
}

#[tokio::test]
async fn grpc_streaming_frames_are_all_inspected() {
    let plugin = grpc_guard("reject");
    let mut body = grpc_frame(&hello_response_bytes("clean one"));
    body.extend_from_slice(&grpc_frame(&hello_response_bytes("clean two")));
    body.extend_from_slice(&grpc_frame(&hello_response_bytes("ops@example.com")));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a match in a later stream frame must still be caught"
    );
}

#[tokio::test]
async fn grpc_compressed_frames_are_decoded_and_bounded() {
    let plugin = grpc_guard("reject");
    let body = gzip_grpc_frame(&hello_response_bytes("ops@example.com"));
    let mut headers = grpc_headers();
    headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));

    // An encoding the guard cannot inflate is uninspectable, not ignored.
    let mut snappy = grpc_headers();
    snappy.insert("grpc-encoding".to_string(), "snappy".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut snappy, &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_malformed_and_oversized_framing_fails_closed() {
    let plugin = grpc_guard("reject");
    let payload = hello_response_bytes("clean");

    // Truncated frame.
    let mut truncated = grpc_frame(&payload);
    truncated.pop();
    // Trailing junk after a complete frame.
    let mut trailing = grpc_frame(&payload);
    trailing.extend_from_slice(&[0u8, 0, 0]);
    // Unrecognized compressed-flag value.
    let mut bad_flag = grpc_frame(&payload);
    bad_flag[0] = 7;

    for body in [truncated, trailing, bad_flag, vec![0u8, 0, 0]] {
        let mut ctx = grpc_ctx("/test.Greeter/SayHello");
        assert!(
            matches!(
                plugin
                    .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
                    .await,
                PluginResult::Reject { .. }
            ),
            "malformed gRPC framing must fail closed"
        );
    }
}

#[tokio::test]
async fn grpc_message_and_stream_bounds_fail_closed() {
    let bounded = make_plugin(json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "max_message_bytes": 8,
            "max_messages": 2,
            "methods": {"/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}}
        }
    }));
    let payload = hello_response_bytes("a message longer than eight bytes");
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        bounded
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &grpc_frame(&payload))
            .await,
        PluginResult::Reject { .. }
    ));

    let small = hello_response_bytes("");
    let mut many = grpc_frame(&small);
    many.extend_from_slice(&grpc_frame(&small));
    many.extend_from_slice(&grpc_frame(&small));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        bounded
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &many)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_undecodable_payload_fails_closed() {
    let plugin = grpc_guard("reject");
    // Field 1 declared as a length-delimited value whose length runs past the
    // buffer: valid framing, invalid protobuf.
    let body = grpc_frame(&[0x0a, 0x7f, 0x01]);
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_unknown_protobuf_fields_fail_closed() {
    let plugin = grpc_guard("reject");
    let mut payload = hello_response_bytes("clean");
    // Field 9, varint — not present in test.HelloResponse.
    payload.extend_from_slice(&[0x48, 0x01]);
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(
        matches!(
            plugin
                .on_response_body(&mut ctx, 200, &mut grpc_headers(), &grpc_frame(&payload))
                .await,
            PluginResult::Reject { .. }
        ),
        "fields outside the descriptor are undecodable evidence and must fail closed"
    );
}

#[tokio::test]
async fn grpc_warn_action_records_and_passes_through() {
    let plugin = grpc_guard("warn");
    let body = grpc_frame(&hello_response_bytes("ops@example.com"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    assert!(ctx.metadata.contains_key("ai_response_guard_detected"));
}

#[tokio::test]
async fn grpc_redact_rewrites_and_reencodes_the_message() {
    let plugin = grpc_guard("redact");
    let body = grpc_frame(&hello_response_bytes("mail ops@example.com now"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    let transformed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &grpc_headers(),
        )
        .await
        .expect("redaction must produce replacement bytes");
    let payloads = grpc_frame_payloads(&transformed);
    assert_eq!(payloads.len(), 1);
    let text = hello_response_text(&payloads[0]);
    assert!(!text.contains("ops@example.com"), "PII survived: {text}");
    assert!(text.contains("[REDACTED:pii:email]"), "unexpected: {text}");
}

#[tokio::test]
async fn grpc_redact_preserves_compressed_framing() {
    let plugin = grpc_guard("redact");
    let body = gzip_grpc_frame(&hello_response_bytes("mail ops@example.com now"));
    let mut headers = grpc_headers();
    headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Continue
    ));
    let transformed = plugin
        .transform_response_body_with_context(&mut ctx, &body, Some("application/grpc"), &headers)
        .await
        .expect("compressed redaction must produce replacement bytes");
    assert_eq!(
        transformed[0], 1,
        "a frame that arrived compressed must stay compressed"
    );
}

#[tokio::test]
async fn grpc_text_fields_narrow_the_scanned_surface() {
    let plugin = make_plugin(json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {
                "response_type": "test.HelloResponse",
                "text_fields": ["message"]
            }}
        }
    }));
    let body = grpc_frame(&hello_response_bytes("ops@example.com"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_missing_descriptor_fails_closed_for_enrolled_methods() {
    let plugin = AiResponseGuard::new(&json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": "/nonexistent/ai-response-guard-descriptor.bin",
            "methods": {"/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}}
        }
    }))
    .expect("an absent node-local descriptor must still construct");
    let body = grpc_frame(&hello_response_bytes("clean"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
    // Still no opportunistic inspection of anything else.
    let mut other = grpc_ctx("/test.Greeter/Unenrolled");
    assert!(matches!(
        plugin
            .on_response_body(&mut other, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn grpc_method_router_metadata_resolves_enrollment() {
    let plugin = grpc_guard("reject");
    let body = grpc_frame(&hello_response_bytes("ops@example.com"));
    let mut ctx = grpc_ctx("/rewritten/path");
    ctx.metadata.insert(
        "grpc_full_method".to_string(),
        "test.Greeter/SayHello".to_string(),
    );
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_empty_and_non_success_bodies_are_not_governed() {
    let plugin = grpc_guard("reject");
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), b"")
            .await,
        PluginResult::Continue
    ));
    let body = grpc_frame(&hello_response_bytes("ops@example.com"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 500, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
}

// ══════════════════════════════════════════════════════════════════════
//  PR #3398 repair regressions
// ══════════════════════════════════════════════════════════════════════

const EXT_PB_LABEL_OPTIONAL: u64 = 1;
const EXT_PB_TYPE_STRING: u64 = 9;
const EXT_PB_TYPE_MESSAGE: u64 = 11;

fn ext_pb_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn ext_pb_tag(out: &mut Vec<u8>, field: u32, wire: u64) {
    ext_pb_varint(out, (u64::from(field) << 3) | wire);
}

fn ext_pb_len_field(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ext_pb_tag(&mut out, field, 2);
    ext_pb_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn ext_pb_str_field(field: u32, value: &str) -> Vec<u8> {
    ext_pb_len_field(field, value.as_bytes())
}

fn ext_pb_varint_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    ext_pb_tag(&mut out, field, 0);
    ext_pb_varint(&mut out, value);
    out
}

fn ext_pb_field(name: &str, number: u32, label: u64, kind: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(ext_pb_str_field(1, name));
    out.extend(ext_pb_varint_field(3, u64::from(number)));
    out.extend(ext_pb_varint_field(4, label));
    out.extend(ext_pb_varint_field(5, kind));
    out
}

fn ext_pb_extension_field(
    name: &str,
    number: u32,
    label: u64,
    kind: u64,
    extendee: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(ext_pb_str_field(1, name));
    out.extend(ext_pb_str_field(2, extendee));
    out.extend(ext_pb_varint_field(3, u64::from(number)));
    out.extend(ext_pb_varint_field(4, label));
    out.extend(ext_pb_varint_field(5, kind));
    out
}

fn ext_pb_extension_message_field(
    name: &str,
    number: u32,
    label: u64,
    ty: &str,
    extendee: &str,
) -> Vec<u8> {
    let mut out = ext_pb_extension_field(name, number, label, EXT_PB_TYPE_MESSAGE, extendee);
    out.extend(ext_pb_str_field(6, ty));
    out
}

/// proto2 FileDescriptorSet:
/// ```proto
/// package ext;
/// message Carrier { optional string base = 1; extensions 100 to 199; }
/// message Nested  { optional string inner = 1; }
/// extend Carrier {
///   optional string note = 100;
///   optional Nested nest = 101;
/// }
/// ```
fn extension_descriptor_set() -> Vec<u8> {
    let base = ext_pb_field("base", 1, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);
    let mut carrier = ext_pb_str_field(1, "Carrier");
    carrier.extend(ext_pb_len_field(2, &base));
    let mut range = Vec::new();
    range.extend(ext_pb_varint_field(1, 100));
    range.extend(ext_pb_varint_field(2, 200));
    carrier.extend(ext_pb_len_field(5, &range));

    let inner = ext_pb_field("inner", 1, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);
    let mut nested = ext_pb_str_field(1, "Nested");
    nested.extend(ext_pb_len_field(2, &inner));

    let note = ext_pb_extension_field(
        "note",
        100,
        EXT_PB_LABEL_OPTIONAL,
        EXT_PB_TYPE_STRING,
        ".ext.Carrier",
    );
    let nest = ext_pb_extension_message_field(
        "nest",
        101,
        EXT_PB_LABEL_OPTIONAL,
        ".ext.Nested",
        ".ext.Carrier",
    );

    let mut file = ext_pb_str_field(1, "ext.proto");
    file.extend(ext_pb_str_field(2, "ext"));
    file.extend(ext_pb_len_field(4, &carrier));
    file.extend(ext_pb_len_field(4, &nested));
    file.extend(ext_pb_len_field(7, &note));
    file.extend(ext_pb_len_field(7, &nest));
    ext_pb_len_field(1, &file)
}

fn extension_descriptor_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("ext.bin"), extension_descriptor_set()).expect("write");
    dir
}

fn extension_guard(dir: &tempfile::TempDir, action: &str) -> AiResponseGuard {
    make_plugin(json!({
        "action": action,
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": dir.path().join("ext.bin").to_string_lossy(),
            "methods": {
                "/ext.Svc/Run": {"response_type": "ext.Carrier"}
            }
        }
    }))
}

fn carrier_with_note(note: &str) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let pool = DescriptorPool::decode(extension_descriptor_set().as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("ext.Carrier").unwrap();
    let extension = pool.get_extension_by_name("ext.note").unwrap();
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("base", Value::String("clean".into()));
    msg.set_extension(&extension, Value::String(note.to_string()));
    msg.encode_to_vec()
}

fn carrier_with_nested_unknown() -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let pool = DescriptorPool::decode(extension_descriptor_set().as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("ext.Carrier").unwrap();
    let nested_desc = pool.get_message_by_name("ext.Nested").unwrap();
    let extension = pool.get_extension_by_name("ext.nest").unwrap();
    let mut nested = DynamicMessage::new(nested_desc.clone());
    nested.set_field_by_name("inner", Value::String("clean".into()));
    let mut nested_bytes = nested.encode_to_vec();
    // Append unknown field 99 (varint 1) outside Nested's descriptor so the
    // extension walk must recurse into the nested message to prove absence.
    ext_pb_tag(&mut nested_bytes, 99, 0);
    ext_pb_varint(&mut nested_bytes, 1);
    let nested = DynamicMessage::decode(nested_desc, nested_bytes.as_slice()).unwrap();
    assert!(
        nested.unknown_fields().next().is_some(),
        "fixture must carry a nested unknown field"
    );
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_extension(&extension, Value::Message(nested));
    msg.encode_to_vec()
}

#[tokio::test]
async fn grpc_string_extension_is_scanned_for_reject_and_redact() {
    let dir = extension_descriptor_dir();
    let reject = extension_guard(&dir, "reject");
    let body = grpc_frame(&carrier_with_note("mail ops@example.com"));
    let mut ctx = grpc_ctx("/ext.Svc/Run");
    assert!(matches!(
        reject
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));

    let redact = extension_guard(&dir, "redact");
    let mut ctx = grpc_ctx("/ext.Svc/Run");
    assert!(matches!(
        redact
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    let transformed = redact
        .transform_response_body_with_context(
            &mut ctx,
            &body,
            Some("application/grpc"),
            &grpc_headers(),
        )
        .await
        .expect("extension redaction must rewrite");
    use prost_reflect::{DescriptorPool, DynamicMessage};
    let pool = DescriptorPool::decode(extension_descriptor_set().as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("ext.Carrier").unwrap();
    let extension = pool.get_extension_by_name("ext.note").unwrap();
    let payloads = grpc_frame_payloads(&transformed);
    let msg = DynamicMessage::decode(descriptor, payloads[0].as_slice()).unwrap();
    let note = msg.get_extension(&extension);
    let note = note.as_str().unwrap();
    assert!(!note.contains("ops@example.com"), "PII survived: {note}");
    assert!(note.contains("[REDACTED:pii:email]"), "unexpected: {note}");
}

#[tokio::test]
async fn grpc_unknown_fields_nested_under_extension_fail_closed() {
    let dir = extension_descriptor_dir();
    let plugin = extension_guard(&dir, "reject");
    let body = grpc_frame(&carrier_with_nested_unknown());
    let mut ctx = grpc_ctx("/ext.Svc/Run");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_split_frame_pii_is_detected_and_redact_fails_closed() {
    let plugin = grpc_guard("reject");
    let mut body = grpc_frame(&hello_response_bytes("ops@"));
    body.extend_from_slice(&grpc_frame(&hello_response_bytes("example.com")));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(
        matches!(
            plugin
                .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
                .await,
            PluginResult::Reject { .. }
        ),
        "email split across frames must still reject"
    );

    let redact = grpc_guard("redact");
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(
        matches!(
            redact
                .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
                .await,
            PluginResult::Reject { .. }
        ),
        "cross-frame-only match must fail closed in redact mode"
    );
    assert!(
        redact
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &grpc_headers(),
            )
            .await
            .is_none(),
        "cross-frame-only match cannot be rewritten in any one scalar"
    );
}

#[tokio::test]
async fn grpc_aggregate_completion_length_covers_selected_stream() {
    let plugin = make_plugin(json!({
        "action": "reject",
        "max_completion_length": 10,
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {"/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}}
        }
    }));
    // Each fragment is under the limit; the ordered aggregate is not.
    let mut body = grpc_frame(&hello_response_bytes("hello "));
    body.extend_from_slice(&grpc_frame(&hello_response_bytes("world!!!")));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_redact_transform_ignores_mislabeled_response_content_type() {
    let plugin = grpc_guard("redact");
    let body = grpc_frame(&hello_response_bytes("mail ops@example.com now"));
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    // Absent or relabeled response Content-Type must not skip the rewrite after
    // a successful framed inspection on an enrolled native-gRPC request.
    for content_type in [None, Some("application/json"), Some("text/plain")] {
        let transformed = plugin
            .transform_response_body_with_context(&mut ctx, &body, content_type, &grpc_headers())
            .await
            .expect("transform gate must follow enrollment, not response Content-Type");
        let text = hello_response_text(&grpc_frame_payloads(&transformed)[0]);
        assert!(
            !text.contains("ops@example.com"),
            "PII leaked under content-type {content_type:?}: {text}"
        );
    }
}

#[tokio::test]
async fn grpc_web_translated_response_is_never_rewritten_as_text() {
    // A gRPC-Web translated response is excluded from the protobuf rewrite
    // (`grpc_web` re-frames the body first), but its bytes are still gRPC
    // framing, so the plain `transform_response_body` must decline them. With
    // `scan_fields: all` the frame bytes of an ASCII payload are valid UTF-8,
    // so a text redaction would rewrite them and change a payload's length
    // without its 5-byte prefix, corrupting the wire while reporting success.
    //
    // This ctx is the native-flavor half of the hazard. The production
    // gRPC-Web shape — `HttpFlavor::Plain` — is covered by
    // `grpc_web_framed_response_fails_closed_instead_of_being_text_redacted`.
    let plugin = make_plugin(json!({
        "action": "redact",
        "scan_fields": "all",
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {
                "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        }
    }));
    let body = grpc_frame(&hello_response_bytes("mail ops@example.com now"));
    assert!(
        std::str::from_utf8(&body).is_ok(),
        "the regression only bites when the framed body is valid UTF-8"
    );

    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    ctx.metadata
        .insert("grpc_web_mode".to_string(), "text".to_string());

    // Detection still fires; redaction cannot reach the delivered bytes, so the
    // enforcing action fails closed rather than claiming a redaction.
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_response_guard_rejected")
            .map(|s| s.as_str()),
        Some("grpc_web_translation_blocks_redaction")
    );

    // The transform must decline these bytes for every response label a
    // translated response can carry, including the gRPC-Web media types that
    // the native-gRPC content-type guard does not recognize.
    for content_type in [
        None,
        Some("application/grpc-web+proto"),
        Some("application/grpc-web-text"),
        Some("application/json"),
        Some("text/plain"),
    ] {
        assert!(
            plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    &body,
                    content_type,
                    &grpc_headers()
                )
                .await
                .is_none(),
            "gRPC framing must never be rewritten as text under content-type {content_type:?}"
        );
    }
}

#[tokio::test]
async fn grpc_gzip_rejects_trailing_garbage_and_concatenated_members() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = grpc_guard("reject");
    let payload = hello_response_bytes("clean");

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&payload).unwrap();
    let mut with_trailer = encoder.finish().unwrap();
    with_trailer.extend_from_slice(b"trailing-garbage");
    let mut frame = Vec::with_capacity(5 + with_trailer.len());
    frame.push(1);
    frame.extend_from_slice(&(with_trailer.len() as u32).to_be_bytes());
    frame.extend_from_slice(&with_trailer);
    let mut headers = grpc_headers();
    headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &frame)
            .await,
        PluginResult::Reject { .. }
    ));

    let mut first = GzEncoder::new(Vec::new(), flate2::Compression::default());
    first.write_all(&payload).unwrap();
    let mut concatenated = first.finish().unwrap();
    let mut second = GzEncoder::new(Vec::new(), flate2::Compression::default());
    second.write_all(&payload).unwrap();
    concatenated.extend_from_slice(&second.finish().unwrap());
    let mut frame = Vec::with_capacity(5 + concatenated.len());
    frame.push(1);
    frame.extend_from_slice(&(concatenated.len() as u32).to_be_bytes());
    frame.extend_from_slice(&concatenated);
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &frame)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn grpc_aggregate_decoded_budget_bounds_compressed_amplification() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    // Small wire body, but decompressed aggregate exceeds max_scan_bytes.
    let plugin = make_plugin(json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "max_scan_bytes": 64,
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "max_message_bytes": 4096,
            "methods": {"/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}}
        }
    }));
    let large = hello_response_bytes(&"x".repeat(1024));
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&large).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    assert!(
        frame.len() <= 64,
        "fixture must amplify under the wire budget: frame {} vs limit 64",
        frame.len()
    );
    assert!(
        large.len() > 64,
        "decompressed payload must exceed max_scan_bytes"
    );
    let mut headers = grpc_headers();
    headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &frame)
            .await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn grpc_method_path_requires_protobuf_identifier_grammar() {
    for invalid in [
        "/a.B/C?x=1",
        "/a.B/C%2F",
        "/a. B/C",
        "/a..B/C",
        "/.B/C",
        "/a.B/",
        "//a.B/C",
        "/a.B/C/extra",
        "/1Service/Method",
        "/a.B/9bad",
        "/a-B/C",
        "not-a-path",
        "",
    ] {
        let mut methods = serde_json::Map::new();
        methods.insert(invalid.to_string(), json!({"response_type": "x"}));
        let config = json!({
            "pii_patterns": ["email"],
            "grpc": {
                "descriptor_path": "/tmp/x.bin",
                "methods": methods
            }
        });
        assert!(
            AiResponseGuard::new(&config).is_err(),
            "must reject method path {invalid:?}"
        );
    }

    // Optional leading slash still normalizes.
    let config = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {
                "test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        }
    });
    assert!(AiResponseGuard::new(&config).is_ok());

    // Duplicate after normalization is rejected.
    let dup = json!({
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "methods": {
                "test.Greeter/SayHello": {"response_type": "test.HelloResponse"},
                "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        }
    });
    assert!(AiResponseGuard::new(&dup).is_err());
}

/// A gRPC-framed response on a request that is NOT native gRPC has no
/// descriptor contract, and `transform_response_body` declines those bytes.
/// `scan_fields: all` must therefore not report a redaction the transform can
/// never apply — it fails closed exactly as content mode already does.
#[tokio::test]
async fn scan_all_grpc_framed_response_on_http_request_fails_closed() {
    let plugin = make_plugin(json!({
        "action": "redact",
        "pii_patterns": ["email"],
        "scan_fields": "all"
    }));
    // Valid UTF-8 framed bytes: without the guard this is scanned as raw text.
    let body = grpc_frame(b"contact ops@example.com now");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let result = plugin
        .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "gRPC-framed response must not be redacted as a text document"
    );
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"grpc_framed_response_requires_grpc_contract".to_string())
    );
    assert!(!ctx.metadata.contains_key("ai_response_guard_redacted"));
    assert!(
        plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &grpc_headers(),
            )
            .await
            .is_none(),
        "the text transform must never rewrite gRPC framing"
    );
}

/// Warn-only guards keep their documented pass-through posture for the same
/// uninspectable response, recording the reason instead of rejecting.
#[tokio::test]
async fn scan_all_grpc_framed_response_on_http_request_warns_in_warn_mode() {
    let plugin = make_plugin(json!({
        "action": "warn",
        "pii_patterns": ["email"],
        "scan_fields": "all"
    }));
    let body = grpc_frame(b"contact ops@example.com now");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut grpc_headers(), &body)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_warning"),
        Some(&"grpc_framed_response_requires_grpc_contract".to_string())
    );
}

/// A highly compressible gzip frame is bounded by the aggregate
/// `max_scan_bytes` budget, not just by the (independently configurable)
/// per-message ceiling, so a small compressed frame cannot inflate to the much
/// larger per-message limit before being refused.
#[tokio::test]
async fn grpc_gzip_bomb_is_bounded_by_max_scan_bytes() {
    let plugin = make_plugin(json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "max_scan_bytes": 4096,
        "grpc": {
            "descriptor_path": grpc_descriptor_path(),
            "max_message_bytes": 1048576,
            "methods": {
                "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        }
    }));
    let payload = vec![b'a'; 512_000];
    let body = gzip_grpc_frame(&payload);
    assert!(
        body.len() <= 4096,
        "the compressed frame itself must fit under max_scan_bytes"
    );
    let mut headers = grpc_headers();
    headers.insert("grpc-encoding".to_string(), "gzip".to_string());
    let mut ctx = grpc_ctx("/test.Greeter/SayHello");
    assert!(matches!(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(
        ctx.metadata.get("ai_response_guard_rejected"),
        Some(&"grpc_decoded_exceeds_max_scan_bytes".to_string())
    );
}

const SCOPE_PB_LABEL_REPEATED: u64 = 3;

fn scope_pb_message_field(name: &str, number: u32, label: u64, ty: &str) -> Vec<u8> {
    let mut out = ext_pb_field(name, number, label, EXT_PB_TYPE_MESSAGE);
    out.extend(ext_pb_str_field(6, ty));
    out
}

fn scope_pb_as_map_entry(mut message: Vec<u8>) -> Vec<u8> {
    // MessageOptions.map_entry = true (options field 7; map_entry field 7).
    let options = ext_pb_varint_field(7, 1);
    message.extend(ext_pb_len_field(7, &options));
    message
}

/// proto2 FileDescriptorSet:
/// ```proto
/// package scope;
/// message Reply {
///   optional string body = 1;
///   optional string meta = 2;
///   map<string, string> labels = 3;
/// }
/// ```
fn scoped_reply_descriptor_set() -> Vec<u8> {
    let body = ext_pb_field("body", 1, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);
    let meta = ext_pb_field("meta", 2, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);

    let key = ext_pb_field("key", 1, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);
    let value = ext_pb_field("value", 2, EXT_PB_LABEL_OPTIONAL, EXT_PB_TYPE_STRING);
    let mut entry = ext_pb_str_field(1, "LabelsEntry");
    entry.extend(ext_pb_len_field(2, &key));
    entry.extend(ext_pb_len_field(2, &value));
    let entry = scope_pb_as_map_entry(entry);

    let labels = scope_pb_message_field(
        "labels",
        3,
        SCOPE_PB_LABEL_REPEATED,
        ".scope.Reply.LabelsEntry",
    );
    let mut reply = ext_pb_str_field(1, "Reply");
    reply.extend(ext_pb_len_field(2, &body));
    reply.extend(ext_pb_len_field(2, &meta));
    reply.extend(ext_pb_len_field(2, &labels));
    reply.extend(ext_pb_len_field(3, &entry));

    let mut file = ext_pb_str_field(1, "scope.proto");
    file.extend(ext_pb_str_field(2, "scope"));
    file.extend(ext_pb_len_field(4, &reply));
    ext_pb_len_field(1, &file)
}

fn scoped_reply_descriptor_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("scope.bin"), scoped_reply_descriptor_set()).expect("write");
    dir
}

fn scoped_reply_bytes(body: &str, meta: &str, map_key: &str, map_value: &str) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, MapKey, Value};
    use std::collections::HashMap;

    let pool = DescriptorPool::decode(scoped_reply_descriptor_set().as_slice()).unwrap();
    let descriptor = pool.get_message_by_name("scope.Reply").unwrap();
    let mut msg = DynamicMessage::new(descriptor);
    msg.set_field_by_name("body", Value::String(body.to_string()));
    msg.set_field_by_name("meta", Value::String(meta.to_string()));
    let mut labels = HashMap::new();
    labels.insert(
        MapKey::String(map_key.to_string()),
        Value::String(map_value.to_string()),
    );
    msg.set_field_by_name("labels", Value::Map(labels));
    msg.encode_to_vec()
}

fn scoped_text_fields_guard(dir: &tempfile::TempDir) -> AiResponseGuard {
    make_plugin(json!({
        "action": "reject",
        "pii_patterns": ["email"],
        "grpc": {
            "descriptor_path": dir.path().join("scope.bin").to_string_lossy(),
            "methods": {
                "/scope.Svc/Run": {
                    "response_type": "scope.Reply",
                    "text_fields": ["body"]
                }
            }
        }
    }))
}

/// `text_fields` is the enrollment contract: out-of-scope strings and map keys
/// must not trigger detection, while an in-scope match still fails closed.
#[tokio::test]
async fn grpc_text_fields_ignore_out_of_scope_strings_and_map_keys() {
    let dir = scoped_reply_descriptor_dir();
    let plugin = scoped_text_fields_guard(&dir);

    // Out-of-scope scalar + map key carry PII; selected `body` is clean.
    let out_of_scope = grpc_frame(&scoped_reply_bytes(
        "clean",
        "mail ops@example.com",
        "ops@example.com",
        "also ops@example.com",
    ));
    let mut ctx = grpc_ctx("/scope.Svc/Run");
    assert!(
        matches!(
            plugin
                .on_response_body(&mut ctx, 200, &mut grpc_headers(), &out_of_scope)
                .await,
            PluginResult::Continue
        ),
        "out-of-scope string/map-key matches must not reject under text_fields"
    );

    // Same out-of-scope PII, but the selected field also matches.
    let in_scope = grpc_frame(&scoped_reply_bytes(
        "mail ops@example.com",
        "mail ops@example.com",
        "ops@example.com",
        "also ops@example.com",
    ));
    let mut ctx = grpc_ctx("/scope.Svc/Run");
    assert!(
        matches!(
            plugin
                .on_response_body(&mut ctx, 200, &mut grpc_headers(), &in_scope)
                .await,
            PluginResult::Reject { .. }
        ),
        "in-scope text_fields matches must still reject"
    );
}

/// A browser gRPC-Web request as the proxy actually classifies it.
///
/// `detect_http_flavor` calls gRPC-Web `HttpFlavor::Plain` — only the request
/// protocol view is gRPC — so a framing guard keyed on
/// `is_native_grpc_request()` never fires for real gRPC-Web traffic.
fn grpc_web_ctx(path: &str, translated: bool) -> RequestContext {
    let ip = "127.0.0.1".to_string();
    let mut ctx = RequestContext::new(ip, "POST".to_string(), path.to_string());
    if translated {
        // `grpc_web` claimed the translation, so the backend answered in native
        // framing and this plugin's transform runs after that re-framing.
        let mode = "binary".to_string();
        ctx.metadata.insert("grpc_web_mode".to_string(), mode);
    }
    // Retained on both the translated and pass-through deployments.
    let ct = "application/grpc-web+proto".to_string();
    ctx.metadata.insert("grpc_web_original_ct".to_string(), ct);
    ctx
}

fn grpc_web_guard(with_grpc_block: bool) -> AiResponseGuard {
    let mut config = json!({
        "action": "redact",
        "scan_fields": "all",
        "pii_patterns": ["email"]
    });
    if with_grpc_block {
        config["grpc"] = json!({
            "descriptor_path": grpc_descriptor_path(),
            "methods": {
                "/test.Greeter/SayHello": {"response_type": "test.HelloResponse"}
            }
        });
    }
    make_plugin(config)
}

fn content_type_headers(value: Option<&str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    if let Some(ct) = value {
        headers.insert("content-type".to_string(), ct.to_string());
    }
    headers
}

async fn guard_inspect(
    plugin: &AiResponseGuard,
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
    body: &[u8],
) -> PluginResult {
    plugin.on_response_body(ctx, 200, headers, body).await
}

async fn guard_transform(
    plugin: &AiResponseGuard,
    ctx: &mut RequestContext,
    body: &[u8],
    headers: &HashMap<String, String>,
) -> Option<Vec<u8>> {
    let content_type = headers.get("content-type").map(String::as_str);
    plugin
        .transform_response_body_with_context(ctx, body, content_type, headers)
        .await
}

fn rejected_reason(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("ai_response_guard_rejected")
        .map(String::as_str)
}

fn assert_framing_reject(verdict: PluginResult, ctx: &RequestContext, label: &str) {
    assert!(matches!(verdict, PluginResult::Reject { .. }), "{label}");
    let expected = Some("grpc_framed_response_requires_grpc_contract");
    assert_eq!(rejected_reason(ctx), expected, "{label}");
    let redacted = ctx.metadata.contains_key("ai_response_guard_redacted");
    assert!(!redacted, "a redaction that cannot reach the wire: {label}");
}

#[tokio::test]
async fn grpc_web_framed_response_fails_closed_instead_of_being_text_redacted() {
    // Regression: the framing guard must not key on the request's HTTP flavor
    // or on `application/grpc` alone. A browser gRPC-Web request is
    // `HttpFlavor::Plain`, so it never reaches the descriptor contract, and
    // `grpc_web`'s `after_proxy` has already relabeled the response to
    // `application/grpc-web*` by the time `on_response_body` runs. Under
    // `scan_fields: all` those frame bytes are valid UTF-8, so the JSON/text
    // model would detect the PII, report `redacted`, and then regex-rewrite the
    // payload without its 5-byte length prefix — corrupting the delivered wire.
    let body = grpc_frame(&hello_response_bytes("mail ops@example.com now"));
    assert!(
        std::str::from_utf8(&body).is_ok(),
        "the regression only bites when the framed body is valid UTF-8"
    );

    for with_grpc_block in [false, true] {
        let plugin = grpc_web_guard(with_grpc_block);
        for translated in [true, false] {
            let label = format!("grpc_block={with_grpc_block} translated={translated}");
            let mut ctx = grpc_web_ctx("/test.Greeter/SayHello", translated);
            let ct = Some("application/grpc-web+proto");
            let mut headers = content_type_headers(ct);

            let verdict = guard_inspect(&plugin, &mut ctx, &mut headers, &body).await;
            assert_framing_reject(verdict, &ctx, &label);

            let rewritten = guard_transform(&plugin, &mut ctx, &body, &headers).await;
            assert!(
                rewritten.is_none(),
                "a gRPC-Web framed body must never be rewritten as text ({label})"
            );
        }
    }
}

#[tokio::test]
async fn grpc_web_framing_is_resolved_without_a_trustworthy_content_type() {
    // A header rule can strip or relabel the response `Content-Type` after the
    // backend answered, so the live label alone cannot decide framing. The
    // pristine backend label stamped before any response hook ran, and failing
    // that a total frame parse under the client's representation, must still
    // recognize these bytes as gRPC-Web framing and fail closed.
    let plugin = grpc_web_guard(true);
    let body = grpc_frame(&hello_response_bytes("mail ops@example.com now"));

    // (a) Live type relabeled to JSON; the pristine backend type proves framing.
    let mut ctx = grpc_web_ctx("/test.Greeter/SayHello", true);
    let key = "ferrum:original_response_content_type".to_string();
    let pristine = "application/grpc+proto".to_string();
    ctx.metadata.insert(key, pristine);
    let mut headers = content_type_headers(Some("application/json"));
    let verdict = guard_inspect(&plugin, &mut ctx, &mut headers, &body).await;
    assert_framing_reject(verdict, &ctx, "relabeled content-type");

    // (b) No live type and no pristine type: the bytes themselves total-parse
    // as complete frames under the retained gRPC-Web binary grammar.
    let mut ctx = grpc_web_ctx("/test.Greeter/SayHello", false);
    let mut headers = content_type_headers(None);
    let verdict = guard_inspect(&plugin, &mut ctx, &mut headers, &body).await;
    assert_framing_reject(verdict, &ctx, "stripped content-type");
}

#[tokio::test]
async fn grpc_web_request_with_a_bare_json_document_is_still_inspected() {
    // The framing resolution is one-directional: it must not turn every
    // response on a gRPC-Web request into a 502. A genuine bare JSON document
    // is not a frame sequence under any gRPC grammar (a frame's first octet is
    // a flag byte, and `{` is not one), so it stays claimed and redactable.
    let plugin = grpc_web_guard(true);
    let body = br#"{"choices":[{"message":{"content":"mail ops@example.com"}}]}"#;

    let mut ctx = grpc_web_ctx("/test.Greeter/SayHello", false);
    let mut headers = content_type_headers(Some("application/json"));
    let verdict = guard_inspect(&plugin, &mut ctx, &mut headers, body).await;
    assert!(matches!(verdict, PluginResult::Continue));
    assert!(
        ctx.metadata.contains_key("ai_response_guard_redacted"),
        "a bare JSON document on a gRPC-Web request must still be redacted"
    );

    let rewritten = guard_transform(&plugin, &mut ctx, body, &headers).await;
    let rewritten = rewritten.expect("bare JSON is still rewritten");
    let rewritten = String::from_utf8(rewritten).unwrap();
    assert!(!rewritten.contains("ops@example.com"));
    assert!(rewritten.contains("[REDACTED:pii:email]"));
}

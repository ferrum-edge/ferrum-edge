use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, is_security_plugin};
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
async fn cidr_text_rules_are_scoped_to_their_configured_target() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-CIDR-HEADER",
            "name": "private forwarding address",
            "category": "custom",
            "severity": "high",
            "target": { "type": "header_values", "names": ["x-forwarded-for"] },
            "match_kind": "cidr",
            "pattern": "10.0.0.0/8",
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut query_ctx = ctx("GET", "/search");
    query_ctx.set_raw_query_string("ip=10.1.2.3".into());
    let result = plugin.on_request_received(&mut query_ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !query_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-CIDR-HEADER"))
    );

    let mut header_ctx = ctx("GET", "/search");
    header_ctx
        .headers
        .insert("x-forwarded-for".into(), "10.1.2.3".into());
    let result = plugin.on_request_received(&mut header_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        header_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-CIDR-HEADER")
    );
}

#[tokio::test]
async fn response_header_cidr_rule_matches_without_regex_header_rules() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "custom_rules": [{
            "id": "CUSTOM-CIDR-RESP",
            "name": "private upstream header",
            "category": "custom",
            "severity": "medium",
            "target": "response_headers",
            "match_kind": "cidr",
            "pattern": "10.0.0.0/8",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/debug");
    let mut headers = HashMap::from([("x-upstream-ip".to_string(), "10.2.3.4".to_string())]);

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-CIDR-RESP")
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

#[test]
fn waf_is_security_critical() {
    assert!(is_security_plugin("waf"));
}

#[tokio::test]
async fn duplicate_query_key_cannot_smuggle_payload_past_query_values_rule() {
    // Regression: `materialize_query_params()` collapses duplicate keys into a
    // `HashMap`, so `?q=<script>&q=ok` previously left only `q=ok` visible to
    // the `query_values` scan and the XSS payload slipped past an enforced
    // rule. The fix scans each raw pair before HashMap collapse.
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E&q=ok".into());

    let result = plugin.on_request_received(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-XSS-001")
    );
}

#[test]
fn unknown_rule_modes_id_fails_construction() {
    // WAF is security-critical: a typo in an `enforce` override would
    // otherwise silently leave the rule monitor-only.
    let err = Waf::new(&json!({
        "rule_modes": { "FE-XSS-99": "enforce" }
    }))
    .unwrap_err();
    assert!(err.contains("unknown rule id"));
    assert!(err.contains("FE-XSS-99"));
}

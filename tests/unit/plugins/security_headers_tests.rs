use ferrum_edge::plugins::security_headers::SecurityHeaders;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, is_security_plugin};
use serde_json::json;
use std::collections::HashMap;

fn ctx() -> RequestContext {
    RequestContext::new("203.0.113.10".into(), "GET".into(), "/".into())
}

#[tokio::test]
async fn adds_secure_defaults_and_strips_fingerprinting_headers() {
    let plugin = SecurityHeaders::new(&json!({})).unwrap();
    let mut ctx = ctx();
    let mut headers = HashMap::from([
        ("Server".to_string(), "nginx".to_string()),
        ("X-Powered-By".to_string(), "Express".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
    ]);

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        headers.get("x-content-type-options").map(String::as_str),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(String::as_str),
        Some("SAMEORIGIN")
    );
    assert!(headers.contains_key("referrer-policy"));
    assert!(headers.keys().all(|k| !k.eq_ignore_ascii_case("server")));
    assert!(
        headers
            .keys()
            .all(|k| !k.eq_ignore_ascii_case("x-powered-by"))
    );
    // Untouched backend headers survive.
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("text/html")
    );
}

#[tokio::test]
async fn opt_in_hsts_csp_and_custom_headers_are_applied() {
    let plugin = SecurityHeaders::new(&json!({
        "hsts": true,
        "content_security_policy": "default-src 'self'",
        "permissions_policy": "geolocation=()",
        "set": { "X-Env": "prod" }
    }))
    .unwrap();
    let mut ctx = ctx();
    let mut headers = HashMap::new();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(
        headers.get("strict-transport-security").map(String::as_str),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        headers.get("content-security-policy").map(String::as_str),
        Some("default-src 'self'")
    );
    assert_eq!(
        headers.get("permissions-policy").map(String::as_str),
        Some("geolocation=()")
    );
    assert_eq!(headers.get("x-env").map(String::as_str), Some("prod"));
}

#[test]
fn security_headers_is_a_security_plugin() {
    assert!(is_security_plugin("security_headers"));
}

#[test]
fn may_add_no_transform_reports_conservative_capability() {
    let mut headers = HashMap::from([("cache-control".to_string(), "max-age=60".to_string())]);
    let ctx = ctx();
    let set_only = SecurityHeaders::new(&json!({
        "override_existing": false,
        "set": { "Cache-Control": "no-transform" }
    }))
    .unwrap();
    assert!(set_only.may_add_response_cache_control_no_transform(&ctx, &headers));

    let remove_then_set = SecurityHeaders::new(&json!({
        "override_existing": false,
        "remove": ["Cache-Control"],
        "set": { "Cache-Control": "no-transform" }
    }))
    .unwrap();
    assert!(remove_then_set.may_add_response_cache_control_no_transform(&ctx, &headers));

    headers.insert("cache-control".to_string(), "private".to_string());
    assert!(remove_then_set.may_add_response_cache_control_no_transform(&ctx, &headers));
}

#[tokio::test]
async fn applies_to_gateway_rejection_responses() {
    let plugin = SecurityHeaders::new(&json!({})).unwrap();
    let mut ctx = ctx();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    assert!(plugin.applies_after_proxy_on_reject());
    let result = plugin.after_proxy(&mut ctx, 403, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        headers.get("x-content-type-options").map(String::as_str),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(String::as_str),
        Some("SAMEORIGIN")
    );
}

#[test]
fn invalid_header_value_is_rejected() {
    let err =
        SecurityHeaders::new(&json!({ "set": { "X-Bad": "line1\r\nInjected: x" } })).unwrap_err();
    assert!(err.contains("CR, LF"));
}

#[test]
fn no_op_config_is_rejected() {
    let err = SecurityHeaders::new(&json!({
        "content_type_options": false,
        "frame_options": false,
        "referrer_policy": false,
        "remove": []
    }))
    .unwrap_err();
    assert!(err.contains("no headers"));
}

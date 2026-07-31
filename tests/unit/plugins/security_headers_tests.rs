use ferrum_edge::plugins::security_headers::SecurityHeaders;
use ferrum_edge::plugins::{
    BufferedInitialResponseHeaderPolicyState, Plugin, PluginFailurePolicy, PluginResult,
    RequestContext, apply_initial_response_header_policies, plugin_failure_policy,
};
use ferrum_edge::proxy::headers::{append_set_cookie_header, apply_response_headers};
use http::{Response, Version};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

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
    assert_eq!(
        plugin_failure_policy("security_headers"),
        Some(PluginFailurePolicy::FailClosed)
    );
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

#[test]
fn may_add_strong_etag_reports_conservative_capability() {
    let headers = HashMap::from([("etag".to_string(), "W/\"weak\"".to_string())]);
    let ctx = ctx();
    let strong = SecurityHeaders::new(&json!({
        "set": { "ETag": "\"strong\"" }
    }))
    .unwrap();
    assert!(strong.may_add_response_strong_etag(&ctx, &headers));

    let weak = SecurityHeaders::new(&json!({
        "set": { "ETag": "W/\"weak\"" }
    }))
    .unwrap();
    assert!(!weak.may_add_response_strong_etag(&ctx, &headers));

    let malformed_weak = SecurityHeaders::new(&json!({
        "set": { "ETag": "w/\"weak\"" }
    }))
    .unwrap();
    assert!(malformed_weak.may_add_response_strong_etag(&ctx, &headers));

    let spaced_weak = SecurityHeaders::new(&json!({
        "set": { "ETag": "W/ \"weak\"" }
    }))
    .unwrap();
    assert!(spaced_weak.may_add_response_strong_etag(&ctx, &headers));
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
    assert!(err.contains("valid HTTP field value"));
}

#[tokio::test]
async fn accepts_complete_http_field_name_grammar_and_canonicalizes_case() {
    let name = "X!#$%&'*+-.^_`|~TOKEN";
    let mut set = serde_json::Map::new();
    set.insert(name.to_string(), json!("accepted"));
    let plugin = SecurityHeaders::new(&json!({ "set": set, "remove": [name] })).unwrap();
    let mut ctx = ctx();
    let mut headers = HashMap::from([(name.to_string(), "backend".to_string())]);

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    let canonical = name.to_ascii_lowercase();
    assert_eq!(
        headers.get(&canonical).map(String::as_str),
        Some("accepted")
    );
    assert_eq!(headers.keys().filter(|key| *key == &canonical).count(), 1);
}

#[test]
fn rejects_names_outside_http_field_name_grammar_without_trimming() {
    let maximum = "a".repeat(65_535);
    let mut maximum_set = serde_json::Map::new();
    maximum_set.insert(maximum, json!("accepted"));
    SecurityHeaders::new(&json!({ "set": maximum_set }))
        .expect("65,535-byte HTTP field name is the accepted builder limit");

    let overlong = "a".repeat(65_536);
    let mut invalid = vec![
        "".to_string(),
        " x-name".to_string(),
        "x-name ".to_string(),
        "x name".to_string(),
        "x\tname".to_string(),
        "x\rname".to_string(),
        "x\nname".to_string(),
        "x\0name".to_string(),
        "x\u{00e9}".to_string(),
        overlong,
    ];
    invalid.extend(
        [
            '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}',
        ]
        .into_iter()
        .map(|separator| format!("x{separator}name")),
    );

    for name in invalid {
        let mut set = serde_json::Map::new();
        set.insert(name.clone(), json!("value"));
        let err = SecurityHeaders::new(&json!({ "set": set })).unwrap_err();
        assert!(
            err.contains("'set' contains invalid HTTP field name"),
            "unexpected set error for {name:?}: {err}"
        );

        let err = SecurityHeaders::new(&json!({ "remove": [name] })).unwrap_err();
        assert!(
            err.contains("'remove' contains invalid HTTP field name"),
            "unexpected remove error: {err}"
        );
    }
}

#[test]
fn invalid_header_name_errors_identify_the_offending_set_or_remove_entry() {
    let err = SecurityHeaders::new(&json!({
        "set": {
            "x-valid-name": "valid",
            "x-bad name": "invalid"
        }
    }))
    .unwrap_err();
    assert!(err.contains("'set'"), "set path missing from: {err}");
    assert!(
        err.contains("x-bad name"),
        "offending set entry missing from: {err}"
    );
    assert!(
        !err.contains("x-valid-name"),
        "the error must diagnose the invalid entry, not a neighboring valid entry: {err}"
    );

    let err = SecurityHeaders::new(&json!({
        "remove": ["x-valid-name", "x-bad\tname"]
    }))
    .unwrap_err();
    assert!(err.contains("'remove'"), "remove path missing from: {err}");
    assert!(
        err.contains(r"x-bad\tname"),
        "offending remove entry must be escaped in: {err}"
    );
}

#[test]
fn invalid_header_name_error_rendering_is_escaped_and_bounded() {
    let hostile = format!("x\r\n{}DO_NOT_ECHO", "a".repeat(8_192));
    let err = SecurityHeaders::new(&json!({ "remove": [hostile] })).unwrap_err();

    assert!(
        err.contains(r"x\r\n"),
        "control characters must be escaped in: {err}"
    );
    assert!(err.contains("..."), "truncated names must be marked: {err}");
    assert!(
        !err.contains("DO_NOT_ECHO"),
        "unbounded hostile suffix leaked into: {err}"
    );
    assert!(
        err.len() < 200,
        "validation error must stay length-bounded, got {} bytes",
        err.len()
    );
}

#[test]
fn validates_every_configurable_field_value_with_http_builder_rules() {
    let invalid_values: Vec<String> = (0u8..=31)
        .filter(|byte| *byte != b'\t')
        .chain(std::iter::once(127))
        .map(|byte| format!("before{}after", char::from(byte)))
        .chain(std::iter::once("caf\u{00e9}".to_string()))
        .collect();

    for value in invalid_values {
        let configs = [
            json!({ "content_type_options": value.clone() }),
            json!({ "frame_options": value.clone() }),
            json!({ "referrer_policy": value.clone() }),
            json!({ "hsts": value.clone() }),
            json!({ "content_security_policy": value.clone() }),
            json!({ "permissions_policy": value.clone() }),
            json!({ "set": { "X-Policy": value.clone() } }),
        ];
        for config in configs {
            let err = SecurityHeaders::new(&config).unwrap_err();
            assert!(
                err.contains("valid HTTP field value"),
                "unexpected error for {config:?}: {err}"
            );
        }
    }

    SecurityHeaders::new(&json!({ "set": { "X-Policy": "one\ttwo" } })).unwrap();
}

#[test]
fn validated_names_and_values_reach_h1_h2_and_h3_builders() {
    let plugin = SecurityHeaders::new(&json!({
        "set": { "X!Policy": "one\ttwo" }
    }))
    .unwrap();

    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let mut headers = HashMap::new();
        plugin.apply_initial_response_header_policy(&mut headers);
        let response = ferrum_edge::proxy::headers::apply_response_headers(
            Response::builder().version(version),
            &headers,
        )
        .body(())
        .unwrap();
        assert_eq!(
            response
                .headers()
                .get("x!policy")
                .map(|value| value.as_bytes()),
            Some(b"one\ttwo".as_slice())
        );
    }
}

#[test]
fn rejects_unknown_top_level_and_nested_hsts_keys_with_paths() {
    let err = SecurityHeaders::new(&json!({
        "fram_options": false,
        "unknown": true
    }))
    .unwrap_err();
    assert!(err.contains("under 'security_headers': fram_options, unknown"));

    let err = SecurityHeaders::new(&json!({
        "hsts": {
            "max_age": 60,
            "include_subdomain": true,
            "unknown": false
        }
    }))
    .unwrap_err();
    assert!(err.contains("under 'security_headers.hsts': include_subdomain, unknown"));
}

#[test]
fn ordered_initial_response_policy_chain_matches_multiple_instance_semantics() {
    let first: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "X-Order": "first", "X-Removed": "first" },
            "remove": []
        }))
        .unwrap(),
    );
    let second: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "X-Order": "second" },
            "remove": ["X-Removed"]
        }))
        .unwrap(),
    );
    let mut headers = HashMap::new();

    apply_initial_response_header_policies(&[first, second], &mut headers);

    assert_eq!(headers.get("x-order").map(String::as_str), Some("second"));
    assert!(!headers.contains_key("x-removed"));
}

#[test]
fn websocket_sticky_cookie_appends_to_security_policy_cookie() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": { "Set-Cookie": "policy=value; Secure" }
        }))
        .unwrap(),
    );
    let mut headers = HashMap::new();

    apply_initial_response_header_policies(&[policy], &mut headers);
    append_set_cookie_header(&mut headers, "affinity=target-a; Secure".to_string());

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("policy=value; Secure\naffinity=target-a; Secure")
    );
    let response = apply_response_headers(Response::builder(), &headers)
        .body(())
        .unwrap();
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(
        cookies,
        vec!["policy=value; Secure", "affinity=target-a; Secure"]
    );
}

#[test]
fn buffered_policy_state_uses_genuine_initial_headers() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": false,
            "set": {
                "X-Security-Policy": "gateway-enforced"
            }
        }))
        .unwrap(),
    );
    let initial_headers = HashMap::new();
    let mut merged_headers = HashMap::from([(
        "x-security-policy".to_string(),
        "backend-trailer".to_string(),
    )]);
    let mut state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::new(policy.initial_response_header_policy_names().to_vec()),
        &initial_headers,
        &merged_headers,
    )
    .unwrap();
    policy.apply_initial_response_header_policy(&mut merged_headers);
    state.record_after_proxy_plugin(policy.as_ref(), &mut merged_headers);
    let mut final_initial_headers = HashMap::new();
    state.apply_to_initial_headers(&mut final_initial_headers);

    assert_eq!(
        final_initial_headers
            .get("x-security-policy")
            .map(String::as_str),
        Some("gateway-enforced")
    );
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

/// The closed set of destinations the gateway's final wire boundary owns.
const PROTOCOL_MANAGED_DESTINATIONS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Every case spelling worth probing for one field name: canonical lowercase,
/// screaming upper, and per-token title case.
fn case_variants(name: &str) -> Vec<String> {
    let title = name
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-");
    vec![name.to_string(), name.to_ascii_uppercase(), title]
}

fn set_config(name: &str, value: &str) -> serde_json::Value {
    let mut set = serde_json::Map::new();
    set.insert(
        name.to_string(),
        serde_json::Value::String(value.to_string()),
    );
    json!({ "set": serde_json::Value::Object(set) })
}

/// GHSA-xvr4 residual: `set` accepted any syntactically valid field name,
/// including protocol-managed framing names, and applied them in `after_proxy`
/// — i.e. after the backend hop-by-hop strip and before the gateway's final
/// wire boundary. A `Content-Length` authored there is a valid-looking length
/// the gateway cannot verify against a streamed body's bytes.
///
/// Rejection uses the shared case-insensitive predicate over the shared closed
/// set, so every case variant of every protocol-managed name fails identically.
#[test]
fn set_rejects_every_protocol_managed_destination_case_insensitively() {
    for name in PROTOCOL_MANAGED_DESTINATIONS {
        for spelling in case_variants(name) {
            let error = SecurityHeaders::new(&set_config(&spelling, "1"))
                .expect_err(&format!("set.{spelling} must be rejected"));
            assert!(
                error.contains("protocol-managed"),
                "diagnostic for set.{spelling} must say why: {error}"
            );
            assert!(
                error.contains(name),
                "diagnostic must name the offending setting with its canonical \
                 lowercase field name: {error}"
            );
        }
    }
}

/// The rejection is scoped to `set` destinations. `remove` of the same names
/// stays allowed: dropping a protocol-managed field is a no-op after the origin
/// strip and can never invent framing.
#[tokio::test]
async fn remove_still_accepts_protocol_managed_names() {
    for name in PROTOCOL_MANAGED_DESTINATIONS {
        for spelling in case_variants(name) {
            SecurityHeaders::new(&json!({ "remove": [spelling.clone()] }))
                .unwrap_or_else(|error| panic!("remove of {spelling} must stay allowed: {error}"));
        }
    }

    // A config that removes framing names and sets an ordinary one is valid, and
    // the ordinary header still applies.
    let plugin = SecurityHeaders::new(&json!({
        "remove": ["Content-Length", "Transfer-Encoding"],
        "set": { "X-Env": "prod" }
    }))
    .expect("mixed remove/set config must construct");
    let mut headers = HashMap::from([("content-length".to_string(), "999".to_string())]);
    let mut request = ctx();
    plugin.after_proxy(&mut request, 200, &mut headers).await;
    assert!(
        !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "a configured remove must still drop the field"
    );
    assert_eq!(headers.get("x-env").map(String::as_str), Some("prod"));
}

/// Ordinary and security-relevant custom destinations are unaffected — the
/// closed set must not grow into a general-purpose name filter.
#[test]
fn set_still_accepts_ordinary_response_header_destinations() {
    for name in [
        "X-Env",
        "Cache-Control",
        "Content-Type",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Content-Encoding",
        "Vary",
        "Set-Cookie",
    ] {
        SecurityHeaders::new(&set_config(name, "1"))
            .unwrap_or_else(|error| panic!("set.{name} must stay allowed: {error}"));
    }
}

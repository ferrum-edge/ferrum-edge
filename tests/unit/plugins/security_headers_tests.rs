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
async fn removes_all_case_insensitive_header_values_in_place() {
    let plugin = SecurityHeaders::new(&json!({ "remove": ["X-Remove", "x-absent"] })).unwrap();
    let mut ctx = ctx();
    let mut headers = HashMap::from([
        ("X-Remove".to_string(), "first".to_string()),
        ("x-REMOVE".to_string(), "second".to_string()),
        ("keep".to_string(), "value".to_string()),
    ]);

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert!(
        headers
            .keys()
            .all(|key| !key.eq_ignore_ascii_case("x-remove"))
    );
    assert_eq!(headers.get("keep").map(String::as_str), Some("value"));
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
            err.contains("`set` contains invalid HTTP field name"),
            "unexpected set error for {name:?}: {err}"
        );

        let err = SecurityHeaders::new(&json!({ "remove": [name] })).unwrap_err();
        assert!(
            err.contains("`remove` contains invalid HTTP field name"),
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
    assert!(err.contains("`set`"), "set path missing from: {err}");
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
    assert!(err.contains("`remove`"), "remove path missing from: {err}");
    assert!(
        err.contains(r"x-bad\\tname"),
        "offending remove entry must be escaped in: {err}"
    );
}

#[test]
fn invalid_header_name_error_rendering_is_escaped_and_bounded() {
    let hostile = format!("x\r\n{}DO_NOT_ECHO", "a".repeat(8_192));
    let err = SecurityHeaders::new(&json!({ "remove": [hostile] })).unwrap_err();

    assert!(
        err.contains(r"x\\r\\n"),
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
    assert!(err.contains("under `security_headers`: \"fram_options, unknown\""));

    let err = SecurityHeaders::new(&json!({
        "hsts": {
            "max_age": 60,
            "include_subdomain": true,
            "unknown": false
        }
    }))
    .unwrap_err();
    assert!(err.contains("under `security_headers.hsts`: \"include_subdomain, unknown\""));
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

/// Dropping a protocol-managed field is at best a no-op the final wire
/// boundary re-derives, so `remove` refuses the same names as `set` rather than
/// accepting a policy that does nothing.
#[test]
fn remove_rejects_every_protocol_managed_destination_case_insensitively() {
    for name in PROTOCOL_MANAGED_DESTINATIONS {
        for spelling in case_variants(name) {
            let error = SecurityHeaders::new(&json!({ "remove": [spelling.clone()] }))
                .expect_err(&format!("remove of {spelling} must be rejected"));
            assert!(
                error.contains("`remove` entry") && error.contains("protocol-managed"),
                "diagnostic for remove.{spelling} must say why: {error}"
            );
            assert!(error.contains(name), "diagnostic must name {name}: {error}");
        }
    }
}

/// Representation metadata the gateway's response pipeline decides from.
const REPRESENTATION_DESTINATIONS: &[&str] = &["content-type", "content-encoding", "content-range"];

/// security_headers-CLAUDE-1: `set`/`remove` could relabel or unlabel the
/// response `Content-Type` after content-type-selective body inspection had
/// already released the body to streaming under the backend's label, and the
/// plugin does not declare `may_modify_response_content_type`. Representation
/// fields are refused at admission on both `set` and `remove`.
#[test]
fn set_and_remove_reject_representation_metadata_case_insensitively() {
    for name in REPRESENTATION_DESTINATIONS {
        for spelling in case_variants(name) {
            let error = SecurityHeaders::new(&set_config(&spelling, "text/html"))
                .expect_err(&format!("set.{spelling} must be rejected"));
            assert!(
                error.contains("`set` entry") && error.contains("representation metadata"),
                "diagnostic for set.{spelling} must say why: {error}"
            );
            assert!(error.contains(name), "diagnostic must name {name}: {error}");
            assert!(
                !error.contains("text/html"),
                "the diagnostic must not echo the configured value: {error}"
            );

            let error = SecurityHeaders::new(&json!({ "remove": [spelling.clone()] }))
                .expect_err(&format!("remove of {spelling} must be rejected"));
            assert!(
                error.contains("`remove` entry") && error.contains("representation metadata"),
                "diagnostic for remove.{spelling} must say why: {error}"
            );
        }
    }
}

/// With representation metadata refused, no accepted policy can move the
/// response content type, so the trait default (`false`) for
/// `may_modify_response_content_type` is exact.
#[tokio::test]
async fn accepted_policies_never_change_the_response_content_type() {
    let plugin = SecurityHeaders::new(&json!({
        "hsts": true,
        "set": { "X-Env": "prod", "Cache-Control": "no-store" },
        "remove": ["server", "x-powered-by", "vary"]
    }))
    .expect("policy");
    let mut request = ctx();
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);

    assert!(!plugin.may_modify_response_content_type(&request, Some("application/octet-stream")));
    plugin.after_proxy(&mut request, 200, &mut headers).await;

    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/octet-stream")
    );
}

/// Ordinary and security-relevant custom destinations are unaffected — the
/// closed sets must not grow into a general-purpose name filter.
#[test]
fn set_still_accepts_ordinary_response_header_destinations() {
    for name in [
        "X-Env",
        "Cache-Control",
        "Content-Security-Policy",
        "Content-Disposition",
        "Vary",
        "Set-Cookie",
    ] {
        SecurityHeaders::new(&set_config(name, "1"))
            .unwrap_or_else(|error| panic!("set.{name} must stay allowed: {error}"));
    }
    SecurityHeaders::new(&set_config("Strict-Transport-Security", "max-age=60"))
        .unwrap_or_else(|error| panic!("set.Strict-Transport-Security must stay allowed: {error}"));
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let header = "'security-diagnostic-canary";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (
            json!({"set": {(header): true}}),
            &["`set`", "must be a string"],
        ),
        (
            json!({"set": {(header): canary}}),
            &["`set`", "valid HTTP field value"],
        ),
        (
            json!({"hsts": {(canary): 8675309}}),
            &["`security_headers.hsts`", "unknown configuration key"],
        ),
        (
            json!({"remove": [canary]}),
            &["`remove`", "invalid HTTP field name"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("security_headers", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}

#[test]
fn builtin_header_strings_must_be_tokens_browsers_recognize() {
    for valid in [
        json!({ "content_type_options": "nosniff" }),
        json!({ "content_type_options": " NoSniff\t" }),
        json!({ "frame_options": "DENY" }),
        json!({ "frame_options": "sameorigin" }),
        json!({ "referrer_policy": "no-referrer" }),
        json!({ "referrer_policy": "Strict-Origin-When-Cross-Origin" }),
        json!({ "referrer_policy": "no-referrer, strict-origin-when-cross-origin" }),
    ] {
        SecurityHeaders::new(&valid)
            .unwrap_or_else(|error| panic!("{valid} must be accepted: {error}"));
    }

    for invalid in [
        json!({ "content_type_options": "nosnif" }),
        json!({ "content_type_options": " " }),
        json!({ "frame_options": "SAMEORGIN" }),
        json!({ "frame_options": "ALLOW-FROM https://example.com" }),
        json!({ "frame_options": "DENY, SAMEORIGIN" }),
        json!({ "referrer_policy": "strict-origin-when-cross-orign" }),
        json!({ "referrer_policy": "no-referrer," }),
        json!({ "referrer_policy": "no-referrer; origin" }),
    ] {
        let error =
            SecurityHeaders::new(&invalid).expect_err(&format!("{invalid} must be rejected"));
        assert!(
            error.contains("browsers ignore any other value"),
            "unexpected error for {invalid}: {error}"
        );
    }
}

#[test]
fn set_entries_for_builtin_headers_use_the_same_token_checks() {
    for valid in [
        json!({ "set": { "X-Frame-Options": "deny" } }),
        json!({ "set": { "x-content-type-options": " nosniff" } }),
        json!({ "set": { "Referrer-Policy": "no-referrer, strict-origin" } }),
        json!({ "frame_options": "DENY", "set": { "X-FRAME-OPTIONS": "SAMEORIGIN" } }),
        json!({ "set": { "X-Other": "SAMEORGIN" } }),
    ] {
        SecurityHeaders::new(&valid)
            .unwrap_or_else(|error| panic!("{valid} must be accepted: {error}"));
    }

    for invalid in [
        json!({ "frame_options": "DENY", "set": { "X-Frame-Options": "SAMEORGIN" } }),
        json!({ "set": { "x-FRAME-options": "ALLOW-FROM https://example.com" } }),
        json!({ "set": { "X-Frame-Options": "" } }),
        json!({ "set": { "X-Content-Type-Options": "nosnif" } }),
        json!({ "content_type_options": false, "set": { "x-content-type-options": " " } }),
        json!({ "set": { "Referrer-Policy": "strict-origin-when-cross-orign" } }),
        json!({ "set": { "referrer-policy": "no-referrer; origin" } }),
    ] {
        let error =
            SecurityHeaders::new(&invalid).expect_err(&format!("{invalid} must be rejected"));
        assert!(
            error.contains("`set` entry") && error.contains("browsers ignore any other value"),
            "unexpected error for {invalid}: {error}"
        );
        for leaked in ["SAMEORGIN", "ALLOW-FROM", "nosnif\"", "orign"] {
            assert!(!error.contains(leaked), "error echoes the value: {error}");
        }
    }
}

/// Strict-Transport-Security values a browser honors, and ones it ignores in
/// full (RFC 6797 §6.1).
const VALID_HSTS_VALUES: &[&str] = &[
    "max-age=0",
    "max-age=31536000",
    "max-age=31536000; includeSubDomains",
    "max-age=31536000; includeSubDomains; preload",
    "MAX-AGE=60;INCLUDESUBDOMAINS",
    " max-age = 60 ; includeSubDomains ",
    "max-age=\"60\"",
    "includeSubDomains; max-age=60",
    "max-age=60;;",
    "max-age=60; ext=token; quoted=\"a=b c\"",
];

const INVALID_HSTS_VALUES: &[&str] = &[
    " ",
    "includeSubDomains",
    "includeSubDomains; preload",
    "maxage=31536000",
    "max-age",
    "max-age=",
    "max-age=-1",
    "max-age=1.5",
    "max-age=1 2",
    "max-age=\"\"",
    "max-age=\"60",
    "max-age=1; max-age=2",
    "max-age=1; MAX-AGE=1",
    "max-age=1, max-age=2",
    "max-age=60; includeSubDomains; includeSubDomains",
    "max-age=60; includeSubDomains=yes",
    "max-age=60; ext=",
    "max-age=60; ext=a=b",
    "max-age=60; bad name",
    "max-age=60; ext=\"quoted\\\\escape\"",
];

/// security_headers-CLAUDE-2: the string form of `hsts` (and a
/// `Strict-Transport-Security` `set` entry) was accepted with syntax-only
/// validation, so a value without a well-formed `max-age` loaded and then
/// provided no downgrade protection at all.
#[test]
fn hsts_strings_and_set_entries_require_one_well_formed_max_age() {
    for value in VALID_HSTS_VALUES {
        let plugin = SecurityHeaders::new(&json!({ "hsts": value }))
            .unwrap_or_else(|error| panic!("hsts {value:?} must be accepted: {error}"));
        let mut headers = HashMap::new();
        plugin.apply_initial_response_header_policy(&mut headers);
        assert_eq!(
            headers.get("strict-transport-security").map(String::as_str),
            Some(*value),
            "a valid string is still emitted verbatim"
        );
        SecurityHeaders::new(&set_config("Strict-Transport-Security", value))
            .unwrap_or_else(|error| panic!("set STS {value:?} must be accepted: {error}"));
    }

    for value in INVALID_HSTS_VALUES {
        let error = SecurityHeaders::new(&json!({ "hsts": value }))
            .expect_err(&format!("hsts {value:?} must be rejected"));
        assert!(
            error.contains("`hsts`") && error.contains("max-age"),
            "unexpected error for hsts {value:?}: {error}"
        );
        let error = SecurityHeaders::new(&set_config("strict-TRANSPORT-security", value))
            .expect_err(&format!("set STS {value:?} must be rejected"));
        assert!(
            error.contains("`set` entry") && error.contains("browsers ignore any other value"),
            "unexpected error for set STS {value:?}: {error}"
        );
    }

    // `""` still disables the opt-in header rather than failing validation.
    let plugin = SecurityHeaders::new(&json!({ "hsts": "" })).expect("empty hsts disables");
    let mut headers = HashMap::new();
    plugin.apply_initial_response_header_policy(&mut headers);
    assert!(!headers.contains_key("strict-transport-security"));
}

fn single_copy<'a>(headers: &'a HashMap<String, String>, name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect()
}

/// security_headers-CLAUDE-3: with `override_existing: false`, a backend copy
/// of a built-in security header that a browser ignores (empty, unrecognized,
/// or comma-folded duplicates) used to satisfy the policy, so no protection
/// was delivered. Such a copy now counts as absent and every case variant is
/// replaced by the configured value.
#[tokio::test]
async fn override_disabled_replaces_backend_values_browsers_ignore() {
    let plugin = SecurityHeaders::new(&json!({
        "override_existing": false,
        "frame_options": "DENY",
        "hsts": "max-age=600",
        "content_security_policy": "default-src 'self'",
        "permissions_policy": "geolocation=()",
        "set": { "X-Custom": "gateway" }
    }))
    .expect("policy");

    for (name, ignored, configured) in [
        (
            "X-Frame-Options",
            "ALLOW-FROM https://partner.example",
            "DENY",
        ),
        ("X-Frame-Options", "DENY, SAMEORIGIN", "DENY"),
        ("X-Frame-Options", "", "DENY"),
        ("X-Content-Type-Options", "", "nosniff"),
        ("X-Content-Type-Options", "nosniff, nosniff", "nosniff"),
        (
            "Referrer-Policy",
            "no-referer",
            "strict-origin-when-cross-origin",
        ),
        (
            "Strict-Transport-Security",
            "includeSubDomains",
            "max-age=600",
        ),
        (
            "Strict-Transport-Security",
            "max-age=1, max-age=2",
            "max-age=600",
        ),
        ("Content-Security-Policy", " ", "default-src 'self'"),
        ("Permissions-Policy", "", "geolocation=()"),
    ] {
        let mut request = ctx();
        let mut headers = HashMap::from([
            (name.to_string(), ignored.to_string()),
            (name.to_ascii_lowercase(), ignored.to_string()),
        ]);
        plugin.after_proxy(&mut request, 200, &mut headers).await;
        assert_eq!(
            single_copy(&headers, name),
            vec![configured],
            "{name}: {ignored:?} must be replaced by exactly one configured copy"
        );
    }

    // Recognized backend values, and any value of an arbitrary header, keep
    // presence semantics and are preserved.
    for (name, kept) in [
        ("X-Frame-Options", "SAMEORIGIN"),
        ("X-Content-Type-Options", " NOSNIFF "),
        ("Referrer-Policy", "no-referrer, same-origin"),
        ("Strict-Transport-Security", "max-age=60; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'none'"),
        ("X-Custom", ""),
    ] {
        let mut request = ctx();
        let mut headers = HashMap::from([(name.to_string(), kept.to_string())]);
        plugin.after_proxy(&mut request, 200, &mut headers).await;
        assert_eq!(
            single_copy(&headers, name),
            vec![kept],
            "{name}: recognized backend value {kept:?} must be preserved"
        );
    }
}

/// security_headers-CLAUDE-4: entry counts and value lengths are bounded at
/// admission.
#[test]
fn set_remove_and_value_sizes_are_bounded() {
    use ferrum_edge::plugins::security_headers::{
        MAX_HEADER_VALUE_BYTES, MAX_REMOVE_ENTRIES, MAX_SET_ENTRIES,
    };

    let set_of = |count: usize| {
        let mut set = serde_json::Map::new();
        for index in 0..count {
            set.insert(format!("x-policy-{index}"), json!("on"));
        }
        json!({ "set": serde_json::Value::Object(set) })
    };
    SecurityHeaders::new(&set_of(MAX_SET_ENTRIES)).expect("set at the cap is accepted");
    let error = SecurityHeaders::new(&set_of(MAX_SET_ENTRIES + 1)).expect_err("set over the cap");
    assert!(error.contains("`set` accepts at most"), "{error}");

    let remove_of = |count: usize| {
        let names: Vec<String> = (0..count).map(|index| format!("x-strip-{index}")).collect();
        json!({ "remove": names })
    };
    SecurityHeaders::new(&remove_of(MAX_REMOVE_ENTRIES)).expect("remove at the cap is accepted");
    let error =
        SecurityHeaders::new(&remove_of(MAX_REMOVE_ENTRIES + 1)).expect_err("remove over the cap");
    assert!(error.contains("`remove` accepts at most"), "{error}");

    let at_cap = "a".repeat(MAX_HEADER_VALUE_BYTES);
    let over_cap = "a".repeat(MAX_HEADER_VALUE_BYTES + 1);
    for key in ["content_security_policy", "permissions_policy"] {
        SecurityHeaders::new(&json!({ (key): at_cap.clone() }))
            .unwrap_or_else(|error| panic!("{key} at the cap must be accepted: {error}"));
        let error = SecurityHeaders::new(&json!({ (key): over_cap.clone() }))
            .expect_err("value over the cap");
        assert!(error.contains("at most"), "{key}: {error}");
    }
    SecurityHeaders::new(&set_config("X-Policy", &at_cap)).expect("set value at the cap");
    let error = SecurityHeaders::new(&set_config("X-Policy", &over_cap)).expect_err("set over cap");
    assert!(error.contains("`set` value must be at most"), "{error}");
    let long_hsts = format!("max-age=1; ext={}", "a".repeat(MAX_HEADER_VALUE_BYTES));
    let error = SecurityHeaders::new(&json!({ "hsts": long_hsts })).expect_err("hsts over cap");
    assert!(error.contains("`hsts` value must be at most"), "{error}");
}

/// Linear construction keeps the documented precedence: a `set` entry
/// overrides the built-in of the same name, the last case variant of a `set`
/// name wins, and the precomputed policy names stay unique.
#[test]
fn set_overrides_and_case_variants_resolve_to_one_entry() {
    let plugin = SecurityHeaders::new(&json!({
        "frame_options": "DENY",
        "set": { "X-FRAME-OPTIONS": "SAMEORIGIN", "X-A": "first", "x-a": "second" },
        "remove": ["x-a", "server"]
    }))
    .expect("policy");
    let mut headers = HashMap::new();
    plugin.apply_initial_response_header_policy(&mut headers);

    assert_eq!(single_copy(&headers, "x-frame-options"), vec!["SAMEORIGIN"]);
    assert_eq!(single_copy(&headers, "x-a"), vec!["second"]);
    let names = plugin.initial_response_header_policy_names();
    let mut unique = names.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        names.len(),
        "policy names must be unique: {names:?}"
    );
    assert!(names.iter().any(|name| name == "x-a"));
    assert!(names.iter().any(|name| name == "x-frame-options"));
}

//! Admission and hook coverage for the shipped `example_plugin` template.

use ferrum_edge::custom_plugins::{create_custom_plugin, custom_plugin_names};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, ResponseBodyProduction, TCP_ONLY_PROTOCOLS, plugin_failure_policy,
    validate_plugin_config,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

fn example_plugin_registered() -> bool {
    custom_plugin_names().contains(&"example_plugin")
}

fn create_example_plugin(config: &Value) -> Result<Arc<dyn Plugin>, String> {
    create_custom_plugin("example_plugin", config, PluginHttpClient::default())?
        .ok_or_else(|| "example_plugin factory returned no plugin".to_string())
}

fn rejected_config(config: Value) -> String {
    match create_example_plugin(&config) {
        Ok(_) => panic!("example_plugin config should be rejected"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn omitted_header_value_uses_the_documented_default() {
    if !example_plugin_registered() {
        return;
    }

    let plugin = create_example_plugin(&json!({})).expect("empty object is valid");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/example".to_string(),
    );
    let mut request_headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        request_headers.get("x-custom-gateway").map(String::as_str),
        Some("ferrum-custom")
    );
}

#[tokio::test]
async fn valid_config_exercises_request_and_response_hooks() {
    if !example_plugin_registered() {
        return;
    }

    let plugin = create_example_plugin(&json!({
        "header_value": "edge-a",
        "request_body_prefix": "custom:",
        "correlation_header_name": " X-Custom-Correlation-ID "
    }))
    .expect("valid example config");
    assert_eq!(plugin.name(), "example_plugin");
    assert_eq!(
        plugin.correlation_id_header_name(),
        Some(" X-Custom-Correlation-ID "),
        "the example retains configured whitespace and casing at the capability boundary so core validation must trim and compare claims case-insensitively",
    );
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/example".to_string(),
    );
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut request_headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut request_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        request_headers.get("x-custom-gateway").map(String::as_str),
        Some("edge-a")
    );
    assert_eq!(
        request_headers
            .get("x-custom-correlation-id")
            .map(String::as_str),
        Some("edge-a"),
        "runtime writes use the validated normalized lowercase header",
    );
    assert_eq!(
        plugin
            .transform_request_body(b"payload", None, &request_headers)
            .await,
        Some(b"custom:payload".to_vec())
    );

    let mut response_headers = HashMap::new();
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers.get("x-custom-gateway").map(String::as_str),
        Some("edge-a")
    );
    assert_eq!(
        response_headers
            .get("x-custom-correlation-id")
            .map(String::as_str),
        Some("edge-a"),
        "runtime writes use the validated normalized lowercase header",
    );
}

#[test]
fn constructor_rejects_non_object_wrong_type_unknown_and_invalid_header_configs() {
    if !example_plugin_registered() {
        return;
    }

    for config in [json!(null), json!([]), json!("not-an-object"), json!(7)] {
        let error = rejected_config(config);
        assert!(error.contains("JSON object"), "got: {error}");
    }

    for config in [
        json!({"header_value": null}),
        json!({"header_value": 7}),
        json!({"header_value": true}),
        json!({"header_value": {"nested": "value"}}),
    ] {
        let error = rejected_config(config);
        assert!(error.contains("header_value"), "got: {error}");
        assert!(error.contains("string"), "got: {error}");
    }

    let unknown = rejected_config(json!({"header_valeu": "edge-a"}));
    assert!(
        unknown.contains("unknown key 'header_valeu'"),
        "got: {unknown}"
    );

    let invalid = rejected_config(json!({"header_value": "line\r\nbreak"}));
    assert!(
        invalid.contains("valid HTTP header value"),
        "got: {invalid}"
    );

    let oversized = rejected_config(json!({"header_value": "x".repeat(8 * 1024 + 1)}));
    assert!(oversized.contains("at most 8192 bytes"), "got: {oversized}");

    for config in [
        json!({"request_body_prefix": null}),
        json!({"request_body_prefix": 7}),
        json!({"request_body_prefix": ""}),
    ] {
        let error = rejected_config(config);
        assert!(error.contains("request_body_prefix"), "got: {error}");
    }

    for config in [
        json!({"correlation_header_name": null}),
        json!({"correlation_header_name": 7}),
        json!({"correlation_header_name": ""}),
        json!({"correlation_header_name": "bad header"}),
    ] {
        let error = rejected_config(config);
        assert!(error.contains("correlation_header_name"), "got: {error}");
    }

    for config in [
        json!({"protocol": null}),
        json!({"protocol": 7}),
        json!({"protocol": "udp"}),
    ] {
        let error = rejected_config(config);
        assert!(error.contains("protocol"), "got: {error}");
    }
}

#[test]
fn protocol_declaration_can_select_tcp_only() {
    if !example_plugin_registered() {
        return;
    }

    let plugin = create_example_plugin(&json!({
        "protocol": "tcp",
        "correlation_header_name": "x-stream-correlation-id"
    }))
    .expect("valid TCP-only example config");
    assert_eq!(plugin.supported_protocols(), TCP_ONLY_PROTOCOLS);
}

#[test]
fn shared_admission_uses_the_strict_constructor_and_keep_last_known_good_policy() {
    if !example_plugin_registered() {
        return;
    }

    let error = validate_plugin_config("example_plugin", &json!({"header_value": 7}))
        .expect_err("shared admission must reject malformed example config");
    assert!(error.contains("header_value"), "got: {error}");
    assert_eq!(
        plugin_failure_policy("example_plugin"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
}

#[test]
fn declares_never_response_body_production() {
    let source = include_str!("../../../custom_plugins/examples/example_plugin.rs");
    assert!(
        source.contains("ResponseBodyProduction::Never"),
        "example_plugin must explicitly declare Never rather than inherit Undeclared"
    );
    assert!(
        source.contains("fn response_body_production(&self) -> ResponseBodyProduction"),
        "example_plugin must override response_body_production"
    );
    assert!(
        !source.contains("fn transform_response_body")
            && !source.contains("fn normalize_response_body"),
        "Never must stay truthful: example_plugin must not add a response-body producer hook"
    );

    if !example_plugin_registered() {
        return;
    }

    let plugin = create_example_plugin(&json!({})).expect("empty object is valid");
    assert_eq!(
        plugin.response_body_production(),
        ResponseBodyProduction::Never,
        "live trait value must be Never when the opt-in example is compiled in"
    );
}

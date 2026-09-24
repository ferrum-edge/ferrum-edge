//! Gateway API `HTTPRoute.rules[].timeouts` admission and projection (#5646).
//!
//! `timeouts` is a standard-channel rule field on the pinned v1.5.1 CRDs.
//! These tests pin the admission contract (the GEP-2257 duration grammar and
//! the CRD's `backendRequest <= request` CEL rule, re-checked because a
//! file/CP-delivered object never passed through the API server) and the
//! projection onto the selected rule's own `mesh_route_dispatch` entry: never
//! onto the shared proxy, so a sibling rule keeps the proxy defaults.
//! Data-plane behavior is covered by the integration regressions in
//! `tests/integration/k8s_controller_gateway_status_tests.rs`.

use ferrum_edge::_test_support::parse_gateway_api_duration_ms_for_test;
use ferrum_edge::config::types::PluginConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Marker the translator embeds for a CRD-valid shape Ferrum declines; the
/// status writer maps it to `UnsupportedValue`. Anything else is `Invalid`.
const UNSUPPORTED_SHAPE_MARKER: &str = "is not implemented by Ferrum";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn route(kind: &str, rules: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: "sample".to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: HashMap::new(),
        },
        spec: json!({ "rules": rules }),
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translate_route_plugins(kind: &str, rules: Value) -> Vec<PluginConfig> {
    translate_k8s_objects(&[route(kind, rules)], options())
        .expect("route should materialize")
        .config
        .plugin_configs
}

fn translate_route_error(kind: &str, rules: Value) -> String {
    let error = translate_k8s_objects(&[route(kind, rules)], options())
        .expect_err("route should be refused");
    format!("{error}")
}

fn emitted_dispatch_rules(plugins: &[PluginConfig]) -> Vec<Value> {
    plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .flat_map(|plugin| plugin.config["rules"].as_array().cloned())
        .flatten()
        .collect()
}

#[test]
fn gateway_api_duration_parses_exactly_the_crd_grammar() {
    // `^([0-9]{1,5}(h|m|s|ms)){1,4}$`, summed like Go's ParseDuration.
    let valid = [
        ("0s", 0),
        ("0ms", 0),
        ("1ms", 1),
        ("500ms", 500),
        ("10s", 10_000),
        ("1m5s", 65_000),
        ("1h30m", 5_400_000),
        ("1s1s", 2_000),
        ("1h1m1s1ms", 3_661_001),
        ("99999ms", 99_999),
        ("99999h", 359_996_400_000),
    ];
    for (value, expected) in valid {
        let parsed = parse_gateway_api_duration_ms_for_test(value);
        assert_eq!(parsed, Some(expected), "{value}");
    }
    let invalid = [
        "",
        "1",
        "s",
        "ms",
        "1x",
        "1S",
        "1.5s",
        "-1s",
        "+1s",
        " 1s",
        "1s ",
        "123456s",
        "1s1s1s1s1s",
        "1us",
        "1ns",
        "1d",
        "1hms",
        "1m1",
        "1µs",
    ];
    for value in invalid {
        let parsed = parse_gateway_api_duration_ms_for_test(value);
        assert_eq!(parsed, None, "{value:?}");
    }
}

#[test]
fn http_route_timeouts_project_onto_the_selected_dispatch_rule_only() {
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([
            {
                "matches": [{"path": {"type": "PathPrefix", "value": "/timed"}}],
                "backendRefs": [{"name": "api", "port": 8080}],
                "timeouts": {"request": "2m", "backendRequest": "1m500ms"}
            },
            {
                "matches": [{"path": {"type": "PathPrefix", "value": "/disabled"}}],
                "backendRefs": [{"name": "api", "port": 8080}],
                "timeouts": {"request": "0s", "backendRequest": "0s"}
            },
            {
                "matches": [{
                    "path": {"type": "PathPrefix", "value": "/untimed"},
                    "headers": [{"name": "x-variant", "value": "one"}]
                }],
                "backendRefs": [{"name": "api", "port": 8080}]
            }
        ]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let timed: Vec<&Value> = rules
        .iter()
        .filter(|rule| rule.get("request_timeout_ms").is_some())
        .collect();
    assert_eq!(timed.len(), 1, "{rules:?}");
    assert_eq!(timed[0]["request_timeout_ms"], 120_000);
    assert_eq!(timed[0]["timeout_ms"], 60_500);
    assert!(timed[0].get("timeout_disabled").is_none());

    // `0s` disables both bounds: no total deadline, and the per-attempt bound
    // explicitly clears the proxy default.
    let disabled: Vec<&Value> = rules
        .iter()
        .filter(|rule| rule.get("timeout_disabled").is_some())
        .collect();
    assert_eq!(disabled.len(), 1, "{rules:?}");
    assert_eq!(disabled[0]["timeout_disabled"], true);
    assert!(disabled[0].get("timeout_ms").is_none());
    assert!(disabled[0].get("request_timeout_ms").is_none());

    // The sibling rule carries no timeout policy of its own.
    let untimed = rules
        .iter()
        .find(|rule| rule["match"]["headers"]["x-variant"] == "one")
        .expect("untimed sibling rule");
    for field in ["request_timeout_ms", "timeout_ms", "timeout_disabled"] {
        assert!(untimed.get(field).is_none(), "{field}: {untimed}");
    }

    // Every emitted plugin must construct: the dispatch plugin accepts the
    // projected fields exactly as the translator wrote them.
    for plugin in &plugins {
        ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
            .unwrap_or_else(|error| panic!("{}: {error}", plugin.plugin_name));
    }
}

#[test]
fn http_route_timeouts_are_never_promoted_onto_the_generated_proxy() {
    let object = route(
        "HTTPRoute",
        json!([{
            "matches": [{"path": {"type": "PathPrefix", "value": "/timed"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "2s", "backendRequest": "250ms"}
        }]),
    );
    let translation =
        translate_k8s_objects(&[object], options()).expect("route should materialize");
    assert!(!translation.config.proxies.is_empty());
    for proxy in &translation.config.proxies {
        assert_eq!(
            proxy.backend_read_timeout_ms, 30_000,
            "{}: rule timeouts must stay on the dispatch rule",
            proxy.id
        );
        assert!(proxy.retry.is_none(), "{}", proxy.id);
    }
}

#[test]
fn http_route_timeouts_enforce_the_crd_relationship() {
    // CEL: a non-zero `request` bounds `backendRequest`; equal is allowed.
    translate_route_plugins(
        "HTTPRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "2s", "backendRequest": "2000ms"}
        }]),
    );
    // A zero `request` disables the total deadline, so the CEL rule does not
    // constrain `backendRequest`.
    translate_route_plugins(
        "HTTPRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "0s", "backendRequest": "5s"}
        }]),
    );
    let message = translate_route_error(
        "HTTPRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "1s", "backendRequest": "1001ms"}
        }]),
    );
    assert!(
        message.contains("rules[0].timeouts.backendRequest")
            && message.contains("cannot be longer than request timeout")
            && !message.contains(UNSUPPORTED_SHAPE_MARKER),
        "{message}"
    );
}

#[test]
fn http_route_timeouts_reject_malformed_shapes_with_field_specific_reasons() {
    // A value outside the CRD grammar is `Invalid` (no marker); a sub-field the
    // CRD does not define is `UnsupportedValue`. Neither echoes the offending
    // manifest value.
    let cases = [
        (json!("1s"), "rules[0].timeouts must be an object", false),
        (
            json!({"request": "1x-secret"}),
            "rules[0].timeouts.request must be a Gateway API duration",
            false,
        ),
        (
            json!({"backendRequest": 30}),
            "rules[0].timeouts.backendRequest must be a Gateway API duration",
            false,
        ),
        (
            json!({"request": "1s", "idle": "1s"}),
            "rules[0].timeouts contains a field",
            true,
        ),
    ];
    for (timeouts, expected, unsupported) in cases {
        let message = translate_route_error(
            "HTTPRoute",
            json!([{
                "backendRefs": [{"name": "api", "port": 8080}],
                "timeouts": timeouts.clone()
            }]),
        );
        assert!(message.contains(expected), "{timeouts}: {message}");
        let tagged = message.contains(UNSUPPORTED_SHAPE_MARKER);
        assert_eq!(tagged, unsupported, "{timeouts}: {message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn grpc_route_timeouts_and_http_route_retry_stay_refused() {
    // GRPCRoute defines no `timeouts`; `retry` is not implemented on either
    // kind. Both keep the fail-closed `UnsupportedValue` refusal.
    let grpc = translate_route_error(
        "GRPCRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "1s"}
        }]),
    );
    assert!(grpc.contains(UNSUPPORTED_SHAPE_MARKER), "{grpc}");
    let retry = translate_route_error(
        "HTTPRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "1s"},
            "retry": {"attempts": 2}
        }]),
    );
    assert!(retry.contains(UNSUPPORTED_SHAPE_MARKER), "{retry}");
}

#[test]
fn http_route_timeouts_only_rule_without_backend_refs_answers_500() {
    // Timeouts shape a forwarded request; alone they must not send traffic to
    // the unresolvable blackhole backend.
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([{
            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
            "timeouts": {"request": "1s"}
        }]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let rule = rules.first().expect("dispatch rule");
    assert_eq!(rule["fault"]["abort"]["status_code"], 500, "{rule}");
    assert_eq!(rule["request_timeout_ms"], 1_000, "{rule}");
}

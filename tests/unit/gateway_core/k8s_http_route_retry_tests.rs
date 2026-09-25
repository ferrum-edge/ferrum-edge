//! Gateway API `HTTPRoute.rules[].retry` admission and projection (#5646).
//!
//! `retry` is an experimental-channel rule field; the pinned v1.5.1
//! experimental CRD bundle the conformance lab installs defines it as
//! `codes` (integers `400..=599`), `attempts` (an unbounded integer) and
//! `backoff` (a GEP-2257 duration). These tests pin the admission contract —
//! re-checked because a file/CP-delivered object never passed through the API
//! server — and the projection onto the selected rule's own
//! `mesh_route_dispatch` entry: never onto the shared proxy, so a sibling rule
//! is never retried. Data-plane behavior is covered by the integration
//! regressions in `tests/integration/k8s_controller_gateway_status_tests.rs`.

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

fn assert_every_plugin_constructs(plugins: &[PluginConfig]) {
    // The dispatch plugin must accept the projected fields exactly as the
    // translator wrote them, or an accepted route would carry a config no data
    // plane can load.
    for plugin in plugins {
        ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
            .unwrap_or_else(|error| panic!("{}: {error}", plugin.plugin_name));
    }
}

fn rule_with_retry(path: &str, retry: Value) -> Value {
    json!({
        "matches": [{"path": {"type": "PathPrefix", "value": path}}],
        "backendRefs": [{"name": "api", "port": 8080}],
        "retry": retry
    })
}

#[test]
fn http_route_retry_projects_onto_the_selected_dispatch_rule_only() {
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([
            rule_with_retry(
                "/retried",
                json!({"codes": [503, 500, 503], "attempts": 2, "backoff": "1s250ms"})
            ),
            rule_with_retry("/defaults", json!({})),
            rule_with_retry("/disabled", json!({"attempts": 0, "codes": [503]})),
            {
                "matches": [{
                    "path": {"type": "PathPrefix", "value": "/plain"},
                    "headers": [{"name": "x-variant", "value": "one"}]
                }],
                "backendRefs": [{"name": "api", "port": 8080}]
            }
        ]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let with_retry: Vec<&Value> = rules
        .iter()
        .filter(|rule| rule.get("retry").is_some())
        .collect();
    assert_eq!(with_retry.len(), 2, "{rules:?}");

    // `attempts` counts retries after the initial attempt, so it maps to
    // `max_retries` unchanged. Codes are de-duplicated and sorted, `backoff`
    // is a fixed minimum delay, status retries stay on replay-safe methods,
    // and pre-wire connection failures are retried.
    let retried = with_retry
        .iter()
        .find(|rule| rule["retry"].get("max_retries").is_some())
        .expect("rule with explicit attempts");
    assert_eq!(
        retried["retry"],
        json!({
            "max_retries": 2,
            "retryable_status_codes": [500, 503],
            "retryable_methods": ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"],
            "backoff": {"fixed": {"delay_ms": 1_250}},
            "retry_on_connect_failure": true
        })
    );
    assert!(retried.get("retry_disabled").is_none());

    // An empty `retry` stanza leaves `attempts` and `backoff` to Ferrum's
    // route retry defaults and retries no response status.
    let defaults = with_retry
        .iter()
        .find(|rule| rule["retry"].get("max_retries").is_none())
        .expect("rule with the empty retry stanza");
    assert_eq!(
        defaults["retry"],
        json!({
            "retryable_status_codes": [],
            "retryable_methods": ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"],
            "retry_on_connect_failure": true
        })
    );

    // `attempts: 0` disables retries for the rule.
    let disabled: Vec<&Value> = rules
        .iter()
        .filter(|rule| rule.get("retry_disabled").is_some())
        .collect();
    assert_eq!(disabled.len(), 1, "{rules:?}");
    assert_eq!(disabled[0]["retry_disabled"], true);
    assert!(disabled[0].get("retry").is_none());

    // The sibling rule carries no retry policy of its own.
    let plain = rules
        .iter()
        .find(|rule| rule["match"]["headers"]["x-variant"] == "one")
        .expect("plain sibling rule");
    for field in ["retry", "retry_disabled"] {
        assert!(plain.get(field).is_none(), "{field}: {plain}");
    }

    assert_every_plugin_constructs(&plugins);
}

#[test]
fn http_route_retry_is_never_promoted_onto_the_generated_proxy() {
    let retry = json!({"codes": [503], "attempts": 3, "backoff": "10ms"});
    let object = route("HTTPRoute", json!([rule_with_retry("/retried", retry)]));
    let translation =
        translate_k8s_objects(&[object], options()).expect("route should materialize");
    assert!(!translation.config.proxies.is_empty());
    for proxy in &translation.config.proxies {
        assert!(
            proxy.retry.is_none(),
            "{}: rule retry must stay on the dispatch rule",
            proxy.id
        );
    }
}

#[test]
fn http_route_retry_path_only_rule_still_emits_its_own_dispatch_rule() {
    // A path-only rule normally falls through to the proxy default. Carrying
    // `retry`, it must select the policy for exactly the requests it matches,
    // so it emits an action catch-all the dispatch plugin accepts.
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([rule_with_retry("/only", json!({"codes": [502]}))]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let rule = rules
        .iter()
        .find(|rule| rule.get("retry").is_some())
        .expect("path-only retry rule");
    assert_eq!(rule["match"], json!({}), "{rule}");
    assert_eq!(rule["retry"]["retryable_status_codes"], json!([502]));
    assert_every_plugin_constructs(&plugins);
}

#[test]
fn http_route_retry_composes_with_rule_timeouts() {
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([{
            "matches": [{"path": {"type": "PathPrefix", "value": "/timed"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "2s", "backendRequest": "500ms"},
            "retry": {"codes": [504], "attempts": 3, "backoff": "100ms"}
        }]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let rule = rules
        .iter()
        .find(|rule| rule.get("retry").is_some())
        .expect("timed retry rule");
    assert_eq!(rule["request_timeout_ms"], 2_000, "{rule}");
    assert_eq!(rule["timeout_ms"], 500, "{rule}");
    // Each retry attempt runs under its own `backendRequest` budget.
    assert_eq!(rule["attempt_timeout_ms"], 500, "{rule}");
    assert_eq!(rule["retry"]["max_retries"], 3, "{rule}");
    assert_every_plugin_constructs(&plugins);
}

#[test]
fn http_route_retry_accepts_the_crd_boundaries() {
    let retry = json!({"codes": [400, 599], "attempts": 100, "backoff": "5m"});
    let plugins = translate_route_plugins("HTTPRoute", json!([rule_with_retry("/bounds", retry)]));
    let rules = emitted_dispatch_rules(&plugins);
    let rule = rules
        .iter()
        .find(|rule| rule.get("retry").is_some())
        .expect("boundary retry rule");
    assert_eq!(rule["retry"]["max_retries"], 100);
    assert_eq!(rule["retry"]["retryable_status_codes"], json!([400, 599]));
    assert_eq!(
        rule["retry"]["backoff"],
        json!({"fixed": {"delay_ms": 300_000}})
    );
    assert_every_plugin_constructs(&plugins);
}

#[test]
fn http_route_retry_rejects_malformed_shapes_with_field_specific_reasons() {
    // A shape the CRD itself rejects is `Invalid` (no marker); a CRD-valid
    // value Ferrum declines, or a sub-field the CRD does not define, is
    // `UnsupportedValue`. No diagnostic echoes the offending manifest value.
    let cases = [
        (json!("2"), "rules[0].retry must be an object", false),
        (
            json!({"codes": "503"}),
            "rules[0].retry.codes must be an array",
            false,
        ),
        (
            json!({"codes": [503, 399]}),
            "rules[0].retry.codes[1] must be an integer HTTP status code from 400 to 599",
            false,
        ),
        (
            json!({"codes": [600]}),
            "rules[0].retry.codes[0] must be an integer",
            false,
        ),
        (
            json!({"codes": ["503"]}),
            "rules[0].retry.codes[0] must be an integer",
            false,
        ),
        (
            json!({"codes": [503.5]}),
            "rules[0].retry.codes[0] must be an integer",
            false,
        ),
        (
            json!({"attempts": "2"}),
            "rules[0].retry.attempts must be an integer",
            false,
        ),
        (
            json!({"attempts": 1.5}),
            "rules[0].retry.attempts must be an integer",
            false,
        ),
        (json!({"attempts": -1}), "rules[0].retry.attempts", true),
        (json!({"attempts": 101}), "rules[0].retry.attempts", true),
        (
            json!({"backoff": "1x-secret"}),
            "rules[0].retry.backoff must be a Gateway API duration",
            false,
        ),
        (
            json!({"backoff": 100}),
            "rules[0].retry.backoff must be a Gateway API duration",
            false,
        ),
        (
            json!({"backoff": "123456ms"}),
            "rules[0].retry.backoff must be a Gateway API duration",
            false,
        ),
        (json!({"backoff": "5m1ms"}), "rules[0].retry.backoff", true),
        (
            json!({"attempts": 2, "perTryTimeout": "1s"}),
            "rules[0].retry contains a field",
            true,
        ),
    ];
    for (retry, expected, unsupported) in cases {
        let message = translate_route_error(
            "HTTPRoute",
            json!([{
                "backendRefs": [{"name": "api", "port": 8080}],
                "retry": retry.clone()
            }]),
        );
        assert!(message.contains(expected), "{retry}: {message}");
        let tagged = message.contains(UNSUPPORTED_SHAPE_MARKER);
        assert_eq!(tagged, unsupported, "{retry}: {message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn grpc_route_retry_stays_refused() {
    // GRPCRoute defines no `retry` field on any channel.
    let message = translate_route_error(
        "GRPCRoute",
        json!([{
            "backendRefs": [{"name": "api", "port": 8080}],
            "retry": {"attempts": 2}
        }]),
    );
    assert!(message.contains(UNSUPPORTED_SHAPE_MARKER), "{message}");
}

#[test]
fn http_route_retry_only_rule_without_backend_refs_answers_500() {
    // Retry shapes a forwarded request; alone it must not send traffic to the
    // unresolvable blackhole backend.
    let plugins = translate_route_plugins(
        "HTTPRoute",
        json!([{
            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
            "retry": {"codes": [503], "attempts": 1}
        }]),
    );
    let rules = emitted_dispatch_rules(&plugins);
    let rule = rules.first().expect("dispatch rule");
    assert_eq!(rule["fault"]["abort"]["status_code"], 500, "{rule}");
    assert_eq!(rule["retry"]["max_retries"], 1, "{rule}");
}

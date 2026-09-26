//! Gateway API `RequestRedirect` / `URLRewrite` path projection and
//! route-owned response policy (#5752, #5753).
//!
//! Every test builds the `mesh_route_dispatch` plugin the translator emitted
//! and drives a request through it, rather than checking only the translated
//! JSON: an admitted route whose projected config no data plane can load, or
//! whose answer skips the rule's `ResponseHeaderModifier`, is exactly the
//! failure these pin. Data-plane behavior is covered by the integration
//! regressions in `tests/integration/k8s_controller_gateway_status_tests.rs`.

use ferrum_edge::config::types::PluginConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn route(rules: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
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

fn translate_route_plugins(rules: Value) -> Vec<PluginConfig> {
    let plugins = translate_k8s_objects(&[route(rules)], options())
        .expect("route should materialize")
        .config
        .plugin_configs;
    // The dispatch plugin must accept the projected fields exactly as the
    // translator wrote them, or an accepted route would carry a config no data
    // plane can load.
    for plugin in &plugins {
        ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
            .unwrap_or_else(|error| panic!("{}: {error}", plugin.plugin_name));
    }
    plugins
}

/// The single emitted dispatch plugin's config, plus the plugin built from it.
fn emitted_dispatch(plugins: &[PluginConfig]) -> (Value, MeshRouteDispatch) {
    let configs: Vec<&PluginConfig> = plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .collect();
    assert_eq!(configs.len(), 1, "{plugins:?}");
    let config = configs[0].config.clone();
    let plugin = MeshRouteDispatch::new(&config)
        .unwrap_or_else(|error| panic!("emitted dispatch must construct: {error}"));
    (config, plugin)
}

fn request(path: &str, query: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        path.to_string(),
    );
    ctx.set_raw_query_string(query.to_string());
    ctx
}

fn prefix_redirect_rule(prefix: &str, replacement: &str) -> Value {
    json!([{
        "matches": [{"path": {"type": "PathPrefix", "value": prefix}}],
        "filters": [{"type": "RequestRedirect", "requestRedirect": {
            "statusCode": 302,
            "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": replacement}
        }}]
    }])
}

fn prefix_rewrite_rule(prefix: &str, replacement: &str) -> Value {
    json!([{
        "matches": [{"path": {"type": "PathPrefix", "value": prefix}}],
        "backendRefs": [{"name": "api", "port": 8080}],
        "filters": [{"type": "URLRewrite", "urlRewrite": {
            "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": replacement}
        }}]
    }])
}

/// `(matched prefix, replacement, request path, expected path)` rows from the
/// upstream `HTTPPathModifier` table, including the empty replacement (strip
/// the matched prefix) and the root prefix (prepend).
const PREFIX_TABLE: &[(&str, &str, &str, &str)] = &[
    ("/old", "", "/old", "/"),
    ("/old", "", "/old/", "/"),
    ("/old", "", "/old/child", "/child"),
    ("/old/", "", "/old/child", "/child"),
    ("/old", "/", "/old", "/"),
    ("/old", "/", "/old/", "/"),
    ("/old", "/", "/old/child", "/child"),
    ("/old", "/new", "/old", "/new"),
    ("/old", "/new", "/old/", "/new/"),
    ("/old", "/new", "/old/child", "/new/child"),
    ("/old", "/new/", "/old/child", "/new/child"),
    ("/", "", "/", "/"),
    ("/", "", "/child", "/child"),
    ("/", "/new", "/child", "/new/child"),
];

#[test]
fn empty_replace_prefix_match_redirect_is_admitted_and_normalized_to_root() {
    let plugins = translate_route_plugins(prefix_redirect_rule("/old", ""));
    let (config, _) = emitted_dispatch(&plugins);
    let redirect = &config["rules"][0]["redirect"];
    assert_eq!(redirect["uri"], "/", "{redirect}");
    assert_eq!(redirect["match_prefix"], "/old", "{redirect}");
    assert_eq!(redirect["redirect_code"], 302, "{redirect}");
}

#[tokio::test]
async fn replace_prefix_match_redirect_follows_the_upstream_table_and_keeps_the_query() {
    for &(prefix, replacement, path, expected) in PREFIX_TABLE {
        let label = format!("{prefix:?} -> {replacement:?} on {path:?}");
        let plugins = translate_route_plugins(prefix_redirect_rule(prefix, replacement));
        let (_, plugin) = emitted_dispatch(&plugins);
        for (query, suffix) in [("", ""), ("x=1&y=2", "?x=1&y=2")] {
            let mut ctx = request(path, query);
            match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
                PluginResult::Reject {
                    status_code,
                    headers,
                    ..
                } => {
                    assert_eq!(status_code, 302, "{label}");
                    let expected_location = format!("{expected}{suffix}");
                    assert_eq!(
                        headers.get("location").map(String::as_str),
                        Some(expected_location.as_str()),
                        "{label} query={query:?}"
                    );
                }
                other => panic!("{label}: expected redirect Reject, got {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn replace_prefix_match_rewrite_follows_the_upstream_table() {
    for &(prefix, replacement, path, expected) in PREFIX_TABLE {
        let label = format!("{prefix:?} -> {replacement:?} on {path:?}");
        let plugins = translate_route_plugins(prefix_rewrite_rule(prefix, replacement));
        let (config, plugin) = emitted_dispatch(&plugins);
        let rewrite = &config["rules"][0]["rewrite"];
        assert!(
            !rewrite["uri"].as_str().unwrap_or_default().is_empty(),
            "{label}"
        );
        let mut ctx = request(path, "x=1");
        let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{label}: {result:?}"
        );
        assert_eq!(
            ctx.route_override_path.as_deref(),
            Some(expected),
            "{label}"
        );
        // The query is forwarded separately from the rewritten path.
        assert_eq!(ctx.raw_query_string(), Some("x=1"), "{label}");
    }
}

fn response_header_modifier() -> Value {
    json!({"type": "ResponseHeaderModifier", "responseHeaderModifier": {
        "set": [{"name": "X-Route", "value": "generated"}]
    }})
}

fn published_response_keys(ctx: &RequestContext) -> Vec<String> {
    ctx.route_override_response_transform
        .as_deref()
        .map(|rules| rules.iter().map(|rule| rule.key.clone()).collect())
        .unwrap_or_default()
}

fn assert_emits_response_transformer_consumer(plugins: &[PluginConfig]) {
    assert!(
        plugins
            .iter()
            .any(|plugin| plugin.plugin_name == "response_transformer"),
        "a rule with ResponseHeaderModifier needs a consumer: {plugins:?}"
    );
}

#[tokio::test]
async fn redirect_answer_carries_the_rule_response_header_modifier() {
    let plugins = translate_route_plugins(json!([{
        "matches": [{"path": {"type": "PathPrefix", "value": "/old"}}],
        "filters": [
            response_header_modifier(),
            {"type": "RequestRedirect", "requestRedirect": {
                "statusCode": 302,
                "path": {"type": "ReplaceFullPath", "replaceFullPath": "/new"}
            }}
        ]
    }]));
    assert_emits_response_transformer_consumer(&plugins);
    let (config, plugin) = emitted_dispatch(&plugins);
    let rule = &config["rules"][0];
    assert!(rule.get("redirect").is_some(), "{rule}");
    assert_eq!(rule["response_transform"][0]["key"], "X-Route", "{rule}");

    let mut ctx = request("/old/page", "");
    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 302);
            assert_eq!(headers.get("location").map(String::as_str), Some("/new"));
        }
        other => panic!("expected redirect Reject, got {other:?}"),
    }
    assert_eq!(published_response_keys(&ctx), ["x-route"]);
    assert!(ctx.route_override_response_transform_published);
    assert!(ctx.route_override_upstream_id.is_none());
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn generated_fault_answer_carries_the_rule_response_header_modifier() {
    // A rule with no backendRefs forwards nowhere, so upstream requires a 500
    // the route itself generates. Its ResponseHeaderModifier applies to it.
    let plugins = translate_route_plugins(json!([{
        "matches": [{"path": {"type": "PathPrefix", "value": "/nobackend"}}],
        "filters": [response_header_modifier()]
    }]));
    assert_emits_response_transformer_consumer(&plugins);
    let (config, plugin) = emitted_dispatch(&plugins);
    let rule = &config["rules"][0];
    assert_eq!(rule["fault"]["abort"]["status_code"], 500, "{rule}");
    assert_eq!(rule["response_transform"][0]["key"], "X-Route", "{rule}");

    let mut ctx = request("/nobackend/thing", "");
    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 500),
        other => panic!("expected fault Reject, got {other:?}"),
    }
    assert_eq!(published_response_keys(&ctx), ["x-route"]);
    assert!(ctx.route_override_response_transform_published);
}

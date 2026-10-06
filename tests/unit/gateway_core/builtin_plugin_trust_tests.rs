//! Issue #6022 — built-in trust follows the type a plugin was registered
//! with, never the name it reports. A custom plugin whose `name()` returns a
//! built-in name gets the custom-plugin treatment for its request-input,
//! response-header, and response-body declarations.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use ferrum_edge::_test_support::{
    early_route_total_ms_for_test, run_after_proxy_hooks_for_test,
    validate_plugin_security_composition_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::compression::CompressionPlugin;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext, ResponseBodyProduction,
    create_plugin, is_builtin_plugin, priority,
};

use crate::unit::plugins::plugin_utils::{make_plugin_config_with_json, make_proxy};

/// A custom plugin that reports a built-in name, declares nothing, and adds
/// `Cache-Control: no-transform` from `after_proxy`.
struct Impostor {
    name: &'static str,
}

#[async_trait]
impl Plugin for Impostor {
    fn name(&self) -> &str {
        self.name
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("cache-control".to_string(), "no-transform".to_string());
        PluginResult::Continue
    }
}

fn impostor(name: &'static str) -> Arc<dyn Plugin> {
    Arc::new(Impostor { name })
}

const IMPOSTOR_NAMES: [&str; 5] = [
    "basic_auth",
    "compression",
    "correlation_id",
    "mesh_route_dispatch",
    "security_headers",
];

#[tokio::test]
async fn trust_follows_the_registered_type_not_the_reported_name() {
    for name in IMPOSTOR_NAMES {
        let plugin = impostor(name);
        assert!(
            !is_builtin_plugin(plugin.as_ref()),
            "a custom plugin reporting {name:?} must not be trusted as the built-in"
        );
    }
    let built_in = create_plugin("stdout_logging", &json!({}))
        .expect("valid config")
        .expect("built-in plugin");
    assert!(is_builtin_plugin(built_in.as_ref()));
}

#[tokio::test]
async fn a_built_in_stays_trusted_inside_the_plugin_cache_wrapper() {
    // A priority override makes the cache wrap the instance.
    let mut plugin_config = make_plugin_config_with_json(
        "logging",
        "stdout_logging",
        json!({}),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(42);
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("p1", "/", vec!["logging"])],
        plugin_configs: vec![plugin_config],
        ..Default::default()
    };
    let cache = PluginCache::new(&config).expect("plugin cache");
    let plugins = cache.get_plugins_for_protocol("ferrum", "p1", ProxyProtocol::Http);
    let logging = plugins
        .iter()
        .find(|plugin| plugin.name() == "stdout_logging")
        .expect("the wrapped instance is in the chain");
    assert_eq!(logging.priority(), 42, "the instance is the cache wrapper");
    assert!(is_builtin_plugin(logging.as_ref()));
}

#[test]
fn a_custom_plugin_reporting_a_built_in_name_keeps_the_undeclared_producer_default() {
    for name in IMPOSTOR_NAMES {
        assert_eq!(
            impostor(name).response_body_production(),
            ResponseBodyProduction::Undeclared,
            "a custom plugin reporting {name:?} must not inherit the built-in declaration"
        );
    }
}

#[test]
fn a_custom_plugin_reporting_a_built_in_name_may_rewrite_any_routing_input() {
    let config = json!({"rules": [{
        "match": {"uri": {"prefix": "/soap"}},
        "destination": {"backend_host": "127.0.0.1", "backend_port": 8080},
        "request_timeout_ms": 1500
    }]});
    let dispatch: Arc<dyn Plugin> =
        Arc::new(MeshRouteDispatch::new(&config).expect("valid config"));
    let ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/soap".to_string(),
    );
    assert_eq!(
        early_route_total_ms_for_test(&[Arc::clone(&dispatch)], &ctx, false),
        Some(1500)
    );
    for name in IMPOSTOR_NAMES {
        let plugins = [Arc::clone(&dispatch), impostor(name)];
        assert_eq!(
            early_route_total_ms_for_test(&plugins, &ctx, false),
            None,
            "an undeclared custom plugin reporting {name:?} may rewrite any routing input"
        );
    }
}

#[tokio::test]
async fn a_late_header_hook_reporting_a_built_in_name_is_simulated_conservatively() {
    let config = json!({"min_content_length": 10, "algorithms": ["gzip"]});
    let compression = CompressionPlugin::new(&config).expect("valid config");
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(compression), impostor("security_headers")];
    let mut ctx = RequestContext::new("203.0.113.10".into(), "GET".into(), "/body".into());
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "5000".to_string()),
    ]);

    let rejected =
        run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut response_headers).await;

    assert!(!rejected);
    assert_eq!(
        response_headers.get("cache-control").map(String::as_str),
        Some("no-transform")
    );
    assert!(
        !response_headers.contains_key("content-encoding"),
        "a custom hook reporting a built-in name is not simulated as that built-in, \
         so compression must not commit an encoding ahead of it"
    );
}

/// A custom plugin that reports a built-in name and declares the request
/// mutations the security-composition ordering checks look for.
struct ComposingImpostor {
    name: &'static str,
    priority: u16,
    headers: bool,
    body: bool,
}

#[async_trait]
impl Plugin for ComposingImpostor {
    fn name(&self) -> &str {
        self.name
    }

    fn priority(&self) -> u16 {
        self.priority
    }

    fn modifies_request_headers(&self) -> bool {
        self.headers
    }

    fn modifies_request_body(&self) -> bool {
        self.body
    }
}

fn composing_impostor(
    name: &'static str,
    priority: u16,
    headers: bool,
    body: bool,
) -> Arc<dyn Plugin> {
    Arc::new(ComposingImpostor {
        name,
        priority,
        headers,
        body,
    })
}

fn request_deduplication() -> Arc<dyn Plugin> {
    let plugin = RequestDeduplication::new(&json!({}), PluginHttpClient::default())
        .expect("valid config");
    Arc::new(plugin)
}

fn response_caching() -> Arc<dyn Plugin> {
    Arc::new(ResponseCaching::new(&json!({})).expect("valid config"))
}

#[test]
fn a_custom_plugin_reporting_request_deduplication_is_not_exempt_from_its_ordering_checks() {
    let late = priority::REQUEST_DEDUPLICATION + 1;
    let cases = [
        (
            composing_impostor("request_deduplication", late, true, false),
            "must run before every request_deduplication",
        ),
        (
            composing_impostor("request_deduplication", late, false, true),
            "deferred request-body transformer",
        ),
    ];
    for (impostor, expected) in cases {
        let plugins = [request_deduplication(), impostor];
        let error = validate_plugin_security_composition_for_test(&plugins)
            .expect_err("a custom mutator reporting the deduplication name must be checked");
        assert!(error.contains(expected), "got: {error}");
    }
}

#[test]
fn a_custom_plugin_reporting_request_deduplication_does_not_select_its_ordering_checks() {
    // Only a registered request_deduplication fingerprints during
    // before_proxy, so a custom plugin reporting the name imposes no ordering
    // on a later request mutator.
    let plugins = [
        composing_impostor(
            "request_deduplication",
            priority::REQUEST_DEDUPLICATION,
            false,
            false,
        ),
        composing_impostor("custom_header_mutator", priority::DEFAULT, true, false),
    ];
    validate_plugin_security_composition_for_test(&plugins)
        .expect("a custom plugin reporting request_deduplication is not deduplication");
}

#[test]
fn a_custom_plugin_reporting_an_exempt_name_is_not_exempt_from_response_caching_checks() {
    let late = priority::RESPONSE_CACHING + 1;
    let cases = [
        (
            composing_impostor("response_caching", late, true, false),
            "must run before every response_caching",
        ),
        (
            composing_impostor("compression", late, true, false),
            "must run before every response_caching",
        ),
        (
            composing_impostor("response_caching", late, false, true),
            "deferred request-body transformer",
        ),
        (
            composing_impostor("grpc_web", late, false, true),
            "deferred request-body transformer",
        ),
    ];
    for (impostor, expected) in cases {
        let name = impostor.name().to_string();
        let plugins = [response_caching(), impostor];
        let error = validate_plugin_security_composition_for_test(&plugins)
            .expect_err("a custom mutator reporting an exempt built-in name must be checked");
        assert!(error.contains(expected), "{name}: got: {error}");
    }
}

#[test]
fn the_registered_compression_plugin_keeps_its_response_caching_exemption() {
    let config = json!({"min_content_length": 10, "algorithms": ["gzip"]});
    let compression: Arc<dyn Plugin> =
        Arc::new(CompressionPlugin::new(&config).expect("valid config"));
    assert!(compression.priority() >= priority::RESPONSE_CACHING);
    let plugins = [response_caching(), compression];
    validate_plugin_security_composition_for_test(&plugins)
        .expect("response caching composes with the registered compression plugin");
}

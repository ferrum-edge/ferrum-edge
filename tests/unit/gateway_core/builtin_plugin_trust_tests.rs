//! Issue #6022 — built-in trust follows the type a plugin was registered
//! with, never the name it reports. A custom plugin whose `name()` returns a
//! built-in name gets the custom-plugin treatment for its request-input,
//! response-header, and response-body declarations.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use ferrum_edge::_test_support::{
    composition_shape_plugin_for_test, early_route_total_ms_for_test,
    exclusive_effective_instance_errors_for_test, globals_without_adaptive_concurrency_for_test,
    grpc_web_view_omits_admission_policy_for_test, includes_api_chargeback_for_test,
    install_plugin_finalizers_for_test, prepend_proxy_plugin_for_test,
    proxy_alerts_instances_changed_for_test, run_after_proxy_hooks_for_test,
    shadow_global_plugins_by_name_for_test, shadow_global_plugins_for_test,
    validate_plugin_security_composition_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::compression::CompressionPlugin;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, GRPC_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ProxyProtocol,
    RequestContext, ResponseBodyProduction, create_plugin, is_builtin_plugin, priority,
};
use ferrum_edge::{PluginCache, PluginCapabilities};

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
    let plugin =
        RequestDeduplication::new(&json!({}), PluginHttpClient::default()).expect("valid config");
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

// ---------------------------------------------------------------------------
// Plugin-cache lookups key on built-in standing, not the reported name
// ---------------------------------------------------------------------------

fn stdout_logging() -> Arc<dyn Plugin> {
    create_plugin("stdout_logging", &json!({}))
        .expect("valid config")
        .expect("built-in plugin")
}

fn holds(plugins: &[Arc<dyn Plugin>], plugin: &Arc<dyn Plugin>) -> bool {
    plugins.iter().any(|held| Arc::ptr_eq(held, plugin))
}

#[tokio::test]
async fn a_scoped_custom_plugin_reporting_a_built_in_name_keeps_that_global() {
    let global = stdout_logging();
    let scoped = impostor("stdout_logging");
    let merged = shadow_global_plugins_for_test(&[Arc::clone(&global)], &scoped);
    assert_eq!(merged.len(), 2, "the custom plugin replaces nothing");
    assert!(
        holds(&merged, &global),
        "a custom plugin reporting a built-in name must not remove that built-in's global"
    );
}

#[tokio::test]
async fn a_scoped_built_in_keeps_a_custom_global_reporting_its_name() {
    let global = impostor("stdout_logging");
    let scoped = stdout_logging();
    let merged = shadow_global_plugins_for_test(&[Arc::clone(&global)], &scoped);
    assert_eq!(merged.len(), 2);
    assert!(
        holds(&merged, &global),
        "a built-in must not silently drop a custom global that reports its name"
    );
}

#[tokio::test]
async fn scoped_instances_still_shadow_globals_of_their_own_standing() {
    let global = stdout_logging();
    let scoped = stdout_logging();
    let merged = shadow_global_plugins_for_test(&[Arc::clone(&global)], &scoped);
    assert_eq!(merged.len(), 1, "a scoped built-in replaces its global");
    assert!(holds(&merged, &scoped));

    let global = impostor("custom_audit");
    let scoped = impostor("custom_audit");
    let merged = shadow_global_plugins_for_test(&[Arc::clone(&global)], &scoped);
    assert_eq!(
        merged.len(),
        1,
        "a scoped custom plugin replaces its global"
    );
    assert!(holds(&merged, &scoped));
}

#[tokio::test]
async fn exclusive_instance_checks_count_only_the_registered_built_in() {
    let config = json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]});
    let chargeback = create_plugin("api_chargeback", &config)
        .expect("valid config")
        .expect("built-in plugin");
    let plugins = [Arc::clone(&chargeback), impostor("api_chargeback")];
    let errors = exclusive_effective_instance_errors_for_test(&plugins, "p1");
    assert!(
        errors.is_empty(),
        "a custom plugin reporting api_chargeback is not a second instance: {errors:?}"
    );
    let plugins = [Arc::clone(&chargeback), chargeback];
    let errors = exclusive_effective_instance_errors_for_test(&plugins, "p1");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].contains("api_chargeback permits at most one effective instance"),
        "{errors:?}"
    );
}

#[test]
fn candidate_admission_stand_ins_keep_built_in_standing() {
    let config = make_plugin_config_with_json(
        "allow-all",
        "ip_restriction",
        json!({"allow": ["0.0.0.0/0"]}),
        PluginScope::Global,
        None,
    );
    let stand_in =
        composition_shape_plugin_for_test(&config).expect("ip_restriction has a stand-in");
    assert_eq!(stand_in.name(), "ip_restriction");
    assert!(
        is_builtin_plugin(stand_in.as_ref()),
        "admission must see the built-in standing the runtime instance has"
    );
    let global = create_plugin("ip_restriction", &json!({"allow": ["0.0.0.0/0"]}))
        .expect("valid config")
        .expect("built-in plugin");
    let merged = shadow_global_plugins_for_test(&[global], &stand_in);
    assert_eq!(
        merged.len(),
        1,
        "a scoped stand-in shadows the global exactly as the runtime instance does"
    );
}

#[tokio::test]
async fn an_omitted_scoped_config_shadows_only_globals_of_its_registered_standing() {
    let custom = impostor("stdout_logging");
    let globals = [stdout_logging(), Arc::clone(&custom)];
    let merged = shadow_global_plugins_by_name_for_test(&globals, "stdout_logging");
    assert_eq!(
        merged.len(),
        1,
        "an omitted built-in config replaces its global"
    );
    assert!(
        holds(&merged, &custom),
        "an omitted built-in config must not drop a custom global that reports its name"
    );

    let custom = impostor("custom_audit");
    let merged = shadow_global_plugins_by_name_for_test(&[custom], "custom_audit");
    assert!(
        merged.is_empty(),
        "an omitted custom config replaces its custom global"
    );
}

#[tokio::test]
async fn only_the_registered_size_limiters_compose_with_their_globals() {
    let config = json!({"max_bytes": 20});
    let limiter = || {
        create_plugin("request_size_limiting", &config)
            .expect("valid config")
            .expect("built-in plugin")
    };
    let global = limiter();
    let merged = shadow_global_plugins_for_test(&[Arc::clone(&global)], &limiter());
    assert_eq!(
        merged.len(),
        2,
        "a scoped built-in size limiter composes with its global"
    );
    assert!(holds(&merged, &global));

    let global = impostor("request_size_limiting");
    let scoped = impostor("request_size_limiting");
    let merged = shadow_global_plugins_for_test(&[global], &scoped);
    assert_eq!(
        merged.len(),
        1,
        "a scoped custom plugin reporting a size-limit name replaces its custom global"
    );
    assert!(holds(&merged, &scoped));
}

/// A custom plugin that reports a built-in name and runs on every protocol.
struct EveryProtocolImpostor {
    name: &'static str,
}

#[async_trait]
impl Plugin for EveryProtocolImpostor {
    fn name(&self) -> &str {
        self.name
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }
}

fn every_protocol_impostor(name: &'static str) -> Arc<dyn Plugin> {
    Arc::new(EveryProtocolImpostor { name })
}

fn node_waypoint_authz_ready(config: &GatewayConfig, globals: &[Arc<dyn Plugin>]) -> bool {
    ferrum_edge::_test_support::node_waypoint_destination_authz_ready_over_globals_for_test(
        config, globals,
    )
}

#[tokio::test]
async fn a_custom_global_reporting_mesh_authz_does_not_prove_node_waypoint_authz() {
    let managed = make_plugin_config_with_json(
        ferrum_edge::modes::mesh::MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        json!({}),
        PluginScope::Global,
        None,
    );
    let config = GatewayConfig {
        version: "1".to_string(),
        plugin_configs: vec![managed],
        ..Default::default()
    };
    let mesh_authz = create_plugin("mesh_authz", &json!({}))
        .expect("valid config")
        .expect("built-in plugin");
    assert!(
        node_waypoint_authz_ready(&config, &[mesh_authz]),
        "the managed instance in the global TCP chain proves destination authz"
    );
    let custom = every_protocol_impostor("mesh_authz");
    assert!(
        !node_waypoint_authz_ready(&config, &[custom]),
        "a custom plugin reporting mesh_authz in place of the managed instance enforces \
         nothing, so captured destination authz must not be ready"
    );
}

/// A custom gRPC-only authentication plugin that reports the name of a
/// native-gRPC policy the composed gRPC-Web view runs.
struct GrpcOnlyAuthImpostor {
    name: &'static str,
}

#[async_trait]
impl Plugin for GrpcOnlyAuthImpostor {
    fn name(&self) -> &str {
        self.name
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        GRPC_ONLY_PROTOCOLS
    }
}

fn grpc_only_auth_impostor(name: &'static str) -> Arc<dyn Plugin> {
    Arc::new(GrpcOnlyAuthImpostor { name })
}

#[test]
fn a_custom_grpc_plugin_reporting_a_grpc_web_policy_name_keeps_that_view_refused() {
    let config = json!({"deny_methods": ["/pkg.Svc/Dangerous"]});
    let router = create_plugin("grpc_method_router", &config)
        .expect("valid config")
        .expect("built-in plugin");
    assert!(
        !grpc_web_view_omits_admission_policy_for_test(&[router]),
        "the composed gRPC-Web view runs the registered grpc_method_router"
    );
    for name in ["grpc_method_router", "grpc_deadline"] {
        assert!(
            grpc_web_view_omits_admission_policy_for_test(&[grpc_only_auth_impostor(name)]),
            "a custom gRPC-only gating plugin reporting {name:?} is not a policy the \
             gRPC-Web view runs, so the view must be refused (issue #6110)"
        );
    }

    // The custom plugin does not join the route's composed view either.
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("p1", "/", vec![])],
        ..Default::default()
    };
    let cache = PluginCache::new(&config).expect("plugin cache");
    let impostor = grpc_only_auth_impostor("grpc_method_router");
    prepend_proxy_plugin_for_test(&cache, "ferrum", "p1", Arc::clone(&impostor))
        .expect("inject the route-scoped plugin");
    let view = cache.grpc_web_request_view("ferrum", "p1");
    let capabilities = view.capabilities();
    assert!(capabilities.has(PluginCapabilities::OMITS_ROUTE_ADMISSION_POLICY));
    assert!(
        !holds(&view.plugins(), &impostor),
        "a custom gRPC-only plugin must not run on the translated gRPC-Web view"
    );
}

#[tokio::test]
async fn an_adaptive_only_rebuild_keeps_a_custom_global_reporting_adaptive_concurrency() {
    let adaptive = create_plugin("adaptive_concurrency", &json!({}))
        .expect("valid config")
        .expect("built-in plugin");
    let custom = impostor("adaptive_concurrency");
    let globals = [adaptive, Arc::clone(&custom)];
    let kept = globals_without_adaptive_concurrency_for_test(&globals);
    assert_eq!(kept.len(), 1, "only the registered instance is rebuilt");
    assert!(
        holds(&kept, &custom),
        "a custom plugin reporting adaptive_concurrency must stay in the global chain"
    );
}

#[tokio::test]
async fn a_custom_plugin_reporting_api_chargeback_does_not_keep_charges_published() {
    let config = json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]});
    let chargeback = create_plugin("api_chargeback", &config)
        .expect("valid config")
        .expect("built-in plugin");
    assert!(includes_api_chargeback_for_test(&[chargeback]));
    assert!(
        !includes_api_chargeback_for_test(&[impostor("api_chargeback")]),
        "a generation whose only api_chargeback is a custom plugin must publish the \
         /charges absence"
    );
}

#[test]
fn custom_plugins_reporting_proxy_alerts_do_not_reset_alert_ownership() {
    let previous = [impostor("proxy_alerts")];
    let next = [impostor("proxy_alerts")];
    assert!(
        !proxy_alerts_instances_changed_for_test(&previous, &next),
        "swapping custom plugins that report proxy_alerts changes no alert instance"
    );
    assert!(!proxy_alerts_instances_changed_for_test(&[], &next));
}

/// A regression guard rather than a test of this change: the finalizers have
/// keyed on the registered type since before issue #6022's plugin-cache sweep.
#[test]
fn custom_plugins_reporting_finalized_built_in_names_get_no_finalizer() {
    let mut plugins = vec![
        impostor("cors"),
        impostor("mesh_route_dispatch"),
        impostor("cors"),
    ];
    install_plugin_finalizers_for_test(&mut plugins)
        .expect("custom plugins impose no built-in contiguity rule");
    let names: Vec<_> = plugins.iter().map(|plugin| plugin.name()).collect();
    assert_eq!(
        names,
        ["cors", "mesh_route_dispatch", "cors"],
        "no finalizer is installed and no custom plugin is wrapped or dropped"
    );
}

/// Every `.name()` call in the plugin cache that is not an argument of a
/// formatting or logging macro, keyed by its trimmed source line, with how
/// many times that line may occur. Each either pairs the reported name with
/// the registered type's built-in standing or decides nothing. A new lookup
/// must go through `is_builtin_named` (or pair the name with standing the same
/// way) and be listed here.
const REPORTED_NAME_USES: [(&str, usize); 6] = [
    // `is_builtin_named` itself.
    (
        "plugin.name() == name && crate::plugins::is_builtin_plugin(plugin.as_ref())",
        1,
    ),
    // `remove_shadowed_global_plugin` hands over the scoped instance's
    // standing with its name.
    (
        "remove_shadowed_globals(plugins, global_ptrs, scoped.name(), builtin);",
        1,
    ),
    // `remove_shadowed_globals`, which also compares built-in standing.
    ("plugin.name() != plugin_name", 1),
    // `DeferredCorsPlugin` and `PluginInstanceWrapper` report the wrapped
    // instance's name.
    ("self.inner.name()", 2),
    // The sole-authentication check counts `is_auth_plugin()` instances; the
    // names only render its error.
    (".map(|plugin| plugin.name())", 1),
    // The response-presentation digest hashes the name beside the digest the
    // instance declares; it selects nothing.
    (
        "presentation_policy_contributions.push((p.name(), digest));",
        1,
    ),
];

/// The byte offset of every `.name()` call in `source` outside comments and
/// string and character literals, with whether it is an argument of a
/// formatting or logging macro.
fn reported_name_calls(source: &str) -> Vec<(usize, bool)> {
    const FORMAT_MACROS: [&str; 6] = ["format", "error", "warn", "info", "debug", "trace"];
    let bytes = source.as_bytes();
    let mut calls = Vec::new();
    // The bracket depth just outside each open formatting macro's arguments.
    let mut format_depths: Vec<usize> = Vec::new();
    let mut depth = 0usize;
    // The last identifier and the offset just past it.
    let mut ident = ("", 0usize);
    let mut index = 0;
    while index < bytes.len() {
        let rest = &source[index..];
        let len = match bytes[index] {
            _ if rest.starts_with("//") => rest.find('\n').unwrap_or(rest.len()),
            _ if rest.starts_with("/*") => rest.find("*/").map_or(rest.len(), |end| end + 2),
            _ if rest.starts_with(".name()") || rest.starts_with("::name(") => {
                calls.push((index, !format_depths.is_empty()));
                1
            }
            b'"' => quoted_len(rest),
            b'\'' => char_literal_len(rest).unwrap_or(1),
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let len = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                let raw = if matches!(&rest[..len], "r" | "br") {
                    raw_string_len(&rest[len..])
                } else {
                    None
                };
                match raw {
                    Some(raw) => len + raw,
                    None => {
                        ident = (&rest[..len], index + len);
                        len
                    }
                }
            }
            b'!' => {
                let opens = matches!(bytes.get(index + 1), Some(b'(' | b'[' | b'{'));
                if opens && ident.1 == index && FORMAT_MACROS.contains(&ident.0) {
                    format_depths.push(depth);
                }
                1
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                1
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if format_depths.last() == Some(&depth) {
                    format_depths.pop();
                }
                1
            }
            _ => rest.chars().next().map_or(1, char::len_utf8),
        };
        index += len;
    }
    calls
}

/// The length of the string literal `rest` starts with.
fn quoted_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// The length of the raw string literal body `rest` starts with (after its
/// `r` or `br` prefix), or `None` when `rest` does not open one.
fn raw_string_len(rest: &str) -> Option<usize> {
    let hashes = rest.bytes().take_while(|&byte| byte == b'#').count();
    if rest.as_bytes().get(hashes) != Some(&b'"') {
        return None;
    }
    let close = format!("\"{}", "#".repeat(hashes));
    let body = hashes + 1;
    let end = rest[body..].find(&close)?;
    Some(body + end + close.len())
}

/// The length of the character literal `rest` starts with, or `None` when its
/// quote opens a lifetime or label instead.
fn char_literal_len(rest: &str) -> Option<usize> {
    let mut chars = rest[1..].chars();
    match chars.next()? {
        '\\' => rest.get(3..)?.find('\'').map(|end| end + 4),
        first => (chars.next()? == '\'').then_some(first.len_utf8() + 2),
    }
}

/// The 1-based line and trimmed text of every `.name()` call in `source` that
/// is not a formatting or logging macro argument, and how many calls are.
fn reported_name_lookups(source: &str) -> (Vec<(usize, &str)>, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let mut lookups = Vec::new();
    let mut format_arguments = 0;
    for (offset, in_format_macro) in reported_name_calls(source) {
        if in_format_macro {
            format_arguments += 1;
        } else {
            let line = source[..offset].matches('\n').count();
            lookups.push((line + 1, lines[line].trim()));
        }
    }
    (lookups, format_arguments)
}

#[test]
fn the_reported_name_scan_sees_every_lookup_shape() {
    let source = r#"
fn lookups(plugin: &Arc<dyn Plugin>, p: &Arc<dyn Plugin>) {
    let a = NAMES.contains(&plugin.name());
    match plugin.name() {
        _ => {}
    }
    let b = "x" == plugin.name();
    let c = matches!(p.name(), "x" | "y");
    let d = plugin
        .name()
        == "x";
    let e = <dyn Plugin>::name(plugin.as_ref());
    // A comment: plugin.name() == "x"
    /* A block comment: plugin.name() == "x" */
    let f = "a string: plugin.name() == \"x\" (";
    let g = format!("{:?} {}", plugin.name(), '(');
    warn!(plugin = %plugin.name(), "message (with parens)");
    let h: &'static str = plugin.name();
}
"#;
    let (lookups, format_arguments) = reported_name_lookups(source);
    let lines: Vec<&str> = lookups.iter().map(|(_, line)| *line).collect();
    assert_eq!(
        lines,
        [
            "let a = NAMES.contains(&plugin.name());",
            "match plugin.name() {",
            "let b = \"x\" == plugin.name();",
            "let c = matches!(p.name(), \"x\" | \"y\");",
            ".name()",
            "let e = <dyn Plugin>::name(plugin.as_ref());",
            "let h: &'static str = plugin.name();",
        ]
    );
    assert_eq!(format_arguments, 2);
}

/// A custom plugin reporting a built-in name cannot select, exempt, count,
/// shadow, or drop that built-in through the plugin cache: every use of the
/// reported name outside a diagnostic is one of [`REPORTED_NAME_USES`].
#[test]
fn plugin_cache_never_keys_a_built_in_lookup_on_the_reported_name_alone() {
    let source = include_str!("../../../src/plugin_cache.rs");
    let (lookups, format_arguments) = reported_name_lookups(source);
    assert!(
        format_arguments >= 10,
        "the scan must see the plugin cache's diagnostic uses, found {format_arguments}"
    );
    for (line, text) in &lookups {
        let listed = REPORTED_NAME_USES
            .iter()
            .any(|(listed_text, _)| listed_text == text);
        assert!(
            listed,
            "src/plugin_cache.rs:{line}: a lookup keyed on the reported name alone: {text}"
        );
    }
    for (listed, expected) in REPORTED_NAME_USES {
        let found = lookups.iter().filter(|(_, text)| *text == listed).count();
        assert_eq!(found, expected, "{listed:?}");
    }
}

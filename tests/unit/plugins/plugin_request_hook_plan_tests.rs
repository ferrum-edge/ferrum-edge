//! M18: audited request-hook plans preserve plugin behavior, order, and epochs.

use chrono::Utc;
use ferrum_edge::_test_support::{
    await_request_plugin_deadline_for_test, incremental_plugin_rebuild_targets_for_test,
    prepend_proxy_plugin_for_test, run_before_proxy_hooks_for_test,
    set_grpc_deadline_budget_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugin_cache::PluginCacheRequestView;
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use super::plugin_utils::{make_plugin_config_with_json, make_proxy};

fn config(rows: Vec<PluginConfig>) -> GatewayConfig {
    let ids = rows
        .iter()
        .filter(|row| row.scope == PluginScope::Proxy)
        .map(|row| row.id.as_str())
        .collect();
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("p1", "/", ids)],
        plugin_configs: rows,
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

fn builtin(id: &str, name: &str, value: serde_json::Value) -> PluginConfig {
    make_plugin_config_with_json(id, name, value, PluginScope::Proxy, Some("p1"))
}

fn names(plugins: &[Arc<dyn Plugin>]) -> Vec<&str> {
    plugins.iter().map(|plugin| plugin.name()).collect()
}

fn assert_subsequence(full: &[Arc<dyn Plugin>], filtered: &[Arc<dyn Plugin>]) {
    let mut remaining = full.iter();
    for selected in filtered {
        assert!(remaining.any(|plugin| Arc::ptr_eq(plugin, selected)));
    }
}

fn mesh_config() -> GatewayConfig {
    config(vec![
        builtin("identity", "spiffe_identity", json!({})),
        builtin("authz", "mesh_authz", json!({})),
        builtin("metrics", "workload_metrics", json!({})),
        builtin("log", "stdout_logging", json!({})),
        make_plugin_config_with_json(
            "prom",
            "prometheus_metrics",
            json!({}),
            PluginScope::Global,
            None,
        ),
        builtin(
            "route",
            "mesh_route_dispatch",
            json!({"rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]}),
        ),
    ])
}

#[test]
fn mesh_plans_omit_only_defaults_and_retain_phase_order_and_instances() {
    let cache = PluginCache::new(&mesh_config()).unwrap();
    for protocol in [
        ProxyProtocol::Http,
        ProxyProtocol::Grpc,
        ProxyProtocol::WebSocket,
    ] {
        let view = cache.request_view("ferrum", "p1", protocol);
        let full = view.plugins();
        assert_subsequence(&full, view.on_request_received_plugins());
        assert_subsequence(&full, view.before_proxy_plugins());
        assert_eq!(
            names(view.on_request_received_plugins()),
            names(&full)
                .into_iter()
                .filter(|name| matches!(
                    *name,
                    "spiffe_identity" | "workload_metrics" | "prometheus_metrics"
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            names(view.before_proxy_plugins()),
            names(&full)
                .into_iter()
                .filter(|name| matches!(
                    *name,
                    "workload_metrics" | "mesh_route_dispatch" | "__mesh_route_dispatch_finalizer"
                ))
                .collect::<Vec<_>>()
        );
        // Seven instances, including the route finalizer: fourteen boxed calls
        // become six. These are structural savings, not a throughput claim.
        assert_eq!(full.len(), 7);
        assert_eq!(
            full.len() * 2
                - view.on_request_received_plugins().len()
                - view.before_proxy_plugins().len(),
            8
        );
        assert!(names(&view.authorize_plugins()).contains(&"mesh_authz"));
    }
    let grpc_web = cache.grpc_web_request_view("ferrum", "p1");
    assert_eq!(grpc_web.on_request_received_plugins().len(), 3);
    assert_eq!(grpc_web.before_proxy_plugins().len(), 3);
}

#[test]
fn unfiltered_empty_and_custom_chains_reuse_the_original_plugin_slice() {
    let cache = PluginCache::new(&config(Vec::new())).unwrap();
    for custom in [false, true] {
        if custom {
            prepend_proxy_plugin_for_test(
                &cache,
                "ferrum",
                "p1",
                Arc::new(CustomProbe {
                    calls: Arc::new(Mutex::new(Vec::new())),
                }),
            )
            .unwrap();
        }
        let view = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
        let full = view.plugins();
        assert_eq!(full.len(), usize::from(custom));
        assert!(std::ptr::eq(
            view.on_request_received_plugins(),
            full.as_slice()
        ));
        assert!(std::ptr::eq(view.before_proxy_plugins(), full.as_slice()));
    }
    // Guard the hot-view ownership budget as well as the slice results: the
    // optional plan owns plain Vecs, and an unfiltered view has no plan Arc.
    let source = include_str!("../../../src/plugin_cache.rs");
    let start = source.find("struct RequestHookPlans {").unwrap();
    let end = source[start..].find("\n}\n").unwrap() + start;
    assert_eq!(
        source[start..end].matches("Vec<Arc<dyn Plugin>>").count(),
        2
    );
    assert!(!source[start..end].contains("Arc<Vec"));
    assert_eq!(
        source
            .matches("request_hooks: Option<Arc<RequestHookPlans>>")
            .count(),
        2
    );
}

struct CustomProbe {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait::async_trait]
impl Plugin for CustomProbe {
    fn name(&self) -> &str {
        "mesh_authz"
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        self.calls.lock().unwrap().push("received");
        ctx.metadata
            .insert("custom_received".to_string(), "yes".to_string());
        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.calls.lock().unwrap().push("before");
        headers.insert("x-custom".to_string(), "kept".to_string());
        PluginResult::Continue
    }
}

async fn run_request_hooks(
    view: &PluginCacheRequestView,
    ctx: &mut RequestContext,
    planned: bool,
) -> HashMap<String, String> {
    let full = view.plugins();
    let received = if planned {
        view.on_request_received_plugins()
    } else {
        full.as_slice()
    };
    for plugin in received {
        assert!(matches!(
            plugin.on_request_received(ctx).await,
            PluginResult::Continue
        ));
    }
    for plugin in view.authorize_plugins().iter() {
        assert!(matches!(
            plugin.authorize(ctx).await,
            PluginResult::Continue
        ));
    }
    let before = if planned {
        view.before_proxy_plugins()
    } else {
        full.as_slice()
    };
    let mut headers = ctx.headers.clone();
    assert!(matches!(
        run_before_proxy_hooks_for_test(before, ctx, &mut headers).await,
        PluginResult::Continue
    ));
    headers
}

#[tokio::test]
async fn custom_name_spoof_and_mesh_hooks_have_full_chain_parity() {
    let cache = PluginCache::new(&mesh_config()).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let custom: Arc<dyn Plugin> = Arc::new(CustomProbe {
        calls: Arc::clone(&calls),
    });
    prepend_proxy_plugin_for_test(&cache, "ferrum", "p1", Arc::clone(&custom)).unwrap();
    let view = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
    assert!(Arc::ptr_eq(&view.on_request_received_plugins()[0], &custom));
    assert!(Arc::ptr_eq(&view.before_proxy_plugins()[0], &custom));
    let mut baseline =
        RequestContext::new("10.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    baseline.headers.insert(
        "traceparent".to_string(),
        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-00".to_string(),
    );
    let mut candidate = baseline.clone();
    let baseline_headers = run_request_hooks(&view, &mut baseline, false).await;
    let candidate_headers = run_request_hooks(&view, &mut candidate, true).await;
    assert_eq!(baseline_headers, candidate_headers);
    assert_eq!(baseline.metadata, candidate.metadata);
    assert_eq!(
        baseline.route_override_upstream_id,
        candidate.route_override_upstream_id
    );
    assert_eq!(
        candidate.route_override_upstream_id.as_deref(),
        Some("canary")
    );
    assert_eq!(
        *calls.lock().unwrap(),
        ["received", "before", "received", "before"]
    );
}

#[tokio::test]
async fn triggered_default_hook_is_retained_and_memoizes_before_path_changes() {
    let mut gated = builtin(
        "gated",
        "mesh_authz",
        json!({"mesh_policies": [{
            "name": "deny-all", "namespace": "default", "scope": {"kind": "mesh_wide"},
            "rules": [{"action": "deny"}]
        }]}),
    );
    gated.trigger = Some(
        serde_json::from_value(json!({"when": {"match": {
            "path": {"prefix": ["/protected"]}
        }}}))
        .unwrap(),
    );
    let mut priority_only = builtin("priority", "mesh_authz", json!({}));
    priority_only.priority_override = Some(2501);
    let cache = PluginCache::new(&config(vec![gated, priority_only])).unwrap();
    let view = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
    assert_eq!(view.plugins().len(), 2);
    assert_eq!(view.on_request_received_plugins().len(), 1);
    assert_eq!(view.before_proxy_plugins().len(), 1);
    let gated = &view.on_request_received_plugins()[0];
    assert!(gated.has_execution_trigger());
    let mut skipped = RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/public".to_string(),
    );
    assert!(matches!(
        gated.on_request_received(&mut skipped).await,
        PluginResult::Continue
    ));
    skipped.path = "/protected".to_string();
    assert!(matches!(
        gated.authorize(&mut skipped).await,
        PluginResult::Continue
    ));
    let mut matched = RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/protected".to_string(),
    );
    assert!(matches!(
        gated.on_request_received(&mut matched).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        gated.authorize(&mut matched).await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn plans_rebuild_atomically_and_old_views_retain_their_instances() {
    let old = config(vec![builtin("slot", "stdout_logging", json!({}))]);
    let mut next = config(vec![builtin("slot", "spiffe_identity", json!({}))]);
    next.version = "2".to_string();
    for incremental in [false, true] {
        let cache = PluginCache::new(&old).unwrap();
        let retained = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
        let retained_plugins = retained.plugins();
        if incremental {
            cache
                .apply_delta(
                    &next,
                    &incremental_plugin_rebuild_targets_for_test(&old, &next),
                    &[],
                    false,
                )
                .unwrap();
        } else {
            cache.rebuild(&next).unwrap();
        }
        let fresh = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
        assert!(retained.on_request_received_plugins().is_empty());
        assert!(retained.before_proxy_plugins().is_empty());
        assert!(Arc::ptr_eq(&retained.plugins()[0], &retained_plugins[0]));
        assert_eq!(
            names(fresh.on_request_received_plugins()),
            ["spiffe_identity"]
        );
        assert!(fresh.before_proxy_plugins().is_empty());
        assert!(Arc::ptr_eq(
            &fresh.on_request_received_plugins()[0],
            &fresh.plugins()[0]
        ));
    }
}

struct PendingCustomHook;

#[async_trait::async_trait]
impl Plugin for PendingCustomHook {
    fn name(&self) -> &str {
        "stdout_logging"
    }

    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        std::future::pending().await
    }

    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        std::future::pending().await
    }
}

#[tokio::test]
async fn retained_custom_hooks_still_obey_request_deadlines() {
    let cache =
        PluginCache::new(&config(vec![builtin("log", "stdout_logging", json!({}))])).unwrap();
    prepend_proxy_plugin_for_test(&cache, "ferrum", "p1", Arc::new(PendingCustomHook)).unwrap();
    let view = cache.request_view("ferrum", "p1", ProxyProtocol::Http);
    assert_eq!(view.on_request_received_plugins().len(), 1);
    assert_eq!(view.before_proxy_plugins().len(), 1);
    let mut ctx = RequestContext::new("10.0.0.1".to_string(), "POST".to_string(), "/".to_string());
    let receipt = await_request_plugin_deadline_for_test(
        Some(tokio::time::Instant::now()),
        view.on_request_received_plugins()[0].on_request_received(&mut ctx),
    )
    .await;
    assert!(matches!(receipt, PluginResult::Reject { .. }));
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    let before =
        run_before_proxy_hooks_for_test(view.before_proxy_plugins(), &mut ctx, &mut HashMap::new())
            .await;
    assert!(matches!(before, PluginResult::Reject { .. }));
}

fn impl_block<'a>(source: &'a str, type_name: &str) -> &'a str {
    let header = format!("impl Plugin for {type_name} {{");
    let start = source.find(&header).unwrap() + header.len();
    let end = source[start..].find("\n}\n").unwrap() + start;
    &source[start..end]
}

#[test]
fn audited_inventory_fails_when_an_omitted_hook_gains_an_override() {
    let cache = include_str!("../../../src/plugin_cache.rs");
    let start = cache.find("fn audited_request_hook_mask(").unwrap();
    let end = cache[start..].find("\n}\n").unwrap() + start;
    let inventory =
        regex::Regex::new(r"TypeId::of::<([^>]+)>\(\),\s*RequestHookMask::(\w+)").unwrap();
    let declared: BTreeMap<_, _> = inventory
        .captures_iter(&cache[start..end])
        .map(|m| (m[1].to_string(), m[2].to_string()))
        .collect();
    let sources = [
        (
            "crate::plugins::mesh::spiffe_identity::SpiffeIdentity",
            include_str!("../../../src/plugins/mesh/spiffe_identity.rs"),
        ),
        (
            "crate::plugins::mesh::authz::MeshAuthz",
            include_str!("../../../src/plugins/mesh/authz.rs"),
        ),
        (
            "crate::plugins::mesh::outbound_registry::OutboundRegistry",
            include_str!("../../../src/plugins/mesh/outbound_registry.rs"),
        ),
        (
            "crate::plugins::mesh::bpf_metrics::MeshBpfMetrics",
            include_str!("../../../src/plugins/mesh/bpf_metrics.rs"),
        ),
        (
            "crate::plugins::mesh_route_dispatch::MeshRouteDispatch",
            include_str!("../../../src/plugins/mesh_route_dispatch.rs"),
        ),
        ("MeshRouteDispatchFinalizer", cache),
        (
            "crate::plugins::prometheus_metrics::PrometheusMetrics",
            include_str!("../../../src/plugins/prometheus_metrics.rs"),
        ),
        (
            "crate::plugins::stdout_logging::StdoutLogging",
            include_str!("../../../src/plugins/stdout_logging.rs"),
        ),
    ];
    assert_eq!(
        declared.len(),
        sources.len(),
        "every audit entry needs source drift coverage"
    );
    for (kind, source) in sources {
        let mask = declared
            .get(kind)
            .unwrap_or_else(|| panic!("missing audit entry {kind}"));
        let implementation = impl_block(source, kind.rsplit("::").next().unwrap());
        for (hook, included) in [
            ("on_request_received", mask == "RECEIVED" || mask == "ALL"),
            ("before_proxy", mask == "BEFORE_PROXY" || mask == "ALL"),
        ] {
            let declared_hook = implementation
                .lines()
                .any(|line| line.starts_with(&format!("    async fn {hook}(")));
            assert_eq!(
                included, declared_hook,
                "{kind}: review the {hook} audit after changing its implementation"
            );
        }
        if mask != "BEFORE_PROXY" && mask != "ALL" {
            assert!(
                !implementation.contains("fn participates_in_route_request_header_finalization("),
                "an omitted hook cannot own route-header finalization: {kind}"
            );
            assert!(
                !implementation.contains("fn defer_before_proxy_until_backend_path_resolved("),
                "review deferred phase behavior before omitting {kind}"
            );
        }
    }
    let trait_source = include_str!("../../../src/plugins/mod.rs");
    for hook in ["on_request_received", "before_proxy"] {
        let ready_default = regex::Regex::new(&format!(
            r"(?s)async fn {hook}\([^{{]+\{{\s*PluginResult::Continue\s*\}}"
        ))
        .unwrap();
        assert!(
            ready_default.is_match(trait_source),
            "elision requires the ready Continue default for {hook}"
        );
    }
}

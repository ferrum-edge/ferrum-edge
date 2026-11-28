//! `plugin_cache::plugin_configs_applied_to_proxy` — the function behind the
//! Admin API's `GET /plugins/config?applies_to_proxy=` — must name exactly
//! the plugins a built `PluginCache` runs on each proxy.

use super::plugin_utils::{make_plugin_config, make_proxy};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};
use ferrum_edge::plugin_cache::plugin_configs_applied_to_proxy;
use ferrum_edge::time_compat::UtcTimestamp;

fn fixture() -> GatewayConfig {
    let proxies: Vec<Proxy> = vec![
        // Proxy-scoped cors and request_size_limiting plus a group limiter.
        make_proxy("a", "/a", vec!["p-cors-a", "grp-rl", "p-rsl-a"]),
        // Attaches the group limiter and a cors config scoped to `a`, which
        // must not apply here.
        make_proxy("b", "/b", vec!["grp-rl", "p-cors-a"]),
        // Attaches only a DISABLED same-name config: it neither applies nor
        // shadows the global.
        make_proxy("c", "/c", vec!["p-ip-c-disabled"]),
        // No associations at all.
        make_proxy("d", "/d", vec![]),
    ];
    let mut plugin_configs: Vec<PluginConfig> = vec![
        make_plugin_config("g-cors", "cors", PluginScope::Global, None, true),
        make_plugin_config("g-rl", "rate_limiting", PluginScope::Global, None, true),
        make_plugin_config(
            "g-rsl",
            "request_size_limiting",
            PluginScope::Global,
            None,
            true,
        ),
        make_plugin_config("g-ip", "ip_restriction", PluginScope::Global, None, true),
        make_plugin_config(
            "g-rt-disabled",
            "response_transformer",
            PluginScope::Global,
            None,
            false,
        ),
        make_plugin_config("p-cors-a", "cors", PluginScope::Proxy, Some("a"), true),
        make_plugin_config(
            "p-rsl-a",
            "request_size_limiting",
            PluginScope::Proxy,
            Some("a"),
            true,
        ),
        make_plugin_config(
            "p-ip-c-disabled",
            "ip_restriction",
            PluginScope::Proxy,
            Some("c"),
            false,
        ),
        // Scoped to `d` but not in `d`'s association list.
        make_plugin_config(
            "p-ip-d-unattached",
            "ip_restriction",
            PluginScope::Proxy,
            Some("d"),
            true,
        ),
        make_plugin_config(
            "grp-rl",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        ),
    ];
    // A second namespace reusing ids must never leak in.
    let mut other_ns = make_plugin_config("g-other", "cors", PluginScope::Global, None, true);
    other_ns.namespace = "other".to_string();
    plugin_configs.push(other_ns);
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: UtcTimestamp::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names
}

#[test]
fn applied_configs_match_the_built_plugin_cache_within_namespace_and_exclude_foreign_globals() {
    let mut config = fixture();
    // Mirror a single-namespace data plane: the cache is built from the
    // proxy's own namespace only.
    config.plugin_configs.retain(|pc| pc.namespace == "ferrum");
    let cache = PluginCache::new(&config).expect("fixture plugin cache builds");
    let full = fixture();
    // Runtime PluginCache clones process-wide globals across namespaces when
    // multi-namespace configs are loaded (e.g. a mesh waypoint namespace
    // global alongside a tenant bound-Service proxy), while the Admin API
    // helper intentionally stays within `proxy.namespace` to preserve
    // X-Ferrum-Namespace authorization boundaries.
    let multi_ns_cache = PluginCache::new(&full).expect("multi-namespace plugin cache builds");
    for proxy in &config.proxies {
        let runtime: Vec<String> = cache
            .get_plugins("ferrum", &proxy.id)
            .iter()
            .map(|plugin| plugin.name().to_string())
            .collect();
        let applied_configs = plugin_configs_applied_to_proxy(proxy, &full.plugin_configs);
        assert!(
            applied_configs.iter().all(|pc| pc.namespace == "ferrum"),
            "proxy {:?}: applies_to_proxy must never leak foreign-namespace globals",
            proxy.id
        );
        let applied: Vec<String> = applied_configs
            .into_iter()
            .map(|pc| pc.plugin_name.clone())
            .collect();
        assert_eq!(
            sorted(applied),
            sorted(runtime),
            "proxy {:?}: applies_to_proxy must equal the same-namespace plugin cache chain",
            proxy.id
        );
        // Confirm the multi-namespace runtime cache does include the foreign
        // global (`g-other` cors) on a proxy that does not shadow cors (`b`),
        // documenting the intentional namespace-boundary difference.
        if proxy.id == "b" {
            let multi_cors_count = multi_ns_cache
                .get_plugins("ferrum", "b")
                .iter()
                .filter(|p| p.name() == "cors")
                .count();
            assert!(multi_cors_count >= 2);
        }
    }
}

#[test]
fn applied_configs_are_the_expected_ids_ordered_by_id() {
    let config = fixture();
    let ids = |proxy_id: &str| -> Vec<String> {
        let proxy = config
            .proxies
            .iter()
            .find(|proxy| proxy.id == proxy_id)
            .expect("fixture proxy");
        plugin_configs_applied_to_proxy(proxy, &config.plugin_configs)
            .into_iter()
            .map(|pc| pc.id.clone())
            .collect()
    };
    // `a`: scoped cors shadows g-cors, the group limiter shadows g-rl, and a
    // scoped size limiter never shadows the global one.
    assert_eq!(ids("a"), ["g-ip", "g-rsl", "grp-rl", "p-cors-a", "p-rsl-a"]);
    // `b`: p-cors-a is scoped to `a`, so g-cors still applies.
    assert_eq!(ids("b"), ["g-cors", "g-ip", "g-rsl", "grp-rl"]);
    // `c`: a disabled attached config neither applies nor shadows.
    assert_eq!(ids("c"), ["g-cors", "g-ip", "g-rl", "g-rsl"]);
    // `d`: an unattached proxy-scoped config does not apply.
    assert_eq!(ids("d"), ["g-cors", "g-ip", "g-rl", "g-rsl"]);
}

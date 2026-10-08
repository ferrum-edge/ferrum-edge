//! `PolicyGraphScope`: the neighborhood a plugin-graph write is admitted
//! against (issue #6056).

use ferrum_edge::config::policy_graph_scope::{
    NAMESPACE_WIDE_POLICY_PLUGIN_NAMES, PolicyGraphScope, requires_full_policy_graph,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, Proxy};
use serde_json::json;

fn proxy(id: &str, plugin_ids: &[&str]) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
        "plugins": plugin_ids
            .iter()
            .map(|plugin_id| json!({"plugin_config_id": plugin_id}))
            .collect::<Vec<_>>(),
    }))
    .expect("proxy fixture")
}

fn plugin(id: &str, name: &str, scope: &str, proxy_id: Option<&str>) -> PluginConfig {
    let mut value = json!({
        "id": id,
        "plugin_name": name,
        "scope": scope,
        "enabled": true,
        "config": {},
    });
    if let Some(proxy_id) = proxy_id {
        value["proxy_id"] = json!(proxy_id);
    }
    serde_json::from_value(value).expect("plugin fixture")
}

fn graph() -> GatewayConfig {
    GatewayConfig {
        proxies: vec![
            proxy("p1", &["group-a", "local-p1"]),
            proxy("p2", &["group-a"]),
            proxy("p3", &["local-p3"]),
            proxy("p4", &[]),
        ],
        plugin_configs: vec![
            plugin("global-cors", "cors", "global", None),
            plugin("group-a", "rate_limiting", "proxy_group", None),
            plugin("local-p1", "key_auth", "proxy", Some("p1")),
            plugin("local-p3", "key_auth", "proxy", Some("p3")),
            plugin("metrics", "prometheus_metrics", "global", None),
            plugin("charge-p4", "api_chargeback", "proxy", Some("p4")),
            plugin("orphan", "key_auth", "proxy", Some("p4")),
        ],
        ..Default::default()
    }
}

fn ids<T>(items: &[T], id: impl Fn(&T) -> &str) -> Vec<String> {
    items.iter().map(|item| id(item).to_string()).collect()
}

#[test]
fn global_write_has_no_scope() {
    assert!(
        PolicyGraphScope::for_write(&[], &[plugin("g", "cors", "global", None)], None).is_none()
    );
}

#[test]
fn proxy_scoped_plugin_scopes_its_proxy_and_itself() {
    let scope =
        PolicyGraphScope::for_write(&[], &[plugin("new", "key_auth", "proxy", Some("p4"))], None)
            .unwrap();
    assert_eq!(scope.proxy_ids.iter().collect::<Vec<_>>(), ["p4"]);
    assert_eq!(
        scope.changed_plugin_config_ids.iter().collect::<Vec<_>>(),
        ["new"]
    );

    let restricted = scope.restrict(graph());
    assert_eq!(ids(&restricted.proxies, |p| &p.id), ["p4"]);
    // The unattached `orphan` row on p4 is not in its chain, so it stays out;
    // globals and namespace-wide types are always present.
    assert_eq!(
        ids(&restricted.plugin_configs, |p| &p.id),
        ["global-cors", "metrics", "charge-p4"]
    );
}

#[test]
fn changed_group_plugin_pulls_every_associated_proxy() {
    let scope = PolicyGraphScope::for_write(
        &[],
        &[plugin("group-a", "rate_limiting", "proxy_group", None)],
        None,
    )
    .unwrap();
    let restricted = scope.restrict(graph());
    assert_eq!(ids(&restricted.proxies, |p| &p.id), ["p1", "p2"]);
    assert_eq!(
        ids(&restricted.plugin_configs, |p| &p.id),
        ["global-cors", "group-a", "local-p1", "metrics", "charge-p4"]
    );
}

#[test]
fn removed_plugin_pulls_its_proxies() {
    let scope = PolicyGraphScope::for_write(&[], &[], Some("local-p3")).unwrap();
    let restricted = scope.restrict(graph());
    assert_eq!(ids(&restricted.proxies, |p| &p.id), ["p3"]);
}

#[test]
fn submitted_proxy_loads_its_new_references_without_their_other_proxies() {
    // The new p4 version attaches group-a. group-a is loaded, but p1/p2 are
    // not: their chains do not change.
    let scope = PolicyGraphScope::for_write(&[proxy("p4", &["group-a"])], &[], None).unwrap();
    let restricted = scope.restrict(graph());
    assert_eq!(ids(&restricted.proxies, |p| &p.id), ["p4"]);
    assert!(
        restricted
            .plugin_configs
            .iter()
            .any(|plugin| plugin.id == "group-a")
    );
}

#[test]
fn namespace_wide_names_cover_cross_proxy_rules() {
    for name in ["prometheus_metrics", "__mesh_bpf_metrics", "api_chargeback"] {
        assert!(
            NAMESPACE_WIDE_POLICY_PLUGIN_NAMES.contains(&name),
            "{name} has a namespace-wide admission rule"
        );
    }
}

#[test]
fn enabled_global_tcp_throttle_requires_full_graph() {
    let mut config = graph();
    assert!(!requires_full_policy_graph(&config));
    let mut throttle = plugin("throttle", "tcp_connection_throttle", "global", None);
    throttle.enabled = false;
    config.plugin_configs.push(throttle.clone());
    assert!(!requires_full_policy_graph(&config));
    throttle.enabled = true;
    config.plugin_configs.push(throttle);
    assert!(requires_full_policy_graph(&config));
}

/// Scoped plugin-graph admission only sees a write's neighborhood, so every
/// gateway-wide composition rule must be classified here: either per proxy
/// (decided from the affected proxies' chains) or namespace-wide (its plugin
/// type is in `NAMESPACE_WIDE_POLICY_PLUGIN_NAMES`, so every instance is
/// loaded). A new rule that is not classified fails this test instead of
/// silently escaping scoped admission (issue #6056).
#[test]
fn every_gateway_composition_rule_is_classified_for_scoped_admission() {
    const NAMESPACE_WIDE_RULES: &[(&str, &str)] = &[
        (
            "validate_prometheus_metrics_ownership",
            "prometheus_metrics",
        ),
        ("validate_mesh_bpf_metrics_ownership", "__mesh_bpf_metrics"),
        ("validate_api_chargeback_ownership", "api_chargeback"),
    ];
    const PER_PROXY_RULES: &[&str] = &[
        "validate_replay_provenance_composition",
        "validate_soap_ws_security_composition",
    ];

    let source = include_str!("../../../src/plugin_cache.rs");
    let body = source
        .split("fn validate_gateway_plugin_composition(config: &GatewayConfig)")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("validate_gateway_plugin_composition body");
    let mut called: Vec<&str> = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| token.starts_with("validate_"))
        .collect();
    called.sort_unstable();
    called.dedup();

    let mut classified: Vec<&str> = NAMESPACE_WIDE_RULES
        .iter()
        .map(|(rule, _)| *rule)
        .chain(PER_PROXY_RULES.iter().copied())
        .collect();
    classified.sort_unstable();
    assert_eq!(
        called, classified,
        "classify every gateway composition rule as per-proxy or namespace-wide"
    );
    for (rule, plugin_name) in NAMESPACE_WIDE_RULES {
        assert!(
            NAMESPACE_WIDE_POLICY_PLUGIN_NAMES.contains(plugin_name),
            "{rule} compares every {plugin_name} instance, so scoped admission must load them all"
        );
    }
}

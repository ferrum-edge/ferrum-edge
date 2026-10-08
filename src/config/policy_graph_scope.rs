//! The part of a namespace policy graph a plugin-graph admission must see.
//!
//! Admin admission used to load and revalidate every proxy and plugin config
//! in the namespace for each Proxy/PluginConfig write, so one `POST /batch`
//! cost O(namespace) and bulk onboarding cost O(N²) (issue #6056). Most
//! composition invariants are per proxy: a write can only break the chain of a
//! proxy whose own plugin set changes. [`PolicyGraphScope`] names those proxies
//! and plugin configs, and [`PolicyGraphScope::restrict`] is the reference
//! definition of the neighborhood every backend's
//! `DatabaseBackend::load_namespace_policy_neighborhood` must return.
//!
//! The neighborhood contains:
//!
//! - every proxy named by the write, and every proxy associated with a plugin
//!   config the write creates, replaces, or removes;
//! - every plugin config those proxies are associated with, plus every plugin
//!   config the write names (changed or referenced);
//! - every `global` plugin config, because globals join every proxy's chain;
//! - every instance of a plugin type whose admission rule spans the whole
//!   namespace ([`NAMESPACE_WIDE_POLICY_PLUGIN_NAMES`]).
//!
//! Callers must fall back to the full graph when a write changes a global
//! plugin config, or when the neighborhood holds an enabled global
//! `tcp_connection_throttle` (its "no TCP proxy to protect" rule depends on
//! every proxy). See `crud::validate_plugin_graph_candidates`.

use std::collections::{BTreeSet, HashSet};

use crate::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy};

/// Plugin types whose admission rule compares instances across proxies, so a
/// scoped candidate must carry every instance in the namespace:
///
/// - `prometheus_metrics` and the mesh BPF metrics exporter allow at most one
///   enabled global instance;
/// - `api_chargeback` requires every enabled instance to share its registry
///   tunables and `/charges` projection.
pub const NAMESPACE_WIDE_POLICY_PLUGIN_NAMES: &[&str] = &[
    "prometheus_metrics",
    crate::plugins::mesh::bpf_metrics::PLUGIN_NAME,
    "api_chargeback",
];

/// Whether `plugin_name` is one of [`NAMESPACE_WIDE_POLICY_PLUGIN_NAMES`].
pub fn is_namespace_wide_policy_plugin(plugin_name: &str) -> bool {
    NAMESPACE_WIDE_POLICY_PLUGIN_NAMES.contains(&plugin_name)
}

/// The proxies and plugin configs one plugin-graph write can affect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyGraphScope {
    /// Proxies whose effective plugin chain the write replaces or attaches to.
    pub proxy_ids: BTreeSet<String>,
    /// Plugin configs the write creates, replaces, or removes. Every proxy
    /// associated with one of these is in scope too, because its chain changes.
    pub changed_plugin_config_ids: BTreeSet<String>,
    /// Further plugin configs the write references (associations listed on a
    /// submitted proxy). They are loaded, but their other proxies are not.
    pub referenced_plugin_config_ids: BTreeSet<String>,
}

impl PolicyGraphScope {
    /// Scope for a write that submits `proxies` and `plugins` and optionally
    /// removes `removed_plugin_id`. Returns `None` when the write changes a
    /// `global` plugin config: a global joins every proxy's chain, so only the
    /// full graph is a sound candidate.
    pub fn for_write(
        proxies: &[Proxy],
        plugins: &[PluginConfig],
        removed_plugin_id: Option<&str>,
    ) -> Option<Self> {
        if plugins
            .iter()
            .any(|plugin| plugin.scope == PluginScope::Global)
        {
            return None;
        }
        let mut scope = Self::default();
        for proxy in proxies {
            scope.proxy_ids.insert(proxy.id.clone());
            scope.referenced_plugin_config_ids.extend(
                proxy
                    .plugins
                    .iter()
                    .map(|association| association.plugin_config_id.clone()),
            );
        }
        for plugin in plugins {
            scope.changed_plugin_config_ids.insert(plugin.id.clone());
            // Persistence attaches a proxy-scoped config to its `proxy_id`
            // in the same transaction, so that proxy's chain changes.
            if plugin.scope == PluginScope::Proxy
                && let Some(proxy_id) = plugin.proxy_id.as_deref()
            {
                scope.proxy_ids.insert(proxy_id.to_string());
            }
        }
        if let Some(removed) = removed_plugin_id {
            scope.changed_plugin_config_ids.insert(removed.to_string());
        }
        Some(scope)
    }

    /// Every plugin config id the scope names directly.
    pub fn named_plugin_config_ids(&self) -> BTreeSet<&str> {
        self.changed_plugin_config_ids
            .iter()
            .chain(self.referenced_plugin_config_ids.iter())
            .map(String::as_str)
            .collect()
    }

    /// Whether `proxy` belongs to the neighborhood.
    pub fn includes_proxy(&self, proxy: &Proxy) -> bool {
        self.proxy_ids.contains(&proxy.id)
            || proxy.plugins.iter().any(|association| {
                self.changed_plugin_config_ids
                    .contains(&association.plugin_config_id)
            })
    }

    /// Whether `plugin` belongs to the neighborhood, given the plugin config
    /// ids the in-scope proxies are associated with.
    pub fn includes_plugin_config(
        &self,
        plugin: &PluginConfig,
        associated_ids: &HashSet<&str>,
    ) -> bool {
        plugin.scope == PluginScope::Global
            || is_namespace_wide_policy_plugin(&plugin.plugin_name)
            || self.changed_plugin_config_ids.contains(&plugin.id)
            || self.referenced_plugin_config_ids.contains(&plugin.id)
            || associated_ids.contains(plugin.id.as_str())
    }

    /// Reference neighborhood of a full namespace policy graph. Order is kept,
    /// so a backend that sorts by id matches a full load that sorts by id.
    pub fn restrict(&self, mut graph: GatewayConfig) -> GatewayConfig {
        graph.proxies.retain(|proxy| self.includes_proxy(proxy));
        let associated_ids: HashSet<&str> = graph
            .proxies
            .iter()
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let plugin_configs = std::mem::take(&mut graph.plugin_configs)
            .into_iter()
            .filter(|plugin| self.includes_plugin_config(plugin, &associated_ids))
            .collect();
        graph.plugin_configs = plugin_configs;
        graph
    }
}

/// Whether a candidate holds a policy whose admission depends on every proxy
/// in the namespace, so a neighborhood cannot decide it: an enabled global
/// `tcp_connection_throttle` must still protect at least one TCP proxy after
/// the write.
pub fn requires_full_policy_graph(candidate: &GatewayConfig) -> bool {
    candidate.plugin_configs.iter().any(|plugin| {
        plugin.enabled
            && plugin.scope == PluginScope::Global
            && plugin.plugin_name == "tcp_connection_throttle"
    })
}

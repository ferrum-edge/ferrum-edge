//! Configuration delta computation for incremental cache updates.
//!
//! Instead of rebuilding every cache from scratch on each config change,
//! `ConfigDelta` identifies exactly which resources changed so each cache
//! can surgically update only the affected entries. This keeps the hot
//! request path undisturbed — no full cache clears, no thundering herds.
//!
//! Changes are detected by comparing `id` + `updated_at` timestamps.
//! Resources present in the new config but not the old are additions;
//! resources in the old but not the new are removals; resources in both
//! with a newer `updated_at` are modifications.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};

/// Identifies which resources changed between two config snapshots.
///
/// Used by each cache's `apply_delta` method to perform surgical updates
/// instead of full rebuilds.
#[derive(Debug)]
pub struct ConfigDelta {
    // Proxy changes
    pub added_proxies: Vec<Proxy>,
    pub removed_proxy_ids: Vec<String>,
    pub modified_proxies: Vec<Proxy>,

    // Consumer changes
    pub added_consumers: Vec<Consumer>,
    pub removed_consumer_ids: Vec<String>,
    pub modified_consumers: Vec<Consumer>,

    // Plugin config changes
    pub added_plugin_configs: Vec<PluginConfig>,
    pub removed_plugin_config_ids: Vec<String>,
    pub modified_plugin_configs: Vec<PluginConfig>,

    // Upstream changes
    pub added_upstreams: Vec<Upstream>,
    pub removed_upstream_ids: Vec<String>,
    pub modified_upstreams: Vec<Upstream>,
}

impl ConfigDelta {
    /// Compute the delta between an old and new config snapshot.
    ///
    /// Uses `id` for identity and `updated_at` for change detection.
    /// Returns a delta describing exactly which resources were added,
    /// removed, or modified.
    pub fn compute(old: &GatewayConfig, new: &GatewayConfig) -> Self {
        Self {
            added_proxies: diff_added(&old.proxies, &new.proxies),
            removed_proxy_ids: diff_removed_ids(&old.proxies, &new.proxies),
            modified_proxies: diff_modified(&old.proxies, &new.proxies),

            added_consumers: diff_added(&old.consumers, &new.consumers),
            removed_consumer_ids: diff_removed_ids(&old.consumers, &new.consumers),
            modified_consumers: diff_modified(&old.consumers, &new.consumers),

            added_plugin_configs: diff_added(&old.plugin_configs, &new.plugin_configs),
            removed_plugin_config_ids: diff_removed_ids(&old.plugin_configs, &new.plugin_configs),
            modified_plugin_configs: diff_modified(&old.plugin_configs, &new.plugin_configs),

            added_upstreams: diff_added(&old.upstreams, &new.upstreams),
            removed_upstream_ids: diff_removed_ids(&old.upstreams, &new.upstreams),
            modified_upstreams: diff_modified(&old.upstreams, &new.upstreams),
        }
    }

    /// True when nothing changed — skip all cache work.
    pub fn is_empty(&self) -> bool {
        self.added_proxies.is_empty()
            && self.removed_proxy_ids.is_empty()
            && self.modified_proxies.is_empty()
            && self.added_consumers.is_empty()
            && self.removed_consumer_ids.is_empty()
            && self.modified_consumers.is_empty()
            && self.added_plugin_configs.is_empty()
            && self.removed_plugin_config_ids.is_empty()
            && self.modified_plugin_configs.is_empty()
            && self.added_upstreams.is_empty()
            && self.removed_upstream_ids.is_empty()
            && self.modified_upstreams.is_empty()
    }

    /// IDs of all proxies that need their plugin lists rebuilt.
    ///
    /// A proxy needs plugin rebuild if:
    /// - The proxy itself was added or modified (plugin associations may have changed)
    /// - Any of its referenced plugin_configs were added, removed, or modified
    pub fn proxy_ids_needing_plugin_rebuild(&self, new_config: &GatewayConfig) -> HashSet<String> {
        let mut ids = HashSet::new();

        // Added/modified proxies always need plugin rebuild
        for p in &self.added_proxies {
            ids.insert(p.id.clone());
        }
        for p in &self.modified_proxies {
            ids.insert(p.id.clone());
        }

        // If any plugin config changed, find all proxies that reference it
        if !self.added_plugin_configs.is_empty()
            || !self.removed_plugin_config_ids.is_empty()
            || !self.modified_plugin_configs.is_empty()
        {
            let changed_pc_ids: HashSet<&str> = self
                .added_plugin_configs
                .iter()
                .map(|pc| pc.id.as_str())
                .chain(self.removed_plugin_config_ids.iter().map(|s| s.as_str()))
                .chain(self.modified_plugin_configs.iter().map(|pc| pc.id.as_str()))
                .collect();

            // Also include any plugin configs with proxy_id scope that changed
            let changed_proxy_scoped: HashSet<&str> = self
                .added_plugin_configs
                .iter()
                .chain(self.modified_plugin_configs.iter())
                .filter_map(|pc| pc.proxy_id.as_deref())
                .collect();

            for proxy in &new_config.proxies {
                // Check if this proxy references any changed plugin config
                if proxy
                    .plugins
                    .iter()
                    .any(|assoc| changed_pc_ids.contains(assoc.plugin_config_id.as_str()))
                {
                    ids.insert(proxy.id.clone());
                }
                // Check if a proxy-scoped plugin config targets this proxy
                if changed_proxy_scoped.contains(proxy.id.as_str()) {
                    ids.insert(proxy.id.clone());
                }
            }

            // Global plugin config changes affect ALL proxies
            let global_changed = self
                .added_plugin_configs
                .iter()
                .chain(self.modified_plugin_configs.iter())
                .any(|pc| pc.scope == crate::config::types::PluginScope::Global);
            let global_removed = self.removed_plugin_config_ids.iter().any(|id| {
                // We don't have the old config's scope info for removed IDs,
                // so conservatively treat removed plugin configs as potentially global
                // if they're not in the new config
                !new_config.plugin_configs.iter().any(|pc| pc.id == *id)
            });

            if global_changed || global_removed {
                // A global plugin changed — all proxies need rebuild
                for proxy in &new_config.proxies {
                    ids.insert(proxy.id.clone());
                }
            }
        }

        ids
    }

    /// Collect listen_paths that were affected by proxy changes.
    ///
    /// Used by RouterCache to selectively invalidate only the path cache
    /// entries that could match changed routes, instead of clearing everything.
    pub fn affected_listen_paths(&self, old_config: &GatewayConfig) -> Vec<String> {
        let mut paths = Vec::new();

        // Added proxies: their listen_paths may now take priority over existing cache entries
        for p in &self.added_proxies {
            if !p.backend_protocol.is_stream_proxy() {
                paths.push(p.listen_path.clone());
            }
        }

        // Removed proxies: cache entries pointing to them are stale
        let old_proxy_map: HashMap<&str, &Proxy> = old_config
            .proxies
            .iter()
            .map(|p| (p.id.as_str(), p))
            .collect();
        for id in &self.removed_proxy_ids {
            if let Some(old_proxy) = old_proxy_map.get(id.as_str())
                && !old_proxy.backend_protocol.is_stream_proxy()
            {
                paths.push(old_proxy.listen_path.clone());
            }
        }

        // Modified proxies: both old and new listen_paths (in case listen_path changed)
        for p in &self.modified_proxies {
            if !p.backend_protocol.is_stream_proxy() {
                paths.push(p.listen_path.clone());
            }
            if let Some(old_proxy) = old_proxy_map.get(p.id.as_str()) {
                let old_needs_invalidation = !old_proxy.backend_protocol.is_stream_proxy()
                    && (old_proxy.listen_path != p.listen_path
                        || p.backend_protocol.is_stream_proxy());
                if old_needs_invalidation {
                    paths.push(old_proxy.listen_path.clone());
                }
            }
        }

        paths
    }
}

// --- Generic diffing helpers ---
// These work on any type with `id: String` and `updated_at: DateTime<Utc>`.

trait HasIdAndTimestamp {
    fn id(&self) -> &str;
    fn updated_at(&self) -> DateTime<Utc>;
}

impl HasIdAndTimestamp for Proxy {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl HasIdAndTimestamp for Consumer {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl HasIdAndTimestamp for PluginConfig {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl HasIdAndTimestamp for Upstream {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Resources in `new` but not in `old`.
fn diff_added<T: HasIdAndTimestamp + Clone>(old: &[T], new: &[T]) -> Vec<T> {
    let old_ids: HashSet<&str> = old.iter().map(|r| r.id()).collect();
    new.iter()
        .filter(|r| !old_ids.contains(r.id()))
        .cloned()
        .collect()
}

/// IDs of resources in `old` but not in `new`.
fn diff_removed_ids<T: HasIdAndTimestamp>(old: &[T], new: &[T]) -> Vec<String> {
    let new_ids: HashSet<&str> = new.iter().map(|r| r.id()).collect();
    old.iter()
        .filter(|r| !new_ids.contains(r.id()))
        .map(|r| r.id().to_string())
        .collect()
}

/// Resources present in both but with a newer `updated_at` in `new`.
fn diff_modified<T: HasIdAndTimestamp + Clone>(old: &[T], new: &[T]) -> Vec<T> {
    let old_map: HashMap<&str, DateTime<Utc>> =
        old.iter().map(|r| (r.id(), r.updated_at())).collect();
    new.iter()
        .filter(|r| {
            old_map
                .get(r.id())
                .is_some_and(|&old_ts| r.updated_at() > old_ts)
        })
        .cloned()
        .collect()
}

//! Configuration delta computation for incremental cache updates.
//!
//! Instead of rebuilding every cache from scratch on each config change,
//! `ConfigDelta` identifies exactly which resources changed so cache builders
//! can preserve unchanged plugin, consumer, and load-balancer state while
//! publishing a fresh request epoch atomically.
//!
//! Changes are detected by comparing `id` + `updated_at` timestamps.
//! Resources present in the new config but not the old are additions;
//! resources in the old but not the new are removals; resources in both
//! with a different `updated_at` are modifications (uses `!=` to catch
//! both forward progress and backward clock skew).

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

use crate::config::types::{Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream};

/// Summary of routing changes affected by proxy adds, removals, or modifications.
///
/// Path-keyed routes and host-only routes use different cache keys, so callers
/// that need targeted invalidation can inspect them separately.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct AffectedRoutes {
    pub listen_paths: Vec<String>,
    pub host_only_hosts: Vec<String>,
}

#[allow(dead_code)]
impl AffectedRoutes {
    pub fn is_empty(&self) -> bool {
        self.listen_paths.is_empty() && self.host_only_hosts.is_empty()
    }
}

/// Identifies which resources changed between two config snapshots.
///
/// Used by request-epoch builders to decide which pre-computed inners can be
/// reused and which must be rebuilt from the new config.
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
    /// True when a global plugin was added, removed, modified, or changed away
    /// from global scope. Known proxy plugin lists contain merged global
    /// instances, so they must all be rebuilt when this is true.
    pub global_plugin_configs_changed: bool,

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
        let added_plugin_configs = diff_added(&old.plugin_configs, &new.plugin_configs);
        let removed_plugin_config_ids = diff_removed_ids(&old.plugin_configs, &new.plugin_configs);
        let modified_plugin_configs = diff_modified(&old.plugin_configs, &new.plugin_configs);
        let old_global_plugin_ids: HashSet<&str> = old
            .plugin_configs
            .iter()
            .filter(|pc| pc.scope == PluginScope::Global)
            .map(|pc| pc.id.as_str())
            .collect();
        let global_plugin_configs_changed = added_plugin_configs
            .iter()
            .any(|pc| pc.scope == PluginScope::Global)
            || modified_plugin_configs.iter().any(|pc| {
                pc.scope == PluginScope::Global || old_global_plugin_ids.contains(pc.id.as_str())
            })
            || removed_plugin_config_ids
                .iter()
                .any(|id| old_global_plugin_ids.contains(id.as_str()));

        Self {
            added_proxies: diff_added(&old.proxies, &new.proxies),
            removed_proxy_ids: diff_removed_ids(&old.proxies, &new.proxies),
            modified_proxies: diff_modified(&old.proxies, &new.proxies),

            added_consumers: diff_added(&old.consumers, &new.consumers),
            removed_consumer_ids: diff_removed_ids(&old.consumers, &new.consumers),
            modified_consumers: diff_modified(&old.consumers, &new.consumers),

            added_plugin_configs,
            removed_plugin_config_ids,
            modified_plugin_configs,
            global_plugin_configs_changed,

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
            && !self.global_plugin_configs_changed
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

            if self.global_plugin_configs_changed || !self.removed_plugin_config_ids.is_empty() {
                // A global plugin change affects every merged proxy list. Any
                // plugin-config deletion also rebuilds every proxy because DB
                // cascade can remove association rows without updating proxy
                // timestamps, leaving no reliable proxy-level delta.
                for proxy in &new_config.proxies {
                    ids.insert(proxy.id.clone());
                }
            }
        }

        ids
    }

    /// Collect routing identities affected by proxy changes.
    #[allow(dead_code)]
    pub fn affected_routes(&self, old_config: &GatewayConfig) -> AffectedRoutes {
        let mut listen_paths = Vec::new();
        let mut host_only_hosts = Vec::new();

        let record =
            |listen_paths: &mut Vec<String>, host_only_hosts: &mut Vec<String>, p: &Proxy| {
                if p.dispatch_kind.is_stream() {
                    return;
                }

                match p.listen_path.as_deref() {
                    Some(path) => listen_paths.push(path.to_string()),
                    None => host_only_hosts.extend(p.hosts.iter().cloned()),
                }
            };

        for p in &self.added_proxies {
            record(&mut listen_paths, &mut host_only_hosts, p);
        }

        let old_proxy_map: HashMap<&str, &Proxy> = old_config
            .proxies
            .iter()
            .map(|p| (p.id.as_str(), p))
            .collect();

        for id in &self.removed_proxy_ids {
            if let Some(p) = old_proxy_map.get(id.as_str()) {
                record(&mut listen_paths, &mut host_only_hosts, p);
            }
        }

        for p in &self.modified_proxies {
            record(&mut listen_paths, &mut host_only_hosts, p);
            if let Some(old_proxy) = old_proxy_map.get(p.id.as_str()) {
                let routing_changed = old_proxy.dispatch_kind.is_stream()
                    != p.dispatch_kind.is_stream()
                    || old_proxy.listen_path != p.listen_path
                    || old_proxy.hosts != p.hosts;
                if routing_changed {
                    record(&mut listen_paths, &mut host_only_hosts, old_proxy);
                }
            }
        }

        AffectedRoutes {
            listen_paths,
            host_only_hosts,
        }
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

/// Resources present in both whose `updated_at` changed.
///
/// Uses `!=` instead of `>` for snapshot-to-snapshot comparison so a full
/// snapshot can detect backward timestamp drift once both versions are present
/// locally. Incremental SQL polling still depends on its `updated_at > cursor`
/// predicate to fetch candidates in the first place, so this is a defensive
/// diff guard rather than a substitute for monotonic database timestamps.
fn diff_modified<T: HasIdAndTimestamp + Clone>(old: &[T], new: &[T]) -> Vec<T> {
    let old_map: HashMap<&str, DateTime<Utc>> =
        old.iter().map(|r| (r.id(), r.updated_at())).collect();
    new.iter()
        .filter(|r| {
            old_map
                .get(r.id())
                .is_some_and(|&old_ts| r.updated_at() != old_ts)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        BackendScheme, DispatchKind, PluginAssociation, PluginScope, default_namespace,
    };
    use chrono::TimeZone;
    use serde_json::json;

    #[derive(Clone)]
    struct TestResource {
        id: String,
        updated_at: DateTime<Utc>,
    }

    impl HasIdAndTimestamp for TestResource {
        fn id(&self) -> &str {
            &self.id
        }

        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    fn ts(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .expect("fixed timestamp should be valid")
    }

    fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
        GatewayConfig {
            version: "1".to_string(),
            proxies,
            consumers: vec![],
            plugin_configs,
            upstreams: vec![],
            loaded_at: ts(0),
            known_namespaces: vec![],
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
        }
    }

    fn proxy(
        id: &str,
        listen_path: Option<&str>,
        hosts: &[&str],
        plugin_ids: &[&str],
        updated_at: DateTime<Utc>,
    ) -> Proxy {
        let mut proxy: Proxy = serde_json::from_value(json!({
            "id": id,
            "namespace": default_namespace(),
            "hosts": hosts,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "backend.local",
            "backend_port": 8080
        }))
        .expect("test proxy should deserialize");
        proxy.dispatch_kind = DispatchKind::from(BackendScheme::Http);
        proxy.plugins = plugin_ids
            .iter()
            .map(|id| PluginAssociation {
                plugin_config_id: (*id).to_string(),
            })
            .collect();
        proxy.created_at = updated_at;
        proxy.updated_at = updated_at;
        proxy
    }

    fn stream_proxy(id: &str, updated_at: DateTime<Utc>) -> Proxy {
        let mut proxy = proxy(id, None, &[], &[], updated_at);
        proxy.backend_scheme = Some(BackendScheme::Tcp);
        proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
        proxy.listen_port = Some(9000);
        proxy
    }

    fn plugin_config(
        id: &str,
        scope: PluginScope,
        proxy_id: Option<&str>,
        updated_at: DateTime<Utc>,
    ) -> PluginConfig {
        PluginConfig {
            id: id.to_string(),
            plugin_name: "request_transformer".to_string(),
            namespace: default_namespace(),
            config: json!({}),
            scope,
            proxy_id: proxy_id.map(str::to_string),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: updated_at,
            updated_at,
        }
    }

    #[test]
    fn diff_modified_treats_backward_timestamp_drift_as_change() {
        let old = vec![TestResource {
            id: "r1".to_string(),
            updated_at: ts(20),
        }];
        let new = vec![TestResource {
            id: "r1".to_string(),
            updated_at: ts(10),
        }];

        let modified = diff_modified(&old, &new);

        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].id, "r1");
    }

    #[test]
    fn compute_tracks_proxy_add_remove_and_modify() {
        let old = config(
            vec![
                proxy("modified", Some("/old"), &[], &[], ts(10)),
                proxy("removed", Some("/removed"), &[], &[], ts(10)),
            ],
            vec![],
        );
        let new = config(
            vec![
                proxy("modified", Some("/old"), &[], &[], ts(11)),
                proxy("added", Some("/added"), &[], &[], ts(10)),
            ],
            vec![],
        );

        let delta = ConfigDelta::compute(&old, &new);

        assert_eq!(
            delta
                .added_proxies
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            vec!["added"]
        );
        assert_eq!(delta.removed_proxy_ids, vec!["removed"]);
        assert_eq!(
            delta
                .modified_proxies
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            vec!["modified"]
        );
        assert!(!delta.is_empty());
    }

    #[test]
    fn plugin_rebuild_targets_associations_and_proxy_scoped_configs() {
        let old = config(
            vec![
                proxy("p1", Some("/one"), &[], &["pc-a"], ts(10)),
                proxy("p2", Some("/two"), &[], &["pc-b"], ts(10)),
                proxy("p3", Some("/three"), &[], &[], ts(10)),
            ],
            vec![
                plugin_config("pc-a", PluginScope::ProxyGroup, None, ts(10)),
                plugin_config("pc-b", PluginScope::ProxyGroup, None, ts(10)),
            ],
        );
        let new = config(
            old.proxies.clone(),
            vec![
                plugin_config("pc-a", PluginScope::ProxyGroup, None, ts(11)),
                plugin_config("pc-b", PluginScope::ProxyGroup, None, ts(10)),
                plugin_config("pc-p3", PluginScope::Proxy, Some("p3"), ts(10)),
            ],
        );

        let delta = ConfigDelta::compute(&old, &new);
        let ids = delta.proxy_ids_needing_plugin_rebuild(&new);

        assert!(ids.contains("p1"));
        assert!(ids.contains("p3"));
        assert!(!ids.contains("p2"));
    }

    #[test]
    fn removed_plugin_config_conservatively_rebuilds_all_current_proxies() {
        let old = config(
            vec![
                proxy("p1", Some("/one"), &[], &[], ts(10)),
                proxy("p2", Some("/two"), &[], &[], ts(10)),
            ],
            vec![plugin_config(
                "removed",
                PluginScope::ProxyGroup,
                None,
                ts(10),
            )],
        );
        let new = config(old.proxies.clone(), vec![]);

        let delta = ConfigDelta::compute(&old, &new);
        let ids = delta.proxy_ids_needing_plugin_rebuild(&new);

        assert_eq!(ids.len(), 2);
        assert!(ids.contains("p1"));
        assert!(ids.contains("p2"));
    }

    #[test]
    fn affected_routes_collects_old_and_new_http_identities_and_skips_streams() {
        let old = config(
            vec![
                proxy("path", Some("/old"), &[], &[], ts(10)),
                proxy("host", None, &["old.example"], &[], ts(10)),
                stream_proxy("stream", ts(10)),
            ],
            vec![],
        );
        let new = config(
            vec![
                proxy("path", Some("/new"), &[], &[], ts(11)),
                proxy("added-host", None, &["new.example"], &[], ts(10)),
                stream_proxy("stream", ts(11)),
            ],
            vec![],
        );

        let delta = ConfigDelta::compute(&old, &new);
        let mut affected = delta.affected_routes(&old);
        affected.listen_paths.sort();
        affected.host_only_hosts.sort();

        assert_eq!(affected.listen_paths, vec!["/new", "/old"]);
        assert_eq!(affected.host_only_hosts, vec!["new.example", "old.example"]);
        assert!(!affected.is_empty());
    }
}

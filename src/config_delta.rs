//! Configuration delta computation for incremental cache updates.
//!
//! Instead of rebuilding every cache from scratch on each config change,
//! `ConfigDelta` identifies exactly which resources changed so cache builders
//! can preserve unchanged plugin, consumer, and load-balancer state while
//! publishing a fresh request epoch atomically.
//!
//! Changes are detected by comparing the namespace-qualified `(namespace, id)`
//! identity plus `updated_at` timestamps. Resources present in the new config
//! but not the old are additions; resources in the old but not the new are
//! removals; resources in both with a different `updated_at` are modifications
//! (uses `!=` to catch both forward progress and backward clock skew).
//! Consumers, plugin configurations and stream-family proxies additionally
//! compare their own persisted content when `updated_at` is reused, so a
//! rotated credential, a flipped policy, or a re-pointed TCP/UDP backend cannot
//! be classified as unchanged (GHSA-2wrj-vq9m-75jg). That fingerprint
//! deliberately covers a resource's own persisted fields only — see
//! `HasNamespacedIdAndTimestamp::persisted_content_changed`.
//! Proxy/plugin association membership is compared directly because
//! junction-table changes can arrive without advancing the owning proxy's
//! timestamp.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

use crate::config::db_backend::NamespacedResourceId;
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
/// reused and which must be rebuilt from the new config. Removals carry
/// [`NamespacedResourceId`] so cache pruning can drop only the matching
/// tenant's runtime state when the same id exists in another namespace.
#[derive(Debug)]
pub struct ConfigDelta {
    // Proxy changes
    pub added_proxies: Vec<Proxy>,
    pub removed_proxy_ids: Vec<NamespacedResourceId>,
    pub modified_proxies: Vec<Proxy>,

    // Consumer changes
    pub added_consumers: Vec<Consumer>,
    pub removed_consumer_ids: Vec<NamespacedResourceId>,
    pub modified_consumers: Vec<Consumer>,

    // Plugin config changes
    pub added_plugin_configs: Vec<PluginConfig>,
    pub removed_plugin_config_ids: Vec<NamespacedResourceId>,
    pub modified_plugin_configs: Vec<PluginConfig>,
    /// Existing proxies whose plugin association membership changed even
    /// though the proxy resource timestamp may not have advanced.
    pub plugin_association_changed_proxy_ids: Vec<NamespacedResourceId>,
    /// True when a global plugin was added, removed, modified, or changed away
    /// from global scope. Known proxy plugin lists contain merged global
    /// instances, so they must all be rebuilt when this is true.
    pub global_plugin_configs_changed: bool,

    // Upstream changes
    pub added_upstreams: Vec<Upstream>,
    pub removed_upstream_ids: Vec<NamespacedResourceId>,
    pub modified_upstreams: Vec<Upstream>,
}

impl ConfigDelta {
    /// Compute the delta between an old and new config snapshot.
    ///
    /// Uses `(namespace, id)` for identity and `updated_at` for change detection,
    /// plus a persisted-content fingerprint for the resource kinds whose
    /// serialized form carries no projection-derived state.
    /// Returns a delta describing exactly which resources were added,
    /// removed, or modified.
    pub fn compute(old: &GatewayConfig, new: &GatewayConfig) -> Self {
        let added_plugin_configs = diff_added(&old.plugin_configs, &new.plugin_configs);
        let removed_plugin_config_ids = diff_removed_ids(&old.plugin_configs, &new.plugin_configs);
        let modified_plugin_configs = diff_modified(&old.plugin_configs, &new.plugin_configs);
        let plugin_association_changed_proxy_ids =
            diff_plugin_association_changes(&old.proxies, &new.proxies);
        let old_global_plugin_keys: HashSet<ResourceKey<'_>> = old
            .plugin_configs
            .iter()
            .filter(|pc| pc.scope == PluginScope::Global)
            .map(resource_key)
            .collect();
        let global_plugin_configs_changed = added_plugin_configs
            .iter()
            .any(|pc| pc.scope == PluginScope::Global)
            || modified_plugin_configs.iter().any(|pc| {
                pc.scope == PluginScope::Global
                    || old_global_plugin_keys.contains(&resource_key(pc))
            })
            || removed_plugin_config_ids
                .iter()
                .any(|key| old_global_plugin_keys.contains(&key.as_key()));

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
            plugin_association_changed_proxy_ids,
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
            && self.plugin_association_changed_proxy_ids.is_empty()
            && !self.global_plugin_configs_changed
            && self.added_upstreams.is_empty()
            && self.removed_upstream_ids.is_empty()
            && self.modified_upstreams.is_empty()
    }

    /// Namespace-qualified keys of all proxies that need their plugin lists rebuilt.
    ///
    /// A proxy needs plugin rebuild if:
    /// - The proxy itself was added or modified (plugin associations may have changed)
    /// - Its plugin association membership changed without a proxy timestamp change
    /// - Any of its referenced plugin_configs were added, removed, or modified
    pub fn proxy_ids_needing_plugin_rebuild(
        &self,
        old_config: &GatewayConfig,
        new_config: &GatewayConfig,
    ) -> HashSet<NamespacedResourceId> {
        let mut ids = HashSet::new();

        // Added/modified proxies always need plugin rebuild
        for p in &self.added_proxies {
            ids.insert(namespaced_id_of(p));
        }
        for p in &self.modified_proxies {
            ids.insert(namespaced_id_of(p));
        }
        ids.extend(self.plugin_association_changed_proxy_ids.iter().cloned());

        // If any plugin config changed, find all proxies that reference it
        if !self.added_plugin_configs.is_empty()
            || !self.removed_plugin_config_ids.is_empty()
            || !self.modified_plugin_configs.is_empty()
        {
            let changed_pc_keys: HashSet<ResourceKey<'_>> = self
                .added_plugin_configs
                .iter()
                .map(resource_key)
                .chain(self.removed_plugin_config_ids.iter().map(|k| k.as_key()))
                .chain(self.modified_plugin_configs.iter().map(resource_key))
                .collect();

            // Include both the previous and replacement direct placements.
            // A modified PluginConfig contains only its new proxy_id, while a
            // cache entry can still be live on the former proxy. Proxy-scoped
            // plugin_config.proxy_id is an id within the plugin's namespace.
            let old_changed_proxy_scoped: HashSet<ResourceKey<'_>> = old_config
                .plugin_configs
                .iter()
                .filter(|pc| changed_pc_keys.contains(&resource_key(*pc)))
                .filter_map(|pc| {
                    pc.proxy_id
                        .as_deref()
                        .map(|proxy_id| (pc.namespace.as_str(), proxy_id))
                })
                .collect();
            let new_changed_proxy_scoped: HashSet<ResourceKey<'_>> = self
                .added_plugin_configs
                .iter()
                .chain(self.modified_plugin_configs.iter())
                .filter_map(|pc| {
                    pc.proxy_id
                        .as_deref()
                        .map(|proxy_id| (pc.namespace.as_str(), proxy_id))
                })
                .collect();
            let old_proxies_by_key: HashMap<ResourceKey<'_>, &Proxy> = old_config
                .proxies
                .iter()
                .map(|proxy| (resource_key(proxy), proxy))
                .collect();

            for proxy in &new_config.proxies {
                let proxy_key = resource_key(proxy);
                // Check both association generations. Scope/group moves can
                // remove the old association without advancing the proxy's
                // timestamp, but the old cached chain still needs rebuilding.
                // Association plugin_config_id values are namespace-local to
                // the proxy (cross-namespace associations are rejected).
                let references_changed_plugin =
                    proxy.plugins.iter().any(|assoc| {
                        changed_pc_keys
                            .contains(&(proxy.namespace.as_str(), assoc.plugin_config_id.as_str()))
                    }) || old_proxies_by_key.get(&proxy_key).is_some_and(|old_proxy| {
                        old_proxy.plugins.iter().any(|assoc| {
                            changed_pc_keys.contains(&(
                                old_proxy.namespace.as_str(),
                                assoc.plugin_config_id.as_str(),
                            ))
                        })
                    });
                if references_changed_plugin
                    || old_changed_proxy_scoped.contains(&proxy_key)
                    || new_changed_proxy_scoped.contains(&proxy_key)
                {
                    ids.insert(namespaced_id_of(proxy));
                }
            }

            if self.global_plugin_configs_changed || !self.removed_plugin_config_ids.is_empty() {
                // A global plugin change affects every merged proxy list. Any
                // plugin-config deletion also rebuilds every proxy because DB
                // cascade can remove association rows without updating proxy
                // timestamps, leaving no reliable proxy-level delta.
                for proxy in &new_config.proxies {
                    ids.insert(namespaced_id_of(proxy));
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

        let old_proxy_map: HashMap<ResourceKey<'_>, &Proxy> = old_config
            .proxies
            .iter()
            .map(|p| (resource_key(p), p))
            .collect();

        for key in &self.removed_proxy_ids {
            if let Some(p) = old_proxy_map.get(&key.as_key()) {
                record(&mut listen_paths, &mut host_only_hosts, p);
            }
        }

        for p in &self.modified_proxies {
            record(&mut listen_paths, &mut host_only_hosts, p);
            if let Some(old_proxy) = old_proxy_map.get(&resource_key(p)) {
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
// These work on any type with namespace + id + updated_at.

type ResourceKey<'a> = (&'a str, &'a str);

trait HasNamespacedIdAndTimestamp {
    fn namespace(&self) -> &str;
    fn id(&self) -> &str;
    fn updated_at(&self) -> DateTime<Utc>;

    /// Whether this resource's own persisted content differs from `other`,
    /// consulted only when both carry the same `updated_at`.
    ///
    /// # Scope of the fingerprint
    ///
    /// It covers the resource's own persisted row and nothing else. Projected
    /// and derived state is deliberately excluded: DestinationRule projections
    /// (`Upstream.port_overrides`, `dispatch_port_override_fallback`,
    /// `resolved_subset_tls`, the proxy-side `dispatch_port_overrides` /
    /// `resolved_tls` / `dispatch_kind`), service-discovery-resolved
    /// `Upstream.targets`, and junction-table `Proxy.plugins` membership all
    /// change without the owning row changing. Attributing them here would
    /// report a byte-identical proxy or upstream as a modified resource, and
    /// the incremental appliers would then rebuild from the authored snapshot
    /// — rolling live discovered targets back to static ones and undoing the
    /// targeted rebuild guarantees of #3243. Those dimensions keep their own
    /// detection paths: `ProxyState::projected_route_proxy_content_changed`,
    /// `ProxyState::projected_dr_dispatch_changed_upstreams`, and
    /// `diff_plugin_association_changes`.
    ///
    /// The default is "no content comparison", so a resource kind opts in only
    /// for the fields whose serialized form is entirely operator-owned:
    /// consumers, plugin configurations and stream-family proxies.
    fn persisted_content_changed(&self, _other: &Self) -> bool {
        false
    }
}

/// Compare two resources by serialized content with creation and modification
/// metadata neutralized, so timestamps alone never invalidate a cache.
///
/// A serialization failure counts as changed: a reload must never silently
/// retain revoked credentials or superseded policy because the comparison
/// itself could not be made.
fn timestamp_neutral_content_changed<T, F>(old: &T, new: &T, neutralize_timestamps: F) -> bool
where
    T: Clone + serde::Serialize,
    F: Fn(&mut T),
{
    let mut old_normalized = old.clone();
    let mut new_normalized = new.clone();
    neutralize_timestamps(&mut old_normalized);
    neutralize_timestamps(&mut new_normalized);
    let old_serialized = serde_json::to_value(&old_normalized);
    let new_serialized = serde_json::to_value(&new_normalized);
    match (old_serialized, new_serialized) {
        (Ok(old_value), Ok(new_value)) => old_value != new_value,
        _ => true,
    }
}

fn resource_key<T: HasNamespacedIdAndTimestamp>(resource: &T) -> ResourceKey<'_> {
    (resource.namespace(), resource.id())
}

fn namespaced_id_of<T: HasNamespacedIdAndTimestamp>(resource: &T) -> NamespacedResourceId {
    NamespacedResourceId::new(resource.namespace(), resource.id())
}

impl HasNamespacedIdAndTimestamp for Proxy {
    fn namespace(&self) -> &str {
        &self.namespace
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    /// Stream-family proxies compare their own persisted row; route-indexed
    /// proxies never do.
    ///
    /// A TCP/UDP/TLS-passthrough proxy has no other timestamp-neutral detection
    /// path: `ProxyState::projected_route_proxy_content_changed` filters stream
    /// proxies out, and `projected_mesh_stream_relay_dispatch_content_changed`
    /// only covers mesh stream-relay dispatch overrides. Without this
    /// fingerprint a re-pointed `backend_host` / `backend_port`, a moved
    /// `listen_port`, or a relaxed `backend_tls_verify_server_cert` under a
    /// reused `updated_at` would be classified as unchanged and the stream
    /// listeners would keep serving the superseded backend
    /// (GHSA-2wrj-vq9m-75jg).
    ///
    /// Route-indexed proxies keep returning `false`: their timestamp-neutral
    /// route content is already owned by
    /// `ProxyState::projected_route_proxy_content_changed`, and reporting it as
    /// a modified proxy row would drag the DestinationRule projections along
    /// with it. Those projections are `#[serde(skip)]` and so are excluded from
    /// the comparison by construction; junction-table `plugins` membership is
    /// cleared on both sides because it belongs to
    /// `diff_plugin_association_changes`.
    fn persisted_content_changed(&self, other: &Self) -> bool {
        if !self.dispatch_kind.is_stream() && !other.dispatch_kind.is_stream() {
            return false;
        }
        timestamp_neutral_content_changed(other, self, |proxy| {
            proxy.created_at = DateTime::<Utc>::UNIX_EPOCH;
            proxy.updated_at = DateTime::<Utc>::UNIX_EPOCH;
            proxy.plugins.clear();
        })
    }
}

impl HasNamespacedIdAndTimestamp for Consumer {
    fn namespace(&self) -> &str {
        &self.namespace
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    /// Every `Consumer` field is operator-owned persisted state, so a reused
    /// `updated_at` must not hide a rotated or revoked credential.
    fn persisted_content_changed(&self, other: &Self) -> bool {
        timestamp_neutral_content_changed(other, self, |consumer| {
            consumer.created_at = DateTime::<Utc>::UNIX_EPOCH;
            consumer.updated_at = DateTime::<Utc>::UNIX_EPOCH;
        })
    }
}

impl HasNamespacedIdAndTimestamp for PluginConfig {
    fn namespace(&self) -> &str {
        &self.namespace
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    /// Every `PluginConfig` field is operator-owned persisted state, so a
    /// reused `updated_at` must not hide a changed policy body or an
    /// `enabled` flip.
    fn persisted_content_changed(&self, other: &Self) -> bool {
        timestamp_neutral_content_changed(other, self, |plugin_config| {
            plugin_config.created_at = DateTime::<Utc>::UNIX_EPOCH;
            plugin_config.updated_at = DateTime::<Utc>::UNIX_EPOCH;
        })
    }
}

impl HasNamespacedIdAndTimestamp for Upstream {
    fn namespace(&self) -> &str {
        &self.namespace
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    // No persisted-content fingerprint: `targets` is resolved by service
    // discovery and `port_overrides` / `locality_lb_setting` /
    // `dispatch_port_override_fallback` / `resolved_subset_tls` are
    // DestinationRule projections. `projected_dr_dispatch_changed_upstreams`
    // rebuilds exactly the affected balancers instead.
}

/// Resources in `new` but not in `old`.
fn diff_added<T: HasNamespacedIdAndTimestamp + Clone>(old: &[T], new: &[T]) -> Vec<T> {
    let old_keys: HashSet<ResourceKey<'_>> = old.iter().map(resource_key).collect();
    new.iter()
        .filter(|r| !old_keys.contains(&resource_key(*r)))
        .cloned()
        .collect()
}

/// Namespace-qualified keys of resources in `old` but not in `new`.
fn diff_removed_ids<T: HasNamespacedIdAndTimestamp>(
    old: &[T],
    new: &[T],
) -> Vec<NamespacedResourceId> {
    let new_keys: HashSet<ResourceKey<'_>> = new.iter().map(resource_key).collect();
    old.iter()
        .filter(|r| !new_keys.contains(&resource_key(*r)))
        .map(namespaced_id_of)
        .collect()
}

/// Resources present in both whose `updated_at`, or whose own persisted
/// content under a reused `updated_at`, changed.
///
/// Uses `!=` instead of `>` for snapshot-to-snapshot comparison so a full
/// snapshot can detect backward timestamp drift once both versions are present
/// locally. Incremental SQL polling still depends on its `updated_at > cursor`
/// predicate to fetch candidates in the first place, so this is a defensive
/// diff guard rather than a substitute for monotonic database timestamps.
fn diff_modified<T: HasNamespacedIdAndTimestamp + Clone>(old: &[T], new: &[T]) -> Vec<T> {
    let old_map: HashMap<ResourceKey<'_>, &T> = old.iter().map(|r| (resource_key(r), r)).collect();
    new.iter()
        .filter(|new_resource| {
            let Some(old_resource) = old_map.get(&resource_key(*new_resource)) else {
                return false;
            };
            new_resource.updated_at() != old_resource.updated_at()
                || new_resource.persisted_content_changed(old_resource)
        })
        .cloned()
        .collect()
}

/// Existing proxies whose plugin association membership differs between the
/// accepted and candidate snapshots.
///
/// SQL stores these links in a junction table, so an association-only update or
/// cascade need not advance `Proxy.updated_at`. Association order is not part of
/// placement identity; plugin execution order comes from effective priorities.
fn diff_plugin_association_changes(old: &[Proxy], new: &[Proxy]) -> Vec<NamespacedResourceId> {
    let old_by_key: HashMap<ResourceKey<'_>, &Proxy> = old
        .iter()
        .map(|proxy| (resource_key(proxy), proxy))
        .collect();

    new.iter()
        .filter(|proxy| {
            old_by_key
                .get(&resource_key(*proxy))
                .is_some_and(|old_proxy| !same_plugin_associations(old_proxy, proxy))
        })
        .map(namespaced_id_of)
        .collect()
}

fn same_plugin_associations(left: &Proxy, right: &Proxy) -> bool {
    if left.plugins.len() != right.plugins.len() {
        return false;
    }
    let mut left_ids: Vec<&str> = left
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    let mut right_ids: Vec<&str> = right
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    left_ids.sort_unstable();
    right_ids.sort_unstable();
    left_ids == right_ids
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
        namespace: String,
        id: String,
        updated_at: DateTime<Utc>,
    }

    impl HasNamespacedIdAndTimestamp for TestResource {
        fn namespace(&self) -> &str {
            &self.namespace
        }

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
            quarantined_plugin_configs: Vec::new(),
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
            frontend_tls_certificate_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
            http_tls_listen_ports: Default::default(),
            mesh_revision: None,
            node_waypoint_udp_steer_destinations: Vec::new(),
            node_waypoint_udp_destination_routes: Vec::new(),
            k8s_mesh_overlay: Default::default(),
            gateway_trust_bundles: Vec::new(),
        }
    }

    fn proxy(
        id: &str,
        listen_path: Option<&str>,
        hosts: &[&str],
        plugin_ids: &[&str],
        updated_at: DateTime<Utc>,
    ) -> Proxy {
        proxy_in_namespace(
            default_namespace().as_str(),
            id,
            listen_path,
            hosts,
            plugin_ids,
            updated_at,
        )
    }

    fn proxy_in_namespace(
        namespace: &str,
        id: &str,
        listen_path: Option<&str>,
        hosts: &[&str],
        plugin_ids: &[&str],
        updated_at: DateTime<Utc>,
    ) -> Proxy {
        let mut proxy: Proxy = serde_json::from_value(json!({
            "id": id,
            "namespace": namespace,
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
            trigger: None,
            api_spec_id: None,
            created_at: updated_at,
            updated_at,
        }
    }

    fn consumer(namespace: &str, id: &str, updated_at: DateTime<Utc>) -> Consumer {
        Consumer {
            id: id.to_string(),
            namespace: namespace.to_string(),
            username: format!("{namespace}-{id}"),
            custom_id: None,
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: updated_at,
            updated_at,
        }
    }

    #[test]
    fn diff_modified_treats_backward_timestamp_drift_as_change() {
        let old = vec![TestResource {
            namespace: default_namespace(),
            id: "r1".to_string(),
            updated_at: ts(20),
        }];
        let new = vec![TestResource {
            namespace: default_namespace(),
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
        assert_eq!(
            delta.removed_proxy_ids,
            vec![NamespacedResourceId::new(default_namespace(), "removed")]
        );
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
    fn compute_keys_resources_by_namespace_and_id() {
        let mut old = config(
            vec![
                proxy_in_namespace("prod", "p1", Some("/prod"), &[], &[], ts(10)),
                proxy_in_namespace("staging", "p1", Some("/staging"), &[], &[], ts(10)),
            ],
            vec![],
        );
        old.consumers = vec![
            consumer("prod", "c1", ts(10)),
            consumer("staging", "c1", ts(10)),
        ];
        let mut new = config(
            vec![
                proxy_in_namespace("prod", "p1", Some("/prod"), &[], &[], ts(10)),
                proxy_in_namespace("staging", "p1", Some("/staging"), &[], &[], ts(11)),
            ],
            vec![],
        );
        new.consumers = vec![
            consumer("prod", "c1", ts(10)),
            consumer("staging", "c1", ts(11)),
        ];

        let modified = ConfigDelta::compute(&old, &new);
        assert_eq!(modified.modified_proxies.len(), 1);
        assert_eq!(modified.modified_proxies[0].namespace, "staging");
        assert_eq!(modified.modified_consumers.len(), 1);
        assert_eq!(modified.modified_consumers[0].namespace, "staging");

        new.proxies.retain(|proxy| proxy.namespace == "prod");
        new.consumers
            .retain(|consumer| consumer.namespace == "prod");
        let removed = ConfigDelta::compute(&old, &new);
        assert_eq!(
            removed.removed_proxy_ids,
            vec![NamespacedResourceId::new("staging", "p1")]
        );
        assert_eq!(
            removed.removed_consumer_ids,
            vec![NamespacedResourceId::new("staging", "c1")]
        );
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
        let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);

        assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
        assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p3")));
        assert!(!ids.contains(&NamespacedResourceId::new(default_namespace(), "p2")));
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
        let ids = delta.proxy_ids_needing_plugin_rebuild(&old, &new);

        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p1")));
        assert!(ids.contains(&NamespacedResourceId::new(default_namespace(), "p2")));
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

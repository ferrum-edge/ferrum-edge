//! Atomic request-facing runtime snapshot.
//!
//! Request paths load one `RequestEpoch` and use its route table, plugin cache,
//! consumer index, and load-balancer snapshot together. Writers build staged
//! inners before publishing, then swap the whole epoch with one ArcSwap store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::config::types::{GatewayConfig, Proxy};
use crate::consumer_index::ConsumerIndex;
use crate::consumer_index::ConsumerIndexInner;
use crate::load_balancer::LoadBalancerCache;
use crate::load_balancer::LoadBalancerCacheInner;
use crate::plugin_cache::PluginCache;
use crate::plugin_cache::PluginCacheInner;
use crate::router_cache::HostRouteTable;
use crate::router_cache::RouterCache;

#[derive(Clone)]
pub struct RequestEpoch {
    pub(crate) config: Arc<GatewayConfig>,
    pub(crate) proxy_index_by_id: Arc<HashMap<String, usize>>,
    pub(crate) route_table: Arc<HostRouteTable>,
    pub(crate) plugin_cache: Arc<PluginCacheInner>,
    pub(crate) consumer_index: Arc<ConsumerIndexInner>,
    pub(crate) load_balancer: Arc<LoadBalancerCacheInner>,
    pub(crate) config_generation: u64,
    pub(crate) route_generation: u64,
    pub(crate) lb_generation: u64,
}

impl RequestEpoch {
    pub(crate) fn proxy_by_id(&self, id: &str) -> Option<&Proxy> {
        self.proxy_index_by_id
            .get(id)
            .and_then(|idx| self.config.proxies.get(*idx))
            .filter(|proxy| proxy.id == id)
    }
}

pub(crate) fn build_proxy_index_by_id(config: &GatewayConfig) -> Arc<HashMap<String, usize>> {
    Arc::new(
        config
            .proxies
            .iter()
            .enumerate()
            .map(|(idx, proxy)| (proxy.id.clone(), idx))
            .collect(),
    )
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, DispatchKind, LoadBalancerAlgorithm, PluginAssociation,
        PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget, default_namespace,
    };
    use crate::plugins::{PluginHttpClient, ProxyProtocol};
    use chrono::Utc;
    use serde_json::{Map, Value, json};
    use std::cell::Cell;
    use std::collections::HashMap;

    fn proxy(id: &str, path: &str, plugins: Vec<&str>) -> Proxy {
        Proxy {
            id: id.to_string(),
            namespace: default_namespace(),
            name: Some(id.to_string()),
            hosts: vec![],
            listen_path: Some(path.to_string()),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "backend.local".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5000,
            backend_read_timeout_ms: 30000,
            backend_write_timeout_ms: 30000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: Default::default(),
            dispatch_port_overrides: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: plugins
                .into_iter()
                .map(|id| PluginAssociation {
                    plugin_config_id: id.to_string(),
                })
                .collect(),
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            pool_max_requests_per_connection: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: Default::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn target(host: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: host.to_string(),
            port,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }
    }

    fn upstream(id: &str, targets: Vec<UpstreamTarget>) -> Upstream {
        Upstream {
            id: id.to_string(),
            name: Some(id.to_string()),
            namespace: default_namespace(),
            targets,
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: std::collections::HashMap::new(),
            source_locality: None,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: std::collections::HashMap::new(),
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn config(
        proxies: Vec<Proxy>,
        plugin_configs: Vec<PluginConfig>,
        upstreams: Vec<Upstream>,
    ) -> GatewayConfig {
        GatewayConfig {
            version: "1".to_string(),
            proxies,
            consumers: vec![],
            plugin_configs,
            upstreams,
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            trust_bundles: None,
            mesh: None,
        }
    }

    fn plugin_config(id: &str, plugin_name: &str, config: Value) -> PluginConfig {
        PluginConfig {
            id: id.to_string(),
            namespace: default_namespace(),
            plugin_name: plugin_name.to_string(),
            config,
            enabled: true,
            scope: PluginScope::ProxyGroup,
            proxy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            priority_override: None,
            api_spec_id: None,
        }
    }

    fn epoch_store(config: GatewayConfig) -> RequestEpochStore {
        let plugin_cache = PluginCache::new(&config).unwrap_or_else(|e| panic!("{e}"));
        let consumer_index = ConsumerIndex::new(&config.consumers);
        let lb_cache = LoadBalancerCache::new(&config);
        RequestEpochStore::from_runtime_parts(config, &plugin_cache, &consumer_index, &lb_cache)
    }

    #[test]
    fn plugin_validation_failure_leaves_old_epoch_intact() {
        let old = config(vec![proxy("old", "/old", vec![])], vec![], vec![]);
        let store = epoch_store(old);
        let before = store.load();
        let invalid_auth = plugin_config("auth", "jwks_auth", json!({}));
        let new_config = config(
            vec![
                proxy("old", "/old", vec![]),
                proxy("secure", "/secure", vec!["auth"]),
            ],
            vec![invalid_auth],
            vec![],
        );

        let result = store.update_config(
            |current| {
                let plugin_inner =
                    PluginCache::build_inner(&new_config, &PluginHttpClient::default())?;
                Ok(Some(StagedRequestEpoch {
                    config: Arc::new(new_config.clone()),
                    route_table: RouterCache::build_route_table_snapshot(&new_config),
                    plugin_cache: plugin_inner,
                    consumer_index: Arc::clone(&current.consumer_index),
                    load_balancer: Arc::clone(&current.load_balancer),
                    route_changed: true,
                    lb_changed: false,
                }))
            },
            |_| {},
        );

        assert!(result.is_err());
        let after = store.load();
        assert_eq!(after.config_generation, before.config_generation);
        assert_eq!(after.route_generation, before.route_generation);
        assert_eq!(after.config.proxies.len(), 1);
        assert_eq!(after.config.proxies[0].id, "old");
    }

    #[test]
    fn adding_auth_route_publishes_route_and_auth_plugins_together() {
        let old = config(vec![proxy("public", "/public", vec![])], vec![], vec![]);
        let store = epoch_store(old);
        let key_auth = plugin_config("auth", "key_auth", json!({}));
        let new_config = config(
            vec![
                proxy("public", "/public", vec![]),
                proxy("secure", "/secure", vec!["auth"]),
            ],
            vec![key_auth],
            vec![],
        );

        store
            .update_config(
                |current| {
                    let plugin_inner =
                        PluginCache::build_inner(&new_config, &PluginHttpClient::default())?;
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::new(new_config.clone()),
                        route_table: RouterCache::build_route_table_snapshot(&new_config),
                        plugin_cache: plugin_inner,
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: Arc::clone(&current.load_balancer),
                        route_changed: true,
                        lb_changed: false,
                    }))
                },
                |_| {},
            )
            .unwrap_or_else(|e| panic!("{e}"));

        let after = store.load();
        let cache = RouterCache::new(&after.config, 100);
        let matched = cache
            .find_proxy_in_snapshot(&after.route_table, after.route_generation, None, "/secure")
            .unwrap_or_else(|| panic!("secure route should be visible"));
        assert_eq!(matched.proxy.id, "secure");

        let plugin_view = after
            .plugin_cache
            .request_view("secure", ProxyProtocol::Http);
        assert_eq!(plugin_view.auth_plugins().len(), 1);
    }

    #[test]
    fn route_cache_entries_do_not_cross_route_generation() {
        let old = config(vec![proxy("old", "/old", vec![])], vec![], vec![]);
        let cache = RouterCache::new(&old, 100);
        let old_table = RouterCache::build_route_table_snapshot(&old);
        assert!(
            cache
                .find_proxy_in_snapshot(&old_table, 1, None, "/old")
                .is_some()
        );

        let new = config(vec![proxy("new", "/new", vec![])], vec![], vec![]);
        let new_table = RouterCache::build_route_table_snapshot(&new);
        assert!(
            cache
                .find_proxy_in_snapshot(&new_table, 2, None, "/old")
                .is_none()
        );
        assert!(
            cache
                .find_proxy_in_snapshot(&new_table, 2, None, "/new")
                .is_some()
        );
    }

    #[test]
    fn proxy_by_id_index_tracks_published_config_snapshots() {
        let initial = config(vec![proxy("p1", "/one", vec![])], vec![], vec![]);
        let store = epoch_store(initial);
        let before = store.load();
        assert_eq!(
            before
                .proxy_by_id("p1")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/one"))
        );
        assert!(before.proxy_by_id("p2").is_none());

        let next_config = config(
            vec![
                proxy("p1", "/one-renamed", vec![]),
                proxy("p2", "/two", vec![]),
            ],
            vec![],
            vec![],
        );
        store
            .update_config(
                |current| {
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::new(next_config.clone()),
                        route_table: RouterCache::build_route_table_snapshot(&next_config),
                        plugin_cache: Arc::clone(&current.plugin_cache),
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: Arc::clone(&current.load_balancer),
                        route_changed: true,
                        lb_changed: false,
                    }))
                },
                |_| {},
            )
            .unwrap_or_else(|e| panic!("{e}"));

        let after_config_update = store.load();
        assert_eq!(
            after_config_update
                .proxy_by_id("p1")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/one-renamed"))
        );
        assert_eq!(
            after_config_update
                .proxy_by_id("p2")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/two"))
        );

        store.update_load_balancer(|current| Some(Arc::clone(&current.load_balancer)), |_| {});
        let after_lb_update = store.load();
        assert_eq!(
            after_lb_update
                .proxy_by_id("p2")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/two"))
        );
    }

    #[test]
    fn lb_state_for_unchanged_upstream_is_preserved() {
        let old = config(
            vec![proxy("p1", "/one", vec![])],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );
        let current = LoadBalancerCache::build_inner(&old);
        let old_balancer = current.get_balancer("u1").unwrap();
        let new = config(
            vec![proxy("p2", "/two", vec![])],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );

        let next = LoadBalancerCache::build_delta_inner(&current, &new, &[], &[], &[]);
        let next_balancer = next.get_balancer("u1").unwrap();
        assert!(Arc::ptr_eq(&old_balancer, &next_balancer));
    }

    #[test]
    fn lb_only_epoch_updates_do_not_lose_other_upstream_updates() {
        let initial = config(
            vec![],
            vec![],
            vec![
                upstream("u1", vec![target("a.local", 80)]),
                upstream("u2", vec![target("b.local", 80)]),
            ],
        );
        let store = epoch_store(initial);

        store.update_load_balancer(
            |current| {
                Some(LoadBalancerCache::build_update_targets_inner(
                    &current.load_balancer,
                    "u1",
                    vec![target("a2.local", 81)],
                    LoadBalancerAlgorithm::RoundRobin,
                    None,
                ))
            },
            |_| {},
        );
        store.update_load_balancer(
            |current| {
                Some(LoadBalancerCache::build_update_targets_inner(
                    &current.load_balancer,
                    "u2",
                    vec![target("b2.local", 82)],
                    LoadBalancerAlgorithm::RoundRobin,
                    None,
                ))
            },
            |_| {},
        );

        let final_epoch = store.load();
        assert_eq!(
            final_epoch.load_balancer.upstreams()["u1"].targets[0].host,
            "a2.local"
        );
        assert_eq!(
            final_epoch.load_balancer.upstreams()["u2"].targets[0].host,
            "b2.local"
        );
        assert_eq!(final_epoch.route_generation, 1);
        assert_eq!(final_epoch.lb_generation, 3);
    }

    #[test]
    fn consumer_snapshot_facade_uses_expected_generation() {
        let mut credentials = HashMap::new();
        let mut keyauth = Map::new();
        keyauth.insert("key".to_string(), Value::String("secret-key".to_string()));
        credentials.insert(
            "keyauth".to_string(),
            Value::Array(vec![Value::Object(keyauth)]),
        );
        let consumer = crate::config::types::Consumer {
            id: "c1".to_string(),
            namespace: default_namespace(),
            username: "alice".to_string(),
            custom_id: Some("alice-custom".to_string()),
            credentials,
            acl_groups: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let inner = ConsumerIndex::build_inner(&[consumer]);
        let view = ConsumerIndex::from_inner(inner);
        assert_eq!(
            view.find_by_api_key("secret-key")
                .as_ref()
                .map(|c| c.username.as_str()),
            Some("alice")
        );
        assert_eq!(
            view.find_by_identity("alice-custom")
                .as_ref()
                .map(|c| c.id.as_str()),
            Some("c1")
        );
    }

    #[test]
    fn update_config_none_is_noop_and_skips_mirror() {
        let initial = config(vec![proxy("p1", "/one", vec![])], vec![], vec![]);
        let store = epoch_store(initial);
        let before = store.load();
        let mirror_called = Cell::new(false);

        let result = store
            .update_config(|_| Ok(None), |_| mirror_called.set(true))
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(result.is_none());
        assert!(!mirror_called.get());
        let after = store.load();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.config_generation, before.config_generation);
        assert_eq!(after.route_generation, before.route_generation);
        assert_eq!(after.lb_generation, before.lb_generation);
    }

    #[test]
    fn update_config_generation_flags_are_independent_and_mirror_sees_published_epoch() {
        let initial = config(vec![proxy("p1", "/one", vec![])], vec![], vec![]);
        let store = epoch_store(initial);
        let observed_generations = Cell::new((0, 0, 0));

        let next = store
            .update_config(
                |current| {
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::clone(&current.config),
                        route_table: Arc::clone(&current.route_table),
                        plugin_cache: Arc::clone(&current.plugin_cache),
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: Arc::clone(&current.load_balancer),
                        route_changed: false,
                        lb_changed: true,
                    }))
                },
                |published| {
                    observed_generations.set((
                        published.config_generation,
                        published.route_generation,
                        published.lb_generation,
                    ));
                },
            )
            .unwrap_or_else(|e| panic!("{e}"))
            .expect("config update should publish");

        assert_eq!(next.config_generation, 2);
        assert_eq!(next.route_generation, 1);
        assert_eq!(next.lb_generation, 2);
        assert_eq!(observed_generations.get(), (2, 1, 2));
        assert!(Arc::ptr_eq(&next, &store.load()));
    }

    #[test]
    fn update_load_balancer_none_is_noop_and_skips_mirror() {
        let initial = config(
            vec![],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );
        let store = epoch_store(initial);
        let before = store.load();
        let mirror_called = Cell::new(false);

        let result = store.update_load_balancer(|_| None, |_| mirror_called.set(true));

        assert!(result.is_none());
        assert!(!mirror_called.get());
        let after = store.load();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.config_generation, before.config_generation);
        assert_eq!(after.route_generation, before.route_generation);
        assert_eq!(after.lb_generation, before.lb_generation);
    }

    #[test]
    fn update_load_balancer_preserves_config_generations_and_mirrors_published_epoch() {
        let initial = config(
            vec![],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );
        let store = epoch_store(initial);
        let observed_generations = Cell::new((0, 0, 0));

        let next = store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "u1",
                        vec![target("b.local", 81)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |published| {
                    observed_generations.set((
                        published.config_generation,
                        published.route_generation,
                        published.lb_generation,
                    ));
                },
            )
            .expect("lb update should publish");

        assert_eq!(next.config_generation, 1);
        assert_eq!(next.route_generation, 1);
        assert_eq!(next.lb_generation, 2);
        assert_eq!(observed_generations.get(), (1, 1, 2));
        assert_eq!(
            next.load_balancer.upstreams()["u1"].targets[0].host,
            "b.local"
        );
        assert!(Arc::ptr_eq(&next, &store.load()));
    }
}

pub(crate) struct StagedRequestEpoch {
    pub config: Arc<GatewayConfig>,
    pub route_table: Arc<HostRouteTable>,
    pub plugin_cache: Arc<PluginCacheInner>,
    pub consumer_index: Arc<ConsumerIndexInner>,
    pub load_balancer: Arc<LoadBalancerCacheInner>,
    pub route_changed: bool,
    pub lb_changed: bool,
}

pub struct RequestEpochStore {
    current: ArcSwap<RequestEpoch>,
    write_lock: Mutex<()>,
}

impl RequestEpochStore {
    pub fn new(initial: RequestEpoch) -> Self {
        Self {
            current: ArcSwap::new(Arc::new(initial)),
            write_lock: Mutex::new(()),
        }
    }

    pub fn from_runtime_parts(
        config: GatewayConfig,
        plugin_cache: &PluginCache,
        consumer_index: &ConsumerIndex,
        load_balancer_cache: &LoadBalancerCache,
    ) -> Self {
        Self::new(RequestEpoch {
            route_table: RouterCache::build_route_table_snapshot(&config),
            plugin_cache: plugin_cache.load_inner(),
            consumer_index: consumer_index.load_inner(),
            load_balancer: load_balancer_cache.load_inner(),
            proxy_index_by_id: build_proxy_index_by_id(&config),
            config: Arc::new(config),
            config_generation: 1,
            route_generation: 1,
            lb_generation: 1,
        })
    }

    #[inline]
    pub fn load(&self) -> Arc<RequestEpoch> {
        self.current.load_full()
    }

    pub(crate) fn update_config(
        &self,
        build: impl FnOnce(&RequestEpoch) -> Result<Option<StagedRequestEpoch>, String>,
        mirror: impl FnOnce(&RequestEpoch),
    ) -> Result<Option<Arc<RequestEpoch>>, String> {
        // Poison only means a previous writer panicked before publishing; the
        // ArcSwap still holds the last complete epoch, so continuing is safe.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.current.load_full();
        let Some(staged) = build(&current)? else {
            return Ok(None);
        };

        let proxy_index_by_id = build_proxy_index_by_id(&staged.config);
        let next = Arc::new(RequestEpoch {
            config: staged.config,
            proxy_index_by_id,
            route_table: staged.route_table,
            plugin_cache: staged.plugin_cache,
            consumer_index: staged.consumer_index,
            load_balancer: staged.load_balancer,
            config_generation: current.config_generation.saturating_add(1),
            route_generation: if staged.route_changed {
                current.route_generation.saturating_add(1)
            } else {
                current.route_generation
            },
            lb_generation: if staged.lb_changed {
                current.lb_generation.saturating_add(1)
            } else {
                current.lb_generation
            },
        });
        self.current.store(Arc::clone(&next));
        // Compatibility wrapper caches are mirrored while the epoch writer lock
        // is still held so service discovery and config reloads cannot publish
        // newer epochs and then be overwritten by an older post-lock mirror.
        mirror(&next);
        Ok(Some(next))
    }

    pub(crate) fn update_load_balancer(
        &self,
        build: impl FnOnce(&RequestEpoch) -> Option<Arc<LoadBalancerCacheInner>>,
        mirror: impl FnOnce(&RequestEpoch),
    ) -> Option<Arc<RequestEpoch>> {
        // Poison only means a previous writer panicked before publishing; the
        // ArcSwap still holds the last complete epoch, so continuing is safe.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.current.load_full();
        let load_balancer = build(&current)?;
        let next = Arc::new(RequestEpoch {
            config: Arc::clone(&current.config),
            proxy_index_by_id: Arc::clone(&current.proxy_index_by_id),
            route_table: Arc::clone(&current.route_table),
            plugin_cache: Arc::clone(&current.plugin_cache),
            consumer_index: Arc::clone(&current.consumer_index),
            load_balancer,
            config_generation: current.config_generation,
            route_generation: current.route_generation,
            lb_generation: current.lb_generation.saturating_add(1),
        });
        self.current.store(Arc::clone(&next));
        // Keep LB wrapper mirroring serialized with the epoch publication.
        mirror(&next);
        Some(next)
    }
}

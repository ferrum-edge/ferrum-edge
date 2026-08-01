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

thread_local! {
    /// Reusable scratch buffer for `namespace|proxy_id` runtime keys used by
    /// [`RequestEpoch::proxy_by_namespaced_id`].
    ///
    /// The borrow is strictly synchronous inside the lookup helper, is never
    /// held across an `await`, and never re-enters: the returned reference
    /// borrows the epoch's config, not this buffer. This keeps stream/request
    /// proxy resolution allocation-free in steady state.
    static PROXY_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
}

#[derive(Clone)]
pub struct RequestEpoch {
    pub(crate) config: Arc<GatewayConfig>,
    /// `namespace|id` -> index into `config.proxies`.
    ///
    /// Proxy IDs are unique only *within* a namespace, so this index must stay
    /// keyed by the full `(namespace, id)` identity. A bare-ID index silently
    /// drops one of two same-ID proxies and lets stream/SNI traffic resolve the
    /// other tenant's proxy (issue #3094).
    pub(crate) proxy_index_by_key: Arc<HashMap<String, usize>>,
    pub(crate) route_table: Arc<HostRouteTable>,
    pub(crate) plugin_cache: Arc<PluginCacheInner>,
    pub(crate) consumer_index: Arc<ConsumerIndexInner>,
    pub(crate) load_balancer: Arc<LoadBalancerCacheInner>,
    pub(crate) config_generation: u64,
    pub(crate) route_generation: u64,
    pub(crate) lb_generation: u64,
}

impl RequestEpoch {
    /// Namespace-qualified proxy lookup.
    ///
    /// This is the only proxy-by-identity accessor: every runtime caller must
    /// know which namespace owns the proxy it is resolving. The returned
    /// reference borrows the published config snapshot, so the thread-local
    /// scratch borrow is released before the caller sees the result.
    pub(crate) fn proxy_by_namespaced_id(&self, namespace: &str, id: &str) -> Option<&Proxy> {
        let index = PROXY_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            crate::config::db_backend::write_namespaced_runtime_key(&mut key, namespace, id);
            self.proxy_index_by_key.get(key.as_str()).copied()
        })?;
        self.config
            .proxies
            .get(index)
            .filter(|proxy| proxy.id == id && proxy.namespace == namespace)
    }
}

pub(crate) fn build_proxy_index_by_key(config: &GatewayConfig) -> Arc<HashMap<String, usize>> {
    Arc::new(
        config
            .proxies
            .iter()
            .enumerate()
            .map(|(idx, proxy)| {
                (
                    crate::config::db_backend::namespaced_runtime_key(&proxy.namespace, &proxy.id),
                    idx,
                )
            })
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
    use crate::plugins::{
        BackendAdmissionContext, BackendAdmissionDecision, PluginHttpClient, PluginResult,
        ProxyProtocol, RequestContext,
    };
    use chrono::Utc;
    use serde_json::{Map, Value, json};
    use std::cell::Cell;
    use std::collections::HashMap;

    /// Namespace-qualified runtime key (`ferrum|id`) for load-balancer lookups.
    fn rk(id: &str) -> String {
        crate::config::db_backend::namespaced_runtime_key("ferrum", id)
    }

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
            dispatch_port_override_fallback: None,
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
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
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
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn target(host: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: host.to_string(),
            port,
            service_port_policy_key: None,
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
            locality_lb_strict: false,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: std::collections::HashMap::new(),
            dispatch_port_override_fallback: None,
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
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_namespace_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
            mesh_revision: None,
            k8s_mesh_overlay: Default::default(),
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

    fn epoch_store_with_lb_generation(
        config: GatewayConfig,
        lb_generation: u64,
    ) -> RequestEpochStore {
        let store = epoch_store(config);
        let current = store.load();
        RequestEpochStore::new(RequestEpoch {
            config: Arc::clone(&current.config),
            proxy_index_by_key: Arc::clone(&current.proxy_index_by_key),
            route_table: Arc::clone(&current.route_table),
            plugin_cache: Arc::clone(&current.plugin_cache),
            consumer_index: Arc::clone(&current.consumer_index),
            load_balancer: Arc::clone(&current.load_balancer),
            config_generation: current.config_generation,
            route_generation: current.route_generation,
            lb_generation,
        })
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

    #[tokio::test]
    async fn fault_overlay_publication_keeps_in_flight_request_epoch_coherent() {
        use crate::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
        use crate::plugins::Plugin;
        use crate::plugins::fault_injection::runtime_overlay::{
            FaultOverlayMaterialization, materialize_config,
        };

        async fn execute_before_proxy_chain(plugins: Arc<Vec<Arc<dyn Plugin>>>) -> PluginResult {
            let mut ctx = RequestContext::new(
                "192.0.2.10".to_string(),
                "GET".to_string(),
                "/checkout".to_string(),
            );
            let mut headers = HashMap::new();
            for plugin in plugins.iter() {
                match plugin.before_proxy(&mut ctx, &mut headers).await {
                    PluginResult::Continue => {}
                    terminal => return terminal,
                }
            }
            PluginResult::Continue
        }

        let static_fault = || {
            plugin_config(
                "fault",
                "fault_injection",
                json!({
                    "abort": {"status_code": 503, "percentage": 50.0},
                    "runtime_overlay_scope": "checkout"
                }),
            )
        };
        let overlay = |percentage| MeshRuntimeOverlay {
            fields: HashMap::from([(
                "ferrum.fault_injection.checkout.abort_percent".to_string(),
                RuntimeValue::Number(percentage),
            )]),
        };

        let mut fault_a = static_fault();
        assert_eq!(
            materialize_config(&mut fault_a.config, &overlay(100.0)),
            FaultOverlayMaterialization::Changed
        );
        let config_a = config(
            vec![proxy("checkout", "/checkout", vec!["fault"])],
            vec![fault_a],
            vec![],
        );
        let store = epoch_store(config_a);
        let epoch_a = store.load();
        let plugins_a = epoch_a
            .plugin_cache
            .request_view("ferrum", "checkout", ProxyProtocol::Http)
            .plugins();

        let mut fault_b = static_fault();
        assert_eq!(
            materialize_config(&mut fault_b.config, &overlay(0.0)),
            FaultOverlayMaterialization::Disabled
        );
        fault_b.enabled = false;
        let config_b = config(
            vec![proxy("checkout", "/checkout", vec!["fault"])],
            vec![fault_b],
            vec![],
        );
        store
            .update_config(
                |current| {
                    let plugin_cache =
                        PluginCache::build_inner(&config_b, &PluginHttpClient::default())?;
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::new(config_b.clone()),
                        route_table: RouterCache::build_route_table_snapshot(&config_b),
                        plugin_cache,
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: Arc::clone(&current.load_balancer),
                        route_changed: false,
                        lb_changed: false,
                    }))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("generation B should publish: {error}"))
            .expect("generation B should publish");

        let epoch_b = store.load();
        let plugins_b = epoch_b
            .plugin_cache
            .request_view("ferrum", "checkout", ProxyProtocol::Http)
            .plugins();
        assert!(!Arc::ptr_eq(&epoch_a, &epoch_b));
        assert!(matches!(
            execute_before_proxy_chain(Arc::clone(&plugins_a)).await,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ));
        assert!(matches!(
            execute_before_proxy_chain(Arc::clone(&plugins_b)).await,
            PluginResult::Continue
        ));

        let invalid_config = config(
            vec![proxy("checkout", "/checkout", vec!["fault"])],
            vec![plugin_config(
                "fault",
                "fault_injection",
                json!({"runtime_overlay_scope": "checkout"}),
            )],
            vec![],
        );
        let rejection = store.update_config(
            |current| {
                let plugin_cache =
                    PluginCache::build_inner(&invalid_config, &PluginHttpClient::default())?;
                Ok(Some(StagedRequestEpoch {
                    config: Arc::new(invalid_config.clone()),
                    route_table: RouterCache::build_route_table_snapshot(&invalid_config),
                    plugin_cache,
                    consumer_index: Arc::clone(&current.consumer_index),
                    load_balancer: Arc::clone(&current.load_balancer),
                    route_changed: false,
                    lb_changed: false,
                }))
            },
            |_| {},
        );
        assert!(rejection.is_err());
        assert!(Arc::ptr_eq(&epoch_b, &store.load()));
        assert!(matches!(
            execute_before_proxy_chain(plugins_a).await,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ));
        assert!(matches!(
            execute_before_proxy_chain(plugins_b).await,
            PluginResult::Continue
        ));
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
            .request_view("ferrum", "secure", ProxyProtocol::Http);
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
    fn proxy_index_resolves_same_id_in_two_namespaces_independently() {
        let mut tenant_a = proxy("shared", "/a", vec![]);
        tenant_a.namespace = "tenant-a".to_string();
        let mut tenant_b = proxy("shared", "/b", vec![]);
        tenant_b.namespace = "tenant-b".to_string();
        let store = epoch_store(config(
            vec![tenant_a.clone(), tenant_b.clone()],
            vec![],
            vec![],
        ));

        let epoch = store.load();
        assert_eq!(
            epoch
                .proxy_by_namespaced_id("tenant-a", "shared")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/a"))
        );
        assert_eq!(
            epoch
                .proxy_by_namespaced_id("tenant-b", "shared")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/b"))
        );
        assert!(epoch.proxy_by_namespaced_id("ferrum", "shared").is_none());

        // Removing tenant-a's proxy must not let a tenant-a lookup fall through
        // to tenant-b's same-ID proxy.
        let remaining = config(vec![tenant_b], vec![], vec![]);
        store
            .update_config(
                |current| {
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::new(remaining.clone()),
                        route_table: RouterCache::build_route_table_snapshot(&remaining),
                        plugin_cache: Arc::clone(&current.plugin_cache),
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: Arc::clone(&current.load_balancer),
                        route_changed: true,
                        lb_changed: false,
                    }))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("removal should publish: {error}"));

        let after = store.load();
        assert!(after.proxy_by_namespaced_id("tenant-a", "shared").is_none());
        assert_eq!(
            after
                .proxy_by_namespaced_id("tenant-b", "shared")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/b"))
        );
    }

    #[test]
    fn proxy_by_id_index_tracks_published_config_snapshots() {
        let initial = config(vec![proxy("p1", "/one", vec![])], vec![], vec![]);
        let store = epoch_store(initial);
        let before = store.load();
        assert_eq!(
            before
                .proxy_by_namespaced_id("ferrum", "p1")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/one"))
        );
        assert!(before.proxy_by_namespaced_id("ferrum", "p2").is_none());

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
                .proxy_by_namespaced_id("ferrum", "p1")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/one-renamed"))
        );
        assert_eq!(
            after_config_update
                .proxy_by_namespaced_id("ferrum", "p2")
                .map(|proxy| proxy.listen_path.as_deref()),
            Some(Some("/two"))
        );

        store
            .update_load_balancer(|current| Some(Arc::clone(&current.load_balancer)), |_| {})
            .unwrap_or_else(|error| panic!("LB update should succeed: {error}"))
            .expect("LB update should publish");
        let after_lb_update = store.load();
        assert_eq!(
            after_lb_update
                .proxy_by_namespaced_id("ferrum", "p2")
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
        let old_balancer = current.get_balancer("ferrum", "u1").unwrap();
        let new = config(
            vec![proxy("p2", "/two", vec![])],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );

        let next = LoadBalancerCache::build_delta_inner(&current, &new, &[], &[], &[]);
        let next_balancer = next.get_balancer("ferrum", "u1").unwrap();
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

        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u1",
                        vec![target("a2.local", 81)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("first LB update should succeed: {error}"))
            .expect("first LB update should publish");
        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u2",
                        vec![target("b2.local", 82)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("second LB update should succeed: {error}"))
            .expect("second LB update should publish");

        let final_epoch = store.load();
        assert_eq!(
            final_epoch.load_balancer.upstreams()[&rk("u1")].targets[0].host,
            "a2.local"
        );
        assert_eq!(
            final_epoch.load_balancer.upstreams()[&rk("u2")].targets[0].host,
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

        let result = store
            .update_load_balancer(|_| None, |_| mirror_called.set(true))
            .unwrap_or_else(|error| panic!("no-op LB update should succeed: {error}"));

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
                        "ferrum",
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
            .unwrap_or_else(|error| panic!("LB update should succeed: {error}"))
            .expect("lb update should publish");

        assert_eq!(next.config_generation, 1);
        assert_eq!(next.route_generation, 1);
        assert_eq!(next.lb_generation, 2);
        assert_eq!(observed_generations.get(), (1, 1, 2));
        assert_eq!(
            next.load_balancer.upstreams()[&rk("u1")].targets[0].host,
            "b.local"
        );
        assert!(Arc::ptr_eq(&next, &store.load()));
    }

    #[test]
    fn lb_generation_overflow_rejects_config_and_discovery_publication() {
        let initial = config(
            vec![],
            vec![],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );
        let store = epoch_store_with_lb_generation(initial, u64::MAX);
        let before = store.load();
        let config_mirror_called = Cell::new(false);

        let config_error = match store.update_config(
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
            |_| config_mirror_called.set(true),
        ) {
            Err(error) => error,
            Ok(_) => panic!("config publication must reject LB generation overflow"),
        };
        assert!(config_error.contains("load-balancer reload generation counter exhausted"));
        assert!(!config_mirror_called.get());
        assert!(Arc::ptr_eq(&before, &store.load()));

        let discovery_mirror_called = Cell::new(false);
        let discovery_error = match store.update_load_balancer(
            |current| {
                Some(LoadBalancerCache::build_update_targets_inner(
                    &current.load_balancer,
                    "ferrum",
                    "u1",
                    vec![target("b.local", 81)],
                    LoadBalancerAlgorithm::RoundRobin,
                    None,
                ))
            },
            |_| discovery_mirror_called.set(true),
        ) {
            Err(error) => error,
            Ok(_) => panic!("LB-only publication must reject generation overflow"),
        };
        assert!(discovery_error.contains("load-balancer reload generation counter exhausted"));
        assert!(!discovery_mirror_called.get());
        let after = store.load();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.lb_generation, u64::MAX);
        assert_eq!(
            after.load_balancer.upstreams()[&rk("u1")].targets[0].host,
            "a.local"
        );
    }

    #[test]
    fn lb_only_update_keeps_unchanged_adaptive_subset_compatible() {
        let mut protected_proxy = proxy("p1", "/one", vec!["adaptive"]);
        protected_proxy.upstream_id = Some("u1".to_string());
        protected_proxy.upstream_subset = Some("blue".to_string());
        let adaptive = plugin_config(
            "adaptive",
            "adaptive_concurrency",
            json!({
                "min_limit": 1,
                "initial_limit": 2,
                "max_limit": 2
            }),
        );
        let mut blue = target("blue.local", 80);
        blue.tags.insert("version".to_string(), "blue".to_string());
        let mut green = target("green.local", 80);
        green
            .tags
            .insert("version".to_string(), "green".to_string());
        let mut shared_upstream = upstream("u1", vec![blue.clone(), green]);
        shared_upstream.subsets = Some(vec![
            serde_json::from_value(json!({
                "name": "blue",
                "labels": {"version": "blue"}
            }))
            .unwrap_or_else(|error| panic!("blue subset should deserialize: {error}")),
            serde_json::from_value(json!({
                "name": "green",
                "labels": {"version": "green"}
            }))
            .unwrap_or_else(|error| panic!("green subset should deserialize: {error}")),
        ]);
        let store = epoch_store(config(
            vec![protected_proxy],
            vec![adaptive],
            vec![shared_upstream],
        ));

        let acquire = |epoch: &RequestEpoch, target: &UpstreamTarget| {
            let plugin = epoch
                .plugin_cache
                .get_plugins(&rk("p1"))
                .iter()
                .find(|plugin| plugin.name() == "adaptive_concurrency")
                .cloned()
                .unwrap_or_else(|| panic!("adaptive plugin should be cached"));
            let mut ctx =
                RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
            ctx.lb_generation = epoch.lb_generation;
            let admission = BackendAdmissionContext {
                proxy: &epoch.config.proxies[0],
                upstream_target: Some(target),
                protocol: ProxyProtocol::Http,
            };
            plugin.try_backend_admission(&ctx, &admission)
        };

        let initial_epoch = store.load();
        let held = match acquire(&initial_epoch, &blue) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("initial blue request should be admitted"),
        };

        let mut replacement_green = target("replacement-green.local", 81);
        replacement_green
            .tags
            .insert("version".to_string(), "green".to_string());
        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u1",
                        vec![blue.clone(), replacement_green],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("LB update should succeed: {error}"))
            .expect("LB update should publish");

        let replacement_epoch = store.load();
        let second = match acquire(&replacement_epoch, &blue) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("an unchanged blue subset must remain compatible"),
        };
        drop(second);
        drop(held);
    }

    #[test]
    fn lb_only_scale_out_keeps_existing_adaptive_permits_admitted() {
        let mut protected_proxy = proxy("p1", "/one", vec!["adaptive"]);
        protected_proxy.upstream_id = Some("u1".to_string());
        protected_proxy.upstream_subset = Some("blue".to_string());
        let adaptive = plugin_config(
            "adaptive",
            "adaptive_concurrency",
            json!({
                "max_tracked_keys": 2,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }),
        );
        let mut first = target("blue-a.local", 80);
        first.tags.insert("version".to_string(), "blue".to_string());
        let mut shared_upstream = upstream("u1", vec![first.clone()]);
        shared_upstream.service_discovery = Some(
            serde_json::from_value(json!({
                "provider": "dns_sd",
                "dns_sd": {"service_name": "_http._tcp.blue.example.test"}
            }))
            .unwrap_or_else(|error| panic!("service discovery should deserialize: {error}")),
        );
        shared_upstream.subsets = Some(vec![
            serde_json::from_value(json!({
                "name": "blue",
                "labels": {"version": "blue"}
            }))
            .unwrap_or_else(|error| panic!("blue subset should deserialize: {error}")),
        ]);
        let store = epoch_store(config(
            vec![protected_proxy],
            vec![adaptive],
            vec![shared_upstream],
        ));

        let acquire = |epoch: &RequestEpoch, target: &UpstreamTarget| {
            let plugin = epoch
                .plugin_cache
                .get_plugins(&rk("p1"))
                .iter()
                .find(|plugin| plugin.name() == "adaptive_concurrency")
                .cloned()
                .unwrap_or_else(|| panic!("adaptive plugin should be cached"));
            let mut ctx =
                RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
            ctx.lb_generation = epoch.lb_generation;
            plugin.try_backend_admission(
                &ctx,
                &BackendAdmissionContext {
                    proxy: &epoch.config.proxies[0],
                    upstream_target: Some(target),
                    protocol: ProxyProtocol::Http,
                },
            )
        };

        let initial_epoch = store.load();
        let held_old_target = match acquire(&initial_epoch, &first) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("initial selected-subset target should be admitted"),
        };
        let mut added = target("blue-b.local", 80);
        added.tags.insert("version".to_string(), "blue".to_string());
        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u1",
                        vec![first.clone(), added.clone()],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("scale-out publication should succeed: {error}"))
            .expect("scale-out should publish a request epoch");

        let scaled_epoch = store.load();
        let added_target_permit = match acquire(&scaled_epoch, &added) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("new selected-subset target must admit without an old-key drain"),
        };
        drop(added_target_permit);
        drop(held_old_target);
    }

    #[test]
    fn config_reload_resets_route_override_upstream_target_key_space() {
        let protected_proxy = proxy("p1", "/one", vec!["adaptive", "route"]);
        let adaptive = plugin_config(
            "adaptive",
            "adaptive_concurrency",
            json!({
                "max_tracked_keys": 1,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }),
        );
        let route = plugin_config(
            "route",
            "mesh_route_dispatch",
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "canary"}
                }]
            }),
        );
        let initial = config(
            vec![protected_proxy],
            vec![adaptive, route],
            vec![upstream("canary", vec![target("old-canary.local", 80)])],
        );
        let store = epoch_store(initial);

        let acquire = |epoch: &RequestEpoch, target: &UpstreamTarget| {
            let plugin = epoch
                .plugin_cache
                .get_plugins(&rk("p1"))
                .iter()
                .find(|plugin| plugin.name() == "adaptive_concurrency")
                .cloned()
                .unwrap_or_else(|| panic!("adaptive plugin should be cached"));
            let mut ctx =
                RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
            ctx.lb_generation = epoch.lb_generation;
            let admission = BackendAdmissionContext {
                proxy: &epoch.config.proxies[0],
                upstream_target: Some(target),
                protocol: ProxyProtocol::Http,
            };
            plugin.try_backend_admission(&ctx, &admission)
        };

        let initial_epoch = store.load();
        let old_target = initial_epoch.load_balancer.upstreams()[&rk("canary")].targets[0].clone();
        match acquire(&initial_epoch, &old_target) {
            BackendAdmissionDecision::Admit(permit) => drop(permit),
            _ => panic!("initial route-override target should be admitted"),
        }

        let mut replacement_config = initial_epoch.config.as_ref().clone();
        replacement_config.upstreams[0].targets = vec![target("new-canary.local", 81)];
        store
            .update_config(
                |current| {
                    Ok(Some(StagedRequestEpoch {
                        config: Arc::new(replacement_config.clone()),
                        route_table: Arc::clone(&current.route_table),
                        plugin_cache: Arc::clone(&current.plugin_cache),
                        consumer_index: Arc::clone(&current.consumer_index),
                        load_balancer: LoadBalancerCache::build_inner(&replacement_config),
                        route_changed: false,
                        lb_changed: true,
                    }))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("config reload should publish: {error}"));

        let replacement_epoch = store.load();
        let replacement_target =
            replacement_epoch.load_balancer.upstreams()[&rk("canary")].targets[0].clone();
        let held = match acquire(&replacement_epoch, &replacement_target) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("replacement route-override target should be admitted"),
        };
        match acquire(&replacement_epoch, &replacement_target) {
            BackendAdmissionDecision::Reject { status_code, .. } => {
                assert_eq!(status_code, 503)
            }
            _ => panic!("replacement route-override target should remain limited"),
        }
        drop(held);
    }

    #[test]
    fn lb_only_overlapping_target_replacements_do_not_wait_for_retired_permits() {
        let mut protected_proxy = proxy("p1", "/one", vec!["adaptive"]);
        protected_proxy.upstream_id = Some("u1".to_string());
        let adaptive = plugin_config(
            "adaptive",
            "adaptive_concurrency",
            json!({
                "max_tracked_keys": 1,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1,
                "expose_headers": true
            }),
        );
        let initial = config(
            vec![protected_proxy],
            vec![adaptive],
            vec![upstream("u1", vec![target("a.local", 80)])],
        );
        let store = epoch_store(initial);

        let acquire = |epoch: &RequestEpoch, target: &UpstreamTarget| {
            let plugin = epoch
                .plugin_cache
                .get_plugins(&rk("p1"))
                .iter()
                .find(|plugin| plugin.name() == "adaptive_concurrency")
                .cloned()
                .unwrap_or_else(|| panic!("adaptive plugin should be cached"));
            let mut ctx =
                RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
            ctx.lb_generation = epoch.lb_generation;
            let admission = BackendAdmissionContext {
                proxy: &epoch.config.proxies[0],
                upstream_target: Some(target),
                protocol: ProxyProtocol::Http,
            };
            plugin.try_backend_admission(&ctx, &admission)
        };

        let initial_epoch = store.load();
        let first_target = initial_epoch.load_balancer.upstreams()[&rk("u1")].targets[0].clone();
        let old_target_permit = match acquire(&initial_epoch, &first_target) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("initial target should be admitted"),
        };

        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u1",
                        vec![target("b.local", 81)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("LB update should succeed: {error}"))
            .expect("LB update should publish");

        let replacement_epoch = store.load();
        let replacement_target =
            replacement_epoch.load_balancer.upstreams()[&rk("u1")].targets[0].clone();
        match acquire(&initial_epoch, &first_target) {
            BackendAdmissionDecision::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 503);
                assert!(
                    !headers.contains_key("x-adaptive-concurrency-limit"),
                    "a retired LB view has no truthful per-target limit"
                );
                assert!(
                    !headers.contains_key("x-adaptive-concurrency-inflight"),
                    "a retired LB view has no truthful per-target in-flight count"
                );
            }
            _ => panic!("a retired load-balancer view must not recreate the old target"),
        }
        let held = match acquire(&replacement_epoch, &replacement_target) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("replacement target should be admitted"),
        };
        match acquire(&replacement_epoch, &replacement_target) {
            BackendAdmissionDecision::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(
                    headers
                        .get("x-adaptive-concurrency-limit")
                        .map(String::as_str),
                    Some("1")
                );
                assert_eq!(
                    headers
                        .get("x-adaptive-concurrency-inflight")
                        .map(String::as_str),
                    Some("1")
                );
            }
            _ => panic!("replacement target should remain adaptively limited"),
        }

        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u1",
                        vec![target("c.local", 82)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("second LB update should succeed: {error}"))
            .expect("second LB update should publish");

        let newest_epoch = store.load();
        let newest_target = newest_epoch.load_balancer.upstreams()[&rk("u1")].targets[0].clone();
        match acquire(&replacement_epoch, &replacement_target) {
            BackendAdmissionDecision::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 503);
                assert!(
                    !headers.contains_key("x-adaptive-concurrency-limit"),
                    "the middle retired LB view must omit a per-target limit"
                );
                assert!(
                    !headers.contains_key("x-adaptive-concurrency-inflight"),
                    "the middle retired LB view must omit a per-target in-flight count"
                );
            }
            _ => panic!("the middle load-balancer view must stay retired"),
        }
        let newest = match acquire(&newest_epoch, &newest_target) {
            BackendAdmissionDecision::Admit(permit) => permit,
            _ => panic!("newest target should admit independently"),
        };
        match acquire(&newest_epoch, &newest_target) {
            BackendAdmissionDecision::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(
                    headers
                        .get("x-adaptive-concurrency-limit")
                        .map(String::as_str),
                    Some("1")
                );
                assert_eq!(
                    headers
                        .get("x-adaptive-concurrency-inflight")
                        .map(String::as_str),
                    Some("1")
                );
            }
            _ => panic!("newest target should enforce its independent limit"),
        }
        drop(newest);
        drop(held);
        drop(old_target_permit);
    }

    #[test]
    fn unrelated_lb_update_keeps_pinned_adaptive_request_view_compatible() {
        let mut protected_proxy = proxy("p1", "/one", vec!["adaptive"]);
        protected_proxy.upstream_id = Some("u1".to_string());
        let adaptive = plugin_config(
            "adaptive",
            "adaptive_concurrency",
            json!({
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }),
        );
        let initial = config(
            vec![protected_proxy],
            vec![adaptive],
            vec![
                upstream("u1", vec![target("a.local", 80)]),
                upstream("u2", vec![target("unrelated.local", 80)]),
            ],
        );
        let store = epoch_store(initial);
        let pinned_epoch = store.load();
        let pinned_target = pinned_epoch.load_balancer.upstreams()[&rk("u1")].targets[0].clone();

        store
            .update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        "ferrum",
                        "u2",
                        vec![target("replacement-unrelated.local", 81)],
                        LoadBalancerAlgorithm::RoundRobin,
                        None,
                    ))
                },
                |_| {},
            )
            .unwrap_or_else(|error| panic!("LB update should succeed: {error}"))
            .expect("LB update should publish");

        let plugin = pinned_epoch
            .plugin_cache
            .get_plugins(&rk("p1"))
            .iter()
            .find(|plugin| plugin.name() == "adaptive_concurrency")
            .cloned()
            .unwrap_or_else(|| panic!("adaptive plugin should be cached"));
        let mut ctx =
            RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
        ctx.lb_generation = pinned_epoch.lb_generation;
        let admission = BackendAdmissionContext {
            proxy: &pinned_epoch.config.proxies[0],
            upstream_target: Some(&pinned_target),
            protocol: ProxyProtocol::Http,
        };
        match plugin.try_backend_admission(&ctx, &admission) {
            BackendAdmissionDecision::Admit(permit) => drop(permit),
            _ => panic!("an unrelated target update must keep the pinned view compatible"),
        }
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
            proxy_index_by_key: build_proxy_index_by_key(&config),
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

        let proxy_index_by_key = build_proxy_index_by_key(&staged.config);
        let lb_generation = if staged.lb_changed {
            next_lb_generation(current.lb_generation)?
        } else {
            current.lb_generation
        };
        let next = Arc::new(RequestEpoch {
            config: staged.config,
            proxy_index_by_key,
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
            lb_generation,
        });
        // Adaptive policies share in-flight state across plugin-cache
        // generations. Stage the validated replacements, publish the one
        // request epoch, then retire stale feedback/bounds. Compatible old and
        // new plugin objects can both admit during this handoff because their
        // target counters are shared; structural replacements publish an
        // independent accounting space at commit.
        next.plugin_cache.prepare_adaptive_concurrency_generations();
        next.plugin_cache
            .prepare_adaptive_concurrency_lb_generation(
                next.lb_generation,
                &current.load_balancer,
                &next.load_balancer,
            );
        self.current.store(Arc::clone(&next));
        next.plugin_cache.commit_adaptive_concurrency_generations();
        next.plugin_cache.commit_adaptive_concurrency_lb_generation(
            next.lb_generation,
            &current.load_balancer,
            &next.load_balancer,
        );
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
    ) -> Result<Option<Arc<RequestEpoch>>, String> {
        // Poison only means a previous writer panicked before publishing; the
        // ArcSwap still holds the last complete epoch, so continuing is safe.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.current.load_full();
        let Some(load_balancer) = build(&current) else {
            return Ok(None);
        };
        let lb_generation = next_lb_generation(current.lb_generation)?;
        let next = Arc::new(RequestEpoch {
            config: Arc::clone(&current.config),
            proxy_index_by_key: Arc::clone(&current.proxy_index_by_key),
            route_table: Arc::clone(&current.route_table),
            plugin_cache: Arc::clone(&current.plugin_cache),
            consumer_index: Arc::clone(&current.consumer_index),
            load_balancer,
            config_generation: current.config_generation,
            route_generation: current.route_generation,
            lb_generation,
        });
        current
            .plugin_cache
            .prepare_adaptive_concurrency_lb_generation(
                next.lb_generation,
                &current.load_balancer,
                &next.load_balancer,
            );
        self.current.store(Arc::clone(&next));
        next.plugin_cache.commit_adaptive_concurrency_lb_generation(
            next.lb_generation,
            &current.load_balancer,
            &next.load_balancer,
        );
        // Keep LB wrapper mirroring serialized with the epoch publication.
        mirror(&next);
        Ok(Some(next))
    }
}

fn next_lb_generation(current: u64) -> Result<u64, String> {
    current.checked_add(1).ok_or_else(|| {
        "request epoch: load-balancer reload generation counter exhausted".to_string()
    })
}

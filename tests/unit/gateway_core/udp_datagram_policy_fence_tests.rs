//! Established UDP/DTLS sessions bind their datagram-hook list once, at
//! first-datagram admission. The datagram-policy fence they carry ends such a
//! session when a reload changes the proxy's datagram hooks, so adding,
//! tightening, or removing `udp_rate_limiting` reaches flows that keep sending
//! (a busy flow never idles out). Reloads that leave the proxy's hooks alone
//! must not end it.

use std::sync::Arc;

use chrono::Utc;
use ferrum_edge::_test_support::udp_datagram_policy_fence_for_test;
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{
    BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig, PluginScope,
    Proxy, default_namespace,
};
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::request_epoch::RequestEpochStore;
use serde_json::json;

use crate::unit::plugins::plugin_utils::{make_plugin_config_with_json, make_proxy};

fn udp_proxy(id: &str, port: u16, plugin_ids: Vec<&str>) -> Proxy {
    let mut proxy = make_proxy(id, "/", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(port);
    proxy.backend_scheme = Some(BackendScheme::Udp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Udp);
    proxy
}

fn limiter(datagrams_per_second: u64) -> PluginConfig {
    make_plugin_config_with_json(
        "udp-rl",
        "udp_rate_limiting",
        json!({"datagrams_per_second": datagrams_per_second}),
        PluginScope::Proxy,
        Some("udp-a"),
    )
}

fn gateway_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        plugin_configs,
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

/// Plugin cache + request epoch store driven the way the gateway reloads them.
struct Runtime {
    plugin_cache: PluginCache,
    consumer_index: ConsumerIndex,
    load_balancer: LoadBalancerCache,
    store: Arc<RequestEpochStore>,
    config: GatewayConfig,
}

impl Runtime {
    fn new(config: GatewayConfig) -> Self {
        let plugin_cache = PluginCache::new(&config).expect("plugin cache builds");
        let consumer_index = ConsumerIndex::new(&config.consumers);
        let load_balancer = LoadBalancerCache::new(&config);
        let store = Arc::new(RequestEpochStore::from_runtime_parts(
            config.clone(),
            &plugin_cache,
            &consumer_index,
            &load_balancer,
        ));
        Self {
            plugin_cache,
            consumer_index,
            load_balancer,
            store,
            config,
        }
    }

    /// Apply `next` as a delta reload and publish it in a new epoch.
    fn reload(&mut self, next: GatewayConfig) {
        let delta = ConfigDelta::compute(&self.config, &next);
        let rebuild = delta.proxy_ids_needing_plugin_rebuild(&self.config, &next);
        self.plugin_cache
            .apply_delta(
                &next,
                &rebuild,
                &delta.removed_proxy_ids,
                delta.global_plugin_configs_changed,
            )
            .expect("delta reload applies");
        self.store
            .republish_from_runtime_parts_for_test(
                next.clone(),
                &self.plugin_cache,
                &self.consumer_index,
                &self.load_balancer,
            )
            .expect("epoch republishes");
        self.config = next;
    }
}

#[test]
fn tightening_a_datagram_hook_ends_the_established_session() {
    let mut runtime = Runtime::new(gateway_config(
        vec![udp_proxy("udp-a", 19_501, vec!["udp-rl"])],
        vec![limiter(100_000)],
    ));
    let fence = udp_datagram_policy_fence_for_test(&runtime.store, &default_namespace(), "udp-a");
    assert!(fence.is_current(), "nothing changed since admission");

    let mut tightened = runtime.config.clone();
    tightened.plugin_configs[0].config = json!({"datagrams_per_second": 10});
    tightened.plugin_configs[0].updated_at += chrono::Duration::seconds(1);
    runtime.reload(tightened);

    assert!(
        !fence.is_current(),
        "a tightened limit must not leave an established session on the admitted limiter"
    );
    assert!(
        !fence.is_current(),
        "a retired session stays retired on every later datagram"
    );
}

#[test]
fn adding_a_datagram_hook_ends_a_hookless_session() {
    let mut runtime = Runtime::new(gateway_config(
        vec![udp_proxy("udp-a", 19_502, vec![])],
        vec![],
    ));
    let fence = udp_datagram_policy_fence_for_test(&runtime.store, &default_namespace(), "udp-a");
    assert!(fence.is_current());

    let mut added = runtime.config.clone();
    added.proxies[0].plugins = vec![PluginAssociation {
        plugin_config_id: "udp-rl".to_string(),
    }];
    added.proxies[0].updated_at += chrono::Duration::seconds(1);
    added.plugin_configs.push(limiter(10));
    runtime.reload(added);

    assert!(
        !fence.is_current(),
        "a session admitted with no datagram hooks must not stay unlimited after one is added"
    );
}

#[test]
fn removing_a_datagram_hook_ends_the_established_session() {
    let mut runtime = Runtime::new(gateway_config(
        vec![udp_proxy("udp-a", 19_503, vec!["udp-rl"])],
        vec![limiter(10)],
    ));
    let fence = udp_datagram_policy_fence_for_test(&runtime.store, &default_namespace(), "udp-a");
    assert!(fence.is_current());

    let mut removed = runtime.config.clone();
    removed.proxies[0].plugins.clear();
    removed.proxies[0].updated_at += chrono::Duration::seconds(1);
    removed.plugin_configs.clear();
    runtime.reload(removed);

    assert!(
        !fence.is_current(),
        "a removed limiter must not keep enforcing on an established session"
    );
}

#[test]
fn unrelated_reload_keeps_the_established_session() {
    let mut runtime = Runtime::new(gateway_config(
        vec![udp_proxy("udp-a", 19_504, vec!["udp-rl"])],
        vec![limiter(10)],
    ));
    let fence = udp_datagram_policy_fence_for_test(&runtime.store, &default_namespace(), "udp-a");
    let before = runtime.store.load().config_generation();

    let mut unrelated = runtime.config.clone();
    unrelated
        .proxies
        .push(udp_proxy("udp-b", 19_505, Vec::new()));
    runtime.reload(unrelated);

    assert!(
        runtime.store.load().config_generation() > before,
        "the reload must publish a new generation for this check to mean anything"
    );
    assert!(
        fence.is_current(),
        "a reload that leaves this proxy's datagram hooks untouched must not end its sessions"
    );
    assert!(fence.is_current(), "the re-verified generation is cached");
}

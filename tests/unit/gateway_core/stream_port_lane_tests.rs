//! The per-port LB lane admission policy shared by every stream path
//! (`backend_dispatch::stream_port_lane`): TCP, UDP/DTLS, mesh raw-TCP egress
//! and mesh UDP egress. The four paths used to carry their own copies of this
//! decision (they disagreed from day one on `LEAST_CONN`, and only TCP gained
//! the subset refinement). These tests pin the shared invariant, the one
//! intentional input difference (`selection_subset`). The structural pin that
//! every stream path routes through the one helper lives in
//! `shared_invariant_parity_tests.rs`.

use ferrum_edge::_test_support::{stream_health_port_scope_for_test, stream_port_lane_for_test};
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::load_balancer::LoadBalancerCache;
use serde_json::{Value, json};

const PORT: u16 = 5432;

/// One stream proxy on `orders`, two targets on `PORT`, a `canary` subset, and
/// the given upstream algorithm / upstream `hash_on` / subset algorithm / port
/// override.
fn fixture(
    upstream_algorithm: &str,
    upstream_hash_on: Option<&str>,
    subset_algorithm: &str,
    port_override: Value,
) -> (Proxy, LoadBalancerCache) {
    let mut upstream = json!({
        "id": "orders",
        "algorithm": upstream_algorithm,
        "targets": [
            { "host": "a.local", "port": PORT, "tags": { "version": "canary" } },
            { "host": "b.local", "port": PORT, "tags": { "version": "canary" } }
        ],
        "subsets": [{
            "name": "canary",
            "labels": { "version": "canary" },
            "traffic_policy": { "load_balancer_algorithm": subset_algorithm }
        }]
    });
    let mut port_overrides = serde_json::Map::new();
    port_overrides.insert(PORT.to_string(), port_override);
    upstream["port_overrides"] = Value::Object(port_overrides);
    if let Some(hash_on) = upstream_hash_on {
        upstream["hash_on"] = json!(hash_on);
    }
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "orders-proxy",
            "backend_scheme": "tcp",
            "backend_host": "unused.local",
            "backend_port": 0,
            "listen_port": 15432,
            "upstream_id": "orders"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [upstream]
    }))
    .expect("gateway config should deserialize");
    config.resolve_dispatch_port_overrides();
    let proxy = config.proxies[0].clone();
    (proxy, LoadBalancerCache::new(&config))
}

/// The decision a stream path makes: health scope first, then the lane.
fn lane(
    proxy: &Proxy,
    cache: &LoadBalancerCache,
    selection_subset: Option<&str>,
) -> Result<Option<u16>, String> {
    let snapshot = cache.load();
    let scope = stream_health_port_scope_for_test(proxy, &snapshot, "orders", PORT);
    stream_port_lane_for_test(proxy, &snapshot, "orders", scope, selection_subset)
}

#[test]
fn non_selection_overrides_scope_health_without_engaging_a_lane() {
    for port_override in [
        json!({ "connect_timeout_ms": 250 }),
        json!({ "max_connections": 8 }),
        json!({ "tcp_idle_timeout_seconds": 30 }),
        json!({ "passive_health_check": { "unhealthy_threshold": 3, "max_ejection_percent": 50 } }),
    ] {
        let (proxy, cache) = fixture("round_robin", None, "round_robin", port_override.clone());
        let snapshot = cache.load();
        assert_eq!(
            stream_health_port_scope_for_test(&proxy, &snapshot, "orders", PORT),
            Some(PORT),
            "{port_override} must still scope health by port"
        );
        for subset in [None, Some("canary")] {
            assert_eq!(
                lane(&proxy, &cache, subset),
                Ok(None),
                "{port_override} (subset {subset:?}) must not engage a per-port LB lane"
            );
        }
    }
}

#[test]
fn selection_affecting_overrides_engage_the_lane() {
    for port_override in [
        json!({ "algorithm": "round_robin" }),
        json!({ "algorithm": "least_connections" }),
        json!({ "algorithm": "consistent_hashing" }),
        json!({ "hash_on": "ip" }),
        json!({ "locality_lb_setting": { "enabled": true } }),
    ] {
        let (proxy, cache) = fixture("round_robin", None, "round_robin", port_override.clone());
        assert_eq!(
            lane(&proxy, &cache, None),
            Ok(Some(PORT)),
            "{port_override} must engage the per-port lane"
        );
    }
}

#[test]
fn least_latency_is_refused_before_the_selection_and_hash_checks() {
    // A non-IP hash key on the same override would also be refused; the
    // LEAST_LATENCY refusal must win because it is checked first.
    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "round_robin",
        json!({ "algorithm": "least_latency", "hash_on": "header:x-user" }),
    );
    for subset in [None, Some("canary")] {
        assert_eq!(
            lane(&proxy, &cache, subset),
            Err("LeastLatency".to_string()),
            "subset {subset:?}"
        );
    }
}

#[test]
fn non_ip_hash_key_is_refused_only_when_a_lane_engages() {
    // Port override names a non-IP key itself.
    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "round_robin",
        json!({ "hash_on": "header:x-user" }),
    );
    assert_eq!(lane(&proxy, &cache, None), Err("NonIpHashKey".to_string()));

    // Inherited upstream non-IP key under a selection-affecting override.
    let (proxy, cache) = fixture(
        "round_robin",
        Some("cookie:ferrum-affinity"),
        "round_robin",
        json!({ "algorithm": "consistent_hashing" }),
    );
    assert_eq!(lane(&proxy, &cache, None), Err("NonIpHashKey".to_string()));

    // Same inherited key, but the override does not affect selection: no lane,
    // so no refusal.
    let (proxy, cache) = fixture(
        "round_robin",
        Some("cookie:ferrum-affinity"),
        "round_robin",
        json!({ "connect_timeout_ms": 250 }),
    );
    assert_eq!(lane(&proxy, &cache, None), Ok(None));
}

#[test]
fn no_scope_or_absent_override_never_engages_or_refuses() {
    // Even a refusable override is inert without a health scope: the stream
    // paths only consult the lane when every target shares one port.
    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "round_robin",
        json!({ "algorithm": "least_latency" }),
    );
    let snapshot = cache.load();
    assert_eq!(
        stream_port_lane_for_test(&proxy, &snapshot, "orders", None, None),
        Ok(None)
    );
    // A scope for a port the proxy has no override for.
    assert_eq!(
        stream_port_lane_for_test(&proxy, &snapshot, "orders", Some(PORT + 1), None),
        Ok(None)
    );
}

/// INTENTIONAL difference: only TCP selects inside a route subset. With a
/// subset and no per-port algorithm, a hash-only override affects selection
/// only when the subset's effective algorithm is consistent hashing. Folding
/// `selection_subset` into a hidden default would break one side of this.
#[test]
fn selection_subset_refines_hash_only_overrides() {
    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "round_robin",
        json!({ "hash_on": "ip" }),
    );
    assert_eq!(
        lane(&proxy, &cache, Some("canary")),
        Ok(None),
        "a hash-only override must not bypass a non-hashing subset's LB"
    );
    assert_eq!(
        lane(&proxy, &cache, None),
        Ok(Some(PORT)),
        "without a subset the plain predicate applies (UDP/DTLS, mesh egress)"
    );

    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "consistent_hashing",
        json!({ "hash_on": "ip" }),
    );
    assert_eq!(lane(&proxy, &cache, Some("canary")), Ok(Some(PORT)));

    let (proxy, cache) = fixture(
        "round_robin",
        None,
        "consistent_hashing",
        json!({ "hash_on": "cookie:session" }),
    );
    assert_eq!(
        lane(&proxy, &cache, Some("canary")),
        Err("NonIpHashKey".to_string())
    );

    // Locality and an explicit per-port algorithm engage regardless of subset.
    for port_override in [
        json!({ "locality_lb_setting": { "enabled": true } }),
        json!({ "algorithm": "least_connections" }),
    ] {
        let (proxy, cache) = fixture("round_robin", None, "round_robin", port_override.clone());
        assert_eq!(
            lane(&proxy, &cache, Some("canary")),
            Ok(Some(PORT)),
            "{port_override}"
        );
    }
}

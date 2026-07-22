//! Contract coverage for authenticated `GET /admin/metrics`.
//!
//! Fixtures are built from the typed [`ferrum_edge::admin::metrics`] response
//! model so runtime serialization, OpenAPI components, and docs stay aligned.

use ferrum_edge::admin::metrics::{
    ADMIN_METRICS_MODES, AdminMetricsCircuitBreaker, AdminMetricsHealthKind,
    AdminMetricsUnhealthyTarget, build_admin_metrics, contract_fixtures, empty_proxy_metrics,
};
use serde_json::Value;

#[test]
fn admin_metrics_modes_cover_every_serving_runtime() {
    assert_eq!(
        ADMIN_METRICS_MODES,
        ["database", "file", "cp", "dp", "mesh", "node_agent"]
    );
}

#[test]
fn empty_proxy_metrics_serializes_mode_skeletons_for_cp_and_node_agent() {
    for mode in ["cp", "node_agent"] {
        let value = serde_json::to_value(empty_proxy_metrics(mode)).expect("serialize");
        assert_eq!(value["gateway"]["mode"], mode);
        assert_eq!(value["connection_pools"], serde_json::json!({}));
        assert_eq!(value["caches"], serde_json::json!({}));
        assert_eq!(value["circuit_breakers"], serde_json::json!([]));
        assert_eq!(value["health_check"]["unhealthy_target_count"], 0);
        assert!(value.get("database_polling").is_none());
        assert_eq!(
            value["tcp_connection_throttle"]["enforcement_scope"],
            "process_local"
        );
        assert_eq!(
            value["tcp_connection_throttle"]["replica_limit_behavior"],
            "configured_limit_per_replica"
        );
    }
}

#[test]
fn build_admin_metrics_without_proxy_state_matches_empty_skeleton() {
    for mode in ["cp", "node_agent"] {
        let built = build_admin_metrics(mode, false, None, None);
        let expected = empty_proxy_metrics(mode);
        assert_eq!(built, expected);
    }
}

#[test]
fn circuit_breaker_target_semantics_direct_vs_upstream() {
    let direct = AdminMetricsCircuitBreaker::direct_backend("proxy-a", "closed", 0, 0);
    let per_target =
        AdminMetricsCircuitBreaker::upstream_target("proxy-b", "10.0.2.1:8080", "open", 5, 0);

    let direct_json = serde_json::to_value(&direct).expect("direct serializes");
    let target_json = serde_json::to_value(&per_target).expect("target serializes");

    assert!(direct_json.get("target").is_none());
    assert_eq!(direct_json["proxy_id"], "proxy-a");
    assert_eq!(target_json["proxy_id"], "proxy-b");
    assert_eq!(target_json["target"], "10.0.2.1:8080");
    assert_eq!(target_json["state"], "open");
}

#[test]
fn unhealthy_target_active_omits_proxy_id_passive_requires_it() {
    let active = AdminMetricsUnhealthyTarget::active("10.0.3.12:8080", 100);
    let passive = AdminMetricsUnhealthyTarget::passive("proxy-x", "10.0.5.7:8080", 200);

    let active_json = serde_json::to_value(&active).expect("active serializes");
    let passive_json = serde_json::to_value(&passive).expect("passive serializes");

    assert_eq!(active_json["type"], "active");
    assert!(active_json.get("proxy_id").is_none());
    assert_eq!(active.kind, AdminMetricsHealthKind::Active);

    assert_eq!(passive_json["type"], "passive");
    assert_eq!(passive_json["proxy_id"], "proxy-x");
    assert_eq!(passive.kind, AdminMetricsHealthKind::Passive);
}

#[test]
fn contract_fixtures_cover_modes_breakers_and_health_variants() {
    let fixtures = contract_fixtures();
    let modes: Vec<&str> = fixtures
        .iter()
        .map(|fixture| fixture.gateway.mode.as_str())
        .collect();
    for mode in ADMIN_METRICS_MODES {
        assert!(
            modes.contains(mode),
            "missing mode fixture for {mode}: {modes:?}"
        );
    }

    let values: Vec<Value> = fixtures
        .iter()
        .map(|fixture| serde_json::to_value(fixture).expect("fixture serializes"))
        .collect();

    assert!(
        values.iter().any(|value| {
            value["gateway"]["mode"] == "mesh" && value["connection_pools"].get("http").is_some()
        }),
        "mesh fixture must use the proxy-serving shape"
    );
    assert!(
        values.iter().any(|value| {
            value["gateway"]["mode"] == "node_agent"
                && value["connection_pools"] == serde_json::json!({})
        }),
        "node_agent fixture must use the empty-skeleton shape"
    );
    assert!(
        values
            .iter()
            .any(|value| value.get("database_polling").is_some()),
        "database fixture must include database_polling"
    );

    let rich = values
        .iter()
        .find(|value| {
            value["circuit_breakers"]
                .as_array()
                .is_some_and(|items| items.len() >= 4)
        })
        .expect("breaker/health fixture");

    let breakers = rich["circuit_breakers"].as_array().expect("breakers array");
    assert!(
        breakers
            .iter()
            .any(|entry| entry.get("target").is_none() && entry["proxy_id"] == "proxy-payments-v2")
    );
    assert!(
        breakers
            .iter()
            .any(|entry| entry["target"] == "10.0.2.1:8080")
    );

    let unhealthy = rich["health_check"]["unhealthy_targets"]
        .as_array()
        .expect("unhealthy targets");
    assert!(
        unhealthy
            .iter()
            .any(|entry| entry["type"] == "active" && entry.get("proxy_id").is_none())
    );
    assert!(unhealthy.iter().any(|entry| {
        entry["type"] == "passive" && entry["proxy_id"] == "proxy-legacy-billing"
    }));
}

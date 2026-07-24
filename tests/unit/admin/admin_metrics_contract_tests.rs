//! Contract coverage for authenticated `GET /admin/metrics`.
//!
//! Fixtures are built from the typed [`ferrum_edge::admin::metrics`] response
//! model so runtime serialization, OpenAPI components, and docs stay aligned.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferrum_edge::admin::metrics::{
    ADMIN_METRICS_MODES, AdminMetricsCircuitBreaker, AdminMetricsHealthKind,
    AdminMetricsUnhealthyTarget, build_admin_metrics, config_source_status, contract_fixtures,
    empty_proxy_metrics,
};
use ferrum_edge::admin::{
    AdminState, build_metrics,
    jwt_auth::{JwtConfig, JwtManager},
};
use serde_json::Value;

fn test_jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "test-secret-key-for-admin-metrics-32chars!".to_string(),
        issuer: "test-ferrum-edge".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

/// Minimal AdminState for lock-free `db_available` → `config_source_status`
/// coverage without proxy state or real DB probes.
fn admin_state_for_source_status(mode: &str, db_available: Option<Arc<AtomicBool>>) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: test_jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: mode.to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

#[test]
fn admin_metrics_modes_cover_every_serving_runtime() {
    assert_eq!(
        ADMIN_METRICS_MODES,
        ["database", "file", "cp", "dp", "mesh", "node_agent"]
    );
}

#[test]
fn config_source_status_maps_db_available_snapshot() {
    assert_eq!(config_source_status(Some(true)), "online");
    assert_eq!(config_source_status(Some(false)), "offline");
    assert_eq!(config_source_status(None), "n/a");
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
fn build_admin_metrics_without_proxy_state_matches_empty_skeleton_when_na() {
    for mode in ["cp", "node_agent"] {
        let built = build_admin_metrics(mode, None, None, None);
        let expected = empty_proxy_metrics(mode);
        assert_eq!(built, expected);
    }
}

#[test]
fn build_admin_metrics_cp_without_proxy_state_reports_db_availability() {
    let online = build_admin_metrics("cp", Some(true), None, None);
    assert_eq!(online.gateway.config_source_status, "online");

    let offline = build_admin_metrics("cp", Some(false), None, None);
    assert_eq!(offline.gateway.config_source_status, "offline");
}

#[test]
fn database_and_cp_config_source_status_tracks_db_available_atomic() {
    for mode in ["database", "cp"] {
        let db_flag = Arc::new(AtomicBool::new(true));
        let state = admin_state_for_source_status(mode, Some(db_flag.clone()));

        assert_eq!(
            build_metrics(&state).gateway.config_source_status,
            "online",
            "{mode} healthy"
        );

        db_flag.store(false, Ordering::Relaxed);
        assert_eq!(
            build_metrics(&state).gateway.config_source_status,
            "offline",
            "{mode} outage"
        );

        db_flag.store(true, Ordering::Relaxed);
        assert_eq!(
            build_metrics(&state).gateway.config_source_status,
            "online",
            "{mode} recovery"
        );
    }
}

#[test]
fn file_dp_mesh_node_agent_config_source_status_is_na() {
    for mode in ["file", "dp", "mesh", "node_agent"] {
        let state = admin_state_for_source_status(mode, None);
        assert_eq!(
            build_metrics(&state).gateway.config_source_status,
            "n/a",
            "{mode} must report n/a without a DB-backed config source"
        );
        assert_eq!(
            build_admin_metrics(mode, None, None, None)
                .gateway
                .config_source_status,
            "n/a"
        );
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
    assert!(
        values.iter().any(|value| {
            value["gateway"]["mode"] == "cp" && value["gateway"]["config_source_status"] == "online"
        }),
        "cp healthy fixture must report online without proxy_state"
    );
    assert!(
        values.iter().any(|value| {
            value["gateway"]["config_source_status"] == "offline"
                && (value["gateway"]["mode"] == "database" || value["gateway"]["mode"] == "cp")
        }),
        "fixtures must cover offline for DB-backed modes"
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

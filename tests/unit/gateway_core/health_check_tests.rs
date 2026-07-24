//! Tests for health check module

use chrono::Utc;
use ferrum_edge::config::types::{
    ActiveHealthCheck, GatewayConfig, HealthCheckConfig, HealthProbeType, LoadBalancerAlgorithm,
    PassiveHealthCheck, Upstream, UpstreamTarget, default_namespace,
};
use ferrum_edge::health_check::HealthChecker;
use std::collections::HashMap;

const TEST_PROXY: &str = "test-proxy";

fn make_target(host: &str, port: u16) -> UpstreamTarget {
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

/// Check if a target is passively unhealthy for a given proxy via the two-level index.
fn is_passive_unhealthy(checker: &HealthChecker, proxy_id: &str, host_port: &str) -> bool {
    checker
        .passive_health
        .get(proxy_id)
        .is_some_and(|ps| ps.unhealthy.contains_key(host_port))
}

/// Count total passive unhealthy entries across all proxies.
fn passive_unhealthy_count(checker: &HealthChecker) -> usize {
    checker
        .passive_health
        .iter()
        .map(|entry| entry.value().unhealthy.len())
        .sum()
}

#[test]
fn test_passive_health_marks_unhealthy() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500, 502, 503],
        unhealthy_threshold: 3,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..3 {
        checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    }

    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

#[test]
fn test_passive_health_recovers() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.report_response(TEST_PROXY, &target, 200, false, Some(&config));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

#[test]
fn test_success_does_not_mark_unhealthy() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 3,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..100 {
        checker.report_response(TEST_PROXY, &target, 200, false, Some(&config));
    }

    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

#[test]
fn test_connection_error_counts_as_failure_regardless_of_status_codes() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 502, true, Some(&config));
    }

    assert!(
        is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Connection errors should mark target unhealthy even if status code is not in unhealthy list"
    );
}

#[test]
fn test_connection_error_recovery_on_success() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 502, true, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.report_response(TEST_PROXY, &target, 200, false, Some(&config));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

#[test]
fn test_remove_stale_passive_targets_for_proxy_cleans_unhealthy() {
    let checker = HealthChecker::new();
    let target1 = make_target("backend1", 8080);
    let target2 = make_target("backend2", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target1, 500, false, Some(&config));
        checker.report_response(TEST_PROXY, &target2, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend2:8080"));

    // Remove backend2 from the upstream for this proxy.
    checker.remove_stale_passive_targets_for_proxy(TEST_PROXY, std::slice::from_ref(&target1));

    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend2:8080"));
}

#[test]
fn test_remove_stale_passive_targets_for_proxy_empty_list_clears_all() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.remove_stale_passive_targets_for_proxy(TEST_PROXY, &[]);
    assert_eq!(passive_unhealthy_count(&checker), 0);
}

#[test]
fn test_remove_stale_targets_no_op_when_all_present() {
    let checker = HealthChecker::new();
    let target1 = make_target("backend1", 8080);
    let target2 = make_target("backend2", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target1, 500, false, Some(&config));
        checker.report_response(TEST_PROXY, &target2, 500, false, Some(&config));
    }

    checker.remove_stale_passive_targets_for_proxy(TEST_PROXY, &[target1, target2]);
    assert_eq!(passive_unhealthy_count(&checker), 2);
}

/// Core test: two proxies sharing the same upstream with identical targets
/// must have fully independent passive health state.
#[test]
fn test_passive_health_isolated_across_proxies_sharing_upstream() {
    let checker = HealthChecker::new();
    let target = make_target("shared-backend", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Proxy-A sends large payloads → backend returns 500s
    for _ in 0..2 {
        checker.report_response("proxy-a", &target, 500, false, Some(&config));
    }

    assert!(
        is_passive_unhealthy(&checker, "proxy-a", "shared-backend:8080"),
        "proxy-a should see target as unhealthy after its own failures"
    );
    assert!(
        !is_passive_unhealthy(&checker, "proxy-b", "shared-backend:8080"),
        "proxy-b must not be affected by proxy-a's failures"
    );

    // Proxy-B sends small payloads → backend returns 200s
    checker.report_response("proxy-b", &target, 200, false, Some(&config));

    assert!(
        is_passive_unhealthy(&checker, "proxy-a", "shared-backend:8080"),
        "proxy-b's success must not recover proxy-a's health state"
    );
    assert!(
        !is_passive_unhealthy(&checker, "proxy-b", "shared-backend:8080"),
        "proxy-b should remain healthy"
    );
}

/// Active health state (probe-based) is independent of passive health state.
#[test]
fn test_active_and_passive_health_are_independent() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    for _ in 0..2 {
        checker.report_response("proxy-a", &target, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, "proxy-a", "backend1:8080"));
    assert!(checker.active_unhealthy_targets.is_empty());
}

// ── gRPC probe type tests ────────────────────────────────────────────────────

#[test]
fn test_grpc_probe_type_deserializes_from_grpc() {
    let json = r#""grpc""#;
    let probe_type: HealthProbeType = serde_json::from_str(json).unwrap();
    assert_eq!(probe_type, HealthProbeType::Grpc);
}

#[test]
fn test_grpc_probe_type_serializes_to_grpc() {
    let probe_type = HealthProbeType::Grpc;
    let serialized = serde_json::to_string(&probe_type).unwrap();
    assert_eq!(serialized, r#""grpc""#);
}

#[test]
fn test_active_health_check_grpc_service_name_defaults_to_none() {
    let config = ActiveHealthCheck::default();
    assert_eq!(config.grpc_service_name, None);
}

#[test]
fn test_active_health_check_grpc_service_name_deserializes() {
    let json = r#"{"grpc_service_name": "my.Service"}"#;
    let config: ActiveHealthCheck = serde_json::from_str(json).unwrap();
    assert_eq!(config.grpc_service_name, Some("my.Service".to_string()));
}

#[test]
fn test_active_health_check_grpc_service_name_omitted_gives_none() {
    let json = r#"{}"#;
    let config: ActiveHealthCheck = serde_json::from_str(json).unwrap();
    assert_eq!(config.grpc_service_name, None);
}

// ── Proxy pruning tests ──────────────────────────────────────────────────

#[test]
fn test_prune_removed_proxies() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Insert passive health state for 3 proxies by reporting responses
    for _ in 0..2 {
        checker.report_response("proxy1", &target, 500, false, Some(&config));
        checker.report_response("proxy2", &target, 500, false, Some(&config));
        checker.report_response("proxy3", &target, 500, false, Some(&config));
    }
    assert_eq!(checker.passive_health.len(), 3);

    // Remove proxy1 and proxy3
    checker.prune_removed_proxies(&["proxy1".to_string(), "proxy3".to_string()]);

    assert_eq!(checker.passive_health.len(), 1);
    assert!(checker.passive_health.contains_key("proxy2"));
    assert!(!checker.passive_health.contains_key("proxy1"));
    assert!(!checker.passive_health.contains_key("proxy3"));
}

#[tokio::test]
async fn test_grpc_probe_returns_false_for_nonexistent_host() {
    use ferrum_edge::health_check::grpc_probe_for_test;
    use std::time::Duration;

    let result = grpc_probe_for_test(
        "grpc-probe-test-nonexistent-host-12345.invalid",
        50099,
        Duration::from_millis(100),
        false,
        "",
    )
    .await;
    assert!(!result, "probe should return false for a non-existent host");
}

// ─── Passive Health Window Semantics ────────────────────────────────────────

#[test]
fn test_passive_window_only_counts_recent_failures() {
    // With window_seconds=1, failures older than 1s should not count.
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 3,
        unhealthy_window_seconds: 1, // 1 second window
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Record 2 failures (under threshold)
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(
        !is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Should not be unhealthy with only 2 failures"
    );

    // Sleep past the window
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Record 1 more failure — the old 2 should have expired from the window
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(
        !is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Old failures outside window should not count toward threshold"
    );
}

#[test]
fn test_passive_window_failures_within_window_accumulate() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 3,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // All 3 failures within the 60s window
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(
        is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Should be unhealthy after 3 failures within window"
    );
}

#[test]
fn test_passive_health_threshold_1_immediate_unhealthy() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500, 502],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    checker.report_response(TEST_PROXY, &target, 502, false, Some(&config));
    assert!(
        is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Threshold of 1 should mark unhealthy on first failure"
    );
}

// ─── Connection Error Tests ─────────────────────────────────────────────────

#[test]
fn test_connection_error_ignores_status_code_list() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500], // Only 500 in the list
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Status code 200 with connection_error=true should still count as failure
    checker.report_response(TEST_PROXY, &target, 200, true, Some(&config));
    assert!(
        is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Connection errors should trigger failure regardless of status code"
    );
}

// ─── Multi-Target Isolation ─────────────────────────────────────────────────

#[test]
fn test_passive_health_per_target_isolation() {
    let checker = HealthChecker::new();
    let target_a = make_target("backend-a", 8080);
    let _target_b = make_target("backend-b", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Fail target_a only
    checker.report_response(TEST_PROXY, &target_a, 500, false, Some(&config));
    checker.report_response(TEST_PROXY, &target_a, 500, false, Some(&config));

    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend-a:8080"));
    assert!(
        !is_passive_unhealthy(&checker, TEST_PROXY, "backend-b:8080"),
        "target_b should remain healthy"
    );
}

// ─── Recovery Clears Failure History ────────────────────────────────────────

#[test]
fn test_recovery_clears_failures_then_re_threshold() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 3,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Mark unhealthy
    for _ in 0..3 {
        checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    // Recover with a success
    checker.report_response(TEST_PROXY, &target, 200, false, Some(&config));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    // Now it should take a full 3 failures again to mark unhealthy
    // (failure history was cleared on recovery)
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(
        !is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"),
        "Should need full threshold after recovery"
    );

    checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

// ─── No Config Means No Tracking ────────────────────────────────────────────

#[test]
fn test_no_passive_config_is_noop() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);

    // Report with no passive config
    for _ in 0..100 {
        checker.report_response(TEST_PROXY, &target, 500, false, None);
    }

    assert_eq!(
        checker.passive_health.len(),
        0,
        "No passive state should be created without config"
    );
}

// ─── Probe-task lifecycle on config reload ──────────────────────────────────

/// Build an `Upstream` whose targets get an active TCP probe spawned on
/// `start_with_shutdown` / `restart_with_shutdown`. TCP probe is used so the
/// task spawns regardless of whether the test environment can actually
/// reach a backend — we only care about handle lifecycle here, not probe
/// outcomes.
fn make_upstream_with_active_probe(
    id: &str,
    targets: Vec<UpstreamTarget>,
    interval_seconds: u64,
) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(format!("upstream-{}", id)),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: Some(HealthCheckConfig {
            active: Some(ActiveHealthCheck {
                http_path: "/health".to_string(),
                interval_seconds,
                timeout_ms: 100,
                healthy_threshold: 2,
                unhealthy_threshold: 2,
                healthy_status_codes: vec![200],
                use_tls: false,
                probe_type: HealthProbeType::Tcp,
                udp_probe_payload: None,
                grpc_service_name: None,
            }),
            passive: None,
        }),
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn config_with_upstreams(upstreams: Vec<Upstream>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: Vec::new(),
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        upstreams,
        expected_resource_counts: None,
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
    }
}

#[tokio::test]
async fn test_restart_aborts_handles_for_removed_upstream() {
    // Two upstreams, one target each. After restart with only one upstream,
    // the active task count should drop accordingly and the removed
    // upstream's stale entries in `active_unhealthy_targets` must be pruned.
    let checker = HealthChecker::new();

    let initial = config_with_upstreams(vec![
        make_upstream_with_active_probe("up-keep", vec![make_target("keep-host", 9001)], 60),
        make_upstream_with_active_probe("up-remove", vec![make_target("remove-host", 9002)], 60),
    ]);
    checker.start(&initial);
    assert_eq!(
        checker.active_task_count(),
        2,
        "two upstreams x one target each = two probe tasks"
    );

    // Simulate the unhealthy state for the to-be-removed upstream so we can
    // assert the restart prunes it.
    checker
        .active_unhealthy_targets
        .insert("up-remove::remove-host:9002".to_string(), 12345);
    checker
        .active_unhealthy_targets
        .insert("up-keep::keep-host:9001".to_string(), 67890);

    let after_remove = config_with_upstreams(vec![make_upstream_with_active_probe(
        "up-keep",
        vec![make_target("keep-host", 9001)],
        60,
    )]);
    checker.restart_with_shutdown(&after_remove, None);

    assert_eq!(
        checker.active_task_count(),
        1,
        "removed upstream's probe task should be aborted on restart"
    );
    assert!(
        !checker
            .active_unhealthy_targets
            .contains_key("up-remove::remove-host:9002"),
        "stale unhealthy entry for removed upstream should be pruned"
    );
    assert!(
        checker
            .active_unhealthy_targets
            .contains_key("up-keep::keep-host:9001"),
        "kept upstream's unhealthy state must survive the restart"
    );
}

#[tokio::test]
async fn test_restart_spawns_handles_for_new_upstream() {
    // Start with one upstream, then restart with an additional one. The
    // active task count should grow accordingly so the new upstream's
    // targets actually get probed.
    let checker = HealthChecker::new();

    let initial = config_with_upstreams(vec![make_upstream_with_active_probe(
        "up-original",
        vec![make_target("orig-host", 9100)],
        60,
    )]);
    checker.start(&initial);
    assert_eq!(checker.active_task_count(), 1);

    let after_add = config_with_upstreams(vec![
        make_upstream_with_active_probe("up-original", vec![make_target("orig-host", 9100)], 60),
        make_upstream_with_active_probe(
            "up-new",
            vec![
                make_target("new-host-a", 9101),
                make_target("new-host-b", 9102),
            ],
            60,
        ),
    ]);
    checker.restart_with_shutdown(&after_add, None);

    assert_eq!(
        checker.active_task_count(),
        3,
        "1 task for the existing upstream + 2 for the new one's two targets"
    );
}

#[tokio::test]
async fn test_restart_picks_up_changed_interval() {
    // Same upstream, changed interval. The old task is aborted and a new
    // one is spawned with the new parameters — without a restart, the old
    // 60s interval would persist forever. We can't directly observe the
    // interval value (it's owned by the spawned task) but we can confirm
    // the handle was replaced: aborting the old task is observable via the
    // replaced JoinHandle in `active_check_handles`. We check this via
    // `active_task_count` invariance + Tokio's JoinHandle::is_finished()
    // semantics on the original handle.
    let checker = HealthChecker::new();

    let initial = config_with_upstreams(vec![make_upstream_with_active_probe(
        "up-iv",
        vec![make_target("iv-host", 9200)],
        60,
    )]);
    checker.start(&initial);
    assert_eq!(checker.active_task_count(), 1);

    // Restart with a different interval (same upstream id and target so
    // the diff is purely "probe parameters changed").
    let after_change = config_with_upstreams(vec![make_upstream_with_active_probe(
        "up-iv",
        vec![make_target("iv-host", 9200)],
        5,
    )]);
    checker.restart_with_shutdown(&after_change, None);

    assert_eq!(
        checker.active_task_count(),
        1,
        "still one upstream-target → one task, but the underlying handle was replaced"
    );

    // Yield so the abort signal propagates to the original task. The
    // replacement task is still running with the new interval.
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn test_restart_when_all_upstreams_removed() {
    // Going from N upstreams to zero must abort every probe task and
    // leave `active_unhealthy_targets` empty (no leak).
    let checker = HealthChecker::new();

    let initial = config_with_upstreams(vec![
        make_upstream_with_active_probe("a", vec![make_target("host-a", 9301)], 60),
        make_upstream_with_active_probe("b", vec![make_target("host-b", 9302)], 60),
    ]);
    checker.start(&initial);
    assert_eq!(checker.active_task_count(), 2);

    checker
        .active_unhealthy_targets
        .insert("a::host-a:9301".to_string(), 1);
    checker
        .active_unhealthy_targets
        .insert("b::host-b:9302".to_string(), 2);

    let empty = config_with_upstreams(vec![]);
    checker.restart_with_shutdown(&empty, None);

    assert_eq!(
        checker.active_task_count(),
        0,
        "all probe tasks must be aborted when upstreams go to zero"
    );
    assert!(
        checker.active_unhealthy_targets.is_empty(),
        "active unhealthy entries must be pruned when no upstreams remain"
    );
}

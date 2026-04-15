//! Tests for health check module

use ferrum_edge::config::types::{
    ActiveHealthCheck, HealthProbeType, PassiveHealthCheck, UpstreamTarget,
};
use ferrum_edge::health_check::HealthChecker;
use std::collections::HashMap;

const TEST_PROXY: &str = "test-proxy";

fn make_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::new(),
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
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 502, true, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.report_response(TEST_PROXY, &target, 200, false, Some(&config));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
}

#[test]
fn test_remove_stale_targets_cleans_unhealthy() {
    let checker = HealthChecker::new();
    let target1 = make_target("backend1", 8080);
    let target2 = make_target("backend2", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target1, 500, false, Some(&config));
        checker.report_response(TEST_PROXY, &target2, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend2:8080"));

    // Remove backend2 from the upstream
    checker.remove_stale_targets("us1", std::slice::from_ref(&target1));

    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));
    assert!(!is_passive_unhealthy(&checker, TEST_PROXY, "backend2:8080"));
}

#[test]
fn test_remove_stale_targets_empty_list_clears_all() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target, 500, false, Some(&config));
    }
    assert!(is_passive_unhealthy(&checker, TEST_PROXY, "backend1:8080"));

    checker.remove_stale_targets("us1", &[]);
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
    };

    for _ in 0..2 {
        checker.report_response(TEST_PROXY, &target1, 500, false, Some(&config));
        checker.report_response(TEST_PROXY, &target2, 500, false, Some(&config));
    }

    checker.remove_stale_targets("us1", &[target1, target2]);
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

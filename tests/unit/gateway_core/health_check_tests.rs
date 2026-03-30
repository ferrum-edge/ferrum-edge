//! Tests for health check module

use ferrum_edge::config::types::{PassiveHealthCheck, UpstreamTarget};
use ferrum_edge::health_check::HealthChecker;
use std::collections::HashMap;

fn make_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::new(),
        path: None,
    }
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

    // Report 3 failures
    for _ in 0..3 {
        checker.report_response(&target, 500, false, Some(&config));
    }

    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));
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

    // Mark unhealthy
    for _ in 0..2 {
        checker.report_response(&target, 500, false, Some(&config));
    }
    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

    // Recovery
    checker.report_response(&target, 200, false, Some(&config));
    assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
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
        checker.report_response(&target, 200, false, Some(&config));
    }

    assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
}

#[test]
fn test_connection_error_counts_as_failure_regardless_of_status_codes() {
    let checker = HealthChecker::new();
    let target = make_target("backend1", 8080);
    // Only 500 is in the unhealthy list — 502 is NOT
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 2,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
    };

    // Report connection errors with status 502 (synthetic from proxy).
    // Even though 502 is NOT in unhealthy_status_codes, connection_error=true
    // should still count as a failure.
    for _ in 0..2 {
        checker.report_response(&target, 502, true, Some(&config));
    }

    assert!(
        checker.unhealthy_targets.contains_key("backend1:8080"),
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

    // Mark unhealthy via connection errors
    for _ in 0..2 {
        checker.report_response(&target, 502, true, Some(&config));
    }
    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

    // A successful response should recover it
    checker.report_response(&target, 200, false, Some(&config));
    assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
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

    // Mark both unhealthy
    for _ in 0..2 {
        checker.report_response(&target1, 500, false, Some(&config));
        checker.report_response(&target2, 500, false, Some(&config));
    }
    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));
    assert!(checker.unhealthy_targets.contains_key("backend2:8080"));

    // Remove backend2 from the active list
    checker.remove_stale_targets(std::slice::from_ref(&target1));

    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));
    assert!(!checker.unhealthy_targets.contains_key("backend2:8080"));
}

#[test]
fn test_remove_stale_targets_cleans_target_states() {
    let checker = HealthChecker::new();
    let target1 = make_target("backend1", 8080);
    let target2 = make_target("backend2", 8080);
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 10,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
    };

    // Report responses to create target_states entries (below threshold so not unhealthy)
    checker.report_response(&target1, 500, false, Some(&config));
    checker.report_response(&target2, 500, false, Some(&config));

    // Remove backend2 — its target_states entry should be cleaned
    checker.remove_stale_targets(&[target1]);

    // backend1 should still have unhealthy tracking state, backend2 should not
    // (We can't directly inspect target_states, but the method should not panic
    // and the unhealthy_targets map should be consistent)
    assert!(!checker.unhealthy_targets.contains_key("backend2:8080"));
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
        checker.report_response(&target, 500, false, Some(&config));
    }
    assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

    // Empty current list → all stale entries removed
    checker.remove_stale_targets(&[]);
    assert!(checker.unhealthy_targets.is_empty());
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
        checker.report_response(&target1, 500, false, Some(&config));
        checker.report_response(&target2, 500, false, Some(&config));
    }

    // Both targets still active — nothing should be removed
    checker.remove_stale_targets(&[target1, target2]);
    assert_eq!(checker.unhealthy_targets.len(), 2);
}

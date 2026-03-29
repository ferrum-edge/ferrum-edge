//! Tests for circuit breaker module

use ferrum_gateway::circuit_breaker::{CircuitBreaker, CircuitBreakerCache, target_key};
use ferrum_gateway::config::types::CircuitBreakerConfig;
use std::sync::Arc;

fn default_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        timeout_seconds: 1,
        failure_status_codes: vec![500, 502, 503],
        half_open_max_requests: 1,
    }
}

#[test]
fn test_closed_allows_requests() {
    let cb = CircuitBreaker::new(default_config());
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_opens_after_threshold() {
    let cb = CircuitBreaker::new(default_config());

    cb.record_failure(500);
    cb.record_failure(500);
    assert!(cb.can_execute().is_ok()); // Still closed

    cb.record_failure(500);
    assert_eq!(cb.state_name(), "open");
    assert!(cb.can_execute().is_err());
}

#[test]
fn test_non_configured_status_treated_as_success() {
    let cb = CircuitBreaker::new(default_config());

    // 404 is not in failure_status_codes, should be treated as success
    cb.record_failure(404);
    cb.record_failure(404);
    cb.record_failure(404);
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_success_resets_failure_count() {
    let cb = CircuitBreaker::new(default_config());

    cb.record_failure(500);
    cb.record_failure(500);
    cb.record_success(); // Should reset
    cb.record_failure(500);
    cb.record_failure(500);
    // Only 2 failures after reset, should still be closed
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_half_open_recovery() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 2,
        timeout_seconds: 0, // Immediate timeout for testing
        failure_status_codes: vec![500],
        half_open_max_requests: 2,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500);
    cb.record_failure(500);
    assert_eq!(cb.state_name(), "open");

    // Timeout elapsed (0 seconds), should transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Successful probes
    cb.record_success();
    cb.record_success();
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_half_open_probe_failure_reopens() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500);
    cb.record_failure(500);

    // Transition to half-open
    assert!(cb.can_execute().is_ok());

    // Probe fails
    cb.record_failure(500);
    assert_eq!(cb.state_name(), "open");
}

#[test]
fn test_cache_creates_and_reuses() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    let cb1 = cache.get_or_create("proxy-1", None, &config);
    let cb2 = cache.get_or_create("proxy-1", None, &config);

    // Should be the same instance
    assert!(Arc::ptr_eq(&cb1, &cb2));
}

#[test]
fn test_half_open_max_requests_enforced() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 3,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 2,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500);
    assert_eq!(cb.state_name(), "open");

    // First call transitions to half-open and admits (slot 1)
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Second call admits (slot 2)
    assert!(cb.can_execute().is_ok());

    // Third call should be rejected — max 2 in-flight
    assert!(cb.can_execute().is_err());
}

#[test]
fn test_half_open_slot_freed_on_success() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 3,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open, transition to half-open
    cb.record_failure(500);
    assert!(cb.can_execute().is_ok()); // slot 1 taken

    // At max — should reject
    assert!(cb.can_execute().is_err());

    // Record success frees a slot
    cb.record_success();

    // Now should be able to get a slot again
    assert!(cb.can_execute().is_ok());
}

#[test]
fn test_half_open_concurrent_slots() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 10,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 5,
    };
    let cb = Arc::new(CircuitBreaker::new(config));

    // Trip open
    cb.record_failure(500);

    // Spawn threads that all try to get a half-open slot
    let mut handles = Vec::new();
    for _ in 0..20 {
        let cb_clone = cb.clone();
        handles.push(std::thread::spawn(move || cb_clone.can_execute().is_ok()));
    }

    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let admitted = results.iter().filter(|&&r| r).count();

    // Exactly 5 should be admitted (1 CAS winner + 4 from half-open slots)
    assert_eq!(
        admitted, 5,
        "Expected exactly 5 admitted in half-open, got {}",
        admitted
    );
}

#[test]
fn test_concurrent_failure_recording() {
    let config = CircuitBreakerConfig {
        failure_threshold: 50,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    };
    let cb = Arc::new(CircuitBreaker::new(config));

    // Spawn threads that all record failures concurrently
    let mut handles = Vec::new();
    for _ in 0..100 {
        let cb_clone = cb.clone();
        handles.push(std::thread::spawn(move || {
            cb_clone.record_failure(500);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // After 100 failures with threshold 50, circuit must be open
    assert_eq!(cb.state_name(), "open");
}

#[test]
fn test_cache_prune_removes_stale() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    cache.get_or_create("proxy-1", None, &config);
    cache.get_or_create("proxy-2", None, &config);
    cache.get_or_create("proxy-3", None, &config);

    cache.prune(&["proxy-1".to_string(), "proxy-3".to_string()]);

    // proxy-2 should still exist, proxy-1 and proxy-3 should be gone
    assert!(cache.can_execute("proxy-2", None, &config).is_ok());
    // Creating proxy-1 again should give a fresh breaker
    let cb = cache.get_or_create("proxy-1", None, &config);
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_cache_replaces_on_config_change() {
    let cache = CircuitBreakerCache::new();
    let config1 = default_config();
    let cb1 = cache.get_or_create("proxy-1", None, &config1);

    // Change the config
    let config2 = CircuitBreakerConfig {
        failure_threshold: 10,
        ..config1
    };
    let cb2 = cache.get_or_create("proxy-1", None, &config2);

    // Should be a different instance
    assert!(!Arc::ptr_eq(&cb1, &cb2));
}

// --- Per-target circuit breaker tests ---

#[test]
fn test_per_target_independent_breakers() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    };

    let tk_a = target_key("10.0.0.1", 8080);
    let tk_b = target_key("10.0.0.2", 8080);

    // Trip target A's breaker
    let cb_a = cache.get_or_create("proxy-1", Some(&tk_a), &config);
    cb_a.record_failure(500);
    cb_a.record_failure(500);
    assert_eq!(cb_a.state_name(), "open");

    // Target B should still be closed
    let cb_b = cache.get_or_create("proxy-1", Some(&tk_b), &config);
    assert_eq!(cb_b.state_name(), "closed");
    assert!(cache.can_execute("proxy-1", Some(&tk_b), &config).is_ok());

    // Target A should be rejected
    assert!(cache.can_execute("proxy-1", Some(&tk_a), &config).is_err());
}

#[test]
fn test_per_target_does_not_share_with_direct_backend() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
    };

    // Trip breaker for proxy-1 with no target (direct backend)
    let cb_direct = cache.get_or_create("proxy-1", None, &config);
    cb_direct.record_failure(500);
    cb_direct.record_failure(500);
    assert_eq!(cb_direct.state_name(), "open");

    // Same proxy with a target key should have its own breaker (closed)
    let tk = target_key("10.0.0.1", 8080);
    let cb_target = cache.get_or_create("proxy-1", Some(&tk), &config);
    assert_eq!(cb_target.state_name(), "closed");
}

#[test]
fn test_per_target_same_instance_reuse() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();
    let tk = target_key("backend.local", 443);

    let cb1 = cache.get_or_create("proxy-1", Some(&tk), &config);
    let cb2 = cache.get_or_create("proxy-1", Some(&tk), &config);

    assert!(Arc::ptr_eq(&cb1, &cb2));
}

#[test]
fn test_prune_removes_all_targets_for_proxy() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    let tk_a = target_key("10.0.0.1", 8080);
    let tk_b = target_key("10.0.0.2", 8080);

    // Create breakers for proxy-1 (two targets) and proxy-2 (one target)
    cache.get_or_create("proxy-1", Some(&tk_a), &config);
    cache.get_or_create("proxy-1", Some(&tk_b), &config);
    cache.get_or_create("proxy-2", Some(&tk_a), &config);

    // Prune proxy-1 — should remove both target-scoped breakers
    cache.prune(&["proxy-1".to_string()]);

    // proxy-1 targets should be gone (fresh breaker on re-create)
    let cb = cache.get_or_create("proxy-1", Some(&tk_a), &config);
    assert_eq!(cb.state_name(), "closed");

    // proxy-2 target should still exist
    assert!(cache.can_execute("proxy-2", Some(&tk_a), &config).is_ok());
}

#[test]
fn test_target_key_format() {
    assert_eq!(target_key("10.0.0.1", 8080), "10.0.0.1:8080");
    assert_eq!(
        target_key("backend.example.com", 443),
        "backend.example.com:443"
    );
}

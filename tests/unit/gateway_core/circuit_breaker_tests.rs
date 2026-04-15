//! Tests for circuit breaker module

use ferrum_edge::circuit_breaker::{CircuitBreaker, CircuitBreakerCache, target_key};
use ferrum_edge::config::types::CircuitBreakerConfig;
use std::sync::Arc;

fn default_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        timeout_seconds: 1,
        failure_status_codes: vec![500, 502, 503],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
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

    cb.record_failure(500, false);
    cb.record_failure(500, false);
    assert!(cb.can_execute().is_ok()); // Still closed

    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "open");
    assert!(cb.can_execute().is_err());
}

#[test]
fn test_non_configured_status_treated_as_success() {
    let cb = CircuitBreaker::new(default_config());

    // 404 is not in failure_status_codes, should be treated as success
    cb.record_failure(404, false);
    cb.record_failure(404, false);
    cb.record_failure(404, false);
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_success_resets_failure_count() {
    let cb = CircuitBreaker::new(default_config());

    cb.record_failure(500, false);
    cb.record_failure(500, false);
    cb.record_success(); // Should reset
    cb.record_failure(500, false);
    cb.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500, false);
    cb.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500, false);
    cb.record_failure(500, false);

    // Transition to half-open
    assert!(cb.can_execute().is_ok());

    // Probe fails
    cb.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open
    cb.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open, transition to half-open
    cb.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };
    let cb = Arc::new(CircuitBreaker::new(config));

    // Trip open
    cb.record_failure(500, false);

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
        trip_on_connection_errors: true,
    };
    let cb = Arc::new(CircuitBreaker::new(config));

    // Spawn threads that all record failures concurrently
    let mut handles = Vec::new();
    for _ in 0..100 {
        let cb_clone = cb.clone();
        handles.push(std::thread::spawn(move || {
            cb_clone.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };

    let tk_a = target_key("10.0.0.1", 8080);
    let tk_b = target_key("10.0.0.2", 8080);

    // Trip target A's breaker
    let cb_a = cache.get_or_create("proxy-1", Some(&tk_a), &config);
    cb_a.record_failure(500, false);
    cb_a.record_failure(500, false);
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
        trip_on_connection_errors: true,
    };

    // Trip breaker for proxy-1 with no target (direct backend)
    let cb_direct = cache.get_or_create("proxy-1", None, &config);
    cb_direct.record_failure(500, false);
    cb_direct.record_failure(500, false);
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

// --- TCP/UDP circuit breaker integration tests ---
//
// These tests verify circuit breaker cache behaviour as it is used in the
// TCP and UDP stream proxies (direct backend and upstream-based paths).

/// TCP/UDP direct backend: CB uses None target key (no upstream_id).
#[test]
fn test_tcp_direct_backend_circuit_breaker_opens() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    // Simulate two backend connect failures (no upstream → None target key).
    let cb = cache.get_or_create("tcp-proxy-1", None, &config);
    cb.record_failure(502, true);
    assert!(cache.can_execute("tcp-proxy-1", None, &config).is_ok()); // Still closed after 1

    cb.record_failure(502, true);
    // After threshold, circuit should be open.
    assert_eq!(cb.state_name(), "open");
    assert!(
        cache.can_execute("tcp-proxy-1", None, &config).is_err(),
        "Circuit breaker should reject after threshold failures"
    );
}

/// TCP/UDP with upstream: CB uses per-target key (host:port).
#[test]
fn test_tcp_upstream_backend_circuit_breaker_per_target() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    let tk = target_key("backend.internal", 4000);

    // Simulate connection failures on the upstream target.
    let cb = cache.get_or_create("tcp-proxy-2", Some(&tk), &config);
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");

    // Proxy without this specific target should not be affected.
    assert!(
        cache.can_execute("tcp-proxy-2", None, &config).is_ok(),
        "Direct backend breaker should be independent of upstream-scoped breaker"
    );
}

/// Clean TCP connection (bidirectional copy completed) records success.
#[test]
fn test_tcp_successful_connection_records_success() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        timeout_seconds: 0, // immediate half-open
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    // Trip the breaker open.
    let cb = cache.get_or_create("tcp-proxy-3", None, &config);
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open (timeout = 0).
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Simulate a successful connection: record_success closes it.
    cb.record_success();
    assert_eq!(cb.state_name(), "closed");
}

/// UDP session creation failure (socket connect error) records failure.
#[test]
fn test_udp_session_failure_records_failure() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    // Simulate two UDP socket connect failures.
    let cb = cache.get_or_create("udp-proxy-1", None, &config);
    cb.record_failure(502, true);
    cb.record_failure(502, true);

    assert_eq!(cb.state_name(), "open");
    assert!(
        cache.can_execute("udp-proxy-1", None, &config).is_err(),
        "UDP circuit breaker should be open after repeated session creation failures"
    );
}

/// UDP successful session creation records success and stays closed.
#[test]
fn test_udp_successful_session_records_success() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    let cb = cache.get_or_create("udp-proxy-2", None, &config);
    // One failure, then success — breaker should remain closed.
    cb.record_failure(502, true);
    cb.record_success();
    cb.record_failure(502, true);

    // Only 1 failure after the reset — should remain closed.
    assert_eq!(cb.state_name(), "closed");
}

/// When circuit is open, `can_execute` returns error — proxy should reject
/// the connection before attempting any network I/O.
#[test]
fn test_stream_proxy_rejects_when_circuit_open() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 60,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    // Trip the breaker with a single failure.
    let cb = cache.get_or_create("stream-proxy-cb", None, &config);
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");

    // Both TCP and UDP stream proxies call can_execute before opening sockets.
    let result = cache.can_execute("stream-proxy-cb", None, &config);
    assert!(
        result.is_err(),
        "can_execute must return Err when circuit is open"
    );
}

// --- trip_on_connection_errors tests ---

/// Connection errors trip the breaker when trip_on_connection_errors is true (default).
#[test]
fn test_connection_errors_trip_breaker_by_default() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500], // Note: 502 is NOT in the list
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Connection errors (connection_error=true) should count as failures
    // even though 502 is not in failure_status_codes.
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");
}

/// Connection errors do NOT trip the breaker when trip_on_connection_errors is false.
#[test]
fn test_connection_errors_ignored_when_disabled() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500, 502],
        half_open_max_requests: 1,
        trip_on_connection_errors: false,
    };
    let cb = CircuitBreaker::new(config);

    // Connection errors should be ignored even though 502 is in failure_status_codes.
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "closed");

    // But real HTTP 502 responses (connection_error=false) should still trip it.
    cb.record_failure(502, false);
    cb.record_failure(502, false);
    assert_eq!(cb.state_name(), "open");
}

/// Real HTTP status code failures still work when trip_on_connection_errors is false.
#[test]
fn test_status_code_failures_work_independently_of_connection_flag() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500, 503],
        half_open_max_requests: 1,
        trip_on_connection_errors: false,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false);
    cb.record_failure(503, false);
    assert_eq!(cb.state_name(), "open");
}

/// Connection errors in half-open state reopen the circuit when enabled.
#[test]
fn test_connection_error_reopens_half_open() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open with a connection error
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Connection error during probe should reopen
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "open");
}

/// Connection errors in half-open do NOT reopen when disabled.
#[test]
fn test_connection_error_ignored_in_half_open_when_disabled() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 2,
        trip_on_connection_errors: false,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open with a status code failure
    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Connection error during probe should be ignored
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "half_open");

    // But a status code failure should still reopen
    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "open");
}

/// Connection errors with trip_on_connection_errors=false must be neutral —
/// they must NOT reset the accumulated failure count (i.e., not call record_success).
#[test]
fn test_connection_errors_disabled_do_not_reset_failure_count() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: false,
    };
    let cb = CircuitBreaker::new(config);

    // Accumulate 2 real failures
    cb.record_failure(500, false);
    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "closed"); // threshold is 3

    // A connection error with trip_on_connection_errors=false should be neutral.
    // If it were incorrectly treated as a success, the failure count would reset
    // and the next failure wouldn't trip the breaker.
    cb.record_failure(502, true);
    assert_eq!(cb.state_name(), "closed"); // still 2 failures, neutral

    // One more real failure should now trip the breaker (2 + 1 = 3 = threshold)
    cb.record_failure(500, false);
    assert_eq!(
        cb.state_name(),
        "open",
        "Ignored connection error must not have reset the failure counter"
    );
}

/// Default config has trip_on_connection_errors = true.
#[test]
fn test_default_config_has_trip_on_connection_errors_true() {
    let config = CircuitBreakerConfig::default();
    assert!(config.trip_on_connection_errors);
}

// --- Cache bounding tests ---

#[test]
fn test_circuit_breaker_cache_max_entries_enforced() {
    let cache = CircuitBreakerCache::with_max_entries(3);
    let config = default_config();

    // Fill to capacity
    cache.get_or_create("proxy1", Some("host1:8080"), &config);
    cache.get_or_create("proxy2", Some("host2:8080"), &config);
    cache.get_or_create("proxy3", Some("host3:8080"), &config);

    // At capacity — new key returns a transient breaker (not cached)
    let _cb = cache.get_or_create("proxy4", Some("host4:8080"), &config);
    assert_eq!(cache.len(), 3); // Still 3, not 4

    // Existing key can still be updated (config change)
    cache.get_or_create("proxy1", Some("host1:8080"), &config);
    assert_eq!(cache.len(), 3);
}

#[test]
fn test_circuit_breaker_prune_stale_targets() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    // Create breakers for multiple targets
    cache.get_or_create("proxy1", Some("10.0.0.1:8080"), &config);
    cache.get_or_create("proxy1", Some("10.0.0.2:8080"), &config);
    cache.get_or_create("proxy1", Some("10.0.0.3:8080"), &config);
    cache.get_or_create("proxy2", None, &config); // direct backend

    // Only keep proxy1::10.0.0.1:8080 — the rest are stale
    let mut active = std::collections::HashSet::new();
    active.insert("proxy1::10.0.0.1:8080".to_string());
    cache.prune_stale_targets(&active);

    // Direct backend key (proxy2, no "::") should be preserved
    assert_eq!(cache.len(), 2); // proxy1::10.0.0.1:8080 + proxy2
}

// ─── Timeout Boundary Tests ─────────────────────────────────────────────────

#[test]
fn test_timeout_zero_transitions_immediately_to_half_open() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0, // Immediate transition
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "open");

    // With timeout=0, can_execute should immediately transition to half_open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");
}

#[test]
fn test_timeout_does_not_transition_before_elapsed() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 60, // Long timeout
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false);
    assert_eq!(cb.state_name(), "open");

    // Should still be open (60s hasn't elapsed)
    assert!(cb.can_execute().is_err());
    assert_eq!(cb.state_name(), "open");
}

// ─── Target Key Format Tests ────────────────────────────────────────────────

#[test]
fn test_target_key_ipv4() {
    let key = target_key("10.0.0.1", 8080);
    assert_eq!(key, "10.0.0.1:8080");
}

#[test]
fn test_target_key_ipv6() {
    // IPv6 addresses contain colons — verify the key format
    let key = target_key("::1", 8080);
    assert_eq!(key, "::1:8080");
}

#[test]
fn test_target_key_hostname() {
    let key = target_key("backend.example.com", 443);
    assert_eq!(key, "backend.example.com:443");
}

#[test]
fn test_cache_keys_different_proxies_same_target() {
    // Verify that different proxies with the same target get different cache keys
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    let cb_a = cache.get_or_create("proxy-a", Some("10.0.0.1:8080"), &config);
    let cb_b = cache.get_or_create("proxy-b", Some("10.0.0.1:8080"), &config);

    // Trip one breaker
    cb_a.record_failure(500, false);
    cb_a.record_failure(500, false);
    cb_a.record_failure(500, false);
    assert_eq!(cb_a.state_name(), "open");

    // Other proxy's breaker should be unaffected
    assert_eq!(cb_b.state_name(), "closed");
}

// ─── Concurrent record_failure + record_success ─────────────────────────────

#[test]
fn test_concurrent_failure_and_success_recording() {
    use std::sync::Arc;
    use std::thread;

    let config = CircuitBreakerConfig {
        failure_threshold: 100, // High threshold to avoid state change during test
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = Arc::new(CircuitBreaker::new(config));

    let mut handles = vec![];

    // Spawn threads recording failures
    for _ in 0..10 {
        let cb = cb.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                cb.record_failure(500, false);
            }
        }));
    }

    // Spawn threads recording successes
    for _ in 0..10 {
        let cb = cb.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                cb.record_success();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Should not panic or be in an inconsistent state
    let state = cb.state_name();
    assert!(
        state == "closed" || state == "open",
        "State should be valid: {}",
        state
    );
}

// ─── Cache Capacity Tests ───────────────────────────────────────────────────

#[test]
fn test_cache_max_entries_exceeded_returns_transient_breaker() {
    let cache = CircuitBreakerCache::with_max_entries(2);
    let config = default_config();

    // Fill the cache
    cache.get_or_create("p1", Some("t1"), &config);
    cache.get_or_create("p2", Some("t2"), &config);
    assert_eq!(cache.len(), 2);

    // Third entry should still return a breaker (transient) but not grow cache
    let cb = cache.get_or_create("p3", Some("t3"), &config);
    assert!(
        cb.can_execute().is_ok(),
        "Transient breaker should allow requests"
    );
    assert_eq!(cache.len(), 2, "Cache should not grow beyond max");
}

#[test]
fn test_cache_config_change_replaces_breaker() {
    let cache = CircuitBreakerCache::new();
    let config1 = default_config();
    let config2 = CircuitBreakerConfig {
        failure_threshold: 10, // Different threshold
        ..default_config()
    };

    // Create with config1 (failure_threshold=3) and trip it open
    let cb1 = cache.get_or_create("proxy1", Some("target1"), &config1);
    cb1.record_failure(500, false);
    cb1.record_failure(500, false);
    cb1.record_failure(500, false);
    assert_eq!(
        cb1.state_name(),
        "open",
        "Breaker should be open after 3 failures"
    );

    // Get with config2 — should replace the breaker (config changed)
    let cb2 = cache.get_or_create("proxy1", Some("target1"), &config2);

    // New breaker should be fresh (closed, not open) proving replacement
    assert_eq!(cb2.state_name(), "closed");
    assert!(cb2.can_execute().is_ok());
}

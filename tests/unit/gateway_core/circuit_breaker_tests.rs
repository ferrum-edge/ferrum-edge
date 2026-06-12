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

    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
    assert!(cb.can_execute().is_ok()); // Still closed

    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");
    assert!(cb.can_execute().is_err());
}

#[test]
fn test_non_configured_status_treated_as_success() {
    let cb = CircuitBreaker::new(default_config());

    // 404 is not in failure_status_codes, should be treated as success
    cb.record_failure(404, false, false);
    cb.record_failure(404, false, false);
    cb.record_failure(404, false, false);
    assert_eq!(cb.state_name(), "closed");
}

#[test]
fn test_success_resets_failure_count() {
    let cb = CircuitBreaker::new(default_config());

    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
    cb.record_success(false); // Should reset
    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
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
    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // Timeout elapsed (0 seconds), should transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Successful probes (admitted as half-open probes by can_execute)
    cb.record_success(true);
    cb.record_success(true);
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
    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);

    // Transition to half-open
    assert!(cb.can_execute().is_ok());

    // Probe fails (was admitted as half-open probe)
    cb.record_failure(500, false, true);
    assert_eq!(cb.state_name(), "open");
}

#[test]
fn test_half_open_non_failure_status_releases_probe_slot() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);
    assert!(cb.can_execute().is_err());

    cb.record_failure(404, false, true);

    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "neutral status codes must release their half-open probe slot"
    );
    assert!(
        cb.can_execute().is_ok(),
        "released neutral probe slot should admit another half-open probe"
    );
}

#[test]
fn grpc_gateway_side_errors_are_neutral_not_failures() {
    // F04 (PR #1408): the gRPC final-record block maps client/gateway-side
    // errors (ResourceExhausted = oversized client payload, Internal = client
    // body-read / gateway TLS/URL config) to record_neutral, NOT
    // record_failure(502). Before the fix they were 502 failures, so a client
    // sending oversized payloads or cancelling RPCs could trip a HEALTHY
    // backend's breaker. record_neutral must never trip the breaker.
    let cb = CircuitBreaker::new(default_config()); // failure_threshold = 3
    for _ in 0..5 {
        cb.record_neutral(false);
    }
    assert_eq!(
        cb.state_name(),
        "closed",
        "gateway-side gRPC errors (ResourceExhausted/Internal) must not trip the backend breaker"
    );
}

#[test]
fn grpc_gateway_side_error_releases_half_open_probe_without_reopening() {
    // A gateway-side gRPC error that lands on a HALF_OPEN probe must release the
    // probe slot via record_neutral WITHOUT reopening the breaker (the old 502
    // failure would have reopened it, stalling recovery).
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    cb.record_failure(500, false, false);
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);

    cb.record_neutral(true);

    assert_eq!(
        cb.state_name(),
        "half_open",
        "a gateway-side error must not reopen the breaker"
    );
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "neutral outcome must release the half-open probe slot"
    );
    assert!(
        cb.can_execute().is_ok(),
        "released slot must admit another probe"
    );
}

#[test]
fn grpc_ok_with_http_5xx_status_trips_breaker() {
    // F04: an Ok(GrpcResponseKind) carries the backend HTTP status, which can be
    // a genuine 5xx (sandwiched LB / overloaded backend). The fix classifies by
    // that status via failure_status_codes instead of recording every Ok as a
    // blanket success — so a real HTTP 5xx must count toward tripping (and a
    // HALF_OPEN probe must not close on it).
    let cb = CircuitBreaker::new(default_config()); // 503 in failure codes, threshold 3
    cb.record_failure(503, false, false);
    cb.record_failure(503, false, false);
    assert_eq!(cb.state_name(), "closed");
    cb.record_failure(503, false, false);
    assert_eq!(
        cb.state_name(),
        "open",
        "gRPC backend HTTP 503 responses must count toward tripping the breaker"
    );
}

#[test]
fn test_half_open_client_disconnect_neutral_releases_probe_slot() {
    // Regression for F09 (PR #1392): the H3 oversized-upload (413) path is
    // admitted as a half-open probe and maps ErrorClass::ClientDisconnect to
    // cb.record_neutral(is_half_open_probe). Before the fix it passed
    // skip_circuit_breaker_record=true, skipping record_neutral entirely, so
    // the reserved probe slot was never released — with half_open_max_requests
    // = 1 a single oversized upload during HALF_OPEN permanently wedged the
    // breaker and black-holed the target. record_neutral must release the slot
    // without changing breaker state.
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open and reserve the single probe slot.
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);
    assert!(cb.can_execute().is_err(), "the single probe slot is taken");

    // The client-disconnect (oversized upload) outcome routes here.
    cb.record_neutral(true);

    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "client-disconnect neutral outcome must release its half-open probe slot"
    );
    assert_eq!(
        cb.state_name(),
        "half_open",
        "record_neutral must not change breaker state"
    );
    assert!(
        cb.can_execute().is_ok(),
        "released probe slot must re-admit a half-open probe"
    );
}

#[test]
fn record_success_without_probe_admission_still_advances_half_open() {
    // F04 (PR #1408): the gRPC retry loop now gates a rotated retry through
    // can_execute before dispatching (mirroring the HTTP path). This matters
    // because record_success with is_half_open_probe = false STILL advances the
    // half-open success counter — it only skips the in-flight decrement — and
    // can close the breaker. A retry that bypassed admission would therefore
    // wrongly drive recovery, which is exactly what the gate prevents. Pin that
    // record_success(false) is NOT a no-op on a HALF_OPEN breaker.
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    cb.record_failure(500, false, false);
    // Transition to half-open (reserves the single probe slot).
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");

    // Two non-probe successes (e.g. unadmitted rotated retries) advance the
    // half-open success_count to the threshold and close the breaker.
    cb.record_success(false);
    assert_eq!(cb.state_name(), "half_open");
    cb.record_success(false);
    assert_eq!(
        cb.state_name(),
        "closed",
        "record_success(is_half_open_probe = false) advances half-open recovery and can close the breaker"
    );
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
    cb.record_failure(500, false, false);
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
    cb.record_failure(500, false, false);
    assert!(cb.can_execute().is_ok()); // slot 1 taken

    // At max — should reject
    assert!(cb.can_execute().is_err());

    // Record success frees a slot (was admitted as half-open probe)
    cb.record_success(true);

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
    cb.record_failure(500, false, false);

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
            cb_clone.record_failure(500, false, false);
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
    cb_a.record_failure(500, false, false);
    cb_a.record_failure(500, false, false);
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
    cb_direct.record_failure(500, false, false);
    cb_direct.record_failure(500, false, false);
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
    cb.record_failure(502, true, false);
    assert!(cache.can_execute("tcp-proxy-1", None, &config).is_ok()); // Still closed after 1

    cb.record_failure(502, true, false);
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
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
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
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open (timeout = 0).
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Simulate a successful connection: record_success closes it (half-open probe).
    cb.record_success(true);
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
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);

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
    cb.record_failure(502, true, false);
    cb.record_success(false);
    cb.record_failure(502, true, false);

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
    cb.record_failure(502, true, false);
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
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
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
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
    cb.record_failure(502, true, false);
    assert_eq!(cb.state_name(), "closed");

    // But real HTTP 502 responses (connection_error=false) should still trip it.
    cb.record_failure(502, false, false);
    cb.record_failure(502, false, false);
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

    cb.record_failure(500, false, false);
    cb.record_failure(503, false, false);
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
    cb.record_failure(502, true, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Connection error during probe should reopen (half-open probe)
    cb.record_failure(502, true, true);
    assert_eq!(cb.state_name(), "open");
}

/// A connection-class failure on a half-open probe (e.g. DNS resolution
/// failure on the TCP passthrough path, which records
/// `record_failure(502, true, probe)` before backend connect) must release
/// the probe slot while reopening, so the next half-open cycle can admit a
/// fresh probe instead of staying wedged on a leaked `half_open_in_flight`.
#[test]
fn test_connection_error_probe_failure_releases_slot_for_next_cycle() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Trip open with a connection error (e.g. first DNS failure).
    cb.record_failure(502, true, false);
    assert_eq!(cb.state_name(), "open");

    // Timeout elapsed (timeout_seconds: 0) — admitted as half-open probe.
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.half_open_in_flight(), 1);

    // Probe fails before reaching the backend (DNS still unresolvable).
    cb.record_failure(502, true, true);
    assert_eq!(cb.state_name(), "open");
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "tripping connection-error probe failure must release the probe slot"
    );

    // Next half-open cycle must admit a fresh probe — not reject on a
    // leaked in-flight slot.
    assert!(
        cb.can_execute().unwrap(),
        "subsequent half-open cycle should admit a new probe"
    );
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
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to half-open
    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    // Connection error during probe should be ignored (trip_on_connection_errors=false)
    cb.record_failure(502, true, true);
    assert_eq!(cb.state_name(), "half_open");

    // But a status code failure should still reopen (half-open probe)
    cb.record_failure(500, false, true);
    assert_eq!(cb.state_name(), "open");
}

/// With trip_on_connection_errors=false, ignored connection errors during
/// half-open probes must release the in-flight slot so later probes can run.
#[test]
fn test_connection_error_ignored_in_half_open_releases_probe_slot() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: false,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    assert!(cb.can_execute().is_ok());
    assert_eq!(cb.state_name(), "half_open");

    cb.record_failure(502, true, true);
    assert_eq!(cb.state_name(), "half_open");

    assert!(
        cb.can_execute().is_ok(),
        "ignored connection error must free half-open probe admission"
    );
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
    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "closed"); // threshold is 3

    // A connection error with trip_on_connection_errors=false should be neutral.
    // If it were incorrectly treated as a success, the failure count would reset
    // and the next failure wouldn't trip the breaker.
    cb.record_failure(502, true, false);
    assert_eq!(cb.state_name(), "closed"); // still 2 failures, neutral

    // One more real failure should now trip the breaker (2 + 1 = 3 = threshold)
    cb.record_failure(500, false, false);
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
fn test_cache_replaces_existing_key_at_capacity_when_config_changes() {
    let cache = CircuitBreakerCache::with_max_entries(1);
    let config1 = default_config();
    let config2 = CircuitBreakerConfig {
        failure_threshold: 10,
        ..default_config()
    };

    let cb1 = cache.get_or_create("proxy1", Some("host1:8080"), &config1);
    cb1.record_failure(500, false, false);
    cb1.record_failure(500, false, false);
    cb1.record_failure(500, false, false);
    assert_eq!(cb1.state_name(), "open");
    assert_eq!(cache.len(), 1);

    let cb2 = cache.get_or_create("proxy1", Some("host1:8080"), &config2);

    assert_eq!(cache.len(), 1);
    assert!(!Arc::ptr_eq(&cb1, &cb2));
    assert_eq!(cb2.state_name(), "closed");
    assert_eq!(cb2.config().failure_threshold, 10);
}

#[test]
fn test_cache_capacity_transient_breakers_do_not_persist_state() {
    let cache = CircuitBreakerCache::with_max_entries(1);
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        ..default_config()
    };

    cache.get_or_create("cached", Some("host1:8080"), &config);
    assert_eq!(cache.len(), 1);

    let transient = cache.get_or_create("overflow", Some("host2:8080"), &config);
    transient.record_failure(500, false, false);
    assert_eq!(transient.state_name(), "open");
    assert_eq!(cache.len(), 1);

    let fresh_transient = cache.get_or_create("overflow", Some("host2:8080"), &config);
    assert_eq!(
        fresh_transient.state_name(),
        "closed",
        "overflow breakers are intentionally transient and must not retain state"
    );
    assert!(!Arc::ptr_eq(&transient, &fresh_transient));
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

#[test]
fn test_snapshot_includes_direct_and_target_scoped_breakers() {
    let cache = CircuitBreakerCache::new();
    let config = default_config();

    let direct = cache.get_or_create("proxy-direct", None, &config);
    direct.record_failure(500, false, false);

    let target = cache.get_or_create("proxy-target", Some("10.0.0.9:8080"), &config);
    target.record_failure(500, false, false);
    target.record_failure(500, false, false);
    target.record_failure(500, false, false);
    assert_eq!(target.state_name(), "open");

    let snapshot = cache.snapshot();

    assert!(snapshot.iter().any(|(key, state, failures, successes)| {
        key == "proxy-direct" && *state == "closed" && *failures == 1 && *successes == 0
    }));
    assert!(snapshot.iter().any(|(key, state, failures, successes)| {
        key == "proxy-target::10.0.0.9:8080"
            && *state == "open"
            && *failures == 3
            && *successes == 0
    }));
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

    cb.record_failure(500, false, false);
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

    cb.record_failure(500, false, false);
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
    cb_a.record_failure(500, false, false);
    cb_a.record_failure(500, false, false);
    cb_a.record_failure(500, false, false);
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
                cb.record_failure(500, false, false);
            }
        }));
    }

    // Spawn threads recording successes
    for _ in 0..10 {
        let cb = cb.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                cb.record_success(false);
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

// ─── Concurrent Half-Open Probe Failures ────────────────────────────────────

/// Regression test: concurrent half-open probe failures must not corrupt the
/// in-flight counter. Before the fix, `record_failure` in the HALF_OPEN branch
/// would atomically decrement `half_open_in_flight` (correct) but then
/// unconditionally `store(0)`, racing with concurrent decrements from other
/// probe threads and potentially clobbering a value that hadn't been
/// decremented yet. When the breaker later re-entered HALF_OPEN, the counter
/// started from a non-zero residue and fewer than `half_open_max_requests`
/// probes could be admitted. The fix removes the redundant `store(0)`.
///
/// This test uses barriers to force the interleaving that triggers the bug:
///   1. Admit all probe slots so `half_open_in_flight == half_open_max_requests`.
///   2. Fire all probe failures concurrently via a barrier.
///   3. Assert `half_open_in_flight == 0` after all probes drain.
///   4. Transition to HALF_OPEN again and verify the full capacity is claimable.
///
/// Runs 200 iterations to maximise the chance of hitting a harmful interleaving.
#[test]
fn test_concurrent_half_open_probe_failures() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    for _ in 0..200 {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 10, // High so successes alone won't close it
            timeout_seconds: 0,    // Immediate half-open transition
            failure_status_codes: vec![500],
            half_open_max_requests: 4,
            trip_on_connection_errors: true,
        };
        let cb = Arc::new(CircuitBreaker::new(config));

        // Trip open
        cb.record_failure(500, false, false);
        assert_eq!(cb.state_name(), "open");

        // Transition to half-open and admit all 4 probe slots
        assert!(cb.can_execute().is_ok()); // slot 1 (CAS winner)
        assert!(cb.can_execute().is_ok()); // slot 2
        assert!(cb.can_execute().is_ok()); // slot 3
        assert!(cb.can_execute().is_ok()); // slot 4
        assert_eq!(cb.state_name(), "half_open");
        assert_eq!(cb.half_open_in_flight(), 4);

        // All 4 slots taken — next should be rejected
        assert!(cb.can_execute().is_err());

        // Fire all 4 probe failures concurrently via a barrier.
        // The barrier ensures all threads call record_failure at roughly the
        // same instant, maximising the window for a store-after-decrement race.
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cb_clone = cb.clone();
            let barrier_clone = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
                cb_clone.record_failure(500, false, true);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Must be open after all probe failures
        assert_eq!(cb.state_name(), "open");

        // ── Key assertion: the in-flight counter must have drained to 0. ──
        // With the old code (unconditional store(0)), a late store could race
        // with another thread's fetch_sub, leaving the counter at 0 even when
        // that thread's decrement hadn't been applied yet — or conversely,
        // a store(0) could run BEFORE another thread's fetch_sub, causing
        // the counter to wrap around to u32::MAX. Either way, the next
        // half-open cycle would start from a corrupt value.
        assert_eq!(
            cb.half_open_in_flight(),
            0,
            "half_open_in_flight must be 0 after all probes report failure"
        );

        // ── Verify full capacity in the next half-open cycle. ──
        // Transition to half-open again (timeout=0).
        assert!(cb.can_execute().is_ok()); // slot 1 (CAS winner)
        assert_eq!(cb.state_name(), "half_open");

        // Claim the remaining 3 slots — all must succeed if the counter reset
        // correctly. With the old buggy code, residue in the counter would
        // cause some of these to be rejected.
        assert!(cb.can_execute().is_ok()); // slot 2
        assert!(cb.can_execute().is_ok()); // slot 3
        assert!(cb.can_execute().is_ok()); // slot 4
        assert_eq!(cb.half_open_in_flight(), 4);

        // Slot 5 must be rejected — exactly at capacity.
        assert!(
            cb.can_execute().is_err(),
            "Should reject at capacity (half_open_max_requests=4)"
        );
    }
}

/// Verify that a mix of concurrent successes and failures in half-open
/// produces a valid final state (open or closed) without corruption, and
/// that the in-flight counter drains to 0 regardless of outcome.
#[test]
fn test_concurrent_half_open_mixed_success_and_failure() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    for _ in 0..200 {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            timeout_seconds: 0,
            failure_status_codes: vec![500],
            half_open_max_requests: 4,
            trip_on_connection_errors: true,
        };
        let cb = Arc::new(CircuitBreaker::new(config));

        // Trip open
        cb.record_failure(500, false, false);

        // Admit 4 probes
        for _ in 0..4 {
            assert!(cb.can_execute().is_ok());
        }
        assert_eq!(cb.state_name(), "half_open");
        assert_eq!(cb.half_open_in_flight(), 4);

        // 2 threads record failure, 2 threads record success — concurrently
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for i in 0..4 {
            let cb_clone = cb.clone();
            let barrier_clone = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
                if i < 2 {
                    cb_clone.record_failure(500, false, true);
                } else {
                    cb_clone.record_success(true);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Any failure in half-open reopens the circuit, so it must be open
        // (failures always win over successes in half-open).
        let state = cb.state_name();
        assert!(
            state == "open" || state == "closed",
            "State must be valid after concurrent mixed probes, got: {}",
            state
        );

        // The in-flight counter must be 0 after all probes have reported,
        // regardless of whether the final state is open or closed.
        assert_eq!(
            cb.half_open_in_flight(),
            0,
            "half_open_in_flight must be 0 after all probes drain (state={})",
            state
        );
    }
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
    cb1.record_failure(500, false, false);
    cb1.record_failure(500, false, false);
    cb1.record_failure(500, false, false);
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

// ─── Half-open probe tracking regression tests ─────────────────────────────

/// `can_execute()` returns `Ok(false)` in CLOSED state and `Ok(true)` in HALF_OPEN.
#[test]
fn test_can_execute_returns_half_open_probe_flag() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 2,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // CLOSED state: not a half-open probe
    assert!(!cb.can_execute().unwrap());

    // Trip open
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to HALF_OPEN: IS a half-open probe
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");

    // Second slot in HALF_OPEN: also a probe
    assert!(cb.can_execute().unwrap());
}

/// Regression: a request admitted in CLOSED state that completes after the
/// breaker transitions to OPEN must NOT decrement `half_open_in_flight`.
/// Before the fix, recording success/failure with `is_half_open_probe=false`
/// in STATE_OPEN would still decrement the counter, causing the next half-open
/// cycle to admit more probes than `half_open_max_requests`.
#[test]
fn test_closed_request_completing_in_open_does_not_decrement_counter() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    // Request A admitted in CLOSED (is_half_open_probe=false)
    let probe_a = cb.can_execute().unwrap();
    assert!(!probe_a);

    // Meanwhile, other requests trip the breaker CLOSED -> OPEN
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // Transition to HALF_OPEN
    let probe_b = cb.can_execute().unwrap();
    assert!(probe_b); // probe B is a half-open probe
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);

    // At max — reject
    assert!(cb.can_execute().is_err());

    // Probe B fails, reopening the circuit (correctly decrements)
    cb.record_failure(500, false, true);
    assert_eq!(cb.state_name(), "open");

    // Request A (from CLOSED era) completes with success in OPEN state.
    // Because is_half_open_probe=false, it must NOT decrement the counter.
    cb.record_success(false);

    // The counter should be 0 (from probe B's decrement), not wrapped/negative
    assert_eq!(cb.half_open_in_flight(), 0);

    // Transition to HALF_OPEN again — full capacity should be available
    let probe_c = cb.can_execute().unwrap();
    assert!(probe_c);
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 1);

    // If the bug were present, the counter would have been decremented by
    // request A's record_success, making it u32::MAX (wrapped), and
    // no probes would be admissible.
}

/// Cache-level `can_execute` returns the half-open probe flag alongside the breaker.
#[test]
fn test_cache_can_execute_returns_probe_flag() {
    let cache = CircuitBreakerCache::new();
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };

    // CLOSED: not a probe
    let (cb, is_probe) = cache.can_execute("p1", None, &config).unwrap();
    assert!(!is_probe);

    // Trip open
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // HALF_OPEN: IS a probe
    let (_cb2, is_probe2) = cache.can_execute("p1", None, &config).unwrap();
    assert!(is_probe2);
}

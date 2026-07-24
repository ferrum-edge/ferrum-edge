//! Tests for circuit breaker module

use ferrum_edge::circuit_breaker::{CircuitBreaker, CircuitBreakerCache, target_key};
use ferrum_edge::config::types::CircuitBreakerConfig;
use std::sync::Arc;
use std::time::Duration;

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
fn open_state_half_open_straggler_does_not_refresh_recovery_timeout() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 60,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);

    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");
    let opened_at = cb.last_failure_epoch_ms();
    assert!(opened_at > 0);

    std::thread::sleep(Duration::from_millis(10));
    cb.record_failure(500, false, true);

    assert_eq!(
        cb.last_failure_epoch_ms(),
        opened_at,
        "OPEN-state half-open probe stragglers must not restart the recovery timer"
    );
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

/// Concurrent same-key cold creates must share one `Arc` (no detached breakers).
#[test]
fn test_concurrent_same_key_creation_shares_arc() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const THREADS: usize = 32;
    let cache = Arc::new(CircuitBreakerCache::with_max_entries(100));
    let config = default_config();
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let cache = Arc::clone(&cache);
        let config = config.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            cache.get_or_create("proxy-shared", Some("host:8080"), &config)
        }));
    }

    let results: Vec<Arc<CircuitBreaker>> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    let first = &results[0];
    for cb in &results[1..] {
        assert!(
            Arc::ptr_eq(first, cb),
            "concurrent same-key creates must return the same Arc"
        );
    }
    assert_eq!(cache.len(), 1);
}

/// Failures recorded across concurrent same-key callers must open one shared breaker.
#[test]
fn test_concurrent_same_key_failures_open_shared_breaker() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const THREADS: usize = 8;
    let cache = Arc::new(CircuitBreakerCache::with_max_entries(100));
    let config = CircuitBreakerConfig {
        failure_threshold: THREADS as u32,
        ..default_config()
    };
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let cache = Arc::clone(&cache);
        let config = config.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let cb = cache.get_or_create("proxy-fail", Some("host:8080"), &config);
            cb.record_failure(500, false, false);
            cb
        }));
    }

    let results: Vec<Arc<CircuitBreaker>> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    let first = &results[0];
    for cb in &results[1..] {
        assert!(Arc::ptr_eq(first, cb));
    }
    assert_eq!(first.state_name(), "open");
    assert_eq!(cache.len(), 1);
}

/// Concurrent changed-config replacement must publish one new shared generation.
#[test]
fn test_concurrent_config_replacement_shares_new_generation() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const THREADS: usize = 32;
    let cache = Arc::new(CircuitBreakerCache::with_max_entries(100));
    let config1 = default_config();
    let config2 = CircuitBreakerConfig {
        failure_threshold: 10,
        ..default_config()
    };

    let old = cache.get_or_create("proxy-replace", Some("host:8080"), &config1);
    old.record_failure(500, false, false);
    assert_eq!(old.state_name(), "closed");

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let cache = Arc::clone(&cache);
        let config2 = config2.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            cache.get_or_create("proxy-replace", Some("host:8080"), &config2)
        }));
    }

    let results: Vec<Arc<CircuitBreaker>> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    let first = &results[0];
    for cb in &results[1..] {
        assert!(
            Arc::ptr_eq(first, cb),
            "concurrent config replacement must converge on one new Arc"
        );
    }
    assert!(!Arc::ptr_eq(&old, first));
    assert_eq!(first.config().failure_threshold, 10);
    assert_eq!(first.state_name(), "closed");
    assert_eq!(cache.len(), 1);
}

/// Concurrent distinct-key cold admits must never exceed `max_entries`.
#[test]
fn test_concurrent_distinct_key_burst_respects_max_entries() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const MAX_ENTRIES: usize = 8;
    const THREADS: usize = 64;
    let cache = Arc::new(CircuitBreakerCache::with_max_entries(MAX_ENTRIES));
    let config = default_config();
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for i in 0..THREADS {
        let cache = Arc::clone(&cache);
        let config = config.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let proxy = format!("proxy-{i}");
            let target = format!("host-{i}:8080");
            cache.get_or_create(&proxy, Some(&target), &config)
        }));
    }

    let _results: Vec<Arc<CircuitBreaker>> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    assert!(
        cache.len() <= MAX_ENTRIES,
        "cache length {} exceeded max_entries {}",
        cache.len(),
        MAX_ENTRIES
    );
    assert_eq!(cache.len(), MAX_ENTRIES);
}

/// Full-cache overflow returns a fresh transient breaker that is not retained.
#[test]
fn test_full_cache_overflow_returns_uncached_transient_breaker() {
    let cache = CircuitBreakerCache::with_max_entries(1);
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        ..default_config()
    };

    let cached = cache.get_or_create("cached", Some("host1:8080"), &config);
    assert_eq!(cache.len(), 1);

    let transient = cache.get_or_create("overflow", Some("host2:8080"), &config);
    assert!(!Arc::ptr_eq(&cached, &transient));
    transient.record_failure(500, false, false);
    assert_eq!(transient.state_name(), "open");
    assert_eq!(cache.len(), 1, "overflow must not grow the cache");

    // Documented full-cache behavior: overflow breakers are not cached, so a
    // later call for the same overflow key gets a fresh closed instance.
    let again = cache.get_or_create("overflow", Some("host2:8080"), &config);
    assert!(!Arc::ptr_eq(&transient, &again));
    assert_eq!(again.state_name(), "closed");
    assert_eq!(cache.len(), 1);

    // Existing key remains replaceable at capacity.
    let config2 = CircuitBreakerConfig {
        failure_threshold: 9,
        ..default_config()
    };
    let replaced = cache.get_or_create("cached", Some("host1:8080"), &config2);
    assert!(!Arc::ptr_eq(&cached, &replaced));
    assert_eq!(replaced.config().failure_threshold, 9);
    assert_eq!(cache.len(), 1);
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

/// Stress: race `can_execute()` against probe-failure reopens and successes,
/// asserting the half-open in-flight count never exceeds `half_open_max_requests`
/// and the breaker is never wedged.
///
/// This targets the three transition/admission races that fall out of tracking
/// `state` and the probe counter in SEPARATE atomics: over-admission during a
/// reopen (the counter is cleared while the state is still HALF_OPEN),
/// admit-after-reopen (a delayed admission increments the counter after the
/// breaker reopened), and a wedged HALF_OPEN with no admitted request to release
/// a slot. The packed `(state, count)` atomic makes every transition and
/// admission a single CAS, so the bound holds and the breaker always recovers.
///
/// Unlike the sequential-admit tests above, `can_execute()` here runs
/// CONCURRENTLY with the reopen — the only way to exercise those races.
#[test]
fn test_half_open_bound_and_no_wedge_under_admit_reopen_race_stress() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::thread;

    const MAX: u32 = 4;
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1000, // keep it churning in half-open, rarely closing
        timeout_seconds: 0,      // a reopen is immediately re-admittable
        failure_status_codes: vec![500],
        half_open_max_requests: MAX,
        trip_on_connection_errors: true,
    };
    let cb = Arc::new(CircuitBreaker::new(config));
    cb.record_failure(500, false, false); // trip OPEN

    let stop = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU32::new(0));

    // Monitor: continuously sample the in-flight count and track the peak. If
    // any admission/transition race over-admits, the peak exceeds MAX.
    let monitor = {
        let cb = cb.clone();
        let stop = stop.clone();
        let peak = peak.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                peak.fetch_max(cb.half_open_in_flight(), Ordering::Relaxed);
            }
            peak.fetch_max(cb.half_open_in_flight(), Ordering::Relaxed);
        })
    };

    // Workers: hammer the admit → release/reopen cycle so `can_execute()` races
    // concurrent reopens. Every admitted probe is released (via a success or a
    // reopening failure), so no slot is leaked across the run.
    let mut handles = Vec::new();
    for t in 0..8u32 {
        let cb = cb.clone();
        handles.push(thread::spawn(move || {
            for i in 0..20_000u32 {
                // Preserve the probe flag `can_execute()` returns: only a request
                // admitted AS a half-open probe (`Ok(true)`) may complete as one.
                // A CLOSED-state admission (`Ok(false)`) must record as a
                // non-probe — passing `true` there would release a half-open slot
                // the request never held (corrupting the in-flight count) and run
                // a closed-state failure through the probe-reopen path, masking
                // the admission bound this test validates.
                if let Ok(is_probe) = cb.can_execute() {
                    if t.wrapping_add(i) % 3 == 0 {
                        cb.record_failure(500, false, is_probe); // reopen iff a probe
                    } else {
                        cb.record_success(is_probe);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    monitor.join().unwrap();

    let observed_peak = peak.load(Ordering::Relaxed);
    assert!(
        observed_peak <= MAX,
        "half_open_in_flight peaked at {observed_peak}, exceeding the configured \
         max {MAX} — a transition/admission race over-admitted probes"
    );

    // Every admitted probe was released, so no slot is held now. The breaker
    // must NOT be wedged: a fresh request can still be admitted (OPEN re-admits
    // immediately at timeout=0, HALF_OPEN admits a free slot, CLOSED admits as a
    // non-probe). A wedge would strand it HALF_OPEN at capacity with no holder.
    assert!(
        cb.half_open_in_flight() <= MAX,
        "post-run in_flight {} exceeds max {MAX}",
        cb.half_open_in_flight()
    );
    assert!(
        cb.can_execute().is_ok(),
        "breaker wedged after admit/reopen churn: state={} in_flight={}",
        cb.state_name(),
        cb.half_open_in_flight()
    );
}

/// A half-open probe whose failure arrives only AFTER a sibling has already
/// closed the breaker is processed against the CURRENT closed state: it counts
/// toward the closed-state `failure_threshold` and must NOT reopen the recovered
/// breaker. A probe that observes CLOSED cannot be distinguished from an
/// arbitrarily-stale straggler (one that outlived a full reopen→close cycle)
/// without per-probe half-open generation tracking, so reopening here would let
/// a long-hung straggler trip a breaker that has since recovered. The
/// reopen-on-any-probe-failure rule still applies WHILE the breaker is HALF_OPEN
/// (exercised by the admit/reopen stress test above).
#[test]
fn half_open_probe_failure_after_recovery_counts_toward_threshold_not_reopen() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3, // > 1 so a single counted failure does not trip
        success_threshold: 1, // one success closes the breaker
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 2, // admit two probes so one can straggle
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    for _ in 0..3 {
        cb.record_failure(500, false, false);
    }
    assert_eq!(cb.state_name(), "open");

    // Admit two half-open probes.
    assert!(cb.can_execute().unwrap());
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(cb.half_open_in_flight(), 2);

    // One probe succeeds and closes the breaker (success_threshold = 1) while the
    // other is still nominally "in flight".
    cb.record_success(true);
    assert_eq!(
        cb.state_name(),
        "closed",
        "the sibling success must recover the breaker"
    );

    // The straggler now fails, observing the breaker already CLOSED. It must be
    // counted as a single closed-state failure (1 < threshold 3) and must NOT
    // reopen the recovered breaker, nor leak its slot.
    cb.record_failure(500, false, true);
    assert_eq!(
        cb.state_name(),
        "closed",
        "a probe failure arriving after recovery must not reopen the breaker"
    );
    assert_eq!(
        cb.failure_count(),
        1,
        "the straggler failure is counted toward the closed-state threshold, not dropped"
    );
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "the straggler must not leak a slot"
    );

    // Two more closed-state failures reach the threshold and trip normally,
    // confirming the straggler genuinely counted rather than being special-cased.
    cb.record_failure(500, false, false);
    cb.record_failure(500, false, false);
    assert_eq!(
        cb.state_name(),
        "open",
        "the threshold is reached via the counted failures"
    );
}

#[test]
fn open_epoch_is_visible_to_a_probe_admitted_immediately_after_open() {
    // #1649 R5 finding 2: the open generation must be published BEFORE OPEN
    // becomes observable, so a request that observes OPEN and immediately
    // re-enters HALF_OPEN (possible because `timeout_seconds == 0`) captures the
    // NEW generation — never the pre-open value. A deferred streaming outcome
    // compares the captured generation at completion, so capturing the stale
    // generation would wrongly neutralize a valid probe and the breaker could
    // never heal/reopen. This single-threaded test asserts the observable
    // invariant the ordering fix guarantees.
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0, // OPEN is immediately re-admissible as HALF_OPEN
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    assert_eq!(cb.open_epoch(), 0, "fresh breaker starts at generation 0");

    // CLOSED -> OPEN advances the generation.
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");
    let gen_after_open = cb.open_epoch();
    assert_eq!(gen_after_open, 1, "opening advances the generation");

    // A probe admitted immediately after open observes the NEW generation — the
    // increment is published with (not after) the OPEN/HALF_OPEN transition.
    assert!(
        cb.can_execute().unwrap(),
        "timeout=0 admits a probe at once"
    );
    assert_eq!(cb.state_name(), "half_open");
    assert_eq!(
        cb.open_epoch(),
        gen_after_open,
        "HALF_OPEN admission does not change the generation (same open cycle)"
    );

    // Reopening (a probe fails in HALF_OPEN) advances the generation again.
    cb.record_failure(500, false, true);
    assert_eq!(cb.state_name(), "open");
    assert_eq!(
        cb.open_epoch(),
        gen_after_open + 1,
        "reopening after a probe failure advances the generation"
    );
}

#[test]
fn peek_is_read_only_and_does_not_create_or_resurrect() {
    // #1649 R8: the deferred stale check must inspect the cached breaker WITHOUT
    // mutating the cache. `peek` returns None for an absent key (never inserting),
    // and after a config reload it returns the CURRENT cached breaker — so the
    // stale check can never write a request-scoped (old-config) breaker back in.
    let cache = CircuitBreakerCache::new();
    let cfg_a = default_config();
    let tk = target_key("10.0.0.1", 8080);

    // Absent key: peek returns None and must NOT create an entry.
    assert!(cache.peek("proxy-x", Some(&tk)).is_none());
    assert_eq!(cache.len(), 0, "peek must not insert a breaker");

    // After a real admission the breaker is cached and peek observes it.
    let _ = cache.can_execute("proxy-x", Some(&tk), &cfg_a);
    assert_eq!(cache.len(), 1);
    assert_eq!(
        cache
            .peek("proxy-x", Some(&tk))
            .expect("breaker is cached")
            .config()
            .failure_threshold,
        cfg_a.failure_threshold,
        "peek observes the cached breaker's config"
    );

    // A config reload replaces the cached breaker; peek returns the NEW one, and
    // the cache still holds exactly one entry (no resurrection of the old config).
    let cfg_b = CircuitBreakerConfig {
        failure_threshold: cfg_a.failure_threshold + 5,
        ..default_config()
    };
    let _new = cache.get_or_create("proxy-x", Some(&tk), &cfg_b);
    assert_eq!(cache.len(), 1, "reload replaces in place");
    let peeked_b = cache
        .peek("proxy-x", Some(&tk))
        .expect("new breaker is cached");
    assert_eq!(
        peeked_b.config().failure_threshold,
        cfg_b.failure_threshold,
        "peek returns the current (reloaded) config, never resurrecting the old one"
    );
}

#[test]
fn open_generation_is_preserved_across_non_open_transitions() {
    // #1649 R7: the generation is packed into the same atomic as state+count and
    // must be PRESERVED by every non-open transition (probe admission, slot
    // release, recovery/close) and advanced ONLY by opens. A packing bug that
    // dropped or mutated the generation on a slot release or a close would silently
    // break the deferred-streaming stale check. Drive a full open → probe →
    // recover → re-trip cycle and assert the generation only moves on opens.
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2, // two probes recover -> exercises slot churn + close
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 2,
        trip_on_connection_errors: true,
    };
    let cb = CircuitBreaker::new(config);
    assert_eq!(cb.open_epoch(), 0);

    cb.record_failure(500, false, false); // CLOSED -> OPEN, gen 1
    assert_eq!(cb.state_name(), "open");
    assert_eq!(cb.open_epoch(), 1);

    // Admit two probes (slot acquisitions) — generation preserved.
    assert!(cb.can_execute().unwrap());
    assert!(cb.can_execute().unwrap());
    assert_eq!(cb.half_open_in_flight(), 2);
    assert_eq!(cb.open_epoch(), 1, "admission preserves the generation");

    // Two successes release slots and close the breaker (recovery) — generation
    // preserved (a close is not a new open cycle).
    cb.record_success(true);
    cb.record_success(true);
    assert_eq!(cb.state_name(), "closed");
    assert_eq!(cb.half_open_in_flight(), 0);
    assert_eq!(
        cb.open_epoch(),
        1,
        "recovery/close and slot releases preserve the generation"
    );

    // Re-trip: a brand-new open cycle advances the generation again.
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");
    assert_eq!(cb.open_epoch(), 2, "a fresh open advances the generation");
}

#[test]
fn can_execute_with_admission_epoch_returns_the_admitted_generation() {
    // #1649 R6 finding 3: the admission epoch must reflect the generation the
    // request is admitted under. A CLOSED admission captures the last open
    // generation; a HALF_OPEN probe captures the generation it is probing. (The
    // pre-admission snapshot also guarantees the captured value is never NEWER than
    // the admission generation, so a concurrent open can only neutralize — never
    // wrongly heal — a deferred outcome; that race is not reproducible
    // single-threaded, but the per-state values are asserted here.)
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    };
    let cache = CircuitBreakerCache::new();
    let proxy_id = "epoch-proxy";
    let tk = target_key("10.0.0.1", 8080);

    // CLOSED admission captures generation 0 and is not a probe.
    let (_cb, is_probe, epoch) = cache
        .can_execute_with_admission_epoch(proxy_id, Some(&tk), &config)
        .expect("closed admits");
    assert!(!is_probe, "closed-state admission is not a half-open probe");
    assert_eq!(epoch, 0, "closed admission captures the current generation");

    // Trip the breaker (generation -> 1).
    let (cb, _, _) = cache
        .can_execute_with_admission_epoch(proxy_id, Some(&tk), &config)
        .expect("still closed");
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");

    // The next admission (timeout=0) is a HALF_OPEN probe and captures generation 1
    // — the cycle it is probing — not the pre-trip generation 0.
    let (_cb, is_probe, epoch) = cache
        .can_execute_with_admission_epoch(proxy_id, Some(&tk), &config)
        .expect("half-open admits a probe");
    assert!(is_probe, "open+timeout=0 admits a half-open probe");
    assert_eq!(
        epoch, 1,
        "the probe captures the generation it is probing, not the pre-open value"
    );
}

//! Tests for retry logic module

use ferrum_gateway::config::types::{BackoffStrategy, RetryConfig};
use ferrum_gateway::retry::{BackendResponse, ResponseBody, retry_delay, should_retry};
use std::collections::HashMap;
use std::time::Duration;

fn default_config() -> RetryConfig {
    RetryConfig::default()
}

fn http_response(status_code: u16) -> BackendResponse {
    BackendResponse {
        status_code,
        body: ResponseBody::Buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
    }
}

fn connection_failure() -> BackendResponse {
    BackendResponse {
        status_code: 502,
        body: ResponseBody::Buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: true,
    }
}

#[test]
fn test_should_retry_on_retryable_status() {
    let config = default_config();
    assert!(should_retry(&config, "GET", &http_response(502), 0));
    assert!(should_retry(&config, "GET", &http_response(503), 0));
    assert!(should_retry(&config, "GET", &http_response(504), 0));
}

#[test]
fn test_should_not_retry_on_success() {
    let config = default_config();
    assert!(!should_retry(&config, "GET", &http_response(200), 0));
    assert!(!should_retry(&config, "GET", &http_response(404), 0));
}

#[test]
fn test_should_not_retry_post_by_default() {
    let config = default_config();
    assert!(!should_retry(&config, "POST", &http_response(502), 0));
    assert!(!should_retry(&config, "PATCH", &http_response(502), 0));
}

#[test]
fn test_should_retry_put_and_delete() {
    let config = default_config();
    assert!(should_retry(&config, "PUT", &http_response(503), 0));
    assert!(should_retry(&config, "DELETE", &http_response(503), 0));
}

#[test]
fn test_max_retries_exceeded() {
    let config = RetryConfig {
        max_retries: 2,
        ..default_config()
    };
    assert!(should_retry(&config, "GET", &http_response(502), 0));
    assert!(should_retry(&config, "GET", &http_response(502), 1));
    assert!(!should_retry(&config, "GET", &http_response(502), 2));
}

#[test]
fn test_fixed_backoff() {
    let config = RetryConfig {
        backoff: BackoffStrategy::Fixed { delay_ms: 100 },
        ..default_config()
    };
    assert_eq!(retry_delay(&config, 0), Duration::from_millis(100));
    assert_eq!(retry_delay(&config, 5), Duration::from_millis(100));
}

#[test]
fn test_exponential_backoff() {
    let config = RetryConfig {
        backoff: BackoffStrategy::Exponential {
            base_ms: 100,
            max_ms: 5000,
        },
        ..default_config()
    };
    // Jitter produces values in [capped/2, capped*3/2) capped at max_ms.
    // Attempt 0: base=100, jitter range [50, 150)
    let d0 = retry_delay(&config, 0).as_millis();
    assert!((50..150).contains(&d0), "attempt 0: got {}ms", d0);
    // Attempt 1: base=200, jitter range [100, 300)
    let d1 = retry_delay(&config, 1).as_millis();
    assert!((100..300).contains(&d1), "attempt 1: got {}ms", d1);
    // Attempt 2: base=400, jitter range [200, 600)
    let d2 = retry_delay(&config, 2).as_millis();
    assert!((200..600).contains(&d2), "attempt 2: got {}ms", d2);
    // Attempt 3: base=800, jitter range [400, 1200)
    let d3 = retry_delay(&config, 3).as_millis();
    assert!((400..1200).contains(&d3), "attempt 3: got {}ms", d3);
    // Should cap at max_ms
    let d10 = retry_delay(&config, 10).as_millis();
    assert!(
        (2500..=5000).contains(&d10),
        "attempt 10: got {}ms, should be capped at 5000",
        d10
    );
}

#[test]
fn test_case_insensitive_method_matching() {
    let config = default_config();
    assert!(should_retry(&config, "get", &http_response(502), 0));
    assert!(should_retry(&config, "Get", &http_response(502), 0));
}

// --- Connection failure vs HTTP status tests ---

#[test]
fn test_connection_failure_retried_by_default() {
    let config = default_config();
    assert!(should_retry(&config, "GET", &connection_failure(), 0));
}

#[test]
fn test_connection_failure_not_retried_when_disabled() {
    let config = RetryConfig {
        retry_on_connect_failure: false,
        ..default_config()
    };
    assert!(!should_retry(&config, "GET", &connection_failure(), 0));
}

#[test]
fn test_connection_failure_retried_even_without_502_in_status_codes() {
    // Remove 502 from retryable status codes — connection failures
    // should still be retried because they're a different category.
    let config = RetryConfig {
        retryable_status_codes: vec![503, 504],
        ..default_config()
    };
    assert!(should_retry(&config, "GET", &connection_failure(), 0));
}

#[test]
fn test_http_502_not_retried_when_removed_from_status_codes() {
    // A real HTTP 502 (not a connection failure) should NOT be retried
    // when 502 is removed from retryable_status_codes.
    let config = RetryConfig {
        retryable_status_codes: vec![503, 504],
        ..default_config()
    };
    assert!(!should_retry(&config, "GET", &http_response(502), 0));
}

#[test]
fn test_connection_failure_still_respects_method_filter() {
    let config = default_config();
    // POST is not in default retryable_methods
    assert!(!should_retry(&config, "POST", &connection_failure(), 0));
}

#[test]
fn test_connection_failure_still_respects_max_retries() {
    let config = RetryConfig {
        max_retries: 1,
        ..default_config()
    };
    assert!(should_retry(&config, "GET", &connection_failure(), 0));
    assert!(!should_retry(&config, "GET", &connection_failure(), 1));
}

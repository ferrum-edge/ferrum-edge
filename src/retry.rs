//! Retry logic for failed backend requests.
//!
//! Wraps backend requests with configurable retry policies including
//! max retries, retryable status codes/methods, and backoff strategies.
//! Distinguishes between TCP/connection-level failures and HTTP status
//! failures so operators can control retry behavior for each independently.

use crate::config::types::{BackoffStrategy, RetryConfig};
use std::collections::HashMap;
use std::time::Duration;
use tracing::warn;

/// The response body, either fully buffered or still streaming from the backend.
pub enum ResponseBody {
    /// Body has been fully collected into memory.
    Buffered(Vec<u8>),
    /// Body is still attached to the backend response and will be streamed
    /// to the client. The status code and headers have already been extracted.
    Streaming(reqwest::Response),
}

/// Result of a backend request, carrying enough context for the retry
/// logic to distinguish connection-level failures from HTTP-level ones.
pub struct BackendResponse {
    pub status_code: u16,
    pub body: ResponseBody,
    pub headers: HashMap<String, String>,
    /// True when the backend was never reached — TCP connect refused,
    /// DNS resolution failure, TLS handshake error, connect timeout, etc.
    /// False when we got an actual HTTP response (even if it's a 502).
    pub connection_error: bool,
}

impl BackendResponse {
    /// Returns the buffered body bytes, or an empty slice for streaming responses.
    #[allow(dead_code)]
    pub fn body_bytes(&self) -> &[u8] {
        match &self.body {
            ResponseBody::Buffered(b) => b,
            ResponseBody::Streaming(_) => &[],
        }
    }

    /// Consume the response and return the buffered body bytes.
    /// Returns an empty Vec if the body is streaming.
    #[allow(dead_code)]
    pub fn into_buffered_body(self) -> Vec<u8> {
        match self.body {
            ResponseBody::Buffered(b) => b,
            ResponseBody::Streaming(_) => {
                warn!("attempted to extract buffered body from a streaming response");
                Vec::new()
            }
        }
    }
}

/// Determine if a request should be retried.
///
/// Checks two independent retry paths:
/// 1. **Connection failures** (`connection_error = true`): retried when
///    `retry_on_connect_failure` is enabled, regardless of the synthetic
///    status code. These are TCP-layer problems (connect refused, timeout,
///    DNS failure, TLS error) where no HTTP response was received.
/// 2. **HTTP status failures** (`connection_error = false`): retried when
///    the response status code is in `retryable_status_codes`. These are
///    real HTTP responses from the backend (e.g., 502 from an upstream
///    load balancer, 503 during deployment).
///
/// Both paths still respect `max_retries` and `retryable_methods`.
pub fn should_retry(
    config: &RetryConfig,
    method: &str,
    response: &BackendResponse,
    attempt: u32,
) -> bool {
    if attempt >= config.max_retries {
        return false;
    }

    if !config
        .retryable_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return false;
    }

    if response.connection_error {
        return config.retry_on_connect_failure;
    }

    config
        .retryable_status_codes
        .contains(&response.status_code)
}

/// Calculate the delay before the next retry attempt.
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    match &config.backoff {
        BackoffStrategy::Fixed { delay_ms } => Duration::from_millis(*delay_ms),
        BackoffStrategy::Exponential { base_ms, max_ms } => {
            let delay = base_ms.saturating_mul(2u64.saturating_pow(attempt));
            Duration::from_millis(delay.min(*max_ms))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(retry_delay(&config, 0), Duration::from_millis(100));
        assert_eq!(retry_delay(&config, 1), Duration::from_millis(200));
        assert_eq!(retry_delay(&config, 2), Duration::from_millis(400));
        assert_eq!(retry_delay(&config, 3), Duration::from_millis(800));
        // Should cap at max
        assert_eq!(retry_delay(&config, 10), Duration::from_millis(5000));
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
}

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
    /// Body from hyper's HTTP/2 client (used by Http2ConnectionPool for
    /// proper H2 stream multiplexing over persistent connections).
    StreamingH2(hyper::Response<hyper::body::Incoming>),
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
    /// The DNS-resolved IP address of the backend that was connected to.
    /// Populated from the DNS cache before the request is sent. `None` when
    /// DNS resolution fails or the request never reaches the backend.
    pub backend_resolved_ip: Option<String>,
}

impl BackendResponse {
    /// Returns the buffered body bytes, or an empty slice for streaming responses.
    #[allow(dead_code)]
    pub fn body_bytes(&self) -> &[u8] {
        match &self.body {
            ResponseBody::Buffered(b) => b,
            ResponseBody::Streaming(_) | ResponseBody::StreamingH2(_) => &[],
        }
    }

    /// Consume the response and return the buffered body bytes.
    /// Returns an empty Vec if the body is streaming.
    #[allow(dead_code)]
    pub fn into_buffered_body(self) -> Vec<u8> {
        match self.body {
            ResponseBody::Buffered(b) => b,
            ResponseBody::Streaming(_) | ResponseBody::StreamingH2(_) => {
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
///
/// Exponential backoff includes decorrelated jitter to prevent thundering
/// herd effects when multiple clients retry against the same failing backend.
/// The jitter range is [delay * 0.5, delay * 1.5] capped at max_ms.
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    match &config.backoff {
        BackoffStrategy::Fixed { delay_ms } => Duration::from_millis(*delay_ms),
        BackoffStrategy::Exponential { base_ms, max_ms } => {
            let delay = base_ms.saturating_mul(2u64.saturating_pow(attempt));
            let capped = delay.min(*max_ms);
            // Add jitter: random value in [capped/2, capped*3/2] capped at max_ms.
            // Uses a lightweight counter-based pseudo-random to avoid pulling in
            // a full RNG crate. The jitter doesn't need cryptographic quality.
            use std::sync::atomic::{AtomicU64, Ordering};
            static JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);
            let counter = JITTER_COUNTER.fetch_add(1, Ordering::Relaxed);
            // Simple hash to spread values
            let hash = counter
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let jitter_range = capped; // range is [0, capped)
            let jitter_offset = if jitter_range > 0 {
                hash % jitter_range
            } else {
                0
            };
            // Result is in [capped/2, capped/2 + capped) = [capped/2, capped*3/2)
            let jittered = (capped / 2).saturating_add(jitter_offset);
            Duration::from_millis(jittered.min(*max_ms))
        }
    }
}

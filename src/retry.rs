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

/// Human-friendly classification of backend connection/communication errors.
///
/// Populated only when the gateway itself encounters an error reaching the
/// backend — never when the backend returns a normal HTTP error response.
/// Designed to help operators quickly identify the root cause of failed
/// transactions without digging through raw error strings.
///
/// Serializes as a lowercase_snake_case string (e.g. `"connection_timeout"`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// TCP connect timed out before a connection was established.
    ConnectionTimeout,
    /// TCP connect was refused by the backend (port not listening, firewall RST).
    ConnectionRefused,
    /// TCP connection was reset by the backend (RST received mid-stream).
    ConnectionReset,
    /// TCP connection was closed cleanly by the backend before a response was sent.
    ConnectionClosed,
    /// DNS resolution failed — the backend hostname could not be resolved.
    DnsLookupError,
    /// TLS handshake failed (certificate error, protocol mismatch, etc.).
    TlsError,
    /// Backend read/write timed out — connection was established but the
    /// response was not received within the configured timeout.
    ReadWriteTimeout,
    /// Client disconnected before the gateway could forward the request body.
    ClientDisconnect,
    /// HTTP/2 or HTTP/3 protocol-level error (stream reset, GOAWAY, etc.).
    ProtocolError,
    /// Backend response body exceeded the configured maximum size.
    ResponseBodyTooLarge,
    /// Request body exceeded the configured maximum size.
    RequestBodyTooLarge,
    /// Could not acquire or create an HTTP client from the connection pool.
    ConnectionPoolError,
    /// Catch-all for unclassified request errors.
    RequestError,
}

impl std::fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionTimeout => write!(f, "connection_timeout"),
            Self::ConnectionRefused => write!(f, "connection_refused"),
            Self::ConnectionReset => write!(f, "connection_reset"),
            Self::ConnectionClosed => write!(f, "connection_closed"),
            Self::DnsLookupError => write!(f, "dns_lookup_error"),
            Self::TlsError => write!(f, "tls_error"),
            Self::ReadWriteTimeout => write!(f, "read_write_timeout"),
            Self::ClientDisconnect => write!(f, "client_disconnect"),
            Self::ProtocolError => write!(f, "protocol_error"),
            Self::ResponseBodyTooLarge => write!(f, "response_body_too_large"),
            Self::RequestBodyTooLarge => write!(f, "request_body_too_large"),
            Self::ConnectionPoolError => write!(f, "connection_pool_error"),
            Self::RequestError => write!(f, "request_error"),
        }
    }
}

/// Classify a gRPC proxy error into an `ErrorClass`.
///
/// Maps `GrpcProxyError` variants (which carry message strings describing
/// the failure) into the appropriate `ErrorClass`. Called on the error path only.
pub fn classify_grpc_proxy_error(e: &crate::proxy::grpc_proxy::GrpcProxyError) -> ErrorClass {
    use crate::proxy::grpc_proxy::GrpcProxyError;
    match e {
        GrpcProxyError::BackendTimeout(msg) => {
            if msg.contains("Connect timeout") {
                ErrorClass::ConnectionTimeout
            } else {
                ErrorClass::ReadWriteTimeout
            }
        }
        GrpcProxyError::BackendUnavailable(msg) => {
            if msg.contains("TLS handshake failed")
                || msg.contains("h2 handshake failed")
                || msg.contains("certificate")
            {
                ErrorClass::TlsError
            } else if msg.contains("Connection refused") {
                ErrorClass::ConnectionRefused
            } else if msg.contains("h2c handshake failed") {
                ErrorClass::ProtocolError
            } else if msg.contains("Invalid server name") {
                ErrorClass::DnsLookupError
            } else {
                ErrorClass::ConnectionRefused
            }
        }
        GrpcProxyError::Internal(_) => ErrorClass::RequestError,
    }
}

/// Classify a generic boxed error (e.g. from WebSocket connections) into an
/// `ErrorClass` by inspecting its Display and Debug representations. Called
/// on the error path only.
pub fn classify_boxed_error(e: &(dyn std::error::Error + Send + Sync)) -> ErrorClass {
    let error_str = format!("{}", e);
    let debug_str = format!("{:?}", e);

    if error_str.contains("connect timeout") || error_str.contains("timed out") {
        return ErrorClass::ConnectionTimeout;
    }
    if error_str.contains("refused") || debug_str.contains("ConnectionRefused") {
        return ErrorClass::ConnectionRefused;
    }
    if debug_str.contains("dns error")
        || debug_str.contains("resolve")
        || debug_str.contains("Name or service not known")
        || debug_str.contains("No such host")
        || debug_str.contains("no record found")
        || debug_str.contains("failed to lookup address")
    {
        return ErrorClass::DnsLookupError;
    }
    if debug_str.contains("certificate")
        || debug_str.contains("SSL")
        || debug_str.contains("tls")
        || debug_str.contains("TLS")
        || debug_str.contains("AlertReceived")
        || debug_str.contains("HandshakeFailure")
        || debug_str.contains("InvalidCertificate")
    {
        return ErrorClass::TlsError;
    }
    if debug_str.contains("reset") || debug_str.contains("ConnectionReset") {
        return ErrorClass::ConnectionReset;
    }
    if debug_str.contains("broken pipe")
        || debug_str.contains("BrokenPipe")
        || debug_str.contains("connection closed")
    {
        return ErrorClass::ConnectionClosed;
    }
    ErrorClass::RequestError
}

/// Classify a `reqwest::Error` into an `ErrorClass` by inspecting its
/// error chain and message. This is called on the error path only (not hot path).
pub fn classify_reqwest_error(e: &reqwest::Error) -> ErrorClass {
    // Check the error chain for specific std::io errors
    let error_str = format!("{}", e);
    let source_chain = format!("{:?}", e);

    if e.is_connect() {
        // Dig into the connect error to distinguish timeout, refused, TLS, DNS
        if e.is_timeout() {
            return ErrorClass::ConnectionTimeout;
        }
        if source_chain.contains("dns error")
            || source_chain.contains("resolve")
            || source_chain.contains("Name or service not known")
            || source_chain.contains("No such host")
            || source_chain.contains("no record found")
            || source_chain.contains("failed to lookup address")
        {
            return ErrorClass::DnsLookupError;
        }
        if source_chain.contains("certificate")
            || source_chain.contains("SSL")
            || source_chain.contains("tls")
            || source_chain.contains("TLS")
            || source_chain.contains("AlertReceived")
            || source_chain.contains("HandshakeFailure")
            || source_chain.contains("InvalidCertificate")
        {
            return ErrorClass::TlsError;
        }
        if error_str.contains("refused")
            || source_chain.contains("Connection refused")
            || source_chain.contains("ConnectionRefused")
        {
            return ErrorClass::ConnectionRefused;
        }
        if source_chain.contains("reset") || source_chain.contains("ConnectionReset") {
            return ErrorClass::ConnectionReset;
        }
        // Generic connect failure
        return ErrorClass::ConnectionRefused;
    }

    if e.is_timeout() {
        return ErrorClass::ReadWriteTimeout;
    }

    // Check for connection reset/closed during request/response
    if source_chain.contains("reset") || source_chain.contains("ConnectionReset") {
        return ErrorClass::ConnectionReset;
    }
    if source_chain.contains("broken pipe")
        || source_chain.contains("BrokenPipe")
        || source_chain.contains("connection closed")
        || source_chain.contains("closed before")
    {
        return ErrorClass::ConnectionClosed;
    }

    // HTTP/2 specific errors
    if source_chain.contains("h2") || source_chain.contains("GOAWAY") {
        return ErrorClass::ProtocolError;
    }

    ErrorClass::RequestError
}

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
    /// Human-friendly classification of the error when the gateway itself
    /// failed to communicate with the backend. `None` for successful requests
    /// and normal HTTP error responses from the backend.
    pub error_class: Option<ErrorClass>,
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

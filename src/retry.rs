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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// All ephemeral ports are exhausted — the OS returned EADDRNOTAVAIL.
    PortExhaustion,
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
            Self::PortExhaustion => write!(f, "port_exhaustion"),
            Self::RequestError => write!(f, "request_error"),
        }
    }
}

/// Returns `true` if the error's root cause is EADDRNOTAVAIL, which indicates
/// ephemeral port exhaustion.
///
/// OS error codes: Linux = 99, macOS/BSD = 49, Windows = 10049 (WSAEADDRNOTAVAIL).
///
/// Walks the error source chain because transport libraries (reqwest, hyper)
/// wrap `io::Error` inside multiple layers.
pub fn is_port_exhaustion(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            match io_err.raw_os_error() {
                // EADDRNOTAVAIL: Linux = 99, macOS/BSD = 49, Windows = 10049
                Some(99) | Some(49) | Some(10049) => return true,
                _ => {}
            }
        }
        current = err.source();
    }
    false
}

/// Returns `true` if a string representation of an error indicates port
/// exhaustion (EADDRNOTAVAIL). Used for error types that have already been
/// stringified (e.g. `GrpcProxyError::BackendUnavailable(String)`).
pub fn is_port_exhaustion_message(msg: &str) -> bool {
    msg.contains("address not available")
        || msg.contains("os error 99")
        || msg.contains("os error 49")
        || msg.contains("os error 10049")
}

/// Classify a gRPC proxy error into an `ErrorClass`.
///
/// Maps `GrpcProxyError` variants (which carry message strings describing
/// the failure) into the appropriate `ErrorClass`. Called on the error path only.
pub fn classify_grpc_proxy_error(e: &crate::proxy::grpc_proxy::GrpcProxyError) -> ErrorClass {
    use crate::proxy::grpc_proxy::{GrpcProxyError, GrpcTimeoutKind};
    match e {
        GrpcProxyError::BackendTimeout { kind, .. } => match kind {
            GrpcTimeoutKind::Connect => ErrorClass::ConnectionTimeout,
            GrpcTimeoutKind::Read => ErrorClass::ReadWriteTimeout,
        },
        GrpcProxyError::BackendUnavailable(msg) => {
            if is_port_exhaustion_message(msg) {
                ErrorClass::PortExhaustion
            } else if msg.contains("TLS handshake failed")
                || msg.contains("h2 handshake failed")
                || msg.contains("certificate")
            {
                ErrorClass::TlsError
            } else if msg.contains("Connection refused") {
                ErrorClass::ConnectionRefused
            } else if msg.contains("h2c handshake failed") {
                ErrorClass::ProtocolError
            } else if msg.contains("Invalid server name") || msg.contains("DNS resolution") {
                ErrorClass::DnsLookupError
            } else {
                ErrorClass::ConnectionRefused
            }
        }
        GrpcProxyError::ResourceExhausted(_) => ErrorClass::RequestError,
        GrpcProxyError::Internal(_) => ErrorClass::RequestError,
    }
}

/// Classify a generic boxed error (e.g. from WebSocket connections) into an
/// `ErrorClass` by inspecting its Display and Debug representations. Called
/// on the error path only.
pub fn classify_boxed_error(e: &(dyn std::error::Error + Send + Sync + 'static)) -> ErrorClass {
    // Walk the source chain for typed io::Error / hyper::Error first so
    // classification is stable regardless of Display wording.
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            match io_err.kind() {
                std::io::ErrorKind::TimedOut => return ErrorClass::ReadWriteTimeout,
                std::io::ErrorKind::ConnectionRefused => return ErrorClass::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset => return ErrorClass::ConnectionReset,
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
                    return ErrorClass::ConnectionClosed;
                }
                _ => {}
            }
            if let Some(raw) = io_err.raw_os_error()
                && (raw == 99 || raw == 49 || raw == 10049)
            {
                return ErrorClass::PortExhaustion;
            }
        }
        if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
            if hyper_err.is_timeout() {
                return ErrorClass::ReadWriteTimeout;
            }
            if hyper_err.is_incomplete_message() {
                return ErrorClass::ConnectionClosed;
            }
        }
        current = err.source();
    }

    let error_str = format!("{}", e);
    let debug_str = format!("{:?}", e);

    if is_port_exhaustion_message(&error_str) || is_port_exhaustion_message(&debug_str) {
        return ErrorClass::PortExhaustion;
    }
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
    // Check for port exhaustion (EADDRNOTAVAIL) before other classifications.
    // Walk the source chain since reqwest wraps io::Error in multiple layers.
    if is_port_exhaustion(e) {
        return ErrorClass::PortExhaustion;
    }

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

/// Classify an error that was emitted by a streaming response body wrapper
/// (i.e. after response headers have been sent to the client).
///
/// Returns `(ErrorClass, client_disconnected)` where `client_disconnected`
/// is `true` only when the error chain specifically identifies the client as
/// the disconnecting side — i.e. hyper `is_canceled`. `is_incomplete_message`
/// indicates backend truncation and is classified as `ConnectionClosed` with
/// `client_disconnected=false`.
/// Raw IO resets (`BrokenPipe`/`ConnectionReset`/`ConnectionAborted`) are
/// returned with `client_disconnected=false` because in this classifier's
/// context (`ProxyBody::poll_frame` reading the backend response body) those
/// signals identify a backend mid-stream failure, not a client abort.
///
/// Walks `source()` chain so wrapped `hyper::Error` and `io::Error`
/// instances are inspected regardless of how many layers of `Box<dyn Error>`
/// sit between them and the caller.
pub fn classify_body_error(e: &(dyn std::error::Error + 'static)) -> (ErrorClass, bool) {
    // Port exhaustion is extremely unlikely during body streaming, but walk
    // the chain anyway so we never misclassify it as a generic error.
    if is_port_exhaustion(e) {
        return (ErrorClass::PortExhaustion, false);
    }

    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            match io_err.kind() {
                std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted => {
                    // Backend closed mid-stream — not a client disconnect.
                    return (ErrorClass::ConnectionClosed, false);
                }
                std::io::ErrorKind::TimedOut => {
                    return (ErrorClass::ReadWriteTimeout, false);
                }
                _ => {}
            }
        }
        if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
            // `is_canceled` maps to a client-side cancellation (e.g. the client
            // dropped the request future). `is_incomplete_message` means the
            // backend truncated the response — not a client disconnect.
            if hyper_err.is_canceled() {
                return (ErrorClass::ClientDisconnect, true);
            }
            if hyper_err.is_incomplete_message() {
                return (ErrorClass::ConnectionClosed, false);
            }
            if hyper_err.is_timeout() {
                return (ErrorClass::ReadWriteTimeout, false);
            }
            // Fall through to string-based inspection below.
        }
        current = err.source();
    }

    // String fallback for boxed backend errors that don't expose typed
    // downcasts (e.g. reqwest::Error wrapped in Box<dyn Error>).
    let error_str = format!("{}", e);
    let debug_str = format!("{:?}", e);
    // Policy-enforced truncation from SizeLimitedStreamingResponse — classify
    // explicitly so dashboards can distinguish response size-limit enforcement
    // from generic backend/body errors.
    if error_str.contains("response body exceeds maximum size") {
        return (ErrorClass::ResponseBodyTooLarge, false);
    }
    if error_str.contains("broken pipe")
        || debug_str.contains("BrokenPipe")
        || error_str.contains("connection reset")
        || debug_str.contains("ConnectionReset")
        || error_str.contains("connection aborted")
        || debug_str.contains("ConnectionAborted")
        || error_str.contains("canceled")
        || error_str.contains("closed before")
    {
        // Backend-side close during body streaming — keep client_disconnected
        // false so backend resets don't inflate client-disconnect metrics.
        return (ErrorClass::ConnectionClosed, false);
    }
    if error_str.contains("timed out") || debug_str.contains("TimedOut") {
        return (ErrorClass::ReadWriteTimeout, false);
    }
    if debug_str.contains("GOAWAY")
        || debug_str.contains("RESET_STREAM")
        || debug_str.contains("h2::")
        || debug_str.contains("h3::")
    {
        return (ErrorClass::ProtocolError, false);
    }

    (ErrorClass::RequestError, false)
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
    /// Body from the HTTP/3 (QUIC) backend via h3's `RequestStream`. The
    /// response headers have been received; body chunks arrive via
    /// `recv_data()`. This avoids buffering the entire H3 response when
    /// streaming to HTTP/1.1 or HTTP/2 frontends.
    StreamingH3(Box<crate::http3::client::H3StreamingResponse>),
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
            ResponseBody::Streaming(_)
            | ResponseBody::StreamingH2(_)
            | ResponseBody::StreamingH3(_) => &[],
        }
    }

    /// Consume the response and return the buffered body bytes.
    /// Returns an empty Vec if the body is streaming.
    #[allow(dead_code)]
    pub fn into_buffered_body(self) -> Vec<u8> {
        match self.body {
            ResponseBody::Buffered(b) => b,
            ResponseBody::Streaming(_)
            | ResponseBody::StreamingH2(_)
            | ResponseBody::StreamingH3(_) => {
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

    // Connection-level failures (TCP refused, DNS, TLS, timeout) are retried
    // regardless of HTTP method — the request never reached the backend so
    // idempotency is not a concern.
    if response.connection_error {
        return config.retry_on_connect_failure;
    }

    // HTTP status-code retries only apply to configured methods (guards
    // against non-idempotent replays like POST).
    if !config
        .retryable_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return false;
    }

    config
        .retryable_status_codes
        .contains(&response.status_code)
}

/// Returns `true` when the retry config can replay connection-level failures.
///
/// A present but inert config (for example `max_retries = 0` or
/// `retry_on_connect_failure = false`) should not force request buffering or
/// disable streaming fast paths.
pub fn can_retry_connection_failures(config: Option<&RetryConfig>) -> bool {
    config.is_some_and(|config| config.max_retries > 0 && config.retry_on_connect_failure)
}

/// Returns `true` when the retry config can replay HTTP status-code failures
/// for the current method.
pub fn can_retry_http_statuses(config: Option<&RetryConfig>, method: &str) -> bool {
    config.is_some_and(|config| {
        config.max_retries > 0
            && !config.retryable_status_codes.is_empty()
            && config
                .retryable_methods
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(method))
    })
}

/// Returns `true` when the retry config can actually trigger retries for a
/// plain HTTP-family request.
pub fn has_effective_http_retries(config: Option<&RetryConfig>, method: &str) -> bool {
    can_retry_connection_failures(config) || can_retry_http_statuses(config, method)
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

#[cfg(test)]
mod tests {
    use super::{
        can_retry_connection_failures, can_retry_http_statuses, has_effective_http_retries,
    };
    use crate::config::types::RetryConfig;

    #[test]
    fn no_op_retry_config_does_not_enable_connection_retries() {
        let retry = RetryConfig {
            max_retries: 0,
            ..RetryConfig::default()
        };

        assert!(!can_retry_connection_failures(Some(&retry)));

        let retry = RetryConfig {
            max_retries: 3,
            retry_on_connect_failure: false,
            ..RetryConfig::default()
        };
        assert!(!can_retry_connection_failures(Some(&retry)));
    }

    #[test]
    fn http_status_retries_require_method_and_status_codes() {
        let mut retry = RetryConfig {
            max_retries: 3,
            retry_on_connect_failure: false,
            retryable_status_codes: vec![502, 503],
            ..RetryConfig::default()
        };

        assert!(can_retry_http_statuses(Some(&retry), "GET"));
        assert!(!can_retry_http_statuses(Some(&retry), "POST"));

        retry.retryable_methods.push("POST".to_string());
        assert!(can_retry_http_statuses(Some(&retry), "POST"));

        retry.retryable_status_codes.clear();
        assert!(!can_retry_http_statuses(Some(&retry), "GET"));
    }

    #[test]
    fn effective_http_retries_ignore_inert_configs() {
        let mut retry = RetryConfig {
            max_retries: 0,
            ..RetryConfig::default()
        };
        assert!(!has_effective_http_retries(Some(&retry), "GET"));

        retry = RetryConfig {
            max_retries: 3,
            retry_on_connect_failure: false,
            retryable_status_codes: vec![],
            ..RetryConfig::default()
        };
        assert!(!has_effective_http_retries(Some(&retry), "GET"));

        retry.retryable_status_codes = vec![503];
        assert!(has_effective_http_retries(Some(&retry), "GET"));
    }
}

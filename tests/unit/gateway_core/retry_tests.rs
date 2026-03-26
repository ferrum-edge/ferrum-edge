//! Tests for retry logic module

use ferrum_gateway::config::types::{BackoffStrategy, RetryConfig};
use ferrum_gateway::proxy::grpc_proxy::GrpcProxyError;
use ferrum_gateway::retry::{
    BackendResponse, ErrorClass, ResponseBody, classify_boxed_error, classify_grpc_proxy_error,
    retry_delay, should_retry,
};
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
        backend_resolved_ip: None,
        error_class: None,
    }
}

fn connection_failure() -> BackendResponse {
    BackendResponse {
        status_code: 502,
        body: ResponseBody::Buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: true,
        backend_resolved_ip: None,
        error_class: Some(ferrum_gateway::retry::ErrorClass::ConnectionRefused),
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

// --- classify_grpc_proxy_error tests ---

#[test]
fn test_grpc_connect_timeout_classified() {
    let err =
        GrpcProxyError::BackendTimeout("Connect timeout after 5000ms to 10.0.0.1:50051".into());
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_grpc_read_timeout_classified() {
    let err = GrpcProxyError::BackendTimeout("Read timeout after 30000ms".into());
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_grpc_body_read_timeout_classified() {
    let err = GrpcProxyError::BackendTimeout("Body read timeout after 30000ms".into());
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_grpc_tls_handshake_failure_classified() {
    let err = GrpcProxyError::BackendUnavailable(
        "TLS handshake failed: certificate verify failed".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_grpc_h2_handshake_failure_classified() {
    let err = GrpcProxyError::BackendUnavailable("h2 handshake failed: protocol error".into());
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_grpc_connection_refused_classified() {
    let err = GrpcProxyError::BackendUnavailable("Connection refused: connection refused".into());
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_grpc_h2c_handshake_failure_classified() {
    let err = GrpcProxyError::BackendUnavailable("h2c handshake failed: connection reset".into());
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::ProtocolError);
}

#[test]
fn test_grpc_invalid_server_name_classified() {
    let err = GrpcProxyError::BackendUnavailable("Invalid server name: invalid dnsname".into());
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_grpc_generic_unavailable_classified() {
    let err = GrpcProxyError::BackendUnavailable("Backend error: something went wrong".into());
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_grpc_internal_error_classified() {
    let err = GrpcProxyError::Internal("Failed to read client cert from /path: not found".into());
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::RequestError);
}

// --- classify_boxed_error tests (WebSocket / generic errors) ---

#[test]
fn test_boxed_error_connect_timeout() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "WebSocket backend connect timeout (5000ms) for proxy ws-1".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_boxed_error_timed_out() {
    let err: Box<dyn std::error::Error + Send + Sync> = "operation timed out".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_boxed_error_connection_refused() {
    let err: Box<dyn std::error::Error + Send + Sync> = "Connection refused (os error 111)".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_boxed_error_tls() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "TLS handshake failed: certificate verify failed".into();
    assert_eq!(classify_boxed_error(err.as_ref()), ErrorClass::TlsError);
}

#[test]
fn test_boxed_error_dns() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "failed to lookup address information: Name or service not known".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::DnsLookupError
    );
}

#[test]
fn test_boxed_error_connection_reset() {
    let err: Box<dyn std::error::Error + Send + Sync> = "connection reset by peer".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::ConnectionReset
    );
}

#[test]
fn test_boxed_error_broken_pipe() {
    let err: Box<dyn std::error::Error + Send + Sync> = "broken pipe".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::ConnectionClosed
    );
}

#[test]
fn test_boxed_error_unknown_fallback() {
    let err: Box<dyn std::error::Error + Send + Sync> = "some unknown error".into();
    assert_eq!(classify_boxed_error(err.as_ref()), ErrorClass::RequestError);
}

//! Tests for retry logic module

use ferrum_edge::config::types::{BackoffStrategy, RetryConfig};
use ferrum_edge::proxy::grpc_proxy::{GrpcProxyError, GrpcTimeoutKind};
use ferrum_edge::retry::{
    BackendResponse, ErrorClass, ResponseBody, classify_body_error, classify_boxed_error,
    classify_grpc_proxy_error, retry_delay, should_retry,
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
        error_class: Some(ferrum_edge::retry::ErrorClass::ConnectionRefused),
    }
}

#[test]
fn test_should_retry_on_retryable_status() {
    let config = RetryConfig {
        retryable_status_codes: vec![502, 503, 504],
        ..default_config()
    };
    assert!(should_retry(&config, "GET", &http_response(502), 0));
    assert!(should_retry(&config, "GET", &http_response(503), 0));
    assert!(should_retry(&config, "GET", &http_response(504), 0));
}

#[test]
fn test_default_config_no_status_code_retries() {
    // Default config has empty retryable_status_codes — only connection failures retry.
    let config = default_config();
    assert!(!should_retry(&config, "GET", &http_response(502), 0));
    assert!(!should_retry(&config, "GET", &http_response(503), 0));
    assert!(!should_retry(&config, "GET", &http_response(504), 0));
}

#[test]
fn test_should_not_retry_on_success() {
    let config = RetryConfig {
        retryable_status_codes: vec![502, 503, 504],
        ..default_config()
    };
    assert!(!should_retry(&config, "GET", &http_response(200), 0));
    assert!(!should_retry(&config, "GET", &http_response(404), 0));
}

#[test]
fn test_should_not_retry_post_by_default() {
    let config = RetryConfig {
        retryable_status_codes: vec![502],
        ..default_config()
    };
    assert!(!should_retry(&config, "POST", &http_response(502), 0));
    assert!(!should_retry(&config, "PATCH", &http_response(502), 0));
}

#[test]
fn test_should_retry_put_and_delete() {
    let config = RetryConfig {
        retryable_status_codes: vec![503],
        ..default_config()
    };
    assert!(should_retry(&config, "PUT", &http_response(503), 0));
    assert!(should_retry(&config, "DELETE", &http_response(503), 0));
}

#[test]
fn test_max_retries_exceeded() {
    let config = RetryConfig {
        max_retries: 2,
        retryable_status_codes: vec![502],
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
    let config = RetryConfig {
        retryable_status_codes: vec![502],
        ..default_config()
    };
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
fn test_connection_failure_ignores_method_filter() {
    // Connection failures retry regardless of HTTP method — the request
    // never reached the backend so idempotency is not a concern.
    let config = default_config();
    assert!(should_retry(&config, "POST", &connection_failure(), 0));
    assert!(should_retry(&config, "PATCH", &connection_failure(), 0));
}

#[test]
fn test_status_code_retry_respects_method_filter() {
    // HTTP status-code retries should still respect retryable_methods.
    let config = RetryConfig {
        retryable_status_codes: vec![502],
        ..default_config()
    };
    assert!(!should_retry(&config, "POST", &http_response(502), 0));
    assert!(should_retry(&config, "GET", &http_response(502), 0));
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
    let err = GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Connect,
        message: "Connect timeout after 5000ms to 10.0.0.1:50051".into(),
    };
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_grpc_read_timeout_classified() {
    let err = GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Read,
        message: "Read timeout after 30000ms".into(),
    };
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_grpc_body_read_timeout_classified() {
    let err = GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Read,
        message: "Body read timeout after 30000ms".into(),
    };
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_grpc_tls_handshake_failure_classified() {
    // Construction site emits TlsHandshake kind; classifier reads it directly
    // — no substring match against the (now informational-only) message.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::TlsHandshake,
        "TLS handshake failed: certificate verify failed".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_grpc_h2_handshake_failure_classified() {
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::H2Handshake,
        "h2 handshake failed: protocol error".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_grpc_connection_refused_classified() {
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::Connect,
        "Connection refused: connection refused".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_grpc_h2c_handshake_failure_classified_as_pre_wire() {
    // h2c handshake fails BEFORE any HTTP/2 stream is opened — request
    // bytes never reach the backend's application layer. Must classify
    // as a pre-wire class so request_reached_wire returns false and
    // the connect-failure retry can replay regardless of method
    // idempotency, in agreement with is_connect_class().
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::H2cHandshake,
        "h2c handshake failed: connection reset".into(),
    );
    let class = classify_grpc_proxy_error(&err);
    assert_eq!(class, ErrorClass::ConnectionRefused);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "H2cHandshake must be pre-wire to agree with is_connect_class"
    );
}

#[test]
fn test_grpc_invalid_server_name_classified() {
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::InvalidServerName,
        "Invalid server name: invalid dnsname".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_grpc_backend_request_classifies_as_post_wire() {
    // CRITICAL: BackendRequest is emitted from `sender.send_request().await`
    // AFTER the H2 connection is established and ALPN has succeeded — request
    // bytes may already be on the wire. Classify it as ConnectionReset
    // (post-wire / mid-stream) so request_reached_wire returns true and the
    // connect-failure retry path does NOT replay non-idempotent POSTs.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::BackendRequest,
        "Backend error: something went wrong".into(),
    );
    let class = classify_grpc_proxy_error(&err);
    assert_eq!(class, ErrorClass::ConnectionReset);
    assert!(
        ferrum_edge::retry::request_reached_wire(class),
        "BackendRequest must classify as post-wire so retry_on_connect_failure \
         cannot bypass retry_on_methods for non-idempotent gRPC POSTs"
    );
}

#[test]
fn test_grpc_kind_is_connect_class_partitions_correctly() {
    use ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind as K;
    // Pre-wire (safe to replay regardless of method idempotency): retry loops
    // include these in the connect-failure matcher.
    for kind in [
        K::DnsResolution,
        K::Connect,
        K::TlsHandshake,
        K::H2Handshake,
        K::H2cHandshake,
        K::InvalidServerName,
    ] {
        assert!(
            kind.is_connect_class(),
            "{kind:?} must be classified as a connect-class kind"
        );
    }
    // Post-wire: retry loops must EXCLUDE this from the connect-failure
    // matcher so retry_on_methods governs replay decisions.
    assert!(
        !K::BackendRequest.is_connect_class(),
        "BackendRequest is post-handshake — must not be a connect-class kind"
    );
}

#[test]
fn test_every_connect_class_kind_classifies_as_pre_wire() {
    // STRUCTURAL CONTRACT: `is_connect_class()` and the unified
    // `request_reached_wire` boundary must agree for every variant. If a
    // kind is in the connect-class predicate (gRPC retry loops fire
    // `retry_on_connect_failure` for it), its classified `ErrorClass` MUST
    // satisfy `!request_reached_wire(class)` — otherwise the retry path
    // bypasses `retry_on_methods` for a post-wire failure and could replay
    // non-idempotent POSTs.
    //
    // This test enumerates EVERY `GrpcBackendUnavailableKind` variant via
    // an exhaustive match — adding a new variant is a compile error here
    // until you decide its connect-class membership AND its classified
    // ErrorClass, in lockstep.
    use ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind as K;
    let all_kinds = [
        K::DnsResolution,
        K::Connect,
        K::TlsHandshake,
        K::H2Handshake,
        K::H2cHandshake,
        K::InvalidServerName,
        K::BackendRequest,
    ];
    // Compile-time exhaustiveness: if a new variant is added, this match
    // forces an update before tests can compile.
    for kind in all_kinds {
        let _exhaustive: () = match kind {
            K::DnsResolution
            | K::Connect
            | K::TlsHandshake
            | K::H2Handshake
            | K::H2cHandshake
            | K::InvalidServerName
            | K::BackendRequest => (),
        };
        let err = GrpcProxyError::backend_unavailable(kind, format!("{kind:?} test"));
        let class = classify_grpc_proxy_error(&err);
        if kind.is_connect_class() {
            assert!(
                !ferrum_edge::retry::request_reached_wire(class),
                "{kind:?} is connect-class but classified as {class:?} \
                 (request_reached_wire={}); the retry-loop predicate would \
                 fire retry_on_connect_failure for a post-wire failure",
                ferrum_edge::retry::request_reached_wire(class),
            );
        } else {
            assert!(
                ferrum_edge::retry::request_reached_wire(class),
                "{kind:?} is NOT connect-class but classified as {class:?} \
                 (request_reached_wire=false); operators expect post-wire \
                 classes for non-connect kinds — connect-class membership \
                 may need updating",
            );
        }
    }
}

#[test]
fn test_grpc_classifier_ignores_substring_drift_in_message() {
    // Regression: the legacy substring-matching classifier returned
    // `TlsError` for ANY message containing "TLS handshake failed", even when
    // attached to the wrong kind. The typed classifier must read the kind,
    // not the message — so a Connect kind with an arbitrarily-worded
    // message still classifies as ConnectionRefused.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::Connect,
        // Adversarial wording mentioning "TLS" and "handshake" — must NOT
        // mislead the typed classifier.
        "Connection failed: TLS handshake failed by accident".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ConnectionRefused,
        "typed kind must override misleading message wording"
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

// ── Port exhaustion (EADDRNOTAVAIL) classification ─────────────────

#[test]
fn test_is_port_exhaustion_with_io_error_linux() {
    // OS error 99 is EADDRNOTAVAIL on Linux
    let io_err = std::io::Error::from_raw_os_error(99);
    assert!(ferrum_edge::retry::is_port_exhaustion(&io_err));
}

#[test]
fn test_is_port_exhaustion_with_io_error_macos() {
    // OS error 49 is EADDRNOTAVAIL on macOS/BSD
    let io_err = std::io::Error::from_raw_os_error(49);
    assert!(ferrum_edge::retry::is_port_exhaustion(&io_err));
}

#[test]
fn test_is_port_exhaustion_false_for_connection_refused() {
    // OS error 111 is ECONNREFUSED on Linux
    let io_err = std::io::Error::from_raw_os_error(111);
    assert!(!ferrum_edge::retry::is_port_exhaustion(&io_err));
}

#[test]
fn test_is_port_exhaustion_false_for_generic_error() {
    let err = std::io::Error::other("something else");
    assert!(!ferrum_edge::retry::is_port_exhaustion(&err));
}

#[test]
fn test_is_port_exhaustion_message_linux() {
    assert!(ferrum_edge::retry::is_port_exhaustion_message(
        "Connection failed: Cannot assign requested address (os error 99)"
    ));
}

#[test]
fn test_is_port_exhaustion_message_macos() {
    assert!(ferrum_edge::retry::is_port_exhaustion_message(
        "Connection failed: Can't assign requested address (os error 49)"
    ));
}

#[test]
fn test_is_port_exhaustion_message_text() {
    assert!(ferrum_edge::retry::is_port_exhaustion_message(
        "address not available"
    ));
}

#[test]
fn test_is_port_exhaustion_message_false() {
    assert!(!ferrum_edge::retry::is_port_exhaustion_message(
        "Connection refused"
    ));
}

#[test]
fn test_grpc_port_exhaustion_classified() {
    // Port exhaustion is detected via either typed io::Error source walk
    // OR the message-substring fallback. This test exercises the message
    // path (no typed source attached).
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::Connect,
        "Connection failed: Can't assign requested address (os error 99)".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::PortExhaustion);
}

#[test]
fn test_grpc_port_exhaustion_via_typed_source() {
    // The typed io::Error attached as a source must be discoverable by the
    // chain walker even when the message has no port-exhaustion wording.
    let io_err = std::io::Error::from_raw_os_error(99);
    let err = GrpcProxyError::backend_unavailable_with_source(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::Connect,
        "Connection failed".into(),
        io_err,
    );
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::PortExhaustion,
        "typed io::Error source must drive port-exhaustion classification"
    );
}

#[test]
fn test_boxed_error_port_exhaustion_linux() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "Backend connect failed: Can't assign requested address (os error 99)".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::PortExhaustion
    );
}

#[test]
fn test_boxed_error_port_exhaustion_macos() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "Backend connect failed: Can't assign requested address (os error 49)".into();
    assert_eq!(
        classify_boxed_error(err.as_ref()),
        ErrorClass::PortExhaustion
    );
}

#[test]
fn test_port_exhaustion_display() {
    assert_eq!(format!("{}", ErrorClass::PortExhaustion), "port_exhaustion");
}

#[test]
fn test_is_port_exhaustion_with_io_error_windows() {
    // OS error 10049 is WSAEADDRNOTAVAIL on Windows
    let io_err = std::io::Error::from_raw_os_error(10049);
    assert!(ferrum_edge::retry::is_port_exhaustion(&io_err));
}

#[test]
fn test_is_port_exhaustion_message_windows() {
    assert!(ferrum_edge::retry::is_port_exhaustion_message(
        "Connection failed: address not available (os error 10049)"
    ));
}

#[test]
fn test_grpc_dns_failure_classified_as_dns_error() {
    // The H2/gRPC pools attach DnsResolution kind when dns_cache.resolve()
    // fails — the typed kind drives classification regardless of message
    // wording.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::DnsResolution,
        "DNS resolution failed for backend.example.com: no record found".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&err), ErrorClass::DnsLookupError);
}

// -- classify_body_error ------------------------------------------------------
// Covers the streaming-response-body error path. The classifier must return
// (ErrorClass, client_disconnected) where the second field is used by the
// deferred logger to populate `TransactionSummary.client_disconnected`.

#[test]
fn test_classify_body_error_broken_pipe_is_backend_close() {
    // classify_body_error is called from ProxyBody::poll_frame on the backend
    // response body, so a BrokenPipe there means the backend closed — not the
    // client. client_disconnected must remain false.
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "backend went away");
    let (class, disconnected) = classify_body_error(&io_err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_connection_reset_is_backend_close() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "backend RST");
    let (class, disconnected) = classify_body_error(&io_err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_connection_aborted_is_backend_close() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "backend aborted");
    let (class, disconnected) = classify_body_error(&io_err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_hyper_canceled_is_client_disconnect() {
    // hyper::Error::is_canceled / is_incomplete_message are the signals that
    // unambiguously identify a client abort. We can't construct a real
    // hyper::Error here, but the string-fallback path has a "canceled" branch
    // that also maps to ConnectionClosed. Per the updated classifier, the
    // string fallback stays false too — only typed hyper::Error can set
    // client_disconnected=true, which is exercised in integration tests.
    let err: Box<dyn std::error::Error + Send + Sync> = "request canceled by caller".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_timed_out_is_not_client_disconnect() {
    let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "backend read timeout");
    let (class, disconnected) = classify_body_error(&io_err);
    assert_eq!(class, ErrorClass::ReadWriteTimeout);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_unknown_defaults_to_request_error() {
    #[derive(Debug)]
    struct DummyErr;
    impl std::fmt::Display for DummyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "some unrelated failure")
        }
    }
    impl std::error::Error for DummyErr {}
    let err = DummyErr;
    let (class, disconnected) = classify_body_error(&err);
    assert_eq!(class, ErrorClass::RequestError);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_string_fallback_broken_pipe() {
    // Box<dyn Error> constructed from a string — no downcastable io::Error,
    // but the message still indicates a broken pipe and should classify
    // as ConnectionClosed. client_disconnected stays false: a string-only
    // error cannot prove the client was the disconnecting side.
    let err: Box<dyn std::error::Error + Send + Sync> = "hyper::Error(Io, kind: BrokenPipe)".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_string_fallback_protocol_error() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "h2::Error { kind: GOAWAY(INTERNAL_ERROR) }".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ProtocolError);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_response_size_limit_is_explicit() {
    // SizeLimitedStreamingResponse emits this literal message when the backend
    // exceeds max_response_body_size_bytes mid-stream. Must classify as
    // ResponseBodyTooLarge, not the generic RequestError fallback, so
    // policy-enforced truncations are distinguishable in metrics.
    let err: Box<dyn std::error::Error + Send + Sync> = "response body exceeds maximum size".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ResponseBodyTooLarge);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_walks_source_chain_to_io_error() {
    // Wrap an io::Error in a custom error with a `source()` chain — the
    // classifier should walk the chain and find the BrokenPipe underneath.
    #[derive(Debug)]
    struct Wrapper(std::io::Error);
    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }
    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
    let wrapped = Wrapper(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "peer closed",
    ));
    let (class, disconnected) = classify_body_error(&wrapped);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

// --- Typed StreamSetupError classification (Gap 2 + Gap 4) ---

#[test]
fn test_classify_boxed_error_typed_frontend_tls_error() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::new(
        StreamSetupKind::FrontendTlsHandshake,
        "from 1.2.3.4:5678",
    ));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::TlsError);
}

#[test]
fn test_classify_boxed_error_typed_backend_dtls_error() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::new(
        StreamSetupKind::BackendDtlsHandshake,
        ": certificate verify failed",
    ));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::TlsError);
}

#[test]
fn test_classify_boxed_error_typed_no_healthy_targets() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::new(
        StreamSetupKind::NoHealthyTargets,
        "for upstream foo",
    ));
    // RequestError is the umbrella class for gateway-side rejections that
    // weren't TLS/DNS/connect failures. The typed kind is what carries the
    // backend-vs-client attribution downstream.
    assert_eq!(classify_boxed_error(&*err), ErrorClass::RequestError);
}

#[test]
fn test_classify_boxed_error_typed_kind_survives_anyhow_context() {
    // Construction sites convert StreamSetupError to anyhow::Error via
    // .into() and may further .context(...) it before reaching the cause
    // mapper. The downcast must keep working through both layers.
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let original: anyhow::Error = StreamSetupError::new(
        StreamSetupKind::BackendTlsHandshake,
        "to backend.example.com:8443",
    )
    .into();
    let wrapped = original.context("dispatch failed");
    assert_eq!(classify_boxed_error(wrapped.as_ref()), ErrorClass::TlsError);
}

// --- WebSocket graceful close (Gap 3) ---

#[test]
fn test_classify_boxed_error_ws_connection_closed_is_graceful() {
    // RFC 6455 normal closure surfaces as tungstenite::Error::ConnectionClosed.
    // Must classify as GracefulRemoteClose so WS sessions that ended cleanly
    // don't pollute connection-error metrics.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(tokio_tungstenite::tungstenite::Error::ConnectionClosed);
    assert_eq!(classify_boxed_error(&*err), ErrorClass::GracefulRemoteClose);
}

#[test]
fn test_classify_boxed_error_ws_already_closed_is_graceful() {
    // Writing after a Close frame surfaces as Error::AlreadyClosed —
    // semantically the same orderly close.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(tokio_tungstenite::tungstenite::Error::AlreadyClosed);
    assert_eq!(classify_boxed_error(&*err), ErrorClass::GracefulRemoteClose);
}

#[test]
fn test_classify_boxed_error_ws_protocol_error_is_protocol_class() {
    use tokio_tungstenite::tungstenite::error::ProtocolError;
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(
        tokio_tungstenite::tungstenite::Error::Protocol(ProtocolError::HandshakeIncomplete),
    );
    assert_eq!(classify_boxed_error(&*err), ErrorClass::ProtocolError);
}

// --- Typed rustls and io::Error walks (tightened typed-first classification) ---

#[test]
fn test_classify_boxed_error_typed_rustls_alert() {
    // rustls::Error walked via downcast — no message inspection needed.
    // Used to require matching "TLS"/"AlertReceived"/etc substrings.
    let alert = rustls::AlertDescription::HandshakeFailure;
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(rustls::Error::AlertReceived(alert));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::TlsError);
}

#[test]
fn test_classify_boxed_error_typed_rustls_buried_in_chain() {
    // rustls::Error wrapped in another error type — chain walk must reach it.
    #[derive(Debug)]
    struct Wrapper(rustls::Error);
    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "outer wrapper: {}", self.0)
        }
    }
    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
    let wrapped = Wrapper(rustls::Error::HandshakeNotComplete);
    assert_eq!(classify_boxed_error(&wrapped), ErrorClass::TlsError);
}

#[test]
fn test_classify_boxed_error_typed_io_error_takes_precedence_over_substrings() {
    // An io::Error with a Display string that would substring-match
    // something else. The typed walk must win.
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        // Adversarial wording — would substring-match TLS via "tls handshake".
        "tls handshake didn't make it past the kernel",
    ));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::ConnectionRefused);
}

// --- Substring-fallback anchoring regression tests ---

#[test]
fn test_substring_fallback_does_not_match_bare_tls_in_hostname() {
    // Regression: legacy classifier matched bare lowercase `"tls"` and
    // would mis-classify any unrelated error wording containing "tls" as
    // TlsError. Tightened anchors require a more specific token.
    let err: Box<dyn std::error::Error + Send + Sync> =
        "request to backend tls.example.com failed unexpectedly".into();
    // Without "TLS handshake" / "certificate" / "TlsError" / etc. anchors,
    // this falls through to RequestError.
    assert_eq!(classify_boxed_error(&*err), ErrorClass::RequestError);
}

#[test]
fn test_substring_fallback_does_not_match_bare_reset_in_unrelated_wording() {
    // Regression: legacy classifier matched bare `"reset"` which collided
    // with `stream_reset`, `reset_stream`, etc. The tightened anchor
    // requires `"connection reset"` (multi-word) or `"ConnectionReset"`
    // (PascalCase).
    let err: Box<dyn std::error::Error + Send + Sync> =
        "stream_reset received from upstream".into();
    assert_eq!(classify_boxed_error(&*err), ErrorClass::RequestError);
}

#[test]
fn test_substring_fallback_anchored_tls_handshake() {
    // Anchored multi-word phrase "tls handshake" does match — the previous
    // bare `"tls"` was the false-positive risk, not full phrases.
    let err: Box<dyn std::error::Error + Send + Sync> =
        "outbound request failed: tls handshake aborted by peer".into();
    assert_eq!(classify_boxed_error(&*err), ErrorClass::TlsError);
}

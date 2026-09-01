//! Tests for retry logic module

use ferrum_edge::config::types::{BackoffStrategy, RetryConfig};
use ferrum_edge::proxy::grpc_proxy::{GrpcProxyError, GrpcTimeoutKind};
use ferrum_edge::retry::{
    BackendResponse, ErrorClass, ResponseBody, WS_MESH_BACKEND_REQUEST_TARGET_INVALID,
    classify_body_error, classify_boxed_error, classify_boxed_setup_error,
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
        body: ResponseBody::buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
        backend_resolved_ip: None,
        error_class: None,
    }
}

fn connection_failure() -> BackendResponse {
    BackendResponse {
        status_code: 502,
        body: ResponseBody::buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: true,
        backend_resolved_ip: None,
        error_class: Some(ferrum_edge::retry::ErrorClass::ConnectionRefused),
    }
}

fn post_header_body_read_failure() -> BackendResponse {
    BackendResponse {
        status_code: 502,
        body: ResponseBody::buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
        backend_resolved_ip: None,
        error_class: Some(ErrorClass::ConnectionReset),
    }
}

fn dispatch_policy_rejection() -> BackendResponse {
    BackendResponse {
        status_code: 502,
        body: ResponseBody::buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
        backend_resolved_ip: None,
        error_class: Some(ErrorClass::DispatchPolicyRejected),
    }
}

fn terminal_gateway_error(status_code: u16, error_class: ErrorClass) -> BackendResponse {
    BackendResponse {
        status_code,
        body: ResponseBody::buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
        backend_resolved_ip: None,
        error_class: Some(error_class),
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
fn test_post_header_body_read_failure_respects_method_filter() {
    // Once response headers have arrived, a response-body read failure is
    // post-wire: the backend may already have committed side effects. It must
    // not be marked as a connection failure, because that path intentionally
    // bypasses retryable_methods for pre-wire failures only.
    let config = RetryConfig {
        max_retries: 3,
        retry_on_connect_failure: true,
        retryable_status_codes: vec![502],
        ..default_config()
    };
    let response = post_header_body_read_failure();

    assert!(!should_retry(&config, "POST", &response, 0));
    assert!(should_retry(&config, "GET", &response, 0));
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

#[test]
fn test_dispatch_policy_rejection_is_never_retried() {
    let config = RetryConfig {
        max_retries: 3,
        retry_on_connect_failure: true,
        retryable_status_codes: vec![502],
        ..default_config()
    };

    assert!(!should_retry(
        &config,
        "GET",
        &dispatch_policy_rejection(),
        0
    ));
}

#[test]
fn test_terminal_gateway_errors_are_never_retried_by_status_policy() {
    let config = RetryConfig {
        max_retries: 3,
        retry_on_connect_failure: true,
        retryable_status_codes: vec![413, 499, 502, 503],
        retryable_methods: vec!["GET".to_string(), "POST".to_string()],
        ..default_config()
    };

    for (status, class) in [
        (413, ErrorClass::RequestBodyTooLarge),
        (499, ErrorClass::ClientDisconnect),
        (502, ErrorClass::DispatchPolicyRejected),
        (503, ErrorClass::DispatchPolicyRejected),
        (502, ErrorClass::ResponseBodyTooLarge),
    ] {
        assert!(
            !should_retry(&config, "GET", &terminal_gateway_error(status, class), 0),
            "{class:?} must be terminal even when status {status} is configured retryable"
        );
    }
}

#[test]
fn test_terminal_gateway_errors_are_never_retried_as_connection_failures() {
    let config = RetryConfig {
        max_retries: 3,
        retry_on_connect_failure: true,
        retryable_status_codes: vec![502],
        ..default_config()
    };

    for class in [
        ErrorClass::ClientDisconnect,
        ErrorClass::DispatchPolicyRejected,
        ErrorClass::RequestBodyTooLarge,
        ErrorClass::ResponseBodyTooLarge,
    ] {
        let mut response = terminal_gateway_error(502, class);
        response.connection_error = true;

        assert!(
            !should_retry(&config, "POST", &response, 0),
            "{class:?} must be terminal even if a caller marks connection_error=true"
        );
    }
}

#[test]
fn http_retry_re_resolves_mesh_transport_before_each_dispatch() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let retry_loop = src
        .find("while retry::should_retry(retry_config, &method, &result, attempt)")
        .expect("HTTP retry loop not found");
    let retry_tail = &src[retry_loop..];
    let end = retry_tail
        .find("(result, current_cb_target_key, final_upstream_target)")
        .expect("HTTP retry loop end not found");
    let retry_body = &retry_tail[..end];

    let selection = retry_body
        .find("select_next_retry_target(")
        .expect("retry target rotation not found");
    let retry_cap_gate = retry_body
        .find("retry_attempt_allowed_for_target(")
        .expect("HTTP retry must re-check DestinationRule maxRetries for the candidate");
    let current_cap_gate = retry_body
        .find("current_retry_attempt_allowed(")
        .expect("HTTP retry must re-check DestinationRule maxRetries for the current target");
    assert!(
        retry_body.contains("route_retry_ceiling"),
        "HTTP retry must authorize against the original route ceiling"
    );
    assert!(
        current_cap_gate < selection,
        "current-target maxRetries must gate retry authorization before rotation"
    );
    assert!(
        selection < retry_cap_gate,
        "candidate maxRetries must be re-resolved after select_next_retry_target"
    );
    let intermediate_record = retry_body
        .find("permits.record_backend_outcome(BackendAdmissionOutcome {")
        .expect("HTTP retry intermediate outcome recording must remain present");
    assert!(
        retry_cap_gate < intermediate_record
            && retry_body[retry_cap_gate..intermediate_record].contains("break;"),
        "a candidate that exceeds its maxRetries cap must abort before intermediate outcome accounting"
    );
    let hbone = retry_body
        .find("target_hbone_enabled")
        .expect("HBONE transport resolution not found");
    let mesh_mtls = retry_body
        .find("target_mesh_mtls_enabled")
        .expect("sidecar mTLS transport resolution not found");
    let admission = retry_body
        .find("run_backend_admission_plugins(")
        .expect("per-attempt backend admission not found");
    let mesh_dispatch = retry_body
        .find("proxy_to_backend_mesh_retry(")
        .expect("mesh retry dispatch not found");
    let plain_dispatch = retry_body
        .find("proxy_to_backend_retry(")
        .expect("plain retry dispatch not found");

    assert!(selection < hbone && selection < mesh_mtls);
    assert!(hbone < admission && mesh_mtls < admission);
    assert!(admission < mesh_dispatch && mesh_dispatch < plain_dispatch);

    // Capability-aware mesh dispatch stays preferred, but any mesh-required
    // shape that cannot ride HBONE/mTLS — including cross-cluster-only — must
    // still hit the shared refusal helper before CB/admission/plain dial.
    let refusal = retry_body
        .find("direct_http_mesh_transport_refusal(")
        .expect(
            "generic retry loop must screen mesh-required shapes via \
             direct_http_mesh_transport_refusal before plain dial",
        );
    assert!(
        hbone < refusal && mesh_mtls < refusal,
        "refusal must follow per-attempt transport resolution"
    );
    assert!(
        refusal < admission,
        "mesh refusal must precede backend admission and dial"
    );
    assert!(
        retry_body[refusal..].contains("!retry_dispatch_hbone")
            && retry_body[refusal..].contains("!retry_dispatch_mesh_mtls"),
        "refusal gate must only fire when neither mesh transport is dispatchable"
    );

    let mesh_unavailable = retry_body
        .find("Mesh retry target cannot be dispatched securely; failing closed")
        .expect("mesh transport unavailable fail-closed not found");
    let grpc_shape = retry_body[mesh_unavailable..]
        .find("mesh_grpc_unavailable_response(")
        .expect("gRPC mesh-unavailable fail-closed must use Trailers-Only UNAVAILABLE");
    let json_shape = retry_body[mesh_unavailable..]
        .find("Mesh transport dispatch required for this backend target")
        .expect("plain HTTP mesh-unavailable fail-closed must keep JSON 502");
    assert!(
        grpc_shape < json_shape,
        "is_grpc_request must select mesh_grpc_unavailable_response before the JSON 502 arm"
    );
    assert!(
        retry_body[mesh_unavailable..].contains("skip_final_cb_record = true"),
        "mesh dispatch refusal must stay backend-health-neutral"
    );
}

#[test]
fn mesh_retry_replays_finalized_bytes_without_rerunning_body_hooks() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let helper = src
        .find("async fn proxy_to_backend_mesh_retry(")
        .expect("mesh retry helper not found");
    let helper_tail = &src[helper..];
    let end = helper_tail
        .find("/// Proxy the request to the backend.")
        .expect("mesh retry helper end not found");
    let helper_body = &helper_tail[..end];

    assert!(helper_body.contains("MeshClientRequestBody::Replayable {"));
    assert!(helper_body.contains("resolve_effective_proxy_for_target("));
    assert!(!helper_body.contains("apply_request_body_plugins_with_context("));
    assert!(!helper_body.contains("run_final_request_body_hooks("));
}

#[test]
fn buffered_mesh_request_refuses_native_trailers_independent_of_retry_retain() {
    let src = include_str!("../../../src/proxy/mod.rs");
    let helper = src
        .find("async fn prepare_mesh_request_body(")
        .expect("prepare_mesh_request_body not found");
    let helper_tail = &src[helper..];
    let end = helper_tail
        .find("pub(crate) fn store_request_body_metadata(")
        .expect("prepare_mesh_request_body end not found");
    let helper_body = &helper_tail[..end];

    assert!(
        helper_body.contains("ClientRequestBody::Streaming(request) if stream_request_body =>"),
        "streaming native requests must remain the unchanged fast path"
    );
    assert!(
        helper_body.contains(
            ".trailers\n        .as_ref()\n        .is_some_and(|trailers| !trailers.is_empty())"
        ),
        "buffered mesh path must refuse any non-empty native inbound trailers"
    );
    assert!(
        !helper_body.contains("if retain_request_body\n        && buffered"),
        "native trailer refusal must not be gated on retain_request_body / retries"
    );
    assert!(
        helper_body.contains("ErrorClass::DispatchPolicyRejected"),
        "native trailer refusal must stay health-neutral DispatchPolicyRejected"
    );
    assert!(
        helper_body.contains("staged_request_trailers"),
        "validated gRPC-Web staged trailers must still populate Replayable"
    );
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
fn test_grpc_client_deadline_before_dispatch_is_neutral() {
    let err = GrpcProxyError::ClientDeadlineExceeded(
        "gRPC deadline exceeded during backend connection acquisition".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ClientDisconnect
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
fn test_grpc_dispatch_canceled_classifies_as_pre_wire_pool_error() {
    // hyper `is_canceled` on a buffered body proves the request never left
    // the client. Map to ConnectionPoolError so request_reached_wire is
    // false and retry_on_connect_failure can redial after pool invalidation.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::DispatchCanceled,
        "Backend error: canceled".into(),
    );
    let class = classify_grpc_proxy_error(&err);
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::DispatchCanceled
            .is_connect_class()
    );
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "DispatchCanceled must be pre-wire so buffered unary RPCs retry on \
         pooled-sender GOAWAY races"
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
        K::DispatchCanceled,
        K::TrustWithdrawn,
        K::MaxConnections,
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
        K::DispatchCanceled,
        K::MaxConnections,
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
            | K::BackendRequest
            | K::DispatchCanceled
            | K::TrustWithdrawn
            | K::MaxConnections => (),
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

#[test]
fn test_grpc_response_too_large_classified_as_backend_failure() {
    // F04 (PR #1408): an oversized BACKEND response body is
    // GrpcProxyError::ResponseTooLarge — distinct from the oversized CLIENT
    // request (ResourceExhausted, classified as a client-side RequestError).
    // It must classify as ResponseBodyTooLarge so the circuit breaker treats it
    // as a backend failure (502), mirroring the HTTP path, rather than a neutral
    // client-side outcome.
    let err = GrpcProxyError::ResponseTooLarge(
        "gRPC response payload size exceeds maximum of 1024 bytes".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&err),
        ErrorClass::ResponseBodyTooLarge
    );
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
fn test_classify_body_error_bare_canceled_is_not_client_disconnect() {
    let err: Box<dyn std::error::Error + Send + Sync> = "H2 stream canceled by peer".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_classify_body_error_client_canceled_token_is_client_disconnect() {
    let err: Box<dyn std::error::Error + Send + Sync> = "request canceled by client".into();
    let (class, disconnected) = classify_body_error(&*err);
    assert_eq!(class, ErrorClass::ClientDisconnect);
    assert!(disconnected);
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
fn test_classify_boxed_error_typed_dns_lookup() {
    use ferrum_edge::proxy::stream_error::StreamSetupError;
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::dns_lookup(
        "backend.example.com",
        anyhow::Error::from(std::io::Error::other(
            "DNS resolution returned no addresses",
        )),
    ));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::DnsLookupError);
}

/// A resolve refused by the backend egress policy dialed nothing and answered
/// no query. Typing it as a DNS setup error would take precedence over the
/// `"egress policy"` anchor in the typed walk and silently move it from
/// `dispatch_policy_rejected` (non-retryable, backend-health-neutral) to
/// `dns_lookup_error`, contradicting the neutral circuit-breaker accounting the
/// same call sites already perform.
#[test]
fn test_stream_dns_setup_error_keeps_egress_policy_denials_dispatch_rejected() {
    let denied = ferrum_edge::_test_support::stream_dns_setup_error_for_test(
        "10.0.0.5",
        anyhow::anyhow!("literal backend 10.0.0.5 denied by backend egress policy"),
    );
    assert_eq!(
        classify_boxed_error(denied.as_ref()),
        ErrorClass::DispatchPolicyRejected
    );

    let genuine = ferrum_edge::_test_support::stream_dns_setup_error_for_test(
        "backend.local",
        anyhow::anyhow!("DNS resolution returned no addresses for backend.local"),
    );
    assert_eq!(
        classify_boxed_error(genuine.as_ref()),
        ErrorClass::DnsLookupError
    );
}

#[test]
fn test_classify_boxed_error_live_dns_no_addresses_wording() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "DNS resolution returned no addresses for backend.local".into();
    assert_eq!(classify_boxed_error(&*err), ErrorClass::DnsLookupError);
}

#[test]
fn test_classify_boxed_error_tls_close_without_notify_is_connection_closed() {
    use ferrum_edge::retry::TLS_CLOSE_WITHOUT_NOTIFY;
    let io_err = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        format!(
            "peer closed connection {TLS_CLOSE_WITHOUT_NOTIFY}: \
             https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
        ),
    );
    assert_eq!(classify_boxed_error(&io_err), ErrorClass::ConnectionClosed);
}

#[test]
fn test_close_notify_eof_wrapping_rustls_stays_connection_closed() {
    // Nearest false-positive to the handshake-rustls → TlsError change
    // (#4051): omitted close_notify is UnexpectedEof whose Display names
    // the rustls teardown, and get_ref() may hold a rustls::Error. The
    // close_notify check must win before handshake-class rustls can steal
    // it as tls_error.
    use ferrum_edge::retry::TLS_CLOSE_WITHOUT_NOTIFY;
    #[derive(Debug)]
    struct CloseNotifyPayload(rustls::Error);
    impl std::fmt::Display for CloseNotifyPayload {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "peer closed connection {TLS_CLOSE_WITHOUT_NOTIFY}: \
                 https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
            )
        }
    }
    impl std::error::Error for CloseNotifyPayload {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
    let io_err = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        CloseNotifyPayload(rustls::Error::HandshakeNotComplete),
    );
    let class = classify_boxed_error(&io_err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert_ne!(class, ErrorClass::TlsError);
}

#[test]
fn test_classify_boxed_setup_error_handshake_alert_is_tls_error() {
    let rustls_err = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
    assert_eq!(
        classify_boxed_setup_error(&rustls_err),
        ErrorClass::TlsError
    );
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
fn test_classify_boxed_error_typed_client_admission_disconnect() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::new(
        StreamSetupKind::ClientDisconnectedDuringAdmission,
        "TCP",
    ));
    assert_eq!(classify_boxed_error(&*err), ErrorClass::RequestError);
}

#[test]
fn test_classify_boxed_error_typed_sni_admission_refused() {
    // The Display still contains "refused", which the substring fallback
    // maps to ConnectionRefused. The typed kind must win so operators do
    // not treat SNI admission as a backend SYN/RST (issue #4407).
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(StreamSetupError::with_message(
        StreamSetupKind::SniAdmissionRefused,
        "SNI-routed stream listener on port 21582 refused connection (not_tls)",
    ));
    assert_eq!(
        classify_boxed_error(&*err),
        ErrorClass::DispatchPolicyRejected
    );
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

#[test]
fn test_classify_boxed_setup_error_ws_io_reset_stays_post_wire() {
    // Regression for the WSS handshake-reset hazard: tokio-tungstenite's
    // `connect_async_tls_with_config` writes and flushes the Upgrade
    // request BEFORE reading the response. If the backend RSTs the
    // connection after receiving the request but before sending a 101,
    // the failure surfaces as `tungstenite::Error::Io(ConnectionReset)`.
    //
    // The hazard: with phase_is_connect=true (WSS dial uses
    // classify_boxed_setup_error), the io::Error walker would override
    // ConnectionReset → ConnectionRefused (pre-wire) per the standard
    // connect-phase RST rule. The WS retry predicate
    // `!request_reached_wire(...)` would then return true and
    // retry_on_connect_failure would replay the already-sent upgrade.
    // The explicit `WsError::Io` arm in the typed walker keeps the
    // io::Error::ConnectionReset → ConnectionReset (post-wire) mapping
    // even when invoked from the setup classifier.
    let io_reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer");
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(tokio_tungstenite::tungstenite::Error::Io(io_reset));
    let class = classify_boxed_setup_error(&*err);
    assert_eq!(
        class,
        ErrorClass::ConnectionReset,
        "tungstenite Io(ConnectionReset) must stay post-wire even via the setup classifier"
    );
    assert!(
        ferrum_edge::retry::request_reached_wire(class),
        "WS handshake-read reset must be post-wire so retry_on_connect_failure \
         doesn't replay the already-sent Upgrade"
    );
}

#[test]
fn test_classify_boxed_setup_error_ws_io_econnrefused_stays_pre_wire() {
    // Counterpart to the reset test: a genuine ECONNREFUSED on initial
    // TCP connect (SYN got RST before any bytes were written) is still
    // pre-wire and should stay retryable as a connect failure. tungstenite
    // wraps this as Error::Io too, but the io::ErrorKind unambiguously
    // identifies the case.
    let io_refused = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(tokio_tungstenite::tungstenite::Error::Io(io_refused));
    let class = classify_boxed_setup_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionRefused);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "ECONNREFUSED on initial connect must remain pre-wire \
         so retry_on_connect_failure can replay safely"
    );
}

#[test]
fn h3_mesh_websocket_invalid_request_target_is_policy_rejection() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        WS_MESH_BACKEND_REQUEST_TARGET_INVALID.into();
    assert_eq!(
        classify_boxed_setup_error(err.as_ref()),
        ErrorClass::DispatchPolicyRejected
    );
}

#[test]
fn test_classify_boxed_error_ws_http_response_is_post_wire_request_error() {
    // The backend received the upgrade request and replied with a non-101
    // response (e.g., 401, 403, 404). Post-wire by definition — request
    // bytes already crossed to the backend's application layer. Classify
    // as RequestError so request_reached_wire == true and the
    // retry-on-connect-failure path does NOT loop forever replaying an
    // upgrade the backend already rejected.
    let response = http::Response::builder()
        .status(401)
        .body(None)
        .expect("valid http response");
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(
        tokio_tungstenite::tungstenite::Error::Http(Box::new(response)),
    );
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::RequestError);
    assert!(
        ferrum_edge::retry::request_reached_wire(class),
        "WS upgrade rejection (HTTP response from backend) must be post-wire"
    );
    // Setup-phase classifier MUST also keep this post-wire — the WSS dial
    // path uses classify_boxed_setup_error, but a backend-side upgrade
    // rejection is post-wire regardless of phase.
    let setup_class = classify_boxed_setup_error(&*err);
    assert!(
        ferrum_edge::retry::request_reached_wire(setup_class),
        "even via setup classifier, WS Http response is post-wire"
    );
}

// --- Typed rustls and io::Error walks (tightened typed-first classification) ---

#[test]
fn test_classify_boxed_error_post_connect_rustls_is_post_wire() {
    // `classify_boxed_error` calls `classify_typed_chain` with
    // `phase_is_connect=false` because its callers (WebSocket session
    // forwarding, TCP relay mid-stream, response-body classification)
    // are all post-handshake. A *record-layer* rustls error here
    // (decrypt failed, oversized record) MUST classify as a post-wire
    // class so request_reached_wire returns true and
    // `retry_on_connect_failure` does NOT replay non-idempotent
    // requests whose bytes may already have crossed the encrypted
    // channel. Handshake-class rustls (CertificateRequired, etc.) is
    // a different case — see the tests below.
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(rustls::Error::DecryptError);
    let class = classify_boxed_error(&*err);
    assert_eq!(
        class,
        ErrorClass::ConnectionReset,
        "post-handshake rustls record-layer errors must map to a mid-stream class"
    );
    assert!(
        ferrum_edge::retry::request_reached_wire(class),
        "post-handshake rustls error must be post-wire (got {class:?}); \
         a pre-wire class would let retry_on_connect_failure replay \
         non-idempotent requests already on the wire"
    );
}

#[test]
fn test_classify_boxed_error_post_connect_handshake_alert_is_tls_error() {
    // Issue #4406: reqwest reports backend mTLS handshake failures with
    // `is_connect() = false` (TCP already succeeded). A typed handshake
    // alert must still be TlsError so retry_on_connect_failure can replay
    // and operators grepping tls_error see the misconfig.
    let alert = rustls::AlertDescription::CertificateRequired;
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(rustls::Error::AlertReceived(alert));
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "handshake-class rustls must stay pre-wire so retry_on_connect_failure \
         can replay; nothing reached the origin application layer"
    );
}

#[test]
fn test_classify_boxed_error_handshake_failure_alert_is_tls_error() {
    let alert = rustls::AlertDescription::HandshakeFailure;
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(rustls::Error::AlertReceived(alert));
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(!ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_classify_typed_chain_treats_hyper_is_canceled_as_pool_error() {
    // Issue #4406 live reqwest path: hyper reports is_canceled with no
    // rustls in the request chain. classify_typed_chain must map that
    // typed flag to ConnectionPoolError (pre-wire). hyper::Error is not
    // constructible here; this guards the arm, and the live reqwest
    // handshake in backend_mtls_tests exercises the real error.
    let src = include_str!("../../../src/retry.rs");
    assert!(
        src.contains("if hyper_err.is_canceled()")
            && src.contains("// hyper 1.9 contract (issue #3578 rejected a downgrade)")
            && src.contains("return Some(ErrorClass::ConnectionPoolError);"),
        "classify_typed_chain must map hyper is_canceled to ConnectionPoolError"
    );
    assert!(
        !src.contains("source_chain.contains(\"connection was not ready\")")
            && !src.contains("error_str.contains(\"connection was not ready\")")
            && !src.contains("debug_str.contains(\"connection was not ready\")"),
        "must not classify by matching the hyper Display label"
    );
}

#[test]
fn test_classify_boxed_error_close_notify_alert_is_connection_closed() {
    // #4051: CloseNotify is teardown, not a handshake. Must not become
    // tls_error even when the typed rustls error is reachable.
    let alert = rustls::AlertDescription::CloseNotify;
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(rustls::Error::AlertReceived(alert));
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_classify_boxed_error_post_connect_rustls_buried_in_chain() {
    // HandshakeNotComplete is handshake-class even through a wrapper —
    // the chain walker reaches rustls and maps it to TlsError.
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
    let class = classify_boxed_error(&wrapped);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(!ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_classify_boxed_error_post_connect_decrypt_buried_in_chain() {
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
    let wrapped = Wrapper(rustls::Error::DecryptError);
    let class = classify_boxed_error(&wrapped);
    assert_eq!(class, ErrorClass::ConnectionReset);
    assert!(ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_classify_reqwest_setup_phase_rustls_is_pre_wire_via_typed_kinds() {
    // In setup contexts (gRPC pool, H2 pool, reqwest is_connect() branch)
    // the classifier sees `phase_is_connect=true` and rustls errors map
    // to TlsError (pre-wire) — handshake failures predate any wire
    // commit, so retry_on_connect_failure can replay safely. Exercise
    // this via the gRPC TlsHandshake kind which threads through
    // `classify_grpc_proxy_error` with the setup-phase path.
    let err = GrpcProxyError::backend_unavailable(
        ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind::TlsHandshake,
        "TLS handshake failed: certificate verify failed".into(),
    );
    let class = classify_grpc_proxy_error(&err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "setup-phase TLS handshake failure must remain pre-wire so \
         retry_on_connect_failure can replay safely"
    );
}

#[test]
fn test_classify_boxed_setup_error_keeps_rustls_as_tls_error_pre_wire() {
    // The WSS backend dial path uses `classify_boxed_setup_error` because
    // every failure there is pre-wire (the gateway hasn't sent 101/200 to
    // the client yet). A tokio-tungstenite TLS handshake failure surfaces
    // through that path with a rustls::Error in the source chain — it
    // MUST classify as TlsError (pre-wire), NOT ConnectionReset (which
    // post-connect callers get from the same rustls error).
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(rustls::Error::HandshakeNotComplete);
    let class = classify_boxed_setup_error(&*err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "setup-phase rustls error must be pre-wire"
    );
}

#[test]
fn test_connect_phase_io_reset_wrapping_rustls_is_tls_error_not_refused() {
    // tokio-rustls / reqwest wrap handshake failures as io::Error
    // (often ConnectionReset) with rustls::Error in get_ref(), not
    // source(). TCP connected; the failure is TLS. Must not take the
    // connect-phase RST → ConnectionRefused collapse.
    let io_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        rustls::Error::HandshakeNotComplete,
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_setup_error(&*err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(
        !ferrum_edge::retry::request_reached_wire(class),
        "TLS handshake after TCP connect stays pre-wire; retry_on_connect_failure \
         is unchanged versus the previous ConnectionRefused label"
    );
}

#[test]
fn test_connect_phase_io_reset_without_rustls_still_collapses_to_refused() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset by peer",
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_setup_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionRefused);
    assert!(!ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_post_connect_io_reset_without_rustls_is_connection_reset() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset by peer",
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionReset);
    assert!(ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_post_connect_io_reset_wrapping_handshake_rustls_is_tls_error() {
    // tokio-rustls / reqwest wrap a missing-client-cert alert as
    // io::ErrorKind::ConnectionReset with rustls in get_ref(), and
    // reqwest's is_connect() is already false (issue #4406). Must not
    // stay ConnectionReset.
    let io_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired),
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::TlsError);
    assert!(!ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_post_connect_io_reset_wrapping_decrypt_rustls_is_connection_reset() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        rustls::Error::DecryptError,
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionReset);
    assert!(ferrum_edge::retry::request_reached_wire(class));
}

#[test]
fn test_post_connect_unexpected_eof_is_connection_closed() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_error(&*err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(
        ferrum_edge::retry::request_reached_wire(class),
        "a truncated body is post-wire: retry_on_connect_failure must not \
         replay a non-idempotent request the backend may already have processed"
    );
}

#[test]
fn test_connect_phase_unexpected_eof_without_rustls_is_not_connection_closed() {
    // Connect-phase EOF without rustls is not a completed handshake and
    // must not become post-wire ConnectionClosed.
    let io_err = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    );
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io_err);
    let class = classify_boxed_setup_error(&*err);
    assert_ne!(class, ErrorClass::ConnectionClosed);
    assert_ne!(class, ErrorClass::TlsError);
}

#[test]
fn test_classify_body_error_unexpected_eof_is_connection_closed() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    );
    let (class, disconnected) = classify_body_error(&io_err);
    assert_eq!(class, ErrorClass::ConnectionClosed);
    assert!(!disconnected);
}

#[test]
fn test_substring_fallback_matches_capitalized_os_wording() {
    // Several stream paths stringify io::Error before classifying (TCP
    // fast-path copy errors, UDP backend recv/send errors). The OS wording
    // from `io::Error::Display` is capitalized — `Connection reset by peer`,
    // `Broken pipe`, `Connection aborted`. The substring fallback must
    // recognize both lowercase application wording AND the capitalized
    // OS wording so stringified errors don't fall through to RequestError.
    for (msg, want) in [
        (
            "Connection reset by peer (os error 54)",
            ErrorClass::ConnectionReset,
        ),
        (
            "Connection reset by peer (os error 104)",
            ErrorClass::ConnectionReset,
        ),
        ("Broken pipe (os error 32)", ErrorClass::ConnectionClosed),
        (
            "Connection aborted (os error 53)",
            ErrorClass::ConnectionClosed,
        ),
    ] {
        let err: Box<dyn std::error::Error + Send + Sync> = msg.into();
        assert_eq!(
            classify_boxed_error(&*err),
            want,
            "stringified OS wording {msg:?} must classify as {want:?} via the substring fallback"
        );
    }
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

#[test]
fn test_classify_boxed_setup_error_raw_io_broken_pipe_classes_are_pre_wire() {
    // Setup-phase raw IO errors happen before the backend request is committed.
    // They must classify as pre-wire so retry_on_connect_failure can replay
    // safely and the classifier's setup-phase contract stays aligned with
    // request_reached_wire().
    for kind in [
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionAborted,
    ] {
        let err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::new(kind, "setup failed before write"));
        let class = classify_boxed_setup_error(&*err);
        assert_eq!(
            class,
            ErrorClass::ConnectionRefused,
            "{kind:?} during setup must be grouped with pre-wire connect failures"
        );
        assert!(
            !ferrum_edge::retry::request_reached_wire(class),
            "{kind:?} during setup must not be considered post-wire"
        );
    }
}

#[test]
fn test_classify_boxed_error_raw_io_broken_pipe_classes_stay_post_wire() {
    // The normal boxed-error classifier is used by post-connect paths. The same
    // raw IO classes remain post-wire there, so non-idempotent requests do not
    // get replayed via retry_on_connect_failure.
    for kind in [
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionAborted,
    ] {
        let err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::new(kind, "backend closed midstream"));
        let class = classify_boxed_error(&*err);
        assert_eq!(class, ErrorClass::ConnectionClosed);
        assert!(
            ferrum_edge::retry::request_reached_wire(class),
            "{kind:?} after connect must stay post-wire"
        );
    }
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

#[test]
fn test_direct_h2_send_request_error_response_maintains_wire_boundary() {
    // connection_error must equal !request_reached_wire(error_class) for every
    // class the direct-H2 send_request mapper can emit. Flattening everything
    // to ProtocolError with connection_error=true previously violated this.
    use ferrum_edge::_test_support::direct_h2_send_request_error_response_for_class_for_test;
    for class in [
        ErrorClass::ConnectionPoolError,
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionTimeout,
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::ProtocolError,
        ErrorClass::ReadWriteTimeout,
        ErrorClass::TlsError,
        ErrorClass::DnsLookupError,
        ErrorClass::RequestError,
    ] {
        let resp = direct_h2_send_request_error_response_for_class_for_test(
            class,
            Some("127.0.0.1".into()),
        );
        assert_eq!(resp.error_class, Some(class));
        assert_eq!(
            resp.connection_error,
            !ferrum_edge::retry::request_reached_wire(class),
            "{class:?}: connection_error must equal !request_reached_wire"
        );
        let expected_status = if class == ErrorClass::ReadWriteTimeout {
            504
        } else {
            502
        };
        assert_eq!(
            resp.status_code, expected_status,
            "{class:?}: HTTP-family dispatch must map read/write timeout to 504 and everything else to 502"
        );
    }
}

#[test]
fn test_pooled_h2_send_request_classifier_is_public_for_dispatch_sites() {
    // Guard the public surface used by `direct_h2_send_request_error_response`
    // so a future refactor cannot re-privatize the canonical classifier.
    let src = include_str!("../../../src/proxy/http2_pool.rs");
    assert!(
        src.contains("pub fn classify_pooled_h2_send_request_error("),
        "direct-H2 send_request errors must classify through a public helper"
    );
    assert!(
        src.contains("if hyper_err.is_canceled()"),
        "pooled send_request classifier must treat hyper is_canceled as pre-wire"
    );
    assert!(
        src.contains("return normalize_pooled_h2_send_post_wire_class(cls);"),
        "typed source-chain errors must pass through the conservative post-wire boundary"
    );
    let mod_src = include_str!("../../../src/proxy/mod.rs");
    assert!(
        mod_src.contains("classify_pooled_h2_send_request_error"),
        "map_h2_err must use the canonical pooled-send classifier"
    );
    assert!(
        !mod_src.contains(
            "connection_error: true,\n                backend_resolved_ip: resolved_ip,\n                error_class: Some(retry::ErrorClass::ProtocolError)"
        ),
        "must not hard-code connection_error=true with ProtocolError"
    );
}

#[test]
fn test_pooled_h2_send_source_classes_fail_closed_as_post_wire() {
    use ferrum_edge::_test_support::normalize_pooled_h2_send_post_wire_class_for_test as normalize;
    use ferrum_edge::retry::request_reached_wire;

    for class in [
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionTimeout,
        ErrorClass::DnsLookupError,
        ErrorClass::TlsError,
        ErrorClass::PortExhaustion,
        ErrorClass::ConnectionPoolError,
    ] {
        let mapped = normalize(class);
        assert_eq!(mapped, ErrorClass::ProtocolError, "{class:?}");
        assert!(request_reached_wire(mapped), "{class:?} -> {mapped:?}");
    }

    for class in [
        ErrorClass::ReadWriteTimeout,
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::ProtocolError,
        ErrorClass::RequestError,
    ] {
        assert_eq!(normalize(class), class, "{class:?}");
    }
}

#[tokio::test]
async fn test_remaining_grpc_timeout_header_decrements_across_attempts() {
    use ferrum_edge::_test_support::apply_remaining_grpc_timeout_header_for_test;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "grpc-timeout",
        hyper::header::HeaderValue::from_static("500m"),
    );

    apply_remaining_grpc_timeout_header_for_test(&mut headers, deadline);
    let first = headers
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .expect("first remaining timeout")
        .to_string();
    assert!(
        first.ends_with('m'),
        "remaining budget should prefer millisecond units: {first}"
    );
    let first_ms: u64 = first.trim_end_matches('m').parse().expect("parse ms");
    assert!(
        (1..=500).contains(&first_ms),
        "first remaining must be within the original budget, got {first_ms}"
    );

    tokio::time::sleep(Duration::from_millis(80)).await;
    apply_remaining_grpc_timeout_header_for_test(&mut headers, deadline);
    let second = headers
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .expect("second remaining timeout")
        .to_string();
    let second_ms: u64 = second.trim_end_matches('m').parse().expect("parse ms");
    assert!(
        second_ms < first_ms,
        "second attempt must forward a strictly smaller remaining timeout \
         (first={first_ms}m second={second_ms}m) — never re-arm the original"
    );
}

#[test]
fn test_reqwest_grpc_timeout_forwarding_uses_remaining_deadline_on_every_attempt() {
    let src = include_str!("../../../src/proxy/mod.rs");
    assert_eq!(
        src.matches(".map(grpc_proxy::remaining_grpc_timeout_header_value)")
            .count(),
        2,
        "initial and retry reqwest dispatch must derive the outbound header from the absolute deadline"
    );
    assert_eq!(
        src.matches("\"grpc-timeout\" if remaining_grpc_timeout_header.is_some() => continue")
            .count(),
        2,
        "initial and retry reqwest dispatch must suppress the stale relative header"
    );
    assert_eq!(
        src.matches("req_builder = req_builder.header(\"grpc-timeout\", value);")
            .count(),
        2,
        "initial and retry reqwest dispatch must install one remaining-budget header"
    );
}

#[test]
fn test_eager_buffer_body_read_timeout_maps_to_504_read_write_timeout() {
    // #2953: the per-request `backend_read_timeout_ms` covers through body
    // completion in reqwest, so a read timeout during eager buffering lands in
    // `buffered_backend_response_from_body_read`. It must classify as
    // `read_write_timeout`/504 — the pair the direct-H2 arm already emits via
    // `HyperBodyCollectError::ReadTimeout` — instead of the hardcoded
    // `connection_reset`/502 that made one backend fault report two different
    // ways depending on which transport served the request.
    use ferrum_edge::_test_support::eager_buffer_body_read_status_and_class_for_test as classify;

    let (status, class) = classify(ErrorClass::ReadWriteTimeout);
    assert_eq!(status, 504);
    assert_eq!(class, ErrorClass::ReadWriteTimeout);
}

#[test]
fn test_eager_buffer_body_read_preserves_post_wire_classes_with_502() {
    // Every other post-wire class keeps the 502 and its own label, so the
    // reqwest arm no longer flattens reset / closed / protocol faults into one
    // bucket.
    use ferrum_edge::_test_support::eager_buffer_body_read_status_and_class_for_test as classify;

    for class in [
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::ProtocolError,
        ErrorClass::GracefulRemoteClose,
        ErrorClass::ClientDisconnect,
        ErrorClass::RequestError,
    ] {
        let (status, mapped) = classify(class);
        assert_eq!(status, 502, "{class:?} keeps 502");
        assert_eq!(mapped, class, "{class:?} keeps its class");
    }
}

#[test]
fn test_eager_buffer_body_read_never_reports_a_pre_wire_class() {
    // Response headers have already arrived at every call site, so the caller
    // pins `connection_error: false`. A pre-wire class would then violate
    // `connection_error == !request_reached_wire(error_class)` and could let
    // `retry_on_connect_failure` replay a non-idempotent request whose body the
    // backend already processed. Pre-wire verdicts are coerced to the post-wire
    // `ConnectionReset`, and every emitted class must be post-wire.
    use ferrum_edge::_test_support::eager_buffer_body_read_status_and_class_for_test as classify;
    use ferrum_edge::retry::request_reached_wire;

    let coerced = ErrorClass::ConnectionReset;
    for class in [
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionTimeout,
        ErrorClass::DnsLookupError,
        ErrorClass::TlsError,
        ErrorClass::PortExhaustion,
        ErrorClass::ConnectionPoolError,
    ] {
        let (status, mapped) = classify(class);
        assert_eq!(status, 502, "{class:?} must stay 502");
        assert_eq!(mapped, coerced, "{class:?} must be coerced");
    }
    for class in [
        ErrorClass::ReadWriteTimeout,
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::ProtocolError,
        ErrorClass::RequestError,
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionPoolError,
    ] {
        let (_, mapped) = classify(class);
        assert!(request_reached_wire(mapped), "{class:?} -> {mapped:?}");
    }
}

#[test]
fn test_http_backend_dispatch_maps_read_write_timeout_to_504_timeout_body() {
    // #3922: a live `backend_read_timeout_ms` / `backend_write_timeout_ms`
    // expiry classifies as `ReadWriteTimeout` (the log line already said
    // `error_kind=read_timeout`) but the reqwest dispatch path used to flatten
    // it to 502 / `backend_error` / `{"error":"Backend unavailable"}`. The
    // shared mapper is the single HTTP-family status+body boundary.
    use ferrum_edge::_test_support::http_backend_dispatch_error_response_for_test as map;
    use ferrum_edge::_test_support::http_backend_failure_status_and_body_for_test as status_body;
    use ferrum_edge::retry::request_reached_wire;

    let (status, body) = status_body(ErrorClass::ReadWriteTimeout);
    assert_eq!(status, 504);
    assert_eq!(body, r#"{"error":"Backend timeout"}"#);

    let resp = map(ErrorClass::ReadWriteTimeout, Some("127.0.0.1".into()));
    assert_eq!(resp.status_code, 504);
    assert_eq!(
        resp.body_bytes(),
        br#"{"error":"Backend timeout"}"#,
        "timeout body must be timeout-specific, not Backend unavailable"
    );
    assert!(
        !resp.connection_error,
        "post-wire read/write timeout must not look like a connect failure"
    );
    assert_eq!(resp.error_class, Some(ErrorClass::ReadWriteTimeout));
    assert!(request_reached_wire(ErrorClass::ReadWriteTimeout));
    assert_eq!(
        resp.connection_error,
        !request_reached_wire(ErrorClass::ReadWriteTimeout)
    );
}

#[test]
fn test_http_backend_dispatch_keeps_connect_refused_as_502_unavailable() {
    // Connection-refused / connect-timeout / DNS / TLS stay 502 with the
    // generic unavailable body and `connection_error=true` so retry and
    // `X-Gateway-Error: connection_failure` keep their pre-wire meaning.
    use ferrum_edge::_test_support::http_backend_dispatch_error_response_for_test as map;
    use ferrum_edge::retry::request_reached_wire;

    for class in [
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionTimeout,
        ErrorClass::DnsLookupError,
        ErrorClass::TlsError,
        ErrorClass::ConnectionPoolError,
        ErrorClass::PortExhaustion,
    ] {
        let resp = map(class, None);
        assert_eq!(resp.status_code, 502, "{class:?} stays 502");
        assert_eq!(
            resp.body_bytes(),
            br#"{"error":"Backend unavailable"}"#,
            "{class:?} keeps the generic unavailable body"
        );
        assert!(
            resp.connection_error,
            "{class:?} is pre-wire and must set connection_error"
        );
        assert_eq!(resp.error_class, Some(class));
        assert!(!request_reached_wire(class), "{class:?} is pre-wire");
    }
}

#[test]
fn test_http_backend_dispatch_keeps_other_post_wire_failures_as_502() {
    use ferrum_edge::_test_support::http_backend_dispatch_error_response_for_test as map;
    use ferrum_edge::retry::request_reached_wire;

    for class in [
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::ProtocolError,
        ErrorClass::RequestError,
        ErrorClass::GracefulRemoteClose,
    ] {
        let resp = map(class, None);
        assert_eq!(resp.status_code, 502, "{class:?} stays 502");
        assert_eq!(
            resp.body_bytes(),
            br#"{"error":"Backend unavailable"}"#,
            "{class:?} keeps the generic unavailable body"
        );
        assert!(
            !resp.connection_error,
            "{class:?} is post-wire and must not set connection_error"
        );
        assert!(request_reached_wire(class), "{class:?} is post-wire");
    }
}

#[test]
fn test_http_family_dispatch_sites_use_shared_timeout_mapper() {
    // #3922: the live reqwest send-error arms (initial + retry) and the H3
    // cross-protocol reqwest bridge must not hard-code 502 / "Backend
    // unavailable" after classifying a timeout. They funnel through the
    // shared mapper so a future edit cannot reintroduce a one-off status.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy.contains("http_backend_dispatch_error_response(error_class, resolved_ip.clone())"),
        "reqwest dispatch error arms must build the client response via the shared mapper"
    );
    assert_eq!(
        proxy
            .matches("http_backend_dispatch_error_response(error_class, resolved_ip.clone())")
            .count(),
        2,
        "initial and retry reqwest send failures must both use the shared mapper"
    );
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        cross.contains("crate::proxy::http_backend_failure_status_and_body(error_class)"),
        "H3→HTTP reqwest bridge dispatch failures must use the shared status/body mapper"
    );
    assert!(
        cross.contains("crate::proxy::eager_buffer_body_read_status_and_class("),
        "H3→HTTP buffered body-read failures must reuse the eager-buffer 504 mapping"
    );
    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(
        h3.contains("crate::proxy::http_backend_failure_status_and_body(classify_h3_error(e))"),
        "native-H3 dispatch failures must use the shared mapper after typed classification"
    );
}

/// Issue #2949 — the retry loop's response-streaming decision must not be
/// attempt-positional.
///
/// `should_retry` (above) consults only `status_code`, `connection_error`,
/// `error_class`, and the method — every one of which is known from the
/// response headers, before a single body byte is read. So a retry attempt can
/// safely be dispatched with the caller's streaming intent: an attempt that
/// turns out retryable just drops its undrained response, exactly as the
/// initial attempt (always dispatched with `should_stream`) already does.
///
/// Gating on `attempt >= max_retries` instead forced a healthy
/// `text/event-stream` that succeeded on an earlier attempt through the
/// buffered arm, which has no streaming-content-type exemption (unbounded when
/// `max_response_body_size_bytes` is `0`). Hosted acceptance coverage is
/// `functional_retry_test::retry_streams_sse_that_succeeds_before_the_final_attempt`;
/// this guard pins the wiring at every retry dispatch arm (mesh, native-H3,
/// and reqwest).
#[test]
fn retry_dispatch_arms_pass_the_streaming_decision_on_every_attempt() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let dispatch = proxy_src
        .split("// Replay the original request body on retry.")
        .nth(1)
        .expect("retry-loop attempt dispatch block")
        .split("final_upstream_target = current_target.clone();")
        .next()
        .expect("bounded attempt dispatch block");

    assert!(
        dispatch.contains("proxy_to_backend_mesh_retry(")
            && dispatch.contains("proxy_to_backend_http3_retry(")
            && dispatch.contains("proxy_to_backend_retry("),
        "the bounded block must cover mesh, native-H3, and reqwest retry dispatch arms"
    );
    assert!(
        !dispatch.contains("is_last_attempt")
            && !dispatch.contains("attempt >= retry_config.max_retries"),
        "no retry dispatch arm may gate the response-streaming decision on the attempt index"
    );
    assert_eq!(
        dispatch.matches("should_stream,").count(),
        3,
        "mesh, native-H3, and reqwest retry arms must each forward `should_stream` unchanged"
    );
}

/// STRUCTURAL CONTRACT (issue #3290): a DestinationRule
/// `connectionPool.tcp.maxConnections` refusal is the ONE class that must be
/// pre-wire and backend-health-neutral at the same time, on EVERY pooled
/// transport that can emit it.
///
/// * pre-wire — no socket was opened, so `connection_error` is true and
///   `retry_on_connect_failure` may rotate to another load-balanced target with
///   its own admission lane. That is what the raw-TCP over-cap path does.
/// * health-neutral — the ceiling is the operator's own gateway-side policy,
///   not evidence about the backend. Classifying it as the generic
///   `ConnectionPoolError` (which IS a backend-health signal) made every
///   over-cap refusal record a circuit-breaker failure, a passive-health
///   failure, a load-balancer penalty sample, and an adaptive-concurrency
///   shrink — so saturating a configured cap would eject a perfectly healthy
///   destination. The raw-TCP path records `cb.record_neutral()` for exactly
///   this reason.
#[test]
fn max_connections_refusal_is_pre_wire_and_health_neutral_on_every_transport() {
    use ferrum_edge::_test_support::{
        error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    };
    use ferrum_edge::backend_conn_limit::BackendConnectionLimitExceeded;
    use ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind;
    use ferrum_edge::proxy::hbone_pool::HbonePoolError;
    use ferrum_edge::proxy::http2_pool::{Http2PoolError, classify_http2_pool_error};

    let grpc_err = GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::MaxConnections,
        "gRPC pool over cap".to_string(),
    );
    let grpc = classify_grpc_proxy_error(&grpc_err);

    let h2_err = Http2PoolError::MaxConnectionsExceeded {
        message: "direct HTTP/2 pool over cap".to_string(),
    };
    let direct_h2 = classify_http2_pool_error(&h2_err);

    let hbone_err = HbonePoolError::MaxConnectionsExceeded {
        host: "b".to_string(),
        port: 8080,
        current: 1,
        cap: 1,
    };
    let hbone = hbone_err.error_class();

    // The native-H3 / reqwest-connector surface has no typed enum — the refusal
    // travels as the marker error itself, recognized structurally by the shared
    // boxed-setup classifier.
    let refusal = BackendConnectionLimitExceeded { current: 1, cap: 1 };
    let boxed = classify_boxed_setup_error(&refusal);

    for (transport, class) in [
        ("gRPC", grpc),
        ("direct H2", direct_h2),
        ("HBONE / mesh-mTLS", hbone),
        ("native H3 / boxed setup", boxed),
    ] {
        assert_eq!(
            class,
            ErrorClass::BackendConnectionLimit,
            "{transport}: an over-cap refusal must carry the dedicated class"
        );
        assert!(
            !ferrum_edge::retry::request_reached_wire(class),
            "{transport}: nothing was dialed, so the refusal must stay pre-wire \
             and remain replayable on another target"
        );
        assert!(
            error_class_is_health_neutral_for_test(class),
            "{transport}: a gateway-side ceiling must not trip the circuit \
             breaker, ding passive health, penalize the load balancer, or \
             shrink the adaptive-concurrency permit"
        );
        assert!(
            !error_class_is_backend_failure_for_test(class),
            "{transport}: an over-cap refusal is not a post-wire backend failure"
        );
    }
}

/// The retry loop settles the circuit breaker for every INTERMEDIATE attempt
/// with a direct `record_failure`. Until `BackendConnectionLimit` existed, every
/// retryable class was a genuine backend failure, so that was sound. It is not
/// any more: this pins the neutral branch so an over-cap refusal that rotates
/// targets cannot open the breaker on a healthy destination.
#[test]
fn retry_loop_settles_health_neutral_intermediate_attempts_neutrally() {
    let proxy_src = include_str!("../../../src/proxy/mod.rs");
    let loop_body = proxy_src
        .split("// Record the failed attempt against the current target's circuit breaker")
        .nth(1)
        .expect("retry-loop intermediate circuit-breaker record")
        .split("let delay = retry::retry_delay(retry_config, attempt);")
        .next()
        .expect("bounded intermediate circuit-breaker block");

    assert!(
        loop_body.contains("client_side_no_backend_signal(result.error_class)")
            && loop_body.contains("cb.record_neutral(cb_retry_probe_slot_available)"),
        "an intermediate attempt whose class carries no backend signal must \
         settle the breaker neutrally rather than as a failure"
    );
}

/// A gateway-to-mesh transport refused by a trust withdrawal (issue #3859) is
/// the SAME shape as an over-cap refusal: pre-wire AND backend-health neutral.
///
/// Pre-wire, because nothing was queued on the transport — the accepted
/// generation is already published when the refusal is raised, so a redial
/// builds from the new verifier and succeeds. Health-neutral, because
/// withdrawing a trust root is the operator's own gateway policy, not evidence
/// about the destination workload. Classifying it as the generic
/// `ConnectionPoolError` would record a circuit-breaker failure, a
/// passive-health ding, a load-balancer penalty sample and an
/// adaptive-concurrency shrink for every mesh destination the gateway happened
/// to be talking to at the instant of a revocation — turning a
/// millisecond-scale trust rotation into a breaker-length outage for workloads
/// that did nothing wrong.
#[test]
fn trust_withdrawal_refusal_is_pre_wire_and_health_neutral_on_every_mesh_transport() {
    use ferrum_edge::_test_support::{
        error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    };
    use ferrum_edge::proxy::grpc_proxy::GrpcBackendUnavailableKind;
    use ferrum_edge::proxy::hbone_pool::HbonePoolError;

    // Both mesh pools raise the one shared pool error.
    let pool = HbonePoolError::TrustWithdrawn.error_class();
    // Native gRPC over either mesh transport carries its own typed kind.
    let grpc = classify_grpc_proxy_error(&GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::TrustWithdrawn,
        "mesh transport retired by trust withdrawal".to_string(),
    ));

    for (transport, class) in [("HBONE / mesh-mTLS", pool), ("native gRPC", grpc)] {
        assert_eq!(
            class,
            ErrorClass::TrustWithdrawn,
            "{transport}: a trust-withdrawal refusal must carry the dedicated class"
        );
        assert!(
            !ferrum_edge::retry::request_reached_wire(class),
            "{transport}: the refusal is pre-wire, so a retry must be able to \
             re-dial under the freshly published trust generation"
        );
        assert!(
            error_class_is_health_neutral_for_test(class),
            "{transport}: a gateway-side trust withdrawal must not trip the \
             circuit breaker, ding passive health, penalize the load balancer, \
             or shrink the adaptive-concurrency permit"
        );
        assert!(
            !error_class_is_backend_failure_for_test(class),
            "{transport}: a trust-withdrawal refusal is not a post-wire backend failure"
        );
    }

    // The refusal must stay distinguishable from the generic pool error, which
    // IS a backend-health signal.
    assert!(!error_class_is_health_neutral_for_test(
        ErrorClass::ConnectionPoolError
    ));
}

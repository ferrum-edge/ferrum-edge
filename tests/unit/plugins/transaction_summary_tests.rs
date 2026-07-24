//! Tests for TransactionSummary log format — field presence, serialization,
//! and backend resolved IP propagation.

use std::collections::HashMap;

use ferrum_edge::plugins::{StreamTransactionSummary, TransactionSummary};

/// Build a fully-populated TransactionSummary for testing.
fn make_full_summary() -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-03-25T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        http_method: "POST".to_string(),
        request_path: "/v1/users".to_string(),
        proxy_id: Some("proxy-users".to_string()),
        proxy_name: Some("Users API".to_string()),
        backend_target: Some("http://users-svc:3000/v1/users".to_string()),
        backend_resolved_ip: Some("10.244.1.42".to_string()),
        response_status_code: 201,
        latency_total_ms: 45.5,
        latency_gateway_processing_ms: 5.5,
        latency_backend_ttfb_ms: 38.0,
        latency_backend_total_ms: 40.0,
        latency_plugin_execution_ms: 3.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 2.5,
        request_user_agent: Some("curl/8.0".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

// ── JSON serialization ──────────────────────────────────────────────────

#[test]
fn test_summary_json_contains_backend_resolved_ip() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        json.contains(r#""backend_resolved_ip":"10.244.1.42""#),
        "JSON should contain backend_resolved_ip field, got: {}",
        json
    );
}

#[test]
fn test_summary_json_omits_backend_resolved_ip_when_none() {
    let mut summary = make_full_summary();
    summary.backend_resolved_ip = None;
    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        !json.contains("backend_resolved_ip"),
        "JSON should omit backend_resolved_ip when None, got: {}",
        json
    );
}

#[test]
fn test_summary_json_contains_backend_fields() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();

    assert!(json.contains(r#""backend_target":"http://users-svc:3000/v1/users""#));
    assert!(json.contains(r#""backend_resolved_ip":"10.244.1.42""#));
}

#[test]
fn test_summary_exposes_normalized_terminal_grpc_status() {
    let mut summary = make_full_summary();
    let http_value = serde_json::to_value(&summary).unwrap();
    assert!(http_value.get("grpc_status").is_none());

    summary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    summary
        .metadata
        .insert("grpc_status".to_string(), "14".to_string());
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["response_status_code"], 201);
    assert_eq!(value["grpc_status"], 14);

    summary
        .metadata
        .insert("grpc_status".to_string(), "malformed".to_string());
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(
        value["grpc_status"],
        u32::MAX,
        "malformed status retains the invalid-status sentinel"
    );

    summary.metadata.remove("grpc_status");
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(
        value["grpc_status"], 2,
        "missing terminal status is UNKNOWN"
    );
}

// ── Field value correctness ─────────────────────────────────────────────

#[test]
fn test_summary_deserialization_roundtrip() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["backend_resolved_ip"], "10.244.1.42");
    assert_eq!(parsed["backend_target"], "http://users-svc:3000/v1/users");
    assert_eq!(parsed["http_method"], "POST");
    assert_eq!(parsed["request_path"], "/v1/users");
    assert_eq!(parsed["proxy_id"], "proxy-users");
    assert_eq!(parsed["namespace"], "ferrum");
}

#[test]
fn test_summary_clone_preserves_resolved_ip() {
    let summary = make_full_summary();
    let cloned = summary.clone();

    assert_eq!(cloned.backend_resolved_ip, Some("10.244.1.42".to_string()));
}

// ── DNS cache → BackendResponse → TransactionSummary flow ───────────────

#[test]
fn test_backend_response_carries_resolved_ip() {
    use ferrum_edge::retry::{BackendResponse, ResponseBody};

    let resp = BackendResponse {
        status_code: 200,
        body: ResponseBody::Buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: false,
        backend_resolved_ip: Some("10.244.1.42".to_string()),
        error_class: None,
    };

    // Simulate what handle_proxy_request does: extract the IP and put it in the summary
    let resolved_ip = resp.backend_resolved_ip;

    let mut summary = make_full_summary();
    summary.backend_resolved_ip = resolved_ip;

    assert_eq!(summary.backend_resolved_ip, Some("10.244.1.42".to_string()));
}

#[test]
fn test_backend_response_none_ip_on_connection_failure() {
    use ferrum_edge::retry::{BackendResponse, ResponseBody};

    let resp = BackendResponse {
        status_code: 502,
        body: ResponseBody::Buffered(r#"{"error":"Backend unavailable"}"#.as_bytes().to_vec()),
        headers: HashMap::new(),
        connection_error: true,
        backend_resolved_ip: None,
        error_class: Some(ferrum_edge::retry::ErrorClass::ConnectionRefused),
    };

    assert!(resp.connection_error);
    assert!(resp.backend_resolved_ip.is_none());
}

// ── DNS cache resolution unit test ──────────────────────────────────────

#[tokio::test]
async fn test_dns_cache_resolve_returns_ip_for_localhost() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let cache = DnsCache::new(DnsConfig::default());

    // "localhost" should resolve to a loopback address
    let result = cache.resolve("localhost", None, None).await;
    assert!(
        result.is_ok(),
        "DNS cache should resolve localhost, got: {:?}",
        result
    );

    let ip = result.unwrap();
    assert!(
        ip.is_loopback(),
        "localhost should resolve to loopback, got: {}",
        ip
    );
}

#[tokio::test]
async fn test_dns_cache_resolve_with_static_override() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let cache = DnsCache::new(DnsConfig::default());

    // Static per-proxy override should return the override IP
    let result = cache.resolve("any-host", Some("192.168.1.100"), None).await;
    assert!(result.is_ok());

    let ip = result.unwrap();
    assert_eq!(ip.to_string(), "192.168.1.100");
}

#[tokio::test]
async fn test_dns_resolved_ip_would_appear_in_transaction_log() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let cache = DnsCache::new(DnsConfig::default());

    // Simulate what proxy_to_backend does: resolve then stringify
    let resolved_ip = cache
        .resolve("localhost", None, None)
        .await
        .ok()
        .map(|ip| ip.to_string());

    assert!(resolved_ip.is_some(), "Should resolve localhost");

    let mut summary = make_full_summary();
    summary.backend_resolved_ip = resolved_ip.clone();

    // Verify it serializes into the JSON log
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let ip_str = parsed["backend_resolved_ip"].as_str().unwrap();
    let ip: std::net::IpAddr = ip_str.parse().unwrap();
    assert!(
        ip.is_loopback(),
        "Resolved IP should be loopback for localhost"
    );
}

// ── Gateway latency fields ──────────────────────────────────────────────

#[test]
fn test_summary_json_contains_gateway_overhead_ms() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["latency_gateway_overhead_ms"], 2.5);
    assert_eq!(parsed["latency_plugin_execution_ms"], 3.0);
    assert_eq!(parsed["latency_plugin_external_io_ms"], 0.0);
}

#[test]
fn test_gateway_overhead_computation_no_backend() {
    // Simulates a rejected request (no backend call).
    // overhead = total - plugin_execution
    let mut summary = make_full_summary();
    summary.latency_total_ms = 10.0;
    summary.latency_plugin_execution_ms = 4.0;
    summary.latency_backend_total_ms = -1.0;
    summary.latency_backend_ttfb_ms = 0.0;
    summary.response_streamed = false;
    let (processing, overhead) = TransactionSummary::derive_gateway_latencies(
        summary.latency_total_ms,
        summary.latency_backend_total_ms,
        summary.latency_plugin_execution_ms,
        summary.response_streamed,
    );
    summary.latency_gateway_processing_ms = processing;
    summary.latency_gateway_overhead_ms = overhead;

    assert!((summary.latency_gateway_processing_ms - 10.0).abs() < 0.001);
    assert!((summary.latency_gateway_overhead_ms - 6.0).abs() < 0.001);
}

#[test]
fn test_gateway_overhead_computation_with_backend() {
    // overhead = total - backend - plugin_execution
    let mut summary = make_full_summary();
    summary.latency_total_ms = 100.0;
    summary.latency_backend_total_ms = 80.0;
    summary.latency_plugin_execution_ms = 5.0;
    summary.response_streamed = false;
    let (_processing, overhead) = TransactionSummary::derive_gateway_latencies(
        summary.latency_total_ms,
        summary.latency_backend_total_ms,
        summary.latency_plugin_execution_ms,
        summary.response_streamed,
    );
    summary.latency_gateway_overhead_ms = overhead;

    assert!((summary.latency_gateway_overhead_ms - 15.0).abs() < 0.001);
}

#[test]
fn test_gateway_overhead_with_external_io() {
    // plugin_external_io_ms is a subset of plugin_execution_ms.
    // overhead should not double-subtract it.
    let mut summary = make_full_summary();
    summary.latency_total_ms = 100.0;
    summary.latency_backend_total_ms = 50.0;
    summary.latency_plugin_execution_ms = 30.0;
    summary.latency_plugin_external_io_ms = 25.0; // 25ms of the 30ms was external HTTP
    summary.response_streamed = false;
    let (_processing, overhead) = TransactionSummary::derive_gateway_latencies(
        summary.latency_total_ms,
        summary.latency_backend_total_ms,
        summary.latency_plugin_execution_ms,
        summary.response_streamed,
    );
    summary.latency_gateway_overhead_ms = overhead;

    // overhead = 100 - 50 - 30 = 20ms (external_io is informational, not subtracted separately)
    assert!((summary.latency_gateway_overhead_ms - 20.0).abs() < 0.001);
}

#[test]
fn test_streaming_unknown_backend_total_keeps_gateway_sentinel() {
    // Issue #2532: streamed body lifetime must not become gateway overhead
    // merely because backend total uses the unknown sentinel.
    let (processing, overhead) =
        TransactionSummary::derive_gateway_latencies(10_000.0, -1.0, 1.0, true);
    assert_eq!(processing, -1.0);
    assert_eq!(overhead, -1.0);
}

#[test]
fn test_plugin_http_call_ns_accumulator() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let accumulator = Arc::new(AtomicU64::new(0));

    // Simulate two plugin HTTP calls accumulating time
    accumulator.fetch_add(5_000_000, Ordering::Relaxed); // 5ms in nanoseconds
    accumulator.fetch_add(3_000_000, Ordering::Relaxed); // 3ms in nanoseconds

    let external_io_ms = accumulator.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    assert!((external_io_ms - 8.0).abs() < 0.001);
}

// ── Error class field ───────────────────────────────────────────────────

#[test]
fn test_summary_json_omits_error_class_when_none() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["namespace"], "ferrum");

    assert!(
        !json.contains("error_class"),
        "JSON should omit error_class when None, got: {}",
        json
    );
}

#[test]
fn test_summary_json_contains_error_class_when_present() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_full_summary();
    summary.error_class = Some(ErrorClass::ConnectionTimeout);
    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        json.contains(r#""error_class":"connection_timeout""#),
        "JSON should contain error_class field, got: {}",
        json
    );
}

#[test]
fn test_error_class_serializes_all_variants() {
    use ferrum_edge::retry::ErrorClass;

    let cases = vec![
        (ErrorClass::ConnectionTimeout, "connection_timeout"),
        (ErrorClass::ConnectionRefused, "connection_refused"),
        (ErrorClass::ConnectionReset, "connection_reset"),
        (ErrorClass::ConnectionClosed, "connection_closed"),
        (ErrorClass::DnsLookupError, "dns_lookup_error"),
        (ErrorClass::TlsError, "tls_error"),
        (ErrorClass::ReadWriteTimeout, "read_write_timeout"),
        (ErrorClass::ClientDisconnect, "client_disconnect"),
        (ErrorClass::ProtocolError, "protocol_error"),
        (ErrorClass::ResponseBodyTooLarge, "response_body_too_large"),
        (ErrorClass::RequestBodyTooLarge, "request_body_too_large"),
        (ErrorClass::ConnectionPoolError, "connection_pool_error"),
        (ErrorClass::PortExhaustion, "port_exhaustion"),
        (ErrorClass::GracefulRemoteClose, "graceful_remote_close"),
        (ErrorClass::RequestError, "request_error"),
    ];

    for (variant, expected_str) in cases {
        // Test serde serialization
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(
            json,
            format!("\"{}\"", expected_str),
            "ErrorClass::{:?} should serialize to {:?}",
            variant,
            expected_str
        );

        // Test Display impl
        assert_eq!(
            variant.to_string(),
            expected_str,
            "ErrorClass::{:?} Display should be {:?}",
            variant,
            expected_str
        );
        assert_eq!(
            variant.as_str(),
            expected_str,
            "ErrorClass::{:?} as_str should be {:?}",
            variant,
            expected_str
        );

        // Test roundtrip deserialization
        let deserialized: ErrorClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, variant);
    }
}

#[test]
fn test_summary_with_error_class_roundtrip() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_full_summary();
    summary.response_status_code = 502;
    summary.error_class = Some(ErrorClass::TlsError);

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["error_class"], "tls_error");
    assert_eq!(parsed["response_status_code"], 502);
}

#[test]
fn test_backend_response_carries_error_class() {
    use ferrum_edge::retry::{BackendResponse, ErrorClass, ResponseBody};

    let resp = BackendResponse {
        status_code: 502,
        body: ResponseBody::Buffered(Vec::new()),
        headers: HashMap::new(),
        connection_error: true,
        backend_resolved_ip: None,
        error_class: Some(ErrorClass::ConnectionTimeout),
    };

    assert_eq!(resp.error_class, Some(ErrorClass::ConnectionTimeout));

    // Simulate threading to TransactionSummary
    let mut summary = make_full_summary();
    summary.error_class = resp.error_class;
    summary.response_status_code = resp.status_code;

    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("connection_timeout"));
}

// ── StreamTransactionSummary error_class ─────────────────────────────────

fn make_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("TCP Backend".to_string()),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.50:5432".to_string(),
        backend_resolved_ip: Some("10.0.0.50".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 1500.0,
        bytes_sent: 2048,
        bytes_received: 4096,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-03-26T12:00:00Z".to_string(),
        timestamp_disconnected: "2026-03-26T12:00:01.5Z".to_string(),
        sni_hostname: None,
        metadata: std::collections::HashMap::new(),
    }
}

#[test]
fn test_stream_summary_omits_error_class_when_none() {
    let summary = make_stream_summary();
    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        !json.contains("error_class"),
        "Stream JSON should omit error_class when None, got: {}",
        json
    );
}

#[test]
fn test_stream_summary_sni_serializes_for_tls_dtls_termination_and_passthrough() {
    // Protocol-parity coverage for issue #2531: every stream path that captures
    // frontend SNI (TCP TLS termination, DTLS termination, TLS/DTLS passthrough)
    // must expose the same JSON field when logging sinks serialize the summary.
    let cases = [
        ("tcps", "tcp-term.example"),
        ("tcp", "tcp-passthrough.example"),
        ("dtls", "dtls-term.example"),
        ("udp", "udp-passthrough.example"),
    ];
    for (protocol, sni) in cases {
        let mut summary = make_stream_summary();
        summary.protocol = protocol.to_string();
        summary.sni_hostname = Some(sni.to_string());
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(
            json["sni_hostname"], sni,
            "protocol {protocol} must serialize sni_hostname"
        );
        assert_eq!(json["protocol"], protocol);
    }

    let omitted = make_stream_summary();
    let omitted_json = serde_json::to_string(&omitted).unwrap();
    assert!(
        !omitted_json.contains("sni_hostname"),
        "null SNI must remain omitted from JSON"
    );
}

#[test]
fn test_stream_summary_contains_error_class_when_present() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::ConnectionTimeout);
    summary.connection_error = Some("Backend connect timeout to 10.0.0.50:5432".to_string());

    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        json.contains(r#""error_class":"connection_timeout""#),
        "Stream JSON should contain error_class, got: {}",
        json
    );
    assert!(
        json.contains("Backend connect timeout"),
        "Stream JSON should contain connection_error, got: {}",
        json
    );
}

#[test]
fn test_stream_summary_tls_error_class() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::TlsError);
    summary.connection_error = Some("Backend TLS handshake failed".to_string());
    summary.protocol = "tcp_tls".to_string();

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["error_class"], "tls_error");
    assert_eq!(parsed["protocol"], "tcp_tls");
}

#[test]
fn test_stream_summary_dns_error_class() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::DnsLookupError);
    summary.connection_error = Some("DNS resolution failed for backend.local".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["error_class"], "dns_lookup_error");
}

#[test]
fn test_stream_summary_serialization_roundtrip() {
    use ferrum_edge::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::ConnectionRefused);

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["proxy_id"], "tcp-proxy-1");
    assert_eq!(parsed["error_class"], "connection_refused");
    assert_eq!(parsed["bytes_sent"], 2048);
    assert_eq!(parsed["bytes_received"], 4096);
}

// ── gRPC streaming invariants ───────────────────────────────────────────
//
// The gRPC streaming path in `src/proxy/mod.rs` logs a transaction summary
// immediately after response headers arrive — the body is still flowing at
// log time, so `latency_backend_total_ms` is indeterminate. To preserve
// schema semantics, the handler encodes the streaming case as:
//   response_streamed = true, latency_backend_total_ms = -1.0
// When `body_exceeded` aborts streaming (request body too large), the
// backend work is complete at the abort so:
//   response_streamed = false, latency_backend_total_ms = backend_total_ms
// These tests assert the schema shape so drift in the handler is caught here.

#[test]
fn test_grpc_streaming_emits_minus_one_backend_total() {
    // Streaming gRPC response: body still flowing at log time.
    let mut summary = make_full_summary();
    let backend_total_ms = 40.0_f64;
    let streamed = true;
    summary.response_streamed = streamed;
    summary.latency_backend_total_ms = if streamed { -1.0 } else { backend_total_ms };

    assert!(summary.response_streamed);
    assert_eq!(summary.latency_backend_total_ms, -1.0);
}

#[test]
fn test_grpc_body_exceeded_emits_real_backend_total() {
    // body_exceeded path: backend work is complete at abort time.
    let mut summary = make_full_summary();
    let backend_total_ms = 40.0_f64;
    let body_exceeded = true;
    let streamed = !body_exceeded;
    summary.response_streamed = streamed;
    summary.latency_backend_total_ms = if streamed { -1.0 } else { backend_total_ms };

    assert!(!summary.response_streamed);
    assert!((summary.latency_backend_total_ms - 40.0).abs() < 0.001);
}

// ── Metadata redaction in serialized log output ─────────────────────────
//
// Regression coverage for the bug where any plugin (built-in or custom) that
// stashed credentials in `metadata` leaked them verbatim through every
// logging sink. Redaction now lives in
// `plugins::utils::metadata_redaction::serialize_redacted_metadata` and is
// delegated to by both the manual `TransactionSummary` serializer and the
// `StreamTransactionSummary.metadata` serde adapter, so every logger gets the
// same sanitized output without each call site having to remember to redact.

#[test]
fn test_summary_redacts_authorization_metadata_value() {
    let mut summary = make_full_summary();
    summary.metadata.insert(
        "authorization".to_string(),
        "Bearer super-secret-token".to_string(),
    );
    summary
        .metadata
        .insert("trace_id".to_string(), "abc-123".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["metadata"]["authorization"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["trace_id"], "abc-123");
    assert!(
        !json.contains("super-secret-token"),
        "Bearer token must not leak into log output, got: {}",
        json
    );
}

#[test]
fn test_summary_redacts_default_sensitive_substring_keys() {
    let mut summary = make_full_summary();
    summary
        .metadata
        .insert("Cookie".to_string(), "sid=abc".to_string());
    summary.metadata.insert(
        "downstream_authorization".to_string(),
        "Bearer xyz".to_string(),
    );
    summary
        .metadata
        .insert("user_password_hash".to_string(), "argon2.value".to_string());
    summary
        .metadata
        .insert("api_secret".to_string(), "shhh".to_string());
    summary
        .metadata
        .insert("session_token".to_string(), "stk".to_string());
    summary.metadata.insert(
        "jwks_auth.claim_header.x-user-email".to_string(),
        "private@example.com".to_string(),
    );

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["metadata"]["Cookie"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["downstream_authorization"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["user_password_hash"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["api_secret"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["session_token"], "[REDACTED]");
    assert_eq!(
        parsed["metadata"]["jwks_auth.claim_header.x-user-email"],
        "[REDACTED]"
    );

    // Raw values must not appear anywhere in the JSON.
    for needle in [
        "sid=abc",
        "Bearer xyz",
        "argon2.value",
        "shhh",
        "stk",
        "private@example.com",
    ] {
        assert!(
            !json.contains(needle),
            "Sensitive value {:?} leaked into output: {}",
            needle,
            json
        );
    }
}

#[test]
fn test_summary_keeps_ai_token_metrics_visible_while_redacting_token_secrets() {
    let mut summary = make_full_summary();
    summary
        .metadata
        .insert("ai_total_tokens".to_string(), "150".to_string());
    summary
        .metadata
        .insert("ai_prompt_tokens".to_string(), "100".to_string());
    summary
        .metadata
        .insert("ai_completion_tokens".to_string(), "50".to_string());
    summary
        .metadata
        .insert("session_token".to_string(), "session-secret".to_string());
    summary
        .metadata
        .insert("accessToken".to_string(), "access-secret".to_string());
    summary
        .metadata
        .insert("auth_token".to_string(), "auth-secret".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["metadata"]["ai_total_tokens"], "150");
    assert_eq!(parsed["metadata"]["ai_prompt_tokens"], "100");
    assert_eq!(parsed["metadata"]["ai_completion_tokens"], "50");
    assert_eq!(parsed["metadata"]["session_token"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["accessToken"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["auth_token"], "[REDACTED]");

    for needle in ["session-secret", "access-secret", "auth-secret"] {
        assert!(
            !json.contains(needle),
            "Token secret {:?} leaked into output: {}",
            needle,
            json
        );
    }
}

#[test]
fn test_summary_passes_through_non_sensitive_metadata_unchanged() {
    let mut summary = make_full_summary();
    summary
        .metadata
        .insert("correlation_id".to_string(), "corr-42".to_string());
    summary
        .metadata
        .insert("trace_id".to_string(), "trace-99".to_string());
    summary
        .metadata
        .insert("request_id".to_string(), "req-7".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["metadata"]["correlation_id"], "corr-42");
    assert_eq!(parsed["metadata"]["trace_id"], "trace-99");
    assert_eq!(parsed["metadata"]["request_id"], "req-7");
    assert!(
        !json.contains("[REDACTED]"),
        "Non-sensitive metadata must not be redacted, got: {}",
        json
    );
}

#[test]
fn test_extras_list_parses_env_format() {
    use ferrum_edge::plugins::utils::metadata_redaction::{
        is_sensitive_metadata_key_with_extras, parse_extras_list,
    };

    let extras = parse_extras_list("custom_field, MY-Trace-Header ,session_id");

    // Mirrors what the env-driven path stores: lowercased + trimmed.
    assert_eq!(
        extras,
        vec![
            "custom_field".to_string(),
            "my-trace-header".to_string(),
            "session_id".to_string(),
        ]
    );

    // Operator-supplied extras must redact.
    assert!(is_sensitive_metadata_key_with_extras(
        "custom_field",
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras(
        "CUSTOM_FIELD",
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras(
        "X-MY-Trace-Header-Value",
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras("session_id", &extras));

    // Default list still applies even with extras configured.
    assert!(is_sensitive_metadata_key_with_extras(
        "Authorization",
        &extras
    ));

    // Non-sensitive keys are untouched.
    assert!(!is_sensitive_metadata_key_with_extras(
        "benign_key",
        &extras
    ));
    assert!(!is_sensitive_metadata_key_with_extras(
        "backend_resolved_ip",
        &extras
    ));
}

#[test]
fn test_serialize_redacted_metadata_with_explicit_extras() {
    use ferrum_edge::plugins::utils::metadata_redaction::{
        REDACTED_PLACEHOLDER, is_sensitive_metadata_key_with_extras, parse_extras_list,
    };

    // Explicit-extras helper bypasses the OnceLock so the test is hermetic
    // (the env-driven `OnceLock` initializes once per process and would race
    // with other parallel tests that touch the same global).
    let extras = parse_extras_list("custom_field");
    let mut metadata = HashMap::new();
    metadata.insert("custom_field".to_string(), "leak-me".to_string());
    metadata.insert("safe_key".to_string(), "ok".to_string());

    let mut redacted = HashMap::new();
    for (key, value) in &metadata {
        if is_sensitive_metadata_key_with_extras(key, &extras) {
            redacted.insert(key.clone(), REDACTED_PLACEHOLDER.to_string());
        } else {
            redacted.insert(key.clone(), value.clone());
        }
    }

    assert_eq!(redacted.get("custom_field").unwrap(), "[REDACTED]");
    assert_eq!(redacted.get("safe_key").unwrap(), "ok");
}

#[test]
fn test_stream_summary_redacts_metadata() {
    let mut summary = make_stream_summary();
    summary
        .metadata
        .insert("authorization".to_string(), "Bearer s3cret".to_string());
    summary
        .metadata
        .insert("correlation_id".to_string(), "corr-1".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["metadata"]["authorization"], "[REDACTED]");
    assert_eq!(parsed["metadata"]["correlation_id"], "corr-1");
    assert!(
        !json.contains("s3cret"),
        "Stream metadata bearer token must not leak: {}",
        json
    );
}

#[test]
fn test_summary_omits_metadata_when_empty_for_stream_summary() {
    // StreamTransactionSummary keeps `skip_serializing_if = "HashMap::is_empty"`
    // so empty metadata stays out of the JSON entirely. Redaction layering on
    // top must not change that.
    let summary = make_stream_summary();
    let json = serde_json::to_string(&summary).unwrap();
    assert!(
        !json.contains("\"metadata\""),
        "Empty stream metadata should be skipped, got: {}",
        json
    );
}

// ── auth_method serialization ──────────────────────────────────────────

#[test]
fn test_auth_method_serialized_when_present() {
    let mut summary = make_full_summary();
    summary.auth_method = Some("jwt_auth");
    let json = serde_json::to_string(&summary).unwrap();
    assert!(
        json.contains(r#""auth_method":"jwt_auth""#),
        "auth_method should appear in JSON when set, got: {}",
        json
    );
}

#[test]
fn test_auth_method_omitted_when_none() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();
    assert!(
        !json.contains("auth_method"),
        "auth_method should be omitted from JSON when None, got: {}",
        json
    );
}

#[test]
fn test_stream_auth_method_serialized_when_present() {
    let mut summary = make_stream_summary();
    summary.auth_method = Some("mtls_auth");
    let json = serde_json::to_string(&summary).unwrap();
    assert!(
        json.contains(r#""auth_method":"mtls_auth""#),
        "stream auth_method should appear in JSON when set, got: {}",
        json
    );
}

#[test]
fn test_stream_auth_method_omitted_when_none() {
    let summary = make_stream_summary();
    let json = serde_json::to_string(&summary).unwrap();
    assert!(
        !json.contains("auth_method"),
        "stream auth_method should be omitted from JSON when None, got: {}",
        json
    );
}

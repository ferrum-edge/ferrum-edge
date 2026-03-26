//! Tests for TransactionSummary log format — field presence, serialization,
//! and backend resolved IP propagation.

use std::collections::HashMap;

use ferrum_gateway::plugins::{StreamTransactionSummary, TransactionSummary};

/// Build a fully-populated TransactionSummary for testing.
fn make_full_summary() -> TransactionSummary {
    TransactionSummary {
        timestamp_received: "2026-03-25T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        http_method: "POST".to_string(),
        request_path: "/v1/users".to_string(),
        matched_proxy_id: Some("proxy-users".to_string()),
        matched_proxy_name: Some("Users API".to_string()),
        backend_target_url: Some("http://users-svc:3000/v1/users".to_string()),
        backend_resolved_ip: Some("10.244.1.42".to_string()),
        response_status_code: 201,
        latency_total_ms: 45.5,
        latency_gateway_processing_ms: 5.5,
        latency_backend_ttfb_ms: 38.0,
        latency_backend_total_ms: 40.0,
        request_user_agent: Some("curl/8.0".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        metadata: HashMap::new(),
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

    assert!(json.contains(r#""backend_target_url":"http://users-svc:3000/v1/users""#));
    assert!(json.contains(r#""backend_resolved_ip":"10.244.1.42""#));
}

// ── Field value correctness ─────────────────────────────────────────────

#[test]
fn test_summary_deserialization_roundtrip() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["backend_resolved_ip"], "10.244.1.42");
    assert_eq!(
        parsed["backend_target_url"],
        "http://users-svc:3000/v1/users"
    );
    assert_eq!(parsed["http_method"], "POST");
    assert_eq!(parsed["request_path"], "/v1/users");
    assert_eq!(parsed["matched_proxy_id"], "proxy-users");
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
    use ferrum_gateway::retry::{BackendResponse, ResponseBody};

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
    use ferrum_gateway::retry::{BackendResponse, ResponseBody};

    let resp = BackendResponse {
        status_code: 502,
        body: ResponseBody::Buffered(r#"{"error":"Backend unavailable"}"#.as_bytes().to_vec()),
        headers: HashMap::new(),
        connection_error: true,
        backend_resolved_ip: None,
        error_class: Some(ferrum_gateway::retry::ErrorClass::ConnectionRefused),
    };

    assert!(resp.connection_error);
    assert!(resp.backend_resolved_ip.is_none());
}

// ── DNS cache resolution unit test ──────────────────────────────────────

#[tokio::test]
async fn test_dns_cache_resolve_returns_ip_for_localhost() {
    use ferrum_gateway::dns::{DnsCache, DnsConfig};

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
    use ferrum_gateway::dns::{DnsCache, DnsConfig};

    let cache = DnsCache::new(DnsConfig::default());

    // Static per-proxy override should return the override IP
    let result = cache.resolve("any-host", Some("192.168.1.100"), None).await;
    assert!(result.is_ok());

    let ip = result.unwrap();
    assert_eq!(ip.to_string(), "192.168.1.100");
}

#[tokio::test]
async fn test_dns_resolved_ip_would_appear_in_transaction_log() {
    use ferrum_gateway::dns::{DnsCache, DnsConfig};

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

// ── Error class field ───────────────────────────────────────────────────

#[test]
fn test_summary_json_omits_error_class_when_none() {
    let summary = make_full_summary();
    let json = serde_json::to_string(&summary).unwrap();

    assert!(
        !json.contains("error_class"),
        "JSON should omit error_class when None, got: {}",
        json
    );
}

#[test]
fn test_summary_json_contains_error_class_when_present() {
    use ferrum_gateway::retry::ErrorClass;

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
    use ferrum_gateway::retry::ErrorClass;

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

        // Test roundtrip deserialization
        let deserialized: ErrorClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, variant);
    }
}

#[test]
fn test_summary_with_error_class_roundtrip() {
    use ferrum_gateway::retry::ErrorClass;

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
    use ferrum_gateway::retry::{BackendResponse, ErrorClass, ResponseBody};

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
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_name: Some("TCP Backend".to_string()),
        client_ip: "10.0.0.1".to_string(),
        backend_target: "10.0.0.50:5432".to_string(),
        backend_resolved_ip: Some("10.0.0.50".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 1500.0,
        bytes_sent: 2048,
        bytes_received: 4096,
        connection_error: None,
        error_class: None,
        timestamp_connected: "2026-03-26T12:00:00Z".to_string(),
        timestamp_disconnected: "2026-03-26T12:00:01.5Z".to_string(),
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
fn test_stream_summary_contains_error_class_when_present() {
    use ferrum_gateway::retry::ErrorClass;

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
    use ferrum_gateway::retry::ErrorClass;

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
    use ferrum_gateway::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::DnsLookupError);
    summary.connection_error = Some("DNS resolution failed for backend.local".to_string());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["error_class"], "dns_lookup_error");
}

#[test]
fn test_stream_summary_serialization_roundtrip() {
    use ferrum_gateway::retry::ErrorClass;

    let mut summary = make_stream_summary();
    summary.error_class = Some(ErrorClass::ConnectionRefused);

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["proxy_id"], "tcp-proxy-1");
    assert_eq!(parsed["error_class"], "connection_refused");
    assert_eq!(parsed["bytes_sent"], 2048);
    assert_eq!(parsed["bytes_received"], 4096);
}

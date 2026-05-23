//! Tests for otel_tracing plugin

use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, RequestContext, StreamTransactionSummary,
    TransactionSummary, mesh::workload_metrics::WorkloadMetrics, otel_tracing::OtelTracing,
    utils::PluginHttpClient,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn new_otel(config: &serde_json::Value) -> OtelTracing {
    // Merge a default endpoint into the config so tests that don't care about the
    // endpoint still pass now that it's required for OTLP export.
    let mut merged = config.clone();
    if merged.get("endpoint").is_none() {
        merged["endpoint"] =
            serde_json::Value::String("http://localhost:4318/v1/traces".to_string());
    }
    OtelTracing::new_with_http_client(&merged, PluginHttpClient::default()).unwrap()
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    )
}

fn make_summary(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/api/test".to_string(),
        proxy_id: None,
        proxy_name: None,
        backend_target: None,
        backend_resolved_ip: None,
        response_status_code: 200,
        latency_total_ms: 15.0,
        latency_gateway_processing_ms: 3.0,
        latency_backend_ttfb_ms: 10.0,
        latency_backend_total_ms: 12.0,
        latency_plugin_execution_ms: 1.5,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 1.5,
        request_user_agent: None,
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata,
    }
}

fn make_trace_metadata() -> HashMap<String, String> {
    HashMap::from([
        (
            "trace_id".to_string(),
            "abcdef1234567890abcdef1234567890".to_string(),
        ),
        ("span_id".to_string(), "1234567890abcdef".to_string()),
        ("trace_sampled".to_string(), "true".to_string()),
    ])
}

fn make_trace_metadata_without_sampling() -> HashMap<String, String> {
    HashMap::from([
        (
            "trace_id".to_string(),
            "abcdef1234567890abcdef1234567890".to_string(),
        ),
        ("span_id".to_string(), "1234567890abcdef".to_string()),
    ])
}

fn make_stream_summary(metadata: HashMap<String, String>) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("postgres".to_string()),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        backend_target: "10.0.0.20:5432".to_string(),
        backend_resolved_ip: Some("10.0.0.20".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 42.0,
        bytes_sent: 128,
        bytes_received: 512,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-03-23T12:00:00Z".to_string(),
        timestamp_disconnected: "2026-03-23T12:00:00.042Z".to_string(),
        sni_hostname: None,
        metadata,
    }
}

async fn received_json(server: &wiremock::MockServer) -> serde_json::Value {
    for _ in 0..20 {
        if let Some(requests) = server.received_requests().await
            && let Some(request) = requests.first()
        {
            return request.body_json().expect("valid JSON body");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("mock server did not receive exporter request");
}

async fn assert_no_requests(server: &wiremock::MockServer) {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(server.received_requests().await.unwrap().is_empty());
}

fn otlp_span(payload: &Value) -> &Value {
    &payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
}

fn otlp_attr_value<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
    span.get("attributes")?
        .as_array()?
        .iter()
        .find(|attr| attr.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|attr| attr.get("value"))
}

fn otlp_string_attr<'a>(span: &'a Value, key: &str) -> Option<&'a str> {
    otlp_attr_value(span, key).and_then(|value| value.get("stringValue")?.as_str())
}

fn otlp_bool_attr(span: &Value, key: &str) -> Option<bool> {
    otlp_attr_value(span, key).and_then(|value| value.get("boolValue")?.as_bool())
}

fn otlp_resource_string_attr<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload["resourceSpans"][0]["resource"]["attributes"]
        .as_array()?
        .iter()
        .find(|attr| attr.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|attr| attr.get("value"))
        .and_then(|value| value.get("stringValue")?.as_str())
}

fn make_rich_summary(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        http_method: "POST".to_string(),
        request_path: "/api/llm/chat".to_string(),
        proxy_id: Some("proxy-1".to_string()),
        proxy_name: Some("llm-service".to_string()),
        backend_target: Some("http://backend:8080/chat".to_string()),
        backend_resolved_ip: Some("10.1.2.3".to_string()),
        response_status_code: 200,
        latency_total_ms: 150.0,
        latency_gateway_processing_ms: 5.0,
        latency_backend_ttfb_ms: 120.0,
        latency_backend_total_ms: 145.0,
        latency_plugin_execution_ms: 2.0,
        latency_plugin_external_io_ms: 0.5,
        latency_gateway_overhead_ms: 3.0,
        request_user_agent: Some("MyApp/1.0".to_string()),
        response_streamed: true,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata,
    }
}

#[tokio::test]
async fn test_otel_tracing_plugin_creation() {
    let plugin = new_otel(&json!({}));
    assert_eq!(plugin.name(), "otel_tracing");
    assert_eq!(plugin.priority(), 25);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(plugin.modifies_request_headers());
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[tokio::test]
async fn test_otel_tracing_rejects_invalid_endpoint() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "endpoint": "not a url"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("invalid endpoint must be rejected");

    assert!(err.contains("endpoint"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_rejects_endpoint_with_empty_authority() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "endpoint": "https:///v1/traces"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("endpoint with empty authority must be rejected");

    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_rejects_non_http_endpoint_scheme() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "endpoint": "ftp://otel-collector.example.com/v1/traces"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-http endpoint scheme must be rejected");

    assert!(err.contains("http or https"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_rejects_non_bool_generate_trace_id() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "generate_trace_id": "true"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-bool generate_trace_id must be rejected");

    assert!(err.contains("generate_trace_id"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_rejects_invalid_custom_header_name() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "endpoint": "http://localhost:4318/v1/traces",
            "headers": {
                "bad header": "value"
            }
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("invalid custom header name must be rejected");

    assert!(err.contains("invalid HTTP header name"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_rejects_non_string_custom_header_value() {
    let err = OtelTracing::new_with_http_client(
        &json!({
            "endpoint": "http://localhost:4318/v1/traces",
            "headers": {
                "x-tenant-id": 42
            }
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-string custom header value must be rejected");

    assert!(err.contains("headers.x-tenant-id"), "got: {err}");
}

#[tokio::test]
async fn test_otel_tracing_generates_traceparent() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    // Should have generated traceparent
    let traceparent = ctx.metadata.get("traceparent").unwrap();
    assert!(traceparent.starts_with("00-"));
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "00"); // version
    assert_eq!(parts[1].len(), 32); // trace_id
    assert_eq!(parts[2].len(), 16); // span_id
    assert_eq!(parts[3], "01"); // flags

    // Should have stored trace_id and span_id
    assert!(ctx.metadata.contains_key("trace_id"));
    assert!(ctx.metadata.contains_key("span_id"));
}

#[tokio::test]
async fn test_otel_tracing_propagates_existing_traceparent() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "traceparent".to_string(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
    );

    plugin.on_request_received(&mut ctx).await;

    // Should keep the original trace_id
    assert_eq!(
        ctx.metadata.get("trace_id").unwrap(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    // Should record the parent span
    assert_eq!(
        ctx.metadata.get("parent_span_id").unwrap(),
        "00f067aa0ba902b7"
    );
    // Should generate a new span_id for the gateway hop
    let span_id = ctx.metadata.get("span_id").unwrap();
    assert_ne!(span_id, "00f067aa0ba902b7");
    assert_eq!(span_id.len(), 16);

    // Traceparent should use the new span_id
    let traceparent = ctx.metadata.get("traceparent").unwrap();
    assert!(traceparent.contains(span_id));
    assert!(traceparent.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
}

#[tokio::test]
async fn test_otel_tracing_preserves_tracestate() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "traceparent".to_string(),
        "00-abcdef1234567890abcdef1234567890-1234567890abcdef-01".to_string(),
    );
    ctx.headers.insert(
        "tracestate".to_string(),
        "vendor1=value1,vendor2=value2".to_string(),
    );

    plugin.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.metadata.get("tracestate").unwrap(),
        "vendor1=value1,vendor2=value2"
    );
}

#[tokio::test]
async fn test_otel_tracing_injects_headers_before_proxy() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();

    // Simulate on_request_received
    plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(headers.contains_key("traceparent"));
}

#[tokio::test]
async fn test_otel_tracing_echoes_traceparent_in_response() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert!(response_headers.contains_key("traceparent"));
}

#[tokio::test]
async fn test_otel_tracing_no_traceparent_when_generate_disabled() {
    let plugin = new_otel(&json!({"generate_trace_id": false}));
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    // Should not have generated anything
    assert!(!ctx.metadata.contains_key("traceparent"));
}

#[tokio::test]
async fn test_otel_tracing_malformed_traceparent_does_not_generate_when_disabled() {
    let plugin = new_otel(&json!({"generate_trace_id": false}));
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "traceparent".to_string(),
        "not-a-valid-traceparent".to_string(),
    );

    plugin.on_request_received(&mut ctx).await;

    assert!(!ctx.metadata.contains_key("traceparent"));
    assert!(!ctx.metadata.contains_key("trace_id"));
    assert!(!ctx.metadata.contains_key("span_id"));
}

#[tokio::test]
async fn test_otel_tracing_malformed_traceparent_generates_and_stores_context() {
    let plugin = new_otel(&json!({}));
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "traceparent".to_string(),
        "not-a-valid-traceparent".to_string(),
    );

    plugin.on_request_received(&mut ctx).await;

    let traceparent = ctx.metadata.get("traceparent").unwrap();
    assert!(traceparent.starts_with("00-"));
    assert!(ctx.metadata.contains_key("trace_id"));
    assert!(ctx.metadata.contains_key("span_id"));
    assert!(!ctx.metadata.contains_key("parent_span_id"));
}

#[tokio::test]
async fn test_otel_tracing_log_emits_without_otlp() {
    // Propagation-only mode: no endpoint configured
    let plugin =
        OtelTracing::new_with_http_client(&json!({}), PluginHttpClient::default()).unwrap();

    // Just ensure log() doesn't panic when no OTLP endpoint
    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    let summary = make_summary(metadata);
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_otel_tracing_with_otlp_endpoint() {
    // Start a wiremock server to receive OTLP spans
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let endpoint = format!("{}/v1/traces", mock_server.uri());

    let plugin = new_otel(&json!({
        "endpoint": endpoint,
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    let summary = make_summary(metadata);
    plugin.log(&summary).await;

    // Give the background task time to flush
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The mock server should have received at least one request
    // (verified by the expect(1..) on the mock)
}

#[tokio::test]
async fn test_otel_tracing_exports_stream_disconnect_span() {
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = new_otel(&json!({
        "endpoint": format!("{}/v1/traces", mock_server.uri()),
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    plugin
        .on_stream_disconnect(&make_stream_summary(make_trace_metadata()))
        .await;

    let payload = received_json(&mock_server).await;
    let span = &payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(span["name"], "tcp 10.0.0.20:5432");
    let attributes = span["attributes"].as_array().expect("span attributes");
    let protocol = attributes
        .iter()
        .find(|attribute| attribute["key"].as_str() == Some("network.protocol.name"))
        .expect("network protocol attribute");
    assert_eq!(protocol["value"]["stringValue"], "tcp");
    let bytes_sent = attributes
        .iter()
        .find(|attribute| attribute["key"].as_str() == Some("gateway.stream.bytes_sent"))
        .expect("bytes sent attribute");
    assert_eq!(bytes_sent["value"]["intValue"], "128");
}

#[tokio::test]
async fn test_workload_metrics_opentelemetry_exporter_payload() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "opentelemetry",
            "config": {
                "endpoint": format!("{}/v1/traces", mock_server.uri())
            }
        }]
    }))
    .expect("workload metrics with otlp provider");

    plugin.log(&make_summary(make_trace_metadata())).await;

    let payload = received_json(&mock_server).await;
    assert_eq!(
        otlp_resource_string_attr(&payload, "service.name"),
        Some("reviews")
    );
    assert_eq!(
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "GET /api/test"
    );
}

#[tokio::test]
async fn test_workload_metrics_zipkin_exporter_payload() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/api/v2/spans"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "zipkin",
            "config": {
                "url": format!("{}/api/v2/spans", mock_server.uri())
            }
        }]
    }))
    .expect("workload metrics with zipkin provider");

    plugin.log(&make_summary(make_trace_metadata())).await;

    let payload = received_json(&mock_server).await;
    assert_eq!(payload[0]["localEndpoint"]["serviceName"], "reviews");
    assert_eq!(payload[0]["name"], "GET /api/test");
    assert_eq!(payload[0]["tags"]["http.status_code"], "200");
}

#[tokio::test]
async fn test_workload_metrics_datadog_exporter_payload() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("PUT"))
        .and(wiremock::matchers::path("/v0.3/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews-default",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "datadog",
            "config": {
                "agent_url": mock_server.uri(),
                "service": "reviews"
            }
        }]
    }))
    .expect("workload metrics with datadog provider");

    plugin.log(&make_summary(make_trace_metadata())).await;

    let payload = received_json(&mock_server).await;
    assert_eq!(payload[0][0]["service"], "reviews");
    assert_eq!(payload[0][0]["resource"], "GET /api/test");
    assert_eq!(payload[0][0]["meta"]["http.method"], "GET");
}

#[tokio::test]
async fn test_workload_metrics_rejects_datadog_agent_url_with_empty_authority() {
    let err = WorkloadMetrics::new(&json!({
        "service_name": "reviews-default",
        "tracing_providers": [{
            "kind": "datadog",
            "config": {
                "agent_url": "https:///traces"
            }
        }]
    }))
    .err()
    .expect("datadog agent_url with empty authority must be rejected");

    assert!(err.contains("agent_url"), "got: {err}");
    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_workload_metrics_lightstep_exporter_uses_otlp_bearer_payload() {
    // SAFETY: This test uses a unique process env key and only reads it during
    // plugin construction. No other test in this module mutates the same key.
    unsafe { std::env::set_var("FERRUM_TEST_LIGHTSTEP_TOKEN", "test-token") };
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/traces/otlp"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Bearer test-token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "lightstep",
            "config": {
                "collector_url": format!("{}/traces/otlp", mock_server.uri()),
                "access_token_env": "FERRUM_TEST_LIGHTSTEP_TOKEN"
            }
        }]
    }))
    .expect("workload metrics with lightstep provider");

    plugin.log(&make_summary(make_trace_metadata())).await;

    let payload = received_json(&mock_server).await;
    assert_eq!(
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "GET /api/test"
    );
    // SAFETY: Paired cleanup for the unique key set above.
    unsafe { std::env::remove_var("FERRUM_TEST_LIGHTSTEP_TOKEN") };
}

#[tokio::test]
async fn test_workload_metrics_multi_provider_fanout() {
    let zipkin = wiremock::MockServer::start().await;
    let otlp = wiremock::MockServer::start().await;
    for (server, path) in [(&zipkin, "/api/v2/spans"), (&otlp, "/v1/traces")] {
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(path))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(server)
            .await;
    }

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [
            {
                "kind": "zipkin",
                "config": {
                    "url": format!("{}/api/v2/spans", zipkin.uri())
                }
            },
            {
                "kind": "opentelemetry",
                "config": {
                    "endpoint": format!("{}/v1/traces", otlp.uri())
                }
            }
        ]
    }))
    .expect("workload metrics with multiple providers");

    plugin.log(&make_summary(make_trace_metadata())).await;

    let zipkin_payload = received_json(&zipkin).await;
    let otlp_payload = received_json(&otlp).await;
    assert_eq!(zipkin_payload[0]["name"], "GET /api/test");
    assert_eq!(
        otlp_payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "GET /api/test"
    );
}

#[tokio::test]
async fn test_otel_tracing_batches_two_spans_before_export() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = new_otel(&json!({
        "endpoint": format!("{}/v1/traces", mock_server.uri()),
        "batch_size": 2,
        "flush_interval_ms": 5000
    }));

    plugin.log(&make_summary(make_trace_metadata())).await;
    let mut second_metadata = make_trace_metadata();
    second_metadata.insert("span_id".to_string(), "fedcba0987654321".to_string());
    plugin.log(&make_summary(second_metadata)).await;

    let payload = received_json(&mock_server).await;
    let spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .expect("OTLP spans");
    assert_eq!(spans.len(), 2);
}

#[tokio::test]
async fn test_workload_metrics_provider_without_sampling_does_not_export() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "opentelemetry",
            "config": {
                "endpoint": format!("{}/v1/traces", mock_server.uri())
            }
        }]
    }))
    .expect("workload metrics with otlp provider");

    plugin
        .log(&make_summary(make_trace_metadata_without_sampling()))
        .await;
    drop(plugin);
    assert_no_requests(&mock_server).await;
}

#[tokio::test]
async fn test_workload_metrics_explicit_unsampled_metadata_does_not_export() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "service_name": "reviews",
        "batch_size": 1,
        "flush_interval_ms": 100,
        "tracing_providers": [{
            "kind": "opentelemetry",
            "config": {
                "endpoint": format!("{}/v1/traces", mock_server.uri())
            }
        }]
    }))
    .expect("workload metrics with otlp provider");

    let mut metadata = make_trace_metadata();
    metadata.insert("trace_sampled".to_string(), "false".to_string());
    plugin.log(&make_summary(metadata)).await;
    drop(plugin);
    assert_no_requests(&mock_server).await;
}

#[tokio::test]
async fn test_workload_metrics_disable_span_reporting_suppresses_export() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let plugin = WorkloadMetrics::new(&json!({
        "span_reporting_disabled": true,
        "batch_size": 1,
        "tracing_providers": [{
            "kind": "zipkin",
            "config": {
                "url": format!("{}/api/v2/spans", mock_server.uri())
            }
        }]
    }))
    .expect("disabled workload metrics tracing provider");

    plugin.log(&make_summary(make_trace_metadata())).await;
    drop(plugin);
    assert_no_requests(&mock_server).await;
}

#[tokio::test]
async fn test_otel_tracing_otlp_with_authorization() {
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Bearer test-token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let endpoint = format!("{}/v1/traces", mock_server.uri());

    let plugin = new_otel(&json!({
        "endpoint": endpoint,
        "authorization": "Bearer test-token",
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    let summary = make_summary(metadata);
    plugin.log(&summary).await;

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_otel_tracing_warmup_hostnames() {
    let plugin = new_otel(&json!({
        "endpoint": "https://otel-collector.example.com:4318/v1/traces"
    }));

    let hosts = plugin.warmup_hostnames();
    assert_eq!(hosts, vec!["otel-collector.example.com"]);
}

#[tokio::test]
async fn test_otel_tracing_warmup_hostnames_unbrackets_ipv6_literals() {
    let plugin = new_otel(&json!({
        "endpoint": "https://[2001:db8::60]:4318/v1/traces"
    }));

    let hosts = plugin.warmup_hostnames();
    assert_eq!(hosts, vec!["2001:db8::60"]);
}

#[tokio::test]
async fn test_otel_tracing_propagation_only_mode() {
    // No endpoint — should create successfully in propagation-only mode
    let plugin =
        OtelTracing::new_with_http_client(&json!({}), PluginHttpClient::default()).unwrap();

    // Should still generate trace context
    let mut ctx = make_ctx();
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("traceparent"));
    assert!(ctx.metadata.contains_key("trace_id"));

    // Should still inject headers
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(headers.contains_key("traceparent"));

    // No warmup hostnames in propagation-only mode
    assert!(plugin.warmup_hostnames().is_empty());
}

#[tokio::test]
async fn test_otel_tracing_custom_headers() {
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::header("x-honeycomb-team", "my-api-key"))
        .and(wiremock::matchers::header("X-Scope-OrgID", "tenant-123"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let endpoint = format!("{}/v1/traces", mock_server.uri());

    let plugin = new_otel(&json!({
        "endpoint": endpoint,
        "headers": {
            "x-honeycomb-team": "my-api-key",
            "X-Scope-OrgID": "tenant-123"
        },
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    let summary = make_summary(metadata);
    plugin.log(&summary).await;

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_otel_tracing_rich_span_attributes() {
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let endpoint = format!("{}/v1/traces", mock_server.uri());

    let plugin = new_otel(&json!({
        "endpoint": endpoint,
        "deployment_environment": "staging",
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    let summary = make_rich_summary(metadata);
    plugin.log(&summary).await;

    let payload = received_json(&mock_server).await;
    let span = otlp_span(&payload);
    assert_eq!(span["name"], "POST /api/llm/chat");
    assert_eq!(otlp_string_attr(span, "enduser.id"), Some("alice"));
    assert_eq!(
        otlp_string_attr(span, "user_agent.original"),
        Some("MyApp/1.0")
    );
    assert_eq!(otlp_string_attr(span, "gateway.proxy.id"), Some("proxy-1"));
    assert_eq!(otlp_string_attr(span, "http.route"), Some("llm-service"));
    assert_eq!(
        otlp_string_attr(span, "server.address"),
        Some("http://backend:8080/chat")
    );
    assert_eq!(
        otlp_string_attr(span, "server.socket.address"),
        Some("10.1.2.3")
    );
    assert_eq!(
        otlp_bool_attr(span, "gateway.response.streamed"),
        Some(true)
    );
}

#[tokio::test]
async fn test_otel_tracing_error_span_events() {
    let mock_server = wiremock::MockServer::start().await;

    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let endpoint = format!("{}/v1/traces", mock_server.uri());

    let plugin = new_otel(&json!({
        "endpoint": endpoint,
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut metadata = HashMap::new();
    metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    metadata.insert("span_id".to_string(), "1234567890abcdef".to_string());

    // Simulate a gateway error with error_class and client disconnect
    let mut summary = make_summary(metadata);
    summary.response_status_code = 502;
    summary.error_class = Some(ferrum_edge::retry::ErrorClass::ConnectionTimeout);
    summary.client_disconnected = true;

    plugin.log(&summary).await;

    let payload = received_json(&mock_server).await;
    let span = otlp_span(&payload);
    assert_eq!(span["status"]["code"], 2);
    let event_names: Vec<&str> = span["events"]
        .as_array()
        .expect("span events")
        .iter()
        .filter_map(|event| event["name"].as_str())
        .collect();
    assert!(event_names.contains(&"exception"));
    assert!(event_names.contains(&"client.disconnect"));
}

#[tokio::test]
async fn test_otel_tracing_clamps_negative_duration_for_otlp() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = new_otel(&json!({
        "endpoint": format!("{}/v1/traces", mock_server.uri()),
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    let mut summary = make_summary(make_trace_metadata());
    summary.latency_total_ms = -5.0;
    plugin.log(&summary).await;

    let payload = received_json(&mock_server).await;
    let span = otlp_span(&payload);
    let start_ns = span["startTimeUnixNano"]
        .as_str()
        .expect("startTimeUnixNano")
        .parse::<i64>()
        .expect("numeric start time");
    let end_ns = span["endTimeUnixNano"]
        .as_str()
        .expect("endTimeUnixNano")
        .parse::<i64>()
        .expect("numeric end time");
    assert_eq!(end_ns, start_ns);
}

#[tokio::test]
async fn test_otel_tracing_deployment_environment() {
    let mock_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = new_otel(&json!({
        "endpoint": format!("{}/v1/traces", mock_server.uri()),
        "deployment_environment": "production",
        "batch_size": 1,
        "flush_interval_ms": 100
    }));

    plugin.log(&make_summary(make_trace_metadata())).await;

    let payload = received_json(&mock_server).await;
    assert_eq!(
        otlp_resource_string_attr(&payload, "deployment.environment"),
        Some("production")
    );
}

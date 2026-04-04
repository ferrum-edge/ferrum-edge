//! Tests for otel_tracing plugin

use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, TransactionSummary, otel_tracing::OtelTracing,
    utils::PluginHttpClient,
};
use serde_json::json;
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
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        http_method: "GET".to_string(),
        request_path: "/api/test".to_string(),
        matched_proxy_id: None,
        matched_proxy_name: None,
        backend_target_url: None,
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
        mirror: false,
        metadata,
    }
}

fn make_rich_summary(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        http_method: "POST".to_string(),
        request_path: "/api/llm/chat".to_string(),
        matched_proxy_id: Some("proxy-1".to_string()),
        matched_proxy_name: Some("llm-service".to_string()),
        backend_target_url: Some("http://backend:8080/chat".to_string()),
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
        mirror: false,
        metadata,
    }
}

#[tokio::test]
async fn test_otel_tracing_plugin_creation() {
    let plugin = new_otel(&json!({}));
    assert_eq!(plugin.name(), "otel_tracing");
    assert_eq!(plugin.priority(), 25);
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

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify the mock was called (wiremock expect handles this)
    // The rich attributes (user_agent, route, backend_target, etc.) are included
    // in the OTLP payload — we verify they don't break serialization or export.
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

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_otel_tracing_deployment_environment() {
    let plugin = new_otel(&json!({
        "deployment_environment": "production"
    }));

    // Plugin should be created with environment set
    assert_eq!(plugin.name(), "otel_tracing");
}

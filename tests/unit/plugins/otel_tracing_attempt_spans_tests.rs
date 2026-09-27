//! `otel_tracing` per-attempt CLIENT spans (issue #5864).
//!
//! These drive the request-context hooks the proxy retry loops use: an
//! attempt begins at its dispatch site (`run_backend_attempt_for_test` also
//! polls it in the attempt scope the connection pools report into) and ends at
//! `record_backend_attempt`. Live retry coverage is in
//! `tests/functional/functional_otel_attempt_spans_test.rs`.

use std::collections::HashMap;
use std::time::Duration;

use ferrum_edge::_test_support::{
    note_backend_connection_reused_for_test, note_backend_connection_setup_for_test,
    record_backend_attempt_for_test, run_backend_attempt_for_test,
};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, TransactionSummary, otel_tracing::OtelTracing,
    utils::PluginHttpClient,
};
use ferrum_edge::retry::ErrorClass;
use serde_json::{Value, json};

const BACKEND_URL: &str = "http://backend.internal:8080/api/test";
const CLIENT_IP: &str = "10.0.0.1";

fn otel(endpoint: Option<&str>, extra: Value) -> OtelTracing {
    let mut config = json!({ "batch_size": 50, "flush_interval_ms": 100 });
    if let Some(endpoint) = endpoint {
        config["endpoint"] = json!(endpoint);
    }
    if let Some(extra) = extra.as_object() {
        config
            .as_object_mut()
            .expect("config object")
            .extend(extra.clone());
    }
    OtelTracing::new_with_http_client(&config, PluginHttpClient::default())
        .expect("valid otel_tracing config")
}

async fn collector() -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

fn endpoint(server: &wiremock::MockServer) -> String {
    format!("{}/v1/traces", server.uri())
}

/// Every span the collector has received, across export batches.
async fn received_spans(server: &wiremock::MockServer) -> Vec<Value> {
    let requests = server.received_requests().await.unwrap_or_default();
    let mut spans = Vec::new();
    for request in requests {
        let payload: Value = request.body_json().expect("OTLP/JSON body");
        for resource in payload["resourceSpans"].as_array().into_iter().flatten() {
            for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
                spans.extend(scope["spans"].as_array().into_iter().flatten().cloned());
            }
        }
    }
    spans
}

/// Wait until the collector holds `expected` spans, then confirm no more
/// arrive.
async fn exported_spans(server: &wiremock::MockServer, expected: usize) -> Vec<Value> {
    for _ in 0..120 {
        if received_spans(server).await.len() >= expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let spans = received_spans(server).await;
    assert_eq!(spans.len(), expected, "exported spans: {spans:#?}");
    spans
}

async fn assert_nothing_exported(server: &wiremock::MockServer) {
    tokio::time::sleep(Duration::from_millis(400)).await;
    let spans = received_spans(server).await;
    assert!(spans.is_empty(), "unexpected spans: {spans:#?}");
}

fn attr<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
    span["attributes"]
        .as_array()?
        .iter()
        .find(|attribute| attribute["key"] == key)
        .map(|attribute| &attribute["value"])
}

fn string_attr<'a>(span: &'a Value, key: &str) -> Option<&'a str> {
    attr(span, key)?["stringValue"].as_str()
}

fn int_attr(span: &Value, key: &str) -> Option<i64> {
    attr(span, key)?["intValue"].as_str()?.parse().ok()
}

fn bool_attr(span: &Value, key: &str) -> Option<bool> {
    attr(span, key)?["boolValue"].as_bool()
}

fn double_attr(span: &Value, key: &str) -> Option<f64> {
    attr(span, key)?["doubleValue"].as_f64()
}

fn assert_ms(span: &Value, key: &str, expected: f64) {
    let value = double_attr(span, key).unwrap_or_else(|| panic!("{key} missing: {span:#}"));
    assert!(
        (value - expected).abs() < 1e-6,
        "{key}={value}, want {expected}"
    );
}

fn unix_nanos(span: &Value, key: &str) -> u128 {
    span[key]
        .as_str()
        .and_then(|value| value.parse().ok())
        .expect("unix nanos")
}

/// The CLIENT spans, ordered by attempt number.
fn client_spans(spans: &[Value]) -> Vec<Value> {
    let mut clients: Vec<Value> = spans
        .iter()
        .filter(|span| span["kind"] == 3)
        .cloned()
        .collect();
    clients.sort_by_key(|span| int_attr(span, "gateway.backend.attempt"));
    clients
}

/// A request `otel_tracing` admitted exactly as the proxy path runs it:
/// `on_request_received`, then `before_proxy` over the backend header map.
async fn traced_request(plugin: &OtelTracing) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    let mut headers = HashMap::from([("x-app".to_string(), "kept".to_string())]);
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    (ctx, headers)
}

fn summary_for(ctx: &RequestContext, status: u16) -> TransactionSummary {
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/api/test".to_string(),
        proxy_id: Some("attempts".to_string()),
        proxy_name: None,
        backend_target: Some(BACKEND_URL.to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
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
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata: ctx.metadata.clone(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn traceparent_span_id(traceparent: &str) -> &str {
    traceparent.split('-').nth(2).expect("span id")
}

#[tokio::test]
async fn one_client_span_per_attempt_is_parented_under_the_server_span() {
    let server = collector().await;
    let plugin = otel(Some(&endpoint(&server)), json!({}));
    let (ctx, headers) = traced_request(&plugin).await;
    let trace_id = ctx.metadata["trace_id"].clone();
    let server_span_id = ctx.metadata["span_id"].clone();
    let server_traceparent = format!("00-{trace_id}-{server_span_id}-01");
    assert_eq!(headers["traceparent"], server_traceparent);

    let outcomes = [
        (Some(ErrorClass::ConnectionRefused), Some(502)),
        (None, Some(503)),
        (None, Some(200)),
    ];
    let mut dispatched = Vec::new();
    for (error_class, status) in outcomes {
        let (attempt_headers, ()) =
            run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {}).await;
        record_backend_attempt_for_test(&ctx, error_class, error_class.is_none(), status);
        dispatched.push(attempt_headers);
    }
    // The request's own header map (and the client's echo) keep the SERVER
    // span's context; only each attempt's dispatched copy names the attempt.
    assert_eq!(headers["traceparent"], server_traceparent);
    assert_eq!(ctx.metadata["traceparent"], server_traceparent);

    plugin.log(&summary_for(&ctx, 200)).await;
    let spans = exported_spans(&server, 4).await;

    let server_spans: Vec<&Value> = spans.iter().filter(|span| span["kind"] == 2).collect();
    assert_eq!(server_spans.len(), 1);
    let server_span = server_spans[0];
    assert_eq!(server_span["spanId"], server_span_id.as_str());
    // The SERVER span keeps its attributes and gains no attempt attributes.
    assert!(double_attr(server_span, "gateway.latency.total_ms").is_some());
    assert_eq!(string_attr(server_span, "client.address"), Some(CLIENT_IP));
    assert!(attr(server_span, "gateway.backend.attempt").is_none());

    let clients = client_spans(&spans);
    assert_eq!(clients.len(), 3);
    let mut span_ids = Vec::new();
    for (index, (span, attempt_headers)) in clients.iter().zip(&dispatched).enumerate() {
        let span_id = span["spanId"].as_str().expect("span id");
        assert_eq!(span["traceId"], trace_id.as_str());
        assert_eq!(span["parentSpanId"], server_span_id.as_str());
        assert_eq!(span["name"], "GET");
        assert_eq!(
            attempt_headers["traceparent"],
            format!("00-{trace_id}-{span_id}-01"),
            "attempt {} must carry its own span as the backend's parent",
            index + 1
        );
        assert_eq!(attempt_headers["x-app"], "kept");
        assert_eq!(attempt_headers.len(), headers.len());
        assert_eq!(
            int_attr(span, "gateway.backend.attempt"),
            Some(index as i64 + 1)
        );
        assert_eq!(string_attr(span, "http.request.method"), Some("GET"));
        assert_eq!(
            string_attr(span, "server.address"),
            Some("backend.internal")
        );
        assert_eq!(int_attr(span, "server.port"), Some(8080));
        assert!(unix_nanos(span, "startTimeUnixNano") <= unix_nanos(span, "endTimeUnixNano"));
        span_ids.push(span_id.to_string());
    }
    span_ids.push(server_span_id.clone());
    span_ids.sort();
    span_ids.dedup();
    assert_eq!(span_ids.len(), 4, "every attempt has its own span id");

    let first = &clients[0];
    assert_eq!(int_attr(first, "http.request.resend_count"), None);
    assert_eq!(string_attr(first, "gateway.backend.retry_reason"), None);
    assert_eq!(string_attr(first, "error.type"), Some("connection_refused"));
    assert_eq!(
        int_attr(first, "http.response.status_code"),
        None,
        "a gateway-classified failure carries no backend status"
    );
    assert_eq!(first["status"]["code"], 2);

    let second = &clients[1];
    assert_eq!(int_attr(second, "http.request.resend_count"), Some(1));
    assert_eq!(
        string_attr(second, "gateway.backend.retry_reason"),
        Some("connection_refused")
    );
    assert_eq!(int_attr(second, "http.response.status_code"), Some(503));
    assert_eq!(string_attr(second, "error.type"), Some("503"));
    assert_eq!(second["status"]["code"], 2);

    let third = &clients[2];
    assert_eq!(int_attr(third, "http.request.resend_count"), Some(2));
    assert_eq!(
        string_attr(third, "gateway.backend.retry_reason"),
        Some("http_status")
    );
    assert_eq!(int_attr(third, "http.response.status_code"), Some(200));
    assert_eq!(string_attr(third, "error.type"), None);
    assert_eq!(third["status"]["code"], 0);
}

#[tokio::test]
async fn attempt_spans_record_connection_setup_and_reuse_only_when_observed() {
    let server = collector().await;
    let plugin = otel(Some(&endpoint(&server)), json!({}));
    let (ctx, headers) = traced_request(&plugin).await;

    // Attempt 1 establishes a connection; the pool timed each phase.
    run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {
        note_backend_connection_setup_for_test(
            Duration::from_millis(12),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Some(Duration::from_millis(6)),
        );
    })
    .await;
    record_backend_attempt_for_test(&ctx, None, true, Some(503));

    // A pool report outside every attempt's poll belongs to no attempt.
    note_backend_connection_reused_for_test();

    // Attempt 2 rides a pooled connection.
    run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {
        note_backend_connection_reused_for_test();
    })
    .await;
    record_backend_attempt_for_test(&ctx, None, true, Some(503));

    // Attempt 3 goes through a dispatch that observes nothing.
    run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {}).await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));

    let clients = client_spans(&exported_spans(&server, 3).await);
    let timings = [
        "gateway.backend.connection.setup_ms",
        "gateway.backend.connection.dns_ms",
        "gateway.backend.connection.tcp_connect_ms",
        "gateway.backend.connection.tls_handshake_ms",
    ];

    let setup = &clients[0];
    assert_eq!(
        bool_attr(setup, "gateway.backend.connection.reused"),
        Some(false)
    );
    assert_ms(setup, "gateway.backend.connection.setup_ms", 12.0);
    assert_ms(setup, "gateway.backend.connection.dns_ms", 2.0);
    assert_ms(setup, "gateway.backend.connection.tcp_connect_ms", 3.0);
    assert_ms(setup, "gateway.backend.connection.tls_handshake_ms", 6.0);

    let reused = &clients[1];
    assert_eq!(
        bool_attr(reused, "gateway.backend.connection.reused"),
        Some(true)
    );
    for key in timings {
        assert!(attr(reused, key).is_none(), "reused attempt reports {key}");
    }

    let unknown = &clients[2];
    assert!(
        attr(unknown, "gateway.backend.connection.reused").is_none(),
        "an unobserved connection is omitted, never guessed"
    );
    for key in timings {
        assert!(
            attr(unknown, key).is_none(),
            "unobserved attempt reports {key}"
        );
    }
}

#[tokio::test]
async fn an_attempt_no_dispatch_site_began_is_counted_but_not_exported() {
    let server = collector().await;
    let plugin = otel(Some(&endpoint(&server)), json!({}));
    let (ctx, headers) = traced_request(&plugin).await;

    // Attempt 1 went out on a path that does not begin attempt spans, so the
    // backend saw the SERVER span's context and no CLIENT span may claim it.
    record_backend_attempt_for_test(&ctx, Some(ErrorClass::ConnectionReset), true, None);
    let (dispatched, ()) =
        run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {}).await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));

    let clients = client_spans(&exported_spans(&server, 1).await);
    let retry = &clients[0];
    assert_eq!(int_attr(retry, "gateway.backend.attempt"), Some(2));
    assert_eq!(int_attr(retry, "http.request.resend_count"), Some(1));
    assert_eq!(
        string_attr(retry, "gateway.backend.retry_reason"),
        Some("connection_reset")
    );
    assert_eq!(
        traceparent_span_id(&dispatched["traceparent"]),
        retry["spanId"].as_str().unwrap()
    );
}

#[tokio::test]
async fn attempt_span_attributes_respect_max_attribute_bytes() {
    let server = collector().await;
    let plugin = otel(
        Some(&endpoint(&server)),
        json!({ "max_attribute_bytes": 64 }),
    );
    let (ctx, headers) = traced_request(&plugin).await;
    let long_host = format!("{}.example", "backend-label.".repeat(20));
    let backend_url = format!("http://{long_host}:9443/api");

    run_backend_attempt_for_test(&ctx, &backend_url, &headers, async {}).await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));

    let clients = client_spans(&exported_spans(&server, 1).await);
    let address = string_attr(&clients[0], "server.address").expect("server.address");
    assert!(
        address.len() <= 64,
        "server.address is {} bytes",
        address.len()
    );
    assert!(address.ends_with("..."));
    assert_eq!(int_attr(&clients[0], "server.port"), Some(9443));
}

#[tokio::test]
async fn unsampled_requests_dispatch_unchanged_and_export_nothing() {
    let server = collector().await;
    let plugin = otel(
        Some(&endpoint(&server)),
        json!({ "root_sampling": "always_off" }),
    );
    let (ctx, headers) = traced_request(&plugin).await;
    assert!(headers["traceparent"].ends_with("-00"));

    for status in [503, 200] {
        let (dispatched, ()) = run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {
            note_backend_connection_reused_for_test();
        })
        .await;
        assert_eq!(
            dispatched, headers,
            "an unsampled attempt keeps the request headers"
        );
        record_backend_attempt_for_test(&ctx, None, true, Some(status));
    }
    plugin.log(&summary_for(&ctx, 200)).await;
    assert_nothing_exported(&server).await;
}

#[tokio::test]
async fn propagation_only_and_absent_tracing_dispatch_unchanged_headers() {
    // Propagation-only mode has no exporter, so it records no attempt spans
    // and the backend keeps the gateway span's context.
    let plugin = otel(None, json!({}));
    let (ctx, headers) = traced_request(&plugin).await;
    let (dispatched, ()) =
        run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {}).await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));
    assert_eq!(dispatched, headers);
    assert_eq!(
        traceparent_span_id(&dispatched["traceparent"]),
        ctx.metadata["span_id"]
    );

    // Without `otel_tracing` at all, every hook is inert.
    let ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let headers = HashMap::from([("x-app".to_string(), "kept".to_string())]);
    let (dispatched, ()) = run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {
        note_backend_connection_reused_for_test();
    })
    .await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));
    assert_eq!(dispatched, headers);
}

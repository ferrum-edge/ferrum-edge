//! `otel_tracing` production-launch review regressions.
//!
//! Finding IDs refer to the plugin review (`otel_tracing-SOL-N` and the Muse
//! report's `otel_tracing-CLAUDE-N`, triaged as `M<N>`).

use std::collections::HashMap;
use std::io::Read as _;
use std::time::Duration;

use ferrum_edge::_test_support::{record_backend_attempt_for_test, run_backend_attempt_for_test};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginScope};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::otel_tracing::{GatewayTraceOwner, OtelTracing};
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::utils::sink_loss::{SinkLossReason, accepted_total, dropped_total};
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use serde_json::{Value, json};

use super::plugin_utils::{make_plugin_config_with_json, make_proxy};

const BACKEND_URL: &str = "http://backend.internal:8080/api/test";
const CALLER_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const CALLER_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

fn otel(config: Value) -> OtelTracing {
    OtelTracing::new_with_http_client(&config, PluginHttpClient::default())
        .expect("valid otel_tracing config")
}

fn otel_error(config: Value) -> String {
    match OtelTracing::new_with_http_client(&config, PluginHttpClient::default()) {
        Ok(_) => panic!("otel_tracing config must be rejected: {config}"),
        Err(error) => error,
    }
}

fn traced_workload_metrics() -> WorkloadMetrics {
    WorkloadMetrics::new(&json!({"sampling_percentage": 100}))
        .expect("trace-enabled workload_metrics")
}

fn ctx() -> RequestContext {
    RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    )
}

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let mut found = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());
    let value = found.next();
    assert!(
        found.next().is_none(),
        "duplicate {name} headers: {headers:?}"
    );
    value
}

fn span_id(traceparent: &str) -> &str {
    traceparent.split('-').nth(2).expect("span id")
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
        proxy_id: Some("review".to_string()),
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
        response_delivery: Default::default(),
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata: ctx.metadata.clone().into_iter().collect(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn sampled_summary() -> TransactionSummary {
    let mut ctx = ctx();
    ctx.metadata.insert(
        "trace_id".to_string(),
        "abcdef1234567890abcdef1234567890".to_string(),
    );
    ctx.metadata
        .insert("span_id".to_string(), "1234567890abcdef".to_string());
    ctx.metadata
        .insert("trace_sampled".to_string(), "true".to_string());
    summary_for(&ctx, 200)
}

async fn collector(status: u16) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

fn endpoint(server: &wiremock::MockServer) -> String {
    format!("{}/v1/traces", server.uri())
}

/// Wait for the collector's first request.
async fn first_request(server: &wiremock::MockServer) -> wiremock::Request {
    for _ in 0..200 {
        if let Some(request) = server
            .received_requests()
            .await
            .and_then(|requests| requests.into_iter().next())
        {
            return request;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("collector received no export request");
}

fn spans_of(payload: &Value) -> Vec<Value> {
    let mut spans = Vec::new();
    for resource in payload["resourceSpans"].as_array().into_iter().flatten() {
        for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
            spans.extend(scope["spans"].as_array().into_iter().flatten().cloned());
        }
    }
    spans
}

/// Wait until the collector holds `expected` spans.
async fn exported_spans(server: &wiremock::MockServer, expected: usize) -> Vec<Value> {
    let mut spans = Vec::new();
    for _ in 0..200 {
        spans = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .flat_map(|request| spans_of(&request.body_json::<Value>().expect("OTLP JSON")))
            .collect();
        if spans.len() >= expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(spans.len(), expected, "exported spans: {spans:#?}");
    spans
}

// ── otel_tracing-SOL-1 / M1: one owner of the gateway SERVER span ──────────

/// At default priorities `otel_tracing` (25) establishes the SERVER span and
/// a trace-enabled `workload_metrics` (9360) must reuse it: before the fix its
/// `before_proxy` treated the `traceparent` `otel_tracing` had just injected
/// as a new parent and minted a second SERVER span under it, and its
/// `on_request_received` restored the caller's `tracestate` that untrusted
/// `otel_tracing` had dropped.
#[tokio::test]
async fn workload_metrics_reuses_the_server_span_otel_tracing_established() {
    for incoming in [None, Some(CALLER_TRACEPARENT)] {
        let tracer = otel(json!({}));
        let metrics = traced_workload_metrics();
        let mut ctx = ctx();
        if let Some(traceparent) = incoming {
            ctx.headers
                .insert("traceparent".to_string(), traceparent.to_string());
            ctx.headers
                .insert("tracestate".to_string(), "caller=untrusted".to_string());
        }

        tracer.on_request_received(&mut ctx).await;
        metrics.on_request_received(&mut ctx).await;
        assert_eq!(
            ctx.gateway_trace_owner(),
            Some(GatewayTraceOwner::OtelTracing)
        );
        let trace_id = ctx.metadata["trace_id"].clone();
        let server_span = ctx.metadata["span_id"].clone();
        let server_traceparent = ctx.metadata["traceparent"].clone();
        assert_ne!(trace_id, CALLER_TRACE_ID, "untrusted parent is not adopted");
        assert!(
            !ctx.metadata.contains_key("tracestate"),
            "workload_metrics must not restore the untrusted caller tracestate ({incoming:?})"
        );

        let mut headers = ctx.headers.clone();
        tracer.before_proxy(&mut ctx, &mut headers).await;
        metrics.before_proxy(&mut ctx, &mut headers).await;

        assert_eq!(ctx.metadata["trace_id"], trace_id, "{incoming:?}");
        assert_eq!(ctx.metadata["span_id"], server_span, "{incoming:?}");
        assert_eq!(
            ctx.metadata["traceparent"], server_traceparent,
            "{incoming:?}"
        );
        assert!(!ctx.metadata.contains_key("parent_span_id"), "{incoming:?}");
        assert_eq!(
            header(&headers, "traceparent"),
            Some(server_traceparent.as_str())
        );
        assert_eq!(header(&headers, "tracestate"), None, "{incoming:?}");

        let mut response_headers = HashMap::new();
        tracer
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        metrics
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        assert_eq!(
            header(&response_headers, "traceparent"),
            Some(server_traceparent.as_str())
        );
    }
}

/// The exported SERVER span and every attempt CLIENT span share one tree when
/// both plugins trace the request: each CLIENT span's parent is the SERVER span
/// that is actually exported.
#[tokio::test]
async fn attempt_spans_parent_under_the_exported_server_span_with_workload_metrics() {
    let server = collector(200).await;
    let tracer = otel(json!({
        "endpoint": endpoint(&server),
        "batch_size": 50,
        "flush_interval_ms": 100
    }));
    let metrics = traced_workload_metrics();
    let mut ctx = ctx();
    tracer.on_request_received(&mut ctx).await;
    metrics.on_request_received(&mut ctx).await;
    let mut headers = HashMap::from([("x-app".to_string(), "kept".to_string())]);
    tracer.before_proxy(&mut ctx, &mut headers).await;
    metrics.before_proxy(&mut ctx, &mut headers).await;

    let (attempt_headers, ()) =
        run_backend_attempt_for_test(&ctx, BACKEND_URL, &headers, async {}).await;
    record_backend_attempt_for_test(&ctx, None, true, Some(200));
    tracer.log(&summary_for(&ctx, 200)).await;

    let spans = exported_spans(&server, 2).await;
    let server_spans: Vec<&Value> = spans.iter().filter(|span| span["kind"] == 2).collect();
    let client_spans: Vec<&Value> = spans.iter().filter(|span| span["kind"] == 3).collect();
    assert_eq!(server_spans.len(), 1, "{spans:#?}");
    assert_eq!(client_spans.len(), 1, "{spans:#?}");
    let server_span_id = server_spans[0]["spanId"].as_str().expect("server span id");
    assert_eq!(server_span_id, ctx.metadata["span_id"]);
    assert_eq!(client_spans[0]["parentSpanId"], server_span_id);
    assert_eq!(client_spans[0]["traceId"], server_spans[0]["traceId"]);
    // The backend's parent is the attempt span, which is exported.
    let attempt_traceparent = header(&attempt_headers, "traceparent").expect("attempt context");
    assert_eq!(client_spans[0]["spanId"], span_id(attempt_traceparent));
}

/// `otel_tracing` without its own context (generation disabled, no trusted
/// parent) leaves the SERVER span to `workload_metrics`; injecting that span
/// into the backend map must not make `workload_metrics` re-derive it.
#[tokio::test]
async fn workload_metrics_keeps_its_own_server_span_after_otel_tracing_injects_it() {
    let tracer = otel(json!({"generate_trace_id": false}));
    let metrics = traced_workload_metrics();
    let mut ctx = ctx();
    tracer.on_request_received(&mut ctx).await;
    metrics.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.gateway_trace_owner(),
        Some(GatewayTraceOwner::WorkloadMetrics)
    );
    let server_span = ctx.metadata["span_id"].clone();
    let server_traceparent = ctx.metadata["traceparent"].clone();

    let mut headers = ctx.headers.clone();
    tracer.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        header(&headers, "traceparent"),
        Some(server_traceparent.as_str())
    );
    metrics.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(ctx.metadata["span_id"], server_span);
    assert_eq!(ctx.metadata["traceparent"], server_traceparent);
    assert!(!ctx.metadata.contains_key("parent_span_id"));
    assert_eq!(
        header(&headers, "traceparent"),
        Some(server_traceparent.as_str())
    );
}

/// With a priority override ordering `workload_metrics` first, it establishes
/// the SERVER span and `otel_tracing` must not overwrite it.
#[tokio::test]
async fn otel_tracing_does_not_overwrite_a_server_span_workload_metrics_established() {
    let tracer = otel(json!({}));
    let metrics = traced_workload_metrics();
    let mut ctx = ctx();
    metrics.on_request_received(&mut ctx).await;
    let server_span = ctx.metadata["span_id"].clone();
    let server_traceparent = ctx.metadata["traceparent"].clone();
    tracer.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.gateway_trace_owner(),
        Some(GatewayTraceOwner::WorkloadMetrics)
    );
    assert_eq!(ctx.metadata["span_id"], server_span);
    assert_eq!(ctx.metadata["traceparent"], server_traceparent);

    let mut headers = ctx.headers.clone();
    metrics.before_proxy(&mut ctx, &mut headers).await;
    tracer.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.metadata["span_id"], server_span);
    assert_eq!(
        header(&headers, "traceparent"),
        Some(server_traceparent.as_str())
    );
}

// ── otel_tracing-SOL-2 / M3: successful WebSocket handshake echo ───────────

#[tokio::test]
async fn successful_websocket_handshake_echoes_the_server_traceparent() {
    for status in [101u16, 200] {
        let tracer = otel(json!({}));
        let mut ctx = ctx();
        tracer.on_request_received(&mut ctx).await;
        let server_traceparent = ctx.metadata["traceparent"].clone();

        // A backend that echoed its own (attempt) context back.
        let mut response_headers = HashMap::from([(
            "Traceparent".to_string(),
            "00-abcdef1234567890abcdef1234567890-aaaaaaaaaaaaaaaa-01".to_string(),
        )]);
        tracer.apply_websocket_handshake_response_headers(&ctx, status, &mut response_headers);
        assert_eq!(
            header(&response_headers, "traceparent"),
            Some(server_traceparent.as_str()),
            "status {status}"
        );
    }

    // No gateway context (generation disabled, no parent): nothing is added.
    let tracer = otel(json!({"generate_trace_id": false}));
    let mut ctx = ctx();
    tracer.on_request_received(&mut ctx).await;
    let mut response_headers = HashMap::new();
    tracer.apply_websocket_handshake_response_headers(&ctx, 101, &mut response_headers);
    assert!(response_headers.is_empty());
}

// ── M2: at most one effective instance per proxy ───────────────────────────

#[test]
fn two_effective_otel_tracing_instances_on_one_proxy_are_rejected() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", vec!["otel-a", "otel-b"])],
        plugin_configs: vec![
            make_plugin_config_with_json(
                "otel-a",
                "otel_tracing",
                json!({}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "otel-b",
                "otel_tracing",
                json!({}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
        ..Default::default()
    };
    let error = PluginCache::new(&config)
        .err()
        .expect("two effective otel_tracing instances must be rejected");
    assert!(
        error.contains("otel_tracing permits at most one effective instance per proxy"),
        "unexpected composition error: {error}"
    );
}

#[test]
fn a_scoped_otel_tracing_instance_still_replaces_the_global_one() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", vec!["otel-scoped"])],
        plugin_configs: vec![
            make_plugin_config_with_json(
                "otel-global",
                "otel_tracing",
                json!({}),
                PluginScope::Global,
                None,
            ),
            make_plugin_config_with_json(
                "otel-scoped",
                "otel_tracing",
                json!({}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
        ..Default::default()
    };
    assert!(PluginCache::new(&config).is_ok());
}

// ── M4: trusted tracestate must be a valid W3C list ────────────────────────

async fn trusted_tracestate(tracestate: &str) -> (RequestContext, HashMap<String, String>) {
    let tracer = otel(json!({"trace_context_trust": "trusted"}));
    let mut ctx = ctx();
    ctx.headers
        .insert("traceparent".to_string(), CALLER_TRACEPARENT.to_string());
    ctx.headers
        .insert("tracestate".to_string(), tracestate.to_string());
    tracer.on_request_received(&mut ctx).await;
    let mut headers = ctx.headers.clone();
    tracer.before_proxy(&mut ctx, &mut headers).await;
    (ctx, headers)
}

#[tokio::test]
async fn invalid_trusted_tracestate_is_dropped_while_the_parent_is_kept() {
    let too_many: Vec<String> = (0..33).map(|index| format!("k{index}=v")).collect();
    let oversized: Vec<String> = (0..32)
        .map(|index| format!("k{index}={}", "x".repeat(256)))
        .collect();
    let cases = [
        "BAD KEY=x".to_string(),
        "Upper=x".to_string(),
        "dup=1,dup=2".to_string(),
        "missing-value=".to_string(),
        "novalue".to_string(),
        "k=a=b".to_string(),
        format!("k={}", "x".repeat(257)),
        format!("{}=v", "k".repeat(257)),
        "tenant@System=v".to_string(),
        "@vendor=v".to_string(),
        " , ".to_string(),
        too_many.join(","),
        oversized.join(","),
    ];
    for tracestate in cases {
        let (ctx, headers) = trusted_tracestate(&tracestate).await;
        assert_eq!(ctx.metadata["trace_id"], CALLER_TRACE_ID, "{tracestate:?}");
        assert!(
            !ctx.metadata.contains_key("tracestate"),
            "invalid tracestate {tracestate:?} must be dropped"
        );
        assert_eq!(header(&headers, "tracestate"), None, "{tracestate:?}");
        assert!(header(&headers, "traceparent").is_some());
    }
}

#[tokio::test]
async fn valid_trusted_tracestate_is_forwarded_unchanged() {
    let thirty_two: Vec<String> = (0..32).map(|index| format!("k{index}=v")).collect();
    let cases = [
        "vendor1=value1,vendor2=value2".to_string(),
        "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE".to_string(),
        "tenant@vendor=opaque value,a_b-c*d/e=1".to_string(),
        "a=1,,b=2".to_string(),
        "a=1 ,\tb=2".to_string(),
        format!("k={}", "x".repeat(256)),
        thirty_two.join(","),
    ];
    for tracestate in cases {
        let (ctx, headers) = trusted_tracestate(&tracestate).await;
        assert_eq!(
            ctx.metadata.get("tracestate").map(String::as_str),
            Some(tracestate.as_str())
        );
        assert_eq!(header(&headers, "tracestate"), Some(tracestate.as_str()));
    }
}

// ── M5: exporter custom headers ────────────────────────────────────────────

#[test]
fn custom_export_headers_reject_duplicates_and_exporter_managed_names() {
    let duplicate = otel_error(json!({"headers": {"X-Api-Key": "old", "x-api-key": "new"}}));
    assert!(duplicate.contains("`headers`"), "{duplicate}");
    assert!(duplicate.contains("more than once"), "{duplicate}");
    assert!(
        !duplicate.to_ascii_lowercase().contains("x-api-key"),
        "the diagnostic must not echo configured header names: {duplicate}"
    );

    for name in [
        "Content-Type",
        "content-length",
        "Content-Encoding",
        "Transfer-Encoding",
        "Host",
    ] {
        let error = otel_error(json!({"headers": {name: "value"}}));
        assert!(error.contains("exporter-managed"), "{name}: {error}");
    }

    let error = otel_error(json!({
        "authorization": "Bearer configured",
        "headers": {"Authorization": "Bearer duplicate"}
    }));
    assert!(error.contains("Authorization"), "{error}");
    assert!(!error.contains("Bearer"), "{error}");

    // A credential in `headers` alone is still one Authorization field.
    otel(json!({"headers": {"Authorization": "Bearer only"}}));
    otel(json!({"headers": {"x-honeycomb-team": "a", "X-Scope-OrgID": "b"}}));
}

// ── M8: gzip export ────────────────────────────────────────────────────────

#[test]
fn compression_accepts_only_none_and_gzip() {
    otel(json!({"compression": "none"}));
    otel(json!({"compression": " GZIP "}));
    for value in [json!("br"), json!(null), json!(true)] {
        let error = otel_error(json!({"compression": value.clone()}));
        assert!(error.contains("compression"), "{value}: {error}");
        assert!(!error.contains("\"br\""), "{error}");
    }
}

#[tokio::test]
async fn gzip_compression_sends_a_gzip_encoded_otlp_body() {
    let server = collector(200).await;
    let tracer = otel(json!({
        "endpoint": endpoint(&server),
        "compression": "gzip",
        "batch_size": 1,
        "flush_interval_ms": 100
    }));
    tracer.log(&sampled_summary()).await;

    let request = first_request(&server).await;
    assert_eq!(
        request
            .headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(
        request
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let mut json = String::new();
    flate2::read::GzDecoder::new(request.body.as_slice())
        .read_to_string(&mut json)
        .expect("gzip body");
    let payload: Value = serde_json::from_str(&json).expect("OTLP JSON");
    let spans = spans_of(&payload);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0]["traceId"], "abcdef1234567890abcdef1234567890");
}

#[tokio::test]
async fn default_compression_sends_an_uncompressed_body() {
    let server = collector(200).await;
    let tracer = otel(json!({
        "endpoint": endpoint(&server),
        "batch_size": 1,
        "flush_interval_ms": 100
    }));
    tracer.log(&sampled_summary()).await;

    let request = first_request(&server).await;
    assert!(request.headers.get("content-encoding").is_none());
    let payload: Value = request.body_json().expect("plain OTLP JSON");
    assert_eq!(spans_of(&payload).len(), 1);
}

// ── M7: exporter span accounting ───────────────────────────────────────────

#[tokio::test]
async fn rejected_export_batches_are_counted_as_batch_discard() {
    let server = collector(401).await;
    let tracer = otel(json!({
        "endpoint": endpoint(&server),
        "batch_size": 1,
        "flush_interval_ms": 100,
        "max_retries": 0
    }));
    let accepted_before = accepted_total("otel_tracing");
    let discarded_before = dropped_total("otel_tracing", SinkLossReason::BatchDiscard);

    tracer.log(&sampled_summary()).await;

    assert!(accepted_total("otel_tracing") > accepted_before);
    for _ in 0..200 {
        if dropped_total("otel_tracing", SinkLossReason::BatchDiscard) > discarded_before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("a 401-rejected batch must be counted as otel_tracing batch_discard");
}

#[tokio::test]
async fn queue_full_span_refusals_are_counted() {
    // One-slot queue and a flush interval far beyond the test: on this
    // current-thread runtime the flush worker never runs between the two
    // `log` calls, so the second span finds the queue full.
    let tracer = otel(json!({
        "endpoint": "http://127.0.0.1:9/v1/traces",
        "batch_size": 10_000,
        "flush_interval_ms": 600_000,
        "buffer_capacity": 1
    }));
    let before = dropped_total("otel_tracing", SinkLossReason::QueueFull);

    tracer.log(&sampled_summary()).await;
    tracer.log(&sampled_summary()).await;

    assert!(
        dropped_total("otel_tracing", SinkLossReason::QueueFull) > before,
        "a queue-full span refusal must be counted"
    );
}

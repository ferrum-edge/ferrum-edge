//! Allocator-level proof that propagation-only `otel_tracing` builds no span
//! (plugin production-launch review, otel_tracing SOL-3 / M6).
//!
//! Without an `endpoint` there is no exporter, so a terminal hook that
//! materialized an owned `SpanData` (IDs, ~15 bounded attribute copies, a
//! backend URL parse, a mesh-attribute scan) did that work only for the
//! exporter check to drop it. The terminal hooks now return before building
//! the span. The counting allocator installed by
//! `response_coalescing_allocation_tests` makes that observable: a sampled,
//! fully populated transaction costs only the `async_trait` future box, where
//! the old path paid a dozen or more allocations per call.
//!
//! These are allocation REQUESTS on this test's thread, not resident memory.

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use ferrum_edge::plugins::otel_tracing::OtelTracing;
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{
    Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext,
};
use serde_json::json;

use super::response_coalescing_allocation_tests::measure;

/// The terminal hook's own boxed future plus a small margin. The span
/// materialization this guards against costs well over this per call.
const MAX_PROPAGATION_ONLY_ALLOCATIONS: usize = 3;

/// Poll `future` once. A propagation-only terminal hook never waits.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a propagation-only terminal hook must not wait"),
    }
}

fn sampled_metadata() -> HashMap<String, String> {
    HashMap::from([
        (
            "trace_id".to_string(),
            "abcdef1234567890abcdef1234567890".to_string(),
        ),
        ("span_id".to_string(), "1234567890abcdef".to_string()),
        ("parent_span_id".to_string(), "fedcba0987654321".to_string()),
        ("trace_sampled".to_string(), "true".to_string()),
        ("server_address".to_string(), "api.example.com".to_string()),
        ("server_port".to_string(), "443".to_string()),
    ])
}

fn rich_summary() -> TransactionSummary {
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
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
        body_completed: true,
        response_delivery: Default::default(),
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata: sampled_metadata().into_iter().collect(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_lifecycle_generation: None,
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
        metadata: sampled_metadata().into_iter().collect(),
    }
}

fn ws_disconnect() -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("chat".to_string()),
        client_ip: "10.0.0.1".to_string(),
        backend_target: "http://backend:8080/ws".to_string(),
        http_method: "GET".to_string(),
        request_path: "/".to_string(),
        handshake_status_code: 101,
        listen_port: 443,
        duration_ms: 12.0,
        frames_client_to_backend: 2,
        frames_backend_to_client: 3,
        bytes_client_to_backend: 10,
        bytes_backend_to_client: 20,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
        metadata: sampled_metadata().into_iter().collect(),
    }
}

#[test]
fn propagation_only_terminal_hooks_build_no_span() {
    let plugin = OtelTracing::new_with_http_client(&json!({}), PluginHttpClient::default())
        .expect("propagation-only otel_tracing");
    let summary = rich_summary();
    let stream = stream_summary();
    let ws = ws_disconnect();

    // Pay any first-touch lazy state (tracing callsite registration,
    // thread-locals) outside the measured windows.
    ready(plugin.log(&summary));
    ready(plugin.on_stream_disconnect(&stream));
    ready(plugin.on_ws_disconnect(&ws));

    let ((log_allocations, _), ()) = measure(|| ready(plugin.log(&summary)));
    assert!(
        log_allocations <= MAX_PROPAGATION_ONLY_ALLOCATIONS,
        "propagation-only `log` must not materialize a span: {log_allocations} allocations"
    );
    let ((stream_allocations, _), ()) = measure(|| ready(plugin.on_stream_disconnect(&stream)));
    assert!(
        stream_allocations <= MAX_PROPAGATION_ONLY_ALLOCATIONS,
        "propagation-only `on_stream_disconnect` must not materialize a span: \
         {stream_allocations} allocations"
    );
    let ((ws_allocations, _), ()) = measure(|| ready(plugin.on_ws_disconnect(&ws)));
    assert!(
        ws_allocations <= MAX_PROPAGATION_ONLY_ALLOCATIONS,
        "propagation-only `on_ws_disconnect` must not materialize a span: \
         {ws_allocations} allocations"
    );
}

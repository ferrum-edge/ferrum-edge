//! Focused coverage for Istio Telemetry metric families added for #3256:
//! REQUEST_SIZE / RESPONSE_SIZE, TCP connection/byte counters, and gRPC
//! message counters. Asserts values and disable/reload lifecycle, not mere
//! series presence.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::mesh::prometheus_helpers::{
    GrpcLengthPrefixedScanner, GrpcMessageFraming, count_grpc_length_prefixed_messages,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::{MetricsRegistry, PrometheusMetrics};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, StreamConnectionContext, StreamTransactionSummary,
};
use serde_json::json;

fn mesh_http_summary(
    bytes_sent: u64,
    bytes_received: u64,
) -> ferrum_edge::plugins::TransactionSummary {
    ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("orders".into()),
        proxy_name: Some("orders".into()),
        response_status_code: 200,
        latency_total_ms: 12.0,
        body_completed: true,
        bytes_sent,
        bytes_received,
        metadata: HashMap::from([
            ("mesh.source.workload".into(), "frontend".into()),
            ("mesh.source.namespace".into(), "default".into()),
            (
                "mesh.source.principal".into(),
                "spiffe://cluster.local/ns/default/sa/frontend".into(),
            ),
            ("mesh.source.app".into(), "frontend".into()),
            ("mesh.source.service".into(), "frontend".into()),
            ("mesh.destination.workload".into(), "orders".into()),
            ("mesh.destination.namespace".into(), "default".into()),
            (
                "mesh.destination.principal".into(),
                "spiffe://cluster.local/ns/default/sa/orders".into(),
            ),
            ("mesh.destination.app".into(), "orders".into()),
            ("mesh.destination.service".into(), "orders".into()),
            ("mesh.request_protocol".into(), "http".into()),
            ("mesh.response_flags".into(), "-".into()),
            (
                "mesh.connection_security_policy".into(),
                "mutual_tls".into(),
            ),
        ]),
        ..Default::default()
    }
}

#[test]
fn request_and_response_size_histograms_record_authoritative_byte_values() {
    let registry = MetricsRegistry::new();
    registry.record(&mesh_http_summary(100, 250));
    registry.record(&mesh_http_summary(100, 250));
    let output = registry.render_uncached();

    assert!(
        output.contains("ferrum_mesh_request_bytes_count{"),
        "request size series missing:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "response size series missing:\n{output}"
    );
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_request_bytes_sum{")
                && line.ends_with(" 200.00")),
        "request size sum must be 100+100:\n{output}"
    );
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_response_bytes_sum{")
                && line.ends_with(" 500.00")),
        "response size sum must be 250+250:\n{output}"
    );
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_request_bytes_count{") && line.ends_with(" 2")
        ),
        "request size count must be 2:\n{output}"
    );
}

#[tokio::test]
async fn request_size_disable_suppresses_histogram_updates() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": {
            "disabled_metrics": ["REQUEST_SIZE"]
        }
    }))
    .expect("plugin");
    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let mut summary = mesh_http_summary(64, 128);
    summary.metadata.extend(ctx.metadata);
    let registry = MetricsRegistry::new();
    registry.record(&summary);
    let output = registry.render_uncached();
    assert!(
        !output.contains("ferrum_mesh_request_bytes_"),
        "disabled REQUEST_SIZE must not record:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "RESPONSE_SIZE must still record when only REQUEST_SIZE is disabled:\n{output}"
    );
}

#[tokio::test]
async fn reload_clears_disable_and_resumes_request_size_recording() {
    let disabled = WorkloadMetrics::new(&json!({
        "metrics": {"disabled_metrics": ["REQUEST_SIZE", "RESPONSE_SIZE"]}
    }))
    .expect("disabled plugin");
    let enabled = WorkloadMetrics::new(&json!({
        "metrics": {"disabled_metrics": []}
    }))
    .expect("enabled plugin");

    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    disabled.before_proxy(&mut ctx, &mut headers).await;
    let mut summary = mesh_http_summary(10, 20);
    summary.metadata.extend(ctx.metadata.clone());
    let registry = MetricsRegistry::new();
    registry.record(&summary);
    assert!(
        !registry
            .render_uncached()
            .contains("ferrum_mesh_request_bytes_")
    );

    // Simulate Telemetry delete/reload: a new plugin instance without disables.
    ctx.metadata.remove("mesh.metrics.disabled");
    enabled.before_proxy(&mut ctx, &mut headers).await;
    let mut resumed = mesh_http_summary(11, 22);
    resumed.metadata.extend(ctx.metadata);
    registry.record(&resumed);
    let output = registry.render_uncached();
    assert!(
        output.contains("ferrum_mesh_request_bytes_count{"),
        "re-enabled REQUEST_SIZE must resume:\n{output}"
    );
    assert!(
        output.contains("ferrum_mesh_response_bytes_count{"),
        "re-enabled RESPONSE_SIZE must resume:\n{output}"
    );
}

#[test]
fn tcp_opened_closed_and_bytes_follow_connect_disconnect_lifecycle() {
    let registry = MetricsRegistry::new();
    let mut metadata = HashMap::from([
        (
            ferrum_edge::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
                .into(),
            "1".into(),
        ),
        (
            ferrum_edge::plugins::mesh::prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA
                .into(),
            "1".into(),
        ),
        ("mesh.source.workload".into(), "frontend".into()),
        ("mesh.source.namespace".into(), "default".into()),
        (
            "mesh.source.principal".into(),
            "spiffe://cluster.local/ns/default/sa/frontend".into(),
        ),
        ("mesh.source.app".into(), "frontend".into()),
        ("mesh.source.service".into(), "frontend".into()),
        ("mesh.destination.workload".into(), "db".into()),
        ("mesh.destination.namespace".into(), "default".into()),
        (
            "mesh.destination.principal".into(),
            "spiffe://cluster.local/ns/default/sa/db".into(),
        ),
        ("mesh.destination.app".into(), "db".into()),
        ("mesh.destination.service".into(), "db".into()),
        ("mesh.request_protocol".into(), "tcp".into()),
        ("mesh.response_flags".into(), "-".into()),
        (
            "mesh.connection_security_policy".into(),
            "mutual_tls".into(),
        ),
    ]);

    registry.finalize_mesh_tcp_opened(&mut metadata, "db", Some("db"));
    let after_open = registry.render_uncached();
    assert!(
        after_open.lines().any(|line| line
            .starts_with("ferrum_mesh_tcp_connections_opened_total{")
            && line.ends_with(" 1")),
        "opened must increment on connect:\n{after_open}"
    );
    assert!(
        !after_open.contains("ferrum_mesh_tcp_connections_closed_total{"),
        "closed must not increment before disconnect:\n{after_open}"
    );

    let summary = StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "default".into(),
        proxy_id: "db".into(),
        proxy_name: Some("db".into()),
        client_ip: "10.0.0.1".into(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.9:5432".into(),
        backend_resolved_ip: None,
        protocol: "tcp".into(),
        listen_port: 15001,
        duration_ms: 40.0,
        bytes_sent: 700,
        bytes_received: 900,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata: metadata.clone(),
        proxy_lifecycle_generation: None,
    };
    registry.record_stream(&summary);
    let after_close = registry.render_uncached();
    assert!(
        after_close.lines().any(|line| line
            .starts_with("ferrum_mesh_tcp_connections_closed_total{")
            && line.ends_with(" 1")),
        "closed must increment on disconnect:\n{after_close}"
    );
    // Direction contract: these mesh families implement Istio Telemetry's
    // canonical TCP_SENT_BYTES=response and TCP_RECEIVED_BYTES=request
    // semantics. StreamTransactionSummary uses Ferrum's gateway-perspective
    // field names, so the producer intentionally maps bytes_received to sent
    // and bytes_sent to received. General Ferrum transaction/API counters keep
    // their existing gateway-perspective convention.
    assert!(
        after_close
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{")
                && line.ends_with(" 900")),
        "TCP_SENT_BYTES must equal response bytes (backend->client):\n{after_close}"
    );
    assert!(
        after_close.lines().any(
            |line| line.starts_with("ferrum_mesh_tcp_received_bytes_total{")
                && line.ends_with(" 700")
        ),
        "TCP_RECEIVED_BYTES must equal request bytes (client->backend):\n{after_close}"
    );
    assert!(
        after_close.contains("response bytes sent backend->client on closed connections."),
        "sent-bytes HELP must state the Istio response direction:\n{after_close}"
    );
    assert!(
        after_close.contains("request bytes received client->backend on closed connections."),
        "received-bytes HELP must state the Istio request direction:\n{after_close}"
    );
}

#[test]
fn grpc_message_counters_use_authoritative_frame_counts() {
    let registry = MetricsRegistry::new();
    let mut summary = mesh_http_summary(15, 25);
    summary
        .metadata
        .insert("mesh.request_protocol".into(), "grpc".into());
    // Two request frames (5+0 + 5+5) and three response frames.
    summary.grpc_request_messages = 2;
    summary.grpc_response_messages = 3;
    registry.record(&summary);
    let output = registry.render_uncached();
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_request_messages_total{") && line.ends_with(" 2")
        ),
        "request messages must be 2:\n{output}"
    );
    assert!(
        output.lines().any(
            |line| line.starts_with("ferrum_mesh_response_messages_total{") && line.ends_with(" 3")
        ),
        "response messages must be 3:\n{output}"
    );
}

#[test]
fn grpc_length_prefixed_scanner_counts_spanning_frames() {
    let counter = Arc::new(AtomicU64::new(0));
    let mut scanner = GrpcLengthPrefixedScanner::default();
    // One empty message (5-byte header) split across two writes, then a
    // 3-byte payload message.
    scanner.push(&[0, 0, 0, 0], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
    scanner.push(&[0], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    scanner.push(&[0, 0, 0, 0, 3, 1, 2, 3], &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
    assert_eq!(
        count_grpc_length_prefixed_messages(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]),
        2
    );
}

fn grpc_frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(flag);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// Messages a scanner in `framing` counts over `chunks`, fed in order.
fn scanned_messages(framing: GrpcMessageFraming, chunks: &[&[u8]]) -> u64 {
    let counter = AtomicU64::new(0);
    let mut scanner = GrpcLengthPrefixedScanner::new(framing);
    for chunk in chunks {
        scanner.push(chunk, &counter);
    }
    counter.load(Ordering::Relaxed)
}

/// `wire` split into two chunks at every byte offset, then fed one byte at a
/// time, always counts `expected` messages.
fn assert_counts_at_every_split(framing: GrpcMessageFraming, wire: &[u8], expected: u64) {
    for cut in 0..=wire.len() {
        let (head, tail) = wire.split_at(cut);
        let counted = scanned_messages(framing, &[head, tail]);
        assert_eq!(counted, expected, "{framing:?} split at {cut}");
    }
    let bytes: Vec<&[u8]> = wire.chunks(1).collect();
    let counted = scanned_messages(framing, &bytes);
    assert_eq!(counted, expected, "{framing:?} one byte at a time");
}

/// Three gRPC-Web message frames (one compressed, one empty) and the frames a
/// gRPC-Web upload may interleave that are not messages: an empty trailer
/// frame, a trailer frame, and a compressed trailer frame.
fn grpc_web_frames() -> Vec<Vec<u8>> {
    vec![
        grpc_frame(0x00, b"one"),
        grpc_frame(0x80, b""),
        grpc_frame(0x01, b"compressed"),
        grpc_frame(0x00, b""),
        grpc_frame(0x80, b"x-app-id: 42\r\n"),
        grpc_frame(0x81, b"deflated"),
    ]
}

#[test]
fn grpc_web_scanner_counts_message_frames_and_skips_trailer_frames() {
    let wire = grpc_web_frames().concat();
    let framing = GrpcMessageFraming::grpc_web(false);
    assert_eq!(framing, GrpcMessageFraming::GrpcWeb);
    assert_counts_at_every_split(framing, &wire, 3);
    // Native framing has no trailer frames: every length-prefixed frame is a
    // message, exactly as before.
    assert_counts_at_every_split(GrpcMessageFraming::Native, &wire, 6);
    let counter = AtomicU64::new(0);
    let mut native = GrpcLengthPrefixedScanner::default();
    native.push(&wire, &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 6);
}

#[test]
fn grpc_web_text_scanner_decodes_base64_across_chunks() {
    let frames = grpc_web_frames();
    let framing = GrpcMessageFraming::grpc_web(true);
    assert_eq!(framing, GrpcMessageFraming::GrpcWebText);

    // One base64 run over the whole binary body.
    let whole = BASE64.encode(frames.concat()).into_bytes();
    assert_counts_at_every_split(framing, &whole, 3);

    // Each frame encoded on its own, as a sender flushing per frame writes
    // it: independently padded segments, concatenated.
    let segments: Vec<String> = frames.iter().map(|frame| BASE64.encode(frame)).collect();
    let padded_segments = segments.iter().filter(|s| s.ends_with('=')).count();
    assert!(
        padded_segments >= 2,
        "the fixture must carry padded segments: {segments:?}"
    );
    let padded = segments.concat().into_bytes();
    assert_counts_at_every_split(framing, &padded, 3);
}

#[test]
fn grpc_web_text_scanner_counts_messages_as_they_complete() {
    let first = BASE64.encode(grpc_frame(0x00, b"one"));
    let second = BASE64.encode(grpc_frame(0x00, b"two"));
    let counter = AtomicU64::new(0);
    let mut scanner = GrpcLengthPrefixedScanner::new(GrpcMessageFraming::GrpcWebText);
    scanner.push(first.as_bytes(), &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    // A truncated frame is not a message until its last byte arrives.
    let (head, tail) = second.as_bytes().split_at(second.len() - 4);
    scanner.push(head, &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    scanner.push(tail, &counter);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

#[test]
fn grpc_web_text_scanner_stops_counting_at_malformed_base64() {
    let first = BASE64.encode(grpc_frame(0x00, b"one"));
    let second = BASE64.encode(grpc_frame(0x00, b"two"));
    let wire = format!("{first}!!!!{second}");
    let counted = scanned_messages(GrpcMessageFraming::GrpcWebText, &[wire.as_bytes()]);
    assert_eq!(counted, 1, "nothing after undecodable base64 is counted");
    // Binary gRPC-Web bytes are not base64: a text scanner counts nothing.
    let binary = grpc_frame(0x00, b"one");
    let counted = scanned_messages(GrpcMessageFraming::GrpcWebText, &[&binary]);
    assert_eq!(counted, 0);
}

#[tokio::test]
async fn complete_grpc_message_count_uses_fetch_max_not_additive_retry() {
    use ferrum_edge::plugins::mesh::prometheus_helpers::{
        metadata_observes_grpc_messages, record_complete_grpc_message_count,
    };

    let prometheus = PrometheusMetrics::new(&serde_json::Value::Null, "default")
        .expect("prometheus_metrics instance");
    let mut request = RequestContext::new("10.0.0.1".into(), "POST".into(), "/grpc".into());
    request
        .metadata
        .insert("request_protocol".into(), "grpc".into());
    assert!(
        !metadata_observes_grpc_messages(&request.metadata),
        "protocol alone must not enable scanners without prometheus_metrics observation"
    );
    assert!(matches!(
        prometheus.on_request_received(&mut request).await,
        PluginResult::Continue
    ));
    let mut metadata = request.metadata;
    assert!(metadata_observes_grpc_messages(&metadata));
    metadata.insert("request_protocol".into(), "http".into());
    assert!(!metadata_observes_grpc_messages(&metadata));

    let counter = Arc::new(AtomicU64::new(0));
    let body = [0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]; // two messages
    record_complete_grpc_message_count(&counter, &body);
    record_complete_grpc_message_count(&counter, &body); // retry re-observe
    assert_eq!(counter.load(Ordering::Relaxed), 2);

    // Hostile declared length must not count or panic.
    let hostile = [0, 0xff, 0xff, 0xff, 0xff, 1];
    assert_eq!(count_grpc_length_prefixed_messages(&hostile), 0);
    record_complete_grpc_message_count(&counter, &hostile);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn tcp_sent_bytes_tag_override_and_disable_are_honored() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": {
            "disabled_metrics": ["TCP_OPENED_CONNECTIONS"],
            "tag_overrides": [{
                "metric": "TCP_SENT_BYTES",
                "name": "source_workload",
                "operation": {"type": "set", "value": "edge"}
            }, {
                "metric": "TCP_SENT_BYTES",
                "name": "response_code",
                "operation": {"type": "set", "value": "synthetic"}
            }]
        }
    }))
    .expect("plugin");
    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut metadata = ctx.metadata.clone();
    metadata.insert(
        ferrum_edge::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
            .into(),
        "1".into(),
    );
    metadata.insert(
        ferrum_edge::plugins::mesh::prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA
            .into(),
        "1".into(),
    );
    metadata.insert("mesh.request_protocol".into(), "tcp".into());
    // Ensure identity labels exist for key construction.
    metadata
        .entry("mesh.source.workload".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.source.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/frontend".into());
    metadata
        .entry("mesh.source.app".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.source.service".into())
        .or_insert_with(|| "frontend".into());
    metadata
        .entry("mesh.destination.workload".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.destination.namespace".into())
        .or_insert_with(|| "default".into());
    metadata
        .entry("mesh.destination.principal".into())
        .or_insert_with(|| "spiffe://cluster.local/ns/default/sa/db".into());
    metadata
        .entry("mesh.destination.app".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.destination.service".into())
        .or_insert_with(|| "db".into());
    metadata
        .entry("mesh.response_flags".into())
        .or_insert_with(|| "-".into());
    metadata
        .entry("mesh.connection_security_policy".into())
        .or_insert_with(|| "mutual_tls".into());

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(&mut metadata, "db", Some("db"));
    assert!(
        !registry
            .render_uncached()
            .contains("ferrum_mesh_tcp_connections_opened_total{"),
        "disabled TCP_OPENED_CONNECTIONS must not record"
    );

    let summary = StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "default".into(),
        proxy_id: "db".into(),
        proxy_name: Some("db".into()),
        client_ip: "10.0.0.1".into(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.9:5432".into(),
        backend_resolved_ip: None,
        protocol: "tcp".into(),
        listen_port: 15001,
        duration_ms: 10.0,
        bytes_sent: 42,
        bytes_received: 7,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata,
        proxy_lifecycle_generation: None,
    };
    registry.record_stream(&summary);
    let output = registry.render_uncached();
    assert!(
        output
            .lines()
            .any(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{")
                && line.contains("source_workload=\"edge\"")
                && line.ends_with(" 7")),
        "override-scoped TCP_SENT_BYTES must keep the response-byte value 7:\n{output}"
    );
    assert!(
        output
            .lines()
            .filter(|line| line.starts_with("ferrum_mesh_tcp_sent_bytes_total{"))
            .all(|line| !line.contains("response_code=")),
        "TCP families must not gain an HTTP response_code dimension:\n{output}"
    );
}

// ---------------------------------------------------------------------------
// Mesh TCP opened/closed lifecycle is owned by the STREAM PATH finalizer, not
// by the `workload_metrics` hook. Ferrum permits several effective
// `workload_metrics` instances per proxy, and every one of them runs
// `on_stream_connect` over metadata that later instances still change, so an
// increment from the hook counted one connection once per instance under
// intermediate policy. The stream path instead calls `finalize_mesh_tcp_opened`
// once after the last hook that actually ran (accepted, rejected, or
// client-disconnect-during-admission), and that call stamps the finalized
// marker gating the closed/byte half. This is a connection lifecycle family,
// not an authorization-success counter.
// ---------------------------------------------------------------------------

const FINALIZED_MARKER: &str =
    ferrum_edge::plugins::mesh::prometheus_helpers::MESH_TCP_OPENED_FINALIZED_METADATA;
const PROMETHEUS_OBSERVED_MARKER: &str =
    ferrum_edge::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA;
const OBSERVED_MARKER: &str =
    ferrum_edge::plugins::mesh::prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA;

fn mesh_stream_ctx() -> StreamConnectionContext {
    StreamConnectionContext::new(
        "10.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "db".to_string(),
        Some("db".to_string()),
        5432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    )
}

fn workload_metrics_instance(metrics: serde_json::Value) -> WorkloadMetrics {
    WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": metrics,
    }))
    .expect("workload_metrics instance")
}

async fn observe_prometheus_stream(ctx: &mut StreamConnectionContext) {
    let prometheus = PrometheusMetrics::new(&serde_json::Value::Null, "default")
        .expect("prometheus_metrics instance");
    assert!(matches!(
        prometheus.on_stream_connect(ctx).await,
        PluginResult::Continue
    ));
}

fn stream_summary_from(metadata: HashMap<String, String>) -> StreamTransactionSummary {
    StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "default".into(),
        proxy_id: "db".into(),
        proxy_name: Some("db".into()),
        client_ip: "10.0.0.1".into(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.9:5432".into(),
        backend_resolved_ip: None,
        protocol: "tcp".into(),
        listen_port: 15001,
        duration_ms: 25.0,
        bytes_sent: 300,
        bytes_received: 500,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-08-05T00:00:00Z".into(),
        timestamp_disconnected: "2026-08-05T00:00:01Z".into(),
        sni_hostname: None,
        metadata,
        proxy_lifecycle_generation: None,
    }
}

fn series_lines<'a>(output: &'a str, family: &str) -> Vec<&'a str> {
    let prefix = format!("{family}{{");
    output
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect()
}

fn label_value<'a>(series_line: &'a str, label: &str) -> Option<&'a str> {
    let needle = format!("{label}=\"");
    let start = series_line.find(&needle)? + needle.len();
    let end = series_line[start..].find('"')? + start;
    Some(&series_line[start..end])
}

#[tokio::test]
async fn multiple_workload_metrics_applications_record_one_tcp_opened_under_final_policy() {
    // Two effective instances both stamp the connection. The second one owns
    // the final TCP_OPENED_CONNECTIONS tag policy.
    let first = workload_metrics_instance(json!({}));
    let second = workload_metrics_instance(json!({
        "tag_overrides": [{
            "metric": "TCP_OPENED_CONNECTIONS",
            "name": "source_workload",
            "operation": {"type": "set", "value": "edge"}
        }]
    }));

    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    assert!(matches!(
        first.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(
        ctx.metadata.as_mut().expect("mesh stream metadata"),
        "db",
        Some("db"),
    );

    let after_open = registry.render_uncached();
    let opened = series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(
        opened.len(),
        1,
        "two effective workload_metrics instances must not open two series:\n{after_open}"
    );
    assert!(
        opened[0].ends_with(" 1"),
        "one connection must be one opened increment:\n{after_open}"
    );
    assert!(
        opened[0].contains("source_workload=\"edge\""),
        "opened must carry the FINAL instance's tag policy:\n{after_open}"
    );
    assert!(
        !opened[0].contains("response_code="),
        "Istio TCP series carry no response_code:\n{after_open}"
    );

    // The disconnect half stays balanced: one open, one close.
    let metadata = ctx.metadata.clone().expect("mesh stream metadata");
    registry.record_stream(&stream_summary_from(metadata));
    let after_close = registry.render_uncached();
    assert_eq!(
        series_lines(&after_close, "ferrum_mesh_tcp_connections_opened_total").len(),
        1,
        "disconnect must not add an opened series:\n{after_close}"
    );
    let closed = series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total");
    assert_eq!(closed.len(), 1, "one close expected:\n{after_close}");
    assert!(
        closed[0].ends_with(" 1"),
        "open/close lifecycle must stay balanced:\n{after_close}"
    );
}

#[tokio::test]
async fn disabled_final_tcp_opened_policy_records_no_opened_but_keeps_closed() {
    let plugin = workload_metrics_instance(json!({
        "disabled_metrics": ["TCP_OPENED_CONNECTIONS"]
    }));
    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(
        ctx.metadata.as_mut().expect("mesh stream metadata"),
        "db",
        Some("db"),
    );
    let after_open = registry.render_uncached();
    assert!(
        series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total").is_empty(),
        "a disabled final TCP_OPENED_CONNECTIONS policy must record nothing:\n{after_open}"
    );

    // Disabling opened is per-family: the connection was still finalized, so the
    // closed/byte families keep reporting.
    let metadata = ctx.metadata.clone().expect("mesh stream metadata");
    registry.record_stream(&stream_summary_from(metadata));
    let after_close = registry.render_uncached();
    assert_eq!(
        series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total").len(),
        1,
        "disabling opened must not suppress closed:\n{after_close}"
    );
}

#[tokio::test]
async fn rejected_stream_chain_finalizes_balanced_tcp_lifecycle() {
    // `workload_metrics` ran and stamped mesh identity metadata; a later plugin
    // rejected the stream. The stream path still finalizes once after the last
    // hook that ran, before the zero-byte disconnect summary, so opened/closed
    // stay balanced. TCP_OPENED_CONNECTIONS is a lifecycle family, not an
    // authorization-success counter.
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));

    let after_open = registry.render_uncached();
    let opened = series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(
        opened.len(),
        1,
        "rejection after workload-metrics observation must still open once:\n{after_open}"
    );
    assert!(
        opened[0].ends_with(" 1"),
        "rejected path must count exactly one opened:\n{after_open}"
    );

    let mut summary = stream_summary_from(metadata.clone());
    summary.bytes_sent = 0;
    summary.bytes_received = 0;
    registry.record_stream(&summary);

    let after_close = registry.render_uncached();
    let closed = series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total");
    assert_eq!(
        closed.len(),
        1,
        "rejected path must close once under the same lifecycle:\n{after_close}"
    );
    assert!(
        closed[0].ends_with(" 1"),
        "rejected open/close must stay balanced:\n{after_close}"
    );
    let sent = series_lines(&after_close, "ferrum_mesh_tcp_sent_bytes_total");
    let received = series_lines(&after_close, "ferrum_mesh_tcp_received_bytes_total");
    assert!(
        sent.iter().any(|line| line.ends_with(" 0"))
            && received.iter().any(|line| line.ends_with(" 0")),
        "rejected disconnect is a zero-byte close:\n{after_close}"
    );
}

#[tokio::test]
async fn mesh_tcp_finalize_is_idempotent_per_connection() {
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));

    let output = registry.render_uncached();
    let opened = series_lines(&output, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(opened.len(), 1, "one series expected:\n{output}");
    assert!(
        opened[0].ends_with(" 1"),
        "a second finalize call must not double count one connection:\n{output}"
    );
    assert!(
        metadata.get(FINALIZED_MARKER).map(String::as_str) == Some("1"),
        "finalizer must stamp the once-only marker"
    );
}

#[tokio::test]
async fn mesh_tcp_finalize_requires_prometheus_and_workload_metrics_observation() {
    let registry = MetricsRegistry::new();
    let mut metadata = HashMap::from([
        ("mesh.request_protocol".to_string(), "tcp".to_string()),
        ("mesh.destination.service".to_string(), "db".to_string()),
    ]);

    registry.finalize_mesh_tcp_opened(&mut metadata, "db", Some("db"));

    assert!(
        !metadata.contains_key(FINALIZED_MARKER),
        "pre-populated mesh routing metadata must not impersonate workload-metrics observation"
    );
    assert!(
        !metadata.contains_key(OBSERVED_MARKER),
        "the finalizer must never forge the plugin observation marker"
    );
    assert!(
        !registry
            .render_uncached()
            .contains("ferrum_mesh_tcp_connections_opened_total{"),
        "a stream rejected before workload_metrics ran must not emit its metric family"
    );

    let workload_metrics = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    workload_metrics.on_stream_connect(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));
    assert!(
        !metadata.contains_key(FINALIZED_MARKER),
        "workload_metrics alone must stay silent when prometheus_metrics is not configured"
    );
    assert!(
        !metadata.contains_key(PROMETHEUS_OBSERVED_MARKER),
        "the finalizer must never forge prometheus_metrics observation"
    );

    observe_prometheus_stream(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));
    assert_eq!(
        metadata.get(FINALIZED_MARKER).map(String::as_str),
        Some("1"),
        "both plugin observations must enable exactly-once lifecycle finalization"
    );
}

#[tokio::test]
async fn captured_egress_tcp_opened_closed_share_destination_principal() {
    // Captured mesh egress stamps destination/security metadata first, then
    // `set_target` inserts `mesh.destination.principal`. Finalizing only after
    // that insertion keeps opened and closed on the same label set.
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    metadata.insert(
        "mesh.connection_security_policy".into(),
        "mutual_tls".into(),
    );
    metadata.insert("mesh.destination.namespace".into(), "default".into());
    metadata.insert("mesh.destination.workload".into(), "db".into());
    metadata.insert("mesh.destination.app".into(), "db".into());
    metadata.insert("mesh.destination.service".into(), "db".into());
    metadata.insert(
        "mesh.destination.principal".into(),
        "spiffe://cluster.local/ns/default/sa/db".into(),
    );

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));
    let after_open = registry.render_uncached();
    let opened = series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(opened.len(), 1, "one opened series:\n{after_open}");
    assert_eq!(
        label_value(opened[0], "destination_principal"),
        Some("spiffe://cluster.local/ns/default/sa/db"),
        "opened must carry destination principal:\n{after_open}"
    );

    registry.record_stream(&stream_summary_from(metadata.clone()));
    let after_close = registry.render_uncached();
    let closed = series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total");
    assert_eq!(closed.len(), 1, "one closed series:\n{after_close}");
    assert_eq!(
        label_value(closed[0], "destination_principal"),
        Some("spiffe://cluster.local/ns/default/sa/db"),
        "closed must reuse the same destination principal:\n{after_close}"
    );
    let sent = series_lines(&after_close, "ferrum_mesh_tcp_sent_bytes_total");
    assert_eq!(
        label_value(sent[0], "destination_principal"),
        Some("spiffe://cluster.local/ns/default/sa/db"),
        "byte series must share the opened label set:\n{after_close}"
    );
}

#[tokio::test]
async fn captured_egress_no_target_setup_failure_finalizes_balanced_lifecycle() {
    // Setup failed before target selection: finalize under the destination
    // metadata available at teardown (no destination principal).
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = mesh_stream_ctx();
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    metadata.insert(
        "mesh.connection_security_policy".into(),
        "mutual_tls".into(),
    );
    metadata.insert("mesh.destination.service".into(), "db".into());
    // Explicitly clear any destination principal so teardown mirrors a
    // no-target captured egress path.
    metadata.remove("mesh.destination.principal");

    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(metadata, "db", Some("db"));
    let after_open = registry.render_uncached();
    let opened = series_lines(&after_open, "ferrum_mesh_tcp_connections_opened_total");
    assert_eq!(
        opened.len(),
        1,
        "no-target setup failure must still open once:\n{after_open}"
    );
    assert_eq!(
        label_value(opened[0], "destination_principal"),
        Some("unknown"),
        "no-target path must keep the default unknown principal:\n{after_open}"
    );

    let mut summary = stream_summary_from(metadata.clone());
    summary.bytes_sent = 0;
    summary.bytes_received = 0;
    summary.connection_error = Some("captured mesh egress setup failed".into());
    registry.record_stream(&summary);
    let after_close = registry.render_uncached();
    let closed = series_lines(&after_close, "ferrum_mesh_tcp_connections_closed_total");
    assert_eq!(
        closed.len(),
        1,
        "no-target teardown must close once:\n{after_close}"
    );
    assert!(
        closed[0].ends_with(" 1"),
        "no-target open/close must stay balanced:\n{after_close}"
    );
    assert_eq!(
        label_value(closed[0], "destination_principal"),
        Some("unknown"),
        "closed must match the no-principal opened label set:\n{after_close}"
    );
}

#[tokio::test]
async fn udp_stream_finalize_records_no_tcp_series() {
    // UDP/DTLS must never be misclassified as a mesh TCP connection.
    let plugin = workload_metrics_instance(json!({}));
    let mut ctx = StreamConnectionContext::new(
        "10.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "dns".to_string(),
        Some("dns".to_string()),
        53,
        BackendScheme::Udp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    observe_prometheus_stream(&mut ctx).await;
    plugin.on_stream_connect(&mut ctx).await;

    let registry = MetricsRegistry::new();
    let metadata = ctx.metadata.as_mut().expect("mesh stream metadata");
    registry.finalize_mesh_tcp_opened(metadata, "dns", Some("dns"));
    assert!(
        !metadata.contains_key(FINALIZED_MARKER),
        "a UDP stream must not be stamped as a finalized mesh TCP connection"
    );

    let mut summary = stream_summary_from(ctx.metadata.clone().expect("metadata"));
    summary.protocol = "udp".into();
    registry.record_stream(&summary);

    let output = registry.render_uncached();
    for family in [
        "ferrum_mesh_tcp_connections_opened_total",
        "ferrum_mesh_tcp_connections_closed_total",
        "ferrum_mesh_tcp_sent_bytes_total",
        "ferrum_mesh_tcp_received_bytes_total",
    ] {
        assert!(
            series_lines(&output, family).is_empty(),
            "UDP must not populate {family}:\n{output}"
        );
    }
}

#[test]
fn rendered_effective_metric_plan_budget_withholds_proxy_identity_and_values() {
    use super::plugin_utils::{make_plugin_config_with_json, make_proxy};
    use ferrum_edge::config::types::{GatewayConfig, PluginScope};

    let proxy_id = "'MESH_DIAG_PROXY\"\\`";
    let plugin_configs = [("count", "REQUEST_COUNT"), ("duration", "REQUEST_DURATION")]
        .into_iter()
        .map(|(id, metric)| {
            // Each instance fits the existing per-instance limit; together the
            // surviving families exceed the effective-chain admission budget.
            let overrides: Vec<_> = (0..62)
                .map(|_| {
                    json!({
                        "metric": metric,
                        "name": "source_workload",
                        "operation": {"type": "set", "value": "MESH_DIAG_VALUE".repeat(17)}
                    })
                })
                .collect();
            make_plugin_config_with_json(
                id,
                "workload_metrics",
                json!({"metrics": {"tag_overrides": overrides}}),
                PluginScope::Proxy,
                Some(proxy_id),
            )
        })
        .collect();
    let config = GatewayConfig {
        proxies: vec![make_proxy(proxy_id, "/api", vec!["count", "duration"])],
        plugin_configs,
        ..Default::default()
    };
    let error = ferrum_edge::PluginCache::new(&config)
        .err()
        .expect("composed metric families must still exceed the budget");
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    assert!(
        rendered.contains("proxy_id=<redacted scalar>"),
        "{rendered}"
    );
    assert!(
        rendered.contains("exceed 16384 encoded bytes across surviving families"),
        "{rendered}"
    );
    assert!(!rendered.contains("MESH_DIAG_"), "{rendered}");
}

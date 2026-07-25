//! Tests for prometheus_metrics plugin

use ferrum_edge::ebpf::NodeAgentMetrics;
use ferrum_edge::plugins::mesh::prometheus_helpers;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::{
    CounterKey, HboneRelayFailureKey, MeshTcpEgressConnKey, MetricsRegistry, PrometheusMetrics,
    global_registry,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, AiCost, AiUsageExport, Direction, Plugin, RequestContext,
    StreamTransactionSummary, TransactionSummary, WsDisconnectContext,
    ai_token_metrics::AiTokenMetrics,
};
use ferrum_edge::proxy::tcp_proxy::StreamIoSide;
use ferrum_edge::retry::ErrorClass;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn make_summary(
    proxy_id: &str,
    method: &str,
    status: u16,
    total_ms: f64,
    backend_ms: f64,
) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: method.to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some("Test".to_string()),
        backend_target: Some("http://localhost:3000".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: 5.0,
        latency_backend_ttfb_ms: total_ms - 5.0,
        latency_backend_total_ms: backend_ms,
        latency_plugin_execution_ms: 2.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 3.0,
        request_user_agent: Some("test-agent".to_string()),
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

fn make_stream_summary(proxy_id: &str, protocol: &str) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("Stream Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: protocol.to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

fn make_ws_summary(proxy_id: &str) -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("WebSocket Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend.test/socket".to_string(),
        listen_port: 8080,
        duration_ms: 125.0,
        frames_client_to_backend: 3,
        frames_backend_to_client: 5,
        bytes_client_to_backend: 30,
        bytes_backend_to_client: 50,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_prometheus_plugin_creation() {
    let config = json!({});
    let plugin = PrometheusMetrics::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "prometheus_metrics");
    assert_eq!(plugin.priority(), 9300);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(plugin.requires_ws_disconnect_hooks());
}

#[tokio::test]
async fn test_prometheus_plugin_rejects_invalid_config_shapes() {
    let cases = [
        json!("bad"),
        json!({"render_cache_ttl_seconds": "5"}),
        json!({"stale_entry_ttl_seconds": -1}),
        json!({"cache_invalidation_min_age_ms": true}),
    ];

    for config in cases {
        assert!(
            PrometheusMetrics::new(&config, "ferrum").is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_prometheus_plugin_accepts_null_config_as_defaults() {
    let plugin = PrometheusMetrics::new(&serde_json::Value::Null, "ferrum")
        .expect("null config should use defaults");
    assert_eq!(plugin.name(), "prometheus_metrics");
    assert_eq!(plugin.priority(), 9300);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_registry_records_request_counter() {
    let registry = MetricsRegistry::new();
    let summary = make_summary("proxy-1", "GET", 200, 50.0, 40.0);

    registry.record(&summary);

    let key = CounterKey {
        proxy_id: Arc::from("proxy-1"),
        method: "GET",
        status_code: 200,
        grpc_status: None,
    };
    assert!(registry.request_counter.contains_key(&key));
    let count = registry.request_counter.get(&key).unwrap();
    assert_eq!(count.value.load(Ordering::Relaxed), 1);
}

#[test]
fn test_registry_bounds_hostile_http_methods_to_other() {
    let registry = MetricsRegistry::new();
    for index in 0..100 {
        let method = format!("X-HOSTILE-{index}-{}", "x".repeat(2048));
        registry.record(&make_summary("method-bounded", &method, 200, 1.0, 1.0));
    }

    let key = CounterKey {
        proxy_id: Arc::from("method-bounded"),
        method: "OTHER",
        status_code: 200,
        grpc_status: None,
    };
    assert_eq!(registry.request_counter.len(), 1);
    assert_eq!(
        registry
            .request_counter
            .get(&key)
            .expect("all extension methods share one bounded series")
            .value
            .load(Ordering::Relaxed),
        100
    );
    let output = registry.render_uncached();
    assert!(output.contains("method=\"OTHER\""));
    assert!(!output.contains("X-HOSTILE"));
}

#[test]
fn test_registry_distinguishes_bounded_grpc_terminal_statuses() {
    let registry = MetricsRegistry::new();
    for status in ["0", "14", "99", "malformed"] {
        let mut summary = make_summary("grpc-status", "POST", 200, 1.0, 1.0);
        summary
            .metadata
            .insert("grpc_status".to_string(), status.to_string());
        registry.record(&summary);
    }

    let output = registry.render_uncached();
    assert!(
        output
            .contains(r#"proxy_id="grpc-status",method="POST",status_code="200",grpc_status="0""#)
    );
    assert!(
        output
            .contains(r#"proxy_id="grpc-status",method="POST",status_code="200",grpc_status="14""#)
    );
    let other_key = CounterKey {
        proxy_id: Arc::from("grpc-status"),
        method: "POST",
        status_code: 200,
        grpc_status: Some("OTHER"),
    };
    assert_eq!(
        registry
            .request_counter
            .get(&other_key)
            .expect("non-standard and malformed status values share OTHER")
            .value
            .load(Ordering::Relaxed),
        2
    );
}

#[test]
fn test_registry_records_websocket_completion_metrics() {
    let registry = MetricsRegistry::new();
    registry.record_ws_session(&make_ws_summary("ws-metrics"));

    let mut failed = make_ws_summary("ws-metrics");
    failed.duration_ms = 250.0;
    failed.direction = Some(Direction::BackendToClient);
    failed.io_side = Some(StreamIoSide::Read);
    failed.error_class = Some(ErrorClass::ConnectionReset);
    registry.record_ws_session(&failed);

    let output = registry.render_uncached();
    assert!(output.contains(
        r#"ferrum_websocket_sessions_total{proxy_id="ws-metrics",result="success",direction="unknown",io_side="unknown",error_class="none"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_websocket_sessions_total{proxy_id="ws-metrics",result="error",direction="backend_to_client",io_side="read",error_class="connection_reset"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_websocket_bytes_total{proxy_id="ws-metrics",direction="client_to_backend"} 60"#
    ));
    assert!(output.contains(
        r#"ferrum_websocket_frames_total{proxy_id="ws-metrics",direction="backend_to_client"} 10"#
    ));
    assert!(output.contains(
        r#"ferrum_websocket_session_duration_ms_count{proxy_id="ws-metrics",result="error",direction="backend_to_client",io_side="read",error_class="connection_reset"} 1"#
    ));
}

#[tokio::test]
async fn test_registry_ignores_mirror_summary() {
    let registry = MetricsRegistry::new();
    let mut summary = make_summary("proxy-1", "GET", 503, 777.0, 777.0);
    summary.mirror = true;

    registry.record(&summary);

    let key = CounterKey {
        proxy_id: Arc::from("proxy-1"),
        method: "GET",
        status_code: 503,
        grpc_status: None,
    };
    assert!(!registry.request_counter.contains_key(&key));
    assert!(registry.request_duration_buckets.is_empty());
    assert!(registry.backend_duration_buckets.is_empty());
    assert!(registry.gateway_overhead_buckets.is_empty());
}

#[tokio::test]
async fn test_registry_renders_mesh_red_metrics_when_metadata_present() {
    let registry = MetricsRegistry::new();
    let mut summary = make_summary("payments-proxy", "GET", 200, 42.0, 35.0);
    summary.metadata = HashMap::from([
        ("mesh.source.workload".to_string(), "frontend".to_string()),
        ("mesh.source.namespace".to_string(), "default".to_string()),
        (
            "mesh.source.principal".to_string(),
            "spiffe://cluster.local/ns/default/sa/frontend".to_string(),
        ),
        ("mesh.source.app".to_string(), "frontend".to_string()),
        ("mesh.source.service".to_string(), "frontend".to_string()),
        (
            "mesh.destination.workload".to_string(),
            "payments".to_string(),
        ),
        (
            "mesh.destination.namespace".to_string(),
            "default".to_string(),
        ),
        (
            "mesh.destination.service".to_string(),
            "payments".to_string(),
        ),
        ("mesh.request_protocol".to_string(), "http".to_string()),
        (
            "mesh.connection_security_policy".to_string(),
            "mutual_tls".to_string(),
        ),
    ]);

    registry.record(&summary);
    let output = registry.render_uncached();

    assert!(output.contains("# TYPE ferrum_mesh_requests_total counter"));
    assert!(output.contains("ferrum_mesh_requests_total{"));
    assert!(output.contains("source_workload=\"frontend\""));
    assert!(output.contains("destination_service=\"payments\""));
    assert!(output.contains("connection_security_policy=\"mutual_tls\""));
    assert!(output.contains("# TYPE ferrum_mesh_request_duration_ms histogram"));
    assert!(output.contains("ferrum_mesh_request_duration_ms_bucket{"));
    assert!(output.contains("le=\"+Inf\""));
}

#[tokio::test]
async fn test_registry_renders_mesh_cert_telemetry_metrics() {
    let registry = MetricsRegistry::new();

    prometheus_helpers::record_mesh_cert_expiry_seconds(
        "spiffe://cluster.local/ns/default/sa/prom-test",
        "unit_test",
        3600,
    );
    prometheus_helpers::increment_mesh_cert_rotation_failure(
        "spiffe://cluster.local/ns/default/sa/prom-test",
        "unit_test",
    );
    prometheus_helpers::set_mesh_ca_health("unit_test_ca", true);
    prometheus_helpers::record_mesh_trust_bundle_roots(
        "cluster.local",
        "unit_test",
        &[vec![1, 2, 3]],
    );
    prometheus_helpers::record_mesh_config_received("unit-test-ns");
    prometheus_helpers::increment_mesh_mtls_handshake_failure("unit_test");

    let output = registry.render_uncached();

    assert!(output.contains("# TYPE ferrum_mesh_cert_expiry_seconds gauge"));
    assert!(output.contains("ferrum_mesh_cert_expiry_seconds{"));
    assert!(output.contains("spiffe://cluster.local/ns/default/sa/prom-test"));
    let expiry_line = output
        .lines()
        .find(|line| {
            line.contains("ferrum_mesh_cert_expiry_seconds{")
                && line.contains("spiffe://cluster.local/ns/default/sa/prom-test")
                && line.contains("source=\"unit_test\"")
        })
        .expect("mesh cert expiry metric line");
    let expiry_seconds = expiry_line
        .rsplit_once(' ')
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .expect("expiry seconds value");
    assert!(expiry_seconds <= 3600);
    assert!(expiry_seconds > 3500);
    assert!(output.contains("# TYPE ferrum_mesh_cert_rotation_failures_total counter"));
    assert!(output.contains("ferrum_mesh_cert_rotation_failures_total{"));
    assert!(output.contains("# TYPE ferrum_mesh_ca_health gauge"));
    assert!(output.contains("ferrum_mesh_ca_health{ca_type=\"unit_test_ca\"} 1"));
    assert!(output.contains("# TYPE ferrum_mesh_trust_bundle_version gauge"));
    assert!(output.contains(
        "ferrum_mesh_trust_bundle_version{trust_domain=\"cluster.local\",source=\"unit_test\"} 1"
    ));
    assert!(output.contains("# TYPE ferrum_mesh_config_last_received_timestamp_seconds gauge"));
    assert!(output.contains(
        "ferrum_mesh_config_last_received_timestamp_seconds{namespace=\"unit-test-ns\"}"
    ));
    assert!(output.contains("# TYPE ferrum_mesh_mtls_handshake_failures_total counter"));
    assert!(output.contains("ferrum_mesh_mtls_handshake_failures_total{reason=\"unit_test\"} 1"));
}

#[tokio::test]
async fn test_registry_renders_mesh_inbound_plaintext_allowed_gauge() {
    let registry = MetricsRegistry::new();

    // Dev opt-out posture: the inbound listener was allowed up without
    // enforced mTLS. The gauge is a process-global static shared with other
    // parallel tests, so assert only on this gauge's line immediately after
    // setting it in the same test (no other test writes this static).
    prometheus_helpers::set_mesh_inbound_plaintext_allowed(true);
    let output = registry.render_uncached();
    assert!(output.contains("# TYPE ferrum_mesh_inbound_plaintext_allowed gauge"));
    assert!(output.contains("ferrum_mesh_inbound_plaintext_allowed 1"));
    // Coarse by design: no labels on the series (the downgrade reason stays
    // in the enforcement-site logs).
    assert!(!output.contains("ferrum_mesh_inbound_plaintext_allowed{"));

    // A startup or PeerAuthentication live reload that resolves an
    // mTLS-capable inbound config heals the posture back to 0.
    prometheus_helpers::set_mesh_inbound_plaintext_allowed(false);
    let output = registry.render_uncached();
    assert!(output.contains("ferrum_mesh_inbound_plaintext_allowed 0"));
}

#[tokio::test]
async fn test_registry_renders_node_agent_metrics_when_registered() {
    let registry = MetricsRegistry::new();
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.pods_enrolled.fetch_add(3, Ordering::Relaxed);
    metrics.pods_unenrolled.fetch_add(1, Ordering::Relaxed);
    metrics.attach_errors.fetch_add(2, Ordering::Relaxed);
    // T4-B mid-life annotation update counters: distinct values so a
    // regression that swaps applied/failed would be visible in test
    // output. Render needs to include both irrespective of node-agent
    // mode being active in this unit test (the registry treats them as
    // ordinary node-agent counters).
    metrics
        .pod_annotation_updates_applied
        .fetch_add(7, Ordering::Relaxed);
    metrics
        .pod_annotation_updates_failed
        .fetch_add(4, Ordering::Relaxed);
    metrics.record_cni_socket_lifecycle(
        ferrum_edge::ebpf::CniSocketLifecycleReason::OwnershipConflict,
    );
    metrics
        .record_cni_socket_lifecycle(ferrum_edge::ebpf::CniSocketLifecycleReason::OwnershipIoError);

    registry.set_node_agent_metrics(metrics);
    let output = registry.render_uncached();

    assert!(output.contains("# TYPE ferrum_node_agent_pods_enrolled_total counter"));
    assert!(output.contains("ferrum_node_agent_pods_enrolled_total 3"));
    assert!(output.contains("ferrum_node_agent_pods_unenrolled_total 1"));
    assert!(output.contains("ferrum_node_agent_attach_errors_total 2"));
    assert!(
        output.contains("# TYPE ferrum_node_agent_pod_annotation_updates_applied_total counter")
    );
    assert!(output.contains("ferrum_node_agent_pod_annotation_updates_applied_total 7"));
    assert!(
        output.contains("# TYPE ferrum_node_agent_pod_annotation_updates_failed_total counter")
    );
    assert!(output.contains("ferrum_node_agent_pod_annotation_updates_failed_total 4"));
    assert!(output.contains("# TYPE ferrum_node_agent_cni_socket_lifecycle_total counter"));
    assert!(
        output.contains(
            "ferrum_node_agent_cni_socket_lifecycle_total{reason=\"ownership_conflict\"} 1"
        )
    );
    assert!(
        output.contains(
            "ferrum_node_agent_cni_socket_lifecycle_total{reason=\"ownership_io_error\"} 1"
        )
    );
    assert!(output.contains(
        "ferrum_node_agent_cni_socket_lifecycle_total{reason=\"handoff_publication_error\"} 0"
    ));
    assert!(output.contains(
        "ferrum_node_agent_cni_socket_lifecycle_total{reason=\"shutdown_cleanup_error\"} 0"
    ));
    assert!(output.contains("# TYPE ferrum_node_agent_capture_state gauge"));
    assert!(output.contains("ferrum_node_agent_capture_state{state=\"starting\"} 1"));
    assert!(output.contains("ferrum_node_agent_capture_state{state=\"ready\"} 0"));
    // Nominal topology: gauge emitted as 0 with reason=none so dashboards
    // can always pin the expected value.
    assert!(output.contains("# TYPE ferrum_mesh_node_topology_degraded gauge"));
    assert!(output.contains("ferrum_mesh_node_topology_degraded{reason=\"none\"} 0"));
}

#[tokio::test]
async fn test_registry_renders_node_agent_capture_state_condition() {
    let registry = MetricsRegistry::new();
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.set_capture_state(ferrum_edge::ebpf::NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED);

    registry.set_node_agent_metrics(metrics);
    let output = registry.render_uncached();

    assert!(output.contains("ferrum_node_agent_capture_state{state=\"partially_attached\"} 1"));
    assert!(output.contains("ferrum_node_agent_capture_state{state=\"ready\"} 0"));
    assert!(output.contains("ferrum_node_agent_capture_state{state=\"unavailable\"} 0"));
}

#[tokio::test]
async fn test_registry_renders_node_agent_capture_state_with_namespace_label() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "ambient-system");
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.set_capture_state(ferrum_edge::ebpf::NODE_AGENT_CAPTURE_STATE_READY);

    registry.set_node_agent_metrics(metrics);
    let output = registry.render_uncached();

    assert!(output.contains(
        "ferrum_node_agent_capture_state{state=\"ready\",namespace=\"ambient-system\"} 1"
    ));
    assert!(output.contains(
        "ferrum_node_agent_capture_state{state=\"starting\",namespace=\"ambient-system\"} 0"
    ));
}

#[tokio::test]
async fn test_registry_renders_topology_degraded_gauge_with_reason() {
    let registry = MetricsRegistry::new();
    let metrics = Arc::new(NodeAgentMetrics::default());
    metrics.set_topology_degraded("kernel_too_old");

    registry.set_node_agent_metrics(metrics);
    let output = registry.render_uncached();

    assert!(output.contains("# TYPE ferrum_mesh_node_topology_degraded gauge"));
    assert!(output.contains("ferrum_mesh_node_topology_degraded{reason=\"kernel_too_old\"} 1"));
    // The nominal series must NOT appear when degraded — operators alert
    // on the single emitted series.
    assert!(!output.contains("ferrum_mesh_node_topology_degraded{reason=\"none\"}"));
}

#[tokio::test]
async fn test_registry_omits_topology_degraded_gauge_without_node_agent_metrics() {
    // Non-node-agent processes (database/file/cp/dp/mesh) never register a
    // NodeAgentMetrics handle. The gauge must not appear in their /metrics —
    // it would be a misleading "I am a node agent" signal.
    let registry = MetricsRegistry::new();
    let output = registry.render_uncached();
    assert!(!output.contains("ferrum_mesh_node_topology_degraded"));
}

#[tokio::test]
async fn test_registry_increments_counter_on_repeated_requests() {
    let registry = MetricsRegistry::new();

    for _ in 0..5 {
        let summary = make_summary("proxy-1", "POST", 201, 30.0, 25.0);
        registry.record(&summary);
    }

    let key = CounterKey {
        proxy_id: Arc::from("proxy-1"),
        method: "POST",
        status_code: 201,
        grpc_status: None,
    };
    let count = registry.request_counter.get(&key).unwrap();
    assert_eq!(count.value.load(Ordering::Relaxed), 5);
}

#[tokio::test]
async fn test_registry_renders_mesh_tcp_egress_connection_counter() {
    let registry = MetricsRegistry::new();
    // Two successful HBONE (Ambient) relays, one failed mesh-mTLS (Sidecar) relay.
    registry.record_mesh_tcp_egress_connection("hbone", true);
    registry.record_mesh_tcp_egress_connection("hbone", true);
    registry.record_mesh_tcp_egress_connection("mtls", false);

    let output = registry.render();
    assert!(
        output.contains(
            "ferrum_mesh_tcp_egress_connections_total{transport=\"hbone\",result=\"success\""
        ),
        "hbone success series must render: {output}"
    );
    assert!(
        output.contains(
            "ferrum_mesh_tcp_egress_connections_total{transport=\"mtls\",result=\"failure\""
        ),
        "mtls failure series must render: {output}"
    );

    // The two successful HBONE relays accumulate on one labelled series.
    let key = MeshTcpEgressConnKey {
        transport: "hbone",
        result: "success",
    };
    assert_eq!(
        registry
            .mesh_tcp_egress_connection_counter
            .get(&key)
            .unwrap()
            .value
            .load(Ordering::Relaxed),
        2
    );
}

#[tokio::test]
async fn test_registry_separate_counters_per_proxy_method_status() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("proxy-a", "GET", 200, 10.0, 8.0));
    registry.record(&make_summary("proxy-a", "POST", 200, 10.0, 8.0));
    registry.record(&make_summary("proxy-b", "GET", 200, 10.0, 8.0));
    registry.record(&make_summary("proxy-a", "GET", 500, 10.0, 8.0));

    assert_eq!(
        registry
            .request_counter
            .get(&CounterKey {
                proxy_id: Arc::from("proxy-a"),
                method: "GET",
                status_code: 200,
                grpc_status: None,
            })
            .unwrap()
            .value
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get(&CounterKey {
                proxy_id: Arc::from("proxy-a"),
                method: "POST",
                status_code: 200,
                grpc_status: None,
            })
            .unwrap()
            .value
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get(&CounterKey {
                proxy_id: Arc::from("proxy-b"),
                method: "GET",
                status_code: 200,
                grpc_status: None,
            })
            .unwrap()
            .value
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get(&CounterKey {
                proxy_id: Arc::from("proxy-a"),
                method: "GET",
                status_code: 500,
                grpc_status: None,
            })
            .unwrap()
            .value
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_registry_request_duration_histogram() {
    let registry = MetricsRegistry::new();

    // Record a 50ms request — should fall in the <=50 bucket
    registry.record(&make_summary("proxy-hist", "GET", 200, 50.0, 40.0));

    let hist = registry
        .request_duration_buckets
        .get(&Arc::from("proxy-hist") as &Arc<str>)
        .unwrap();
    assert_eq!(hist.count.load(Ordering::Relaxed), 1);

    let sum_bits = hist.sum.load(Ordering::Relaxed);
    let sum = f64::from_bits(sum_bits);
    assert!((sum - 50.0).abs() < 0.001);

    // Bucket boundaries: 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000
    // 50ms should increment buckets for le=50 (idx 3) through le=10000 (idx 10)
    assert_eq!(hist.counts[0].load(Ordering::Relaxed), 0); // le=5
    assert_eq!(hist.counts[1].load(Ordering::Relaxed), 0); // le=10
    assert_eq!(hist.counts[2].load(Ordering::Relaxed), 0); // le=25
    assert_eq!(hist.counts[3].load(Ordering::Relaxed), 1); // le=50
    assert_eq!(hist.counts[4].load(Ordering::Relaxed), 1); // le=100
    assert_eq!(hist.counts[10].load(Ordering::Relaxed), 1); // le=10000
}

#[tokio::test]
async fn test_registry_backend_duration_skips_negative_sentinel() {
    let registry = MetricsRegistry::new();

    // Streaming response uses -1.0 sentinel for unknown backend total
    let summary = make_summary("proxy-stream", "GET", 200, 100.0, -1.0);
    registry.record(&summary);

    // Request duration should be recorded
    assert!(
        registry
            .request_duration_buckets
            .contains_key(&Arc::from("proxy-stream") as &Arc<str>)
    );
    // Backend duration should NOT be recorded
    assert!(
        !registry
            .backend_duration_buckets
            .contains_key(&Arc::from("proxy-stream") as &Arc<str>)
    );
}

#[tokio::test]
async fn test_registry_backend_duration_records_positive() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("proxy-be", "GET", 200, 100.0, 80.0));

    assert!(
        registry
            .backend_duration_buckets
            .contains_key(&Arc::from("proxy-be") as &Arc<str>)
    );
    let hist = registry
        .backend_duration_buckets
        .get(&Arc::from("proxy-be") as &Arc<str>)
        .unwrap();
    assert_eq!(hist.count.load(Ordering::Relaxed), 1);
    let sum = f64::from_bits(hist.sum.load(Ordering::Relaxed));
    assert!((sum - 80.0).abs() < 0.001);
}

#[tokio::test]
async fn test_registry_unknown_proxy_uses_default_key() {
    let registry = MetricsRegistry::new();

    let mut summary = make_summary("", "GET", 200, 10.0, 5.0);
    summary.proxy_id = None;
    registry.record(&summary);

    assert!(registry.request_counter.contains_key(&CounterKey {
        proxy_id: Arc::from("unknown"),
        method: "GET",
        status_code: 200,
        grpc_status: None,
    }));
}

#[tokio::test]
async fn test_registry_render_contains_expected_metrics() {
    let registry = MetricsRegistry::new();
    registry.record(&make_summary("render-test", "GET", 200, 42.0, 35.0));

    let output = registry.render_uncached();

    // Check HELP and TYPE lines
    assert!(output.contains("# HELP ferrum_requests_total"));
    assert!(output.contains("# TYPE ferrum_requests_total counter"));
    assert!(output.contains("# HELP ferrum_request_duration_ms"));
    assert!(output.contains("# TYPE ferrum_request_duration_ms histogram"));
    assert!(output.contains("# HELP ferrum_backend_duration_ms"));
    assert!(output.contains("# TYPE ferrum_backend_duration_ms histogram"));
    assert!(output.contains("# HELP ferrum_rate_limit_exceeded_total"));
    assert!(output.contains("# TYPE ferrum_rate_limit_exceeded_total counter"));
    assert!(output.contains("# HELP ferrum_compression_codec_admitted_total"));
    assert!(output.contains("# TYPE ferrum_compression_codec_admitted_total counter"));
    assert!(output.contains("# HELP ferrum_compression_codec_saturated_total"));
    assert!(output.contains("# TYPE ferrum_compression_codec_saturated_total counter"));
    assert!(output.contains("# HELP ferrum_compression_codec_join_failures_total"));
    assert!(output.contains("# TYPE ferrum_compression_codec_join_failures_total counter"));
    assert!(output.contains("# HELP ferrum_compression_codec_worker_failures_total"));
    assert!(output.contains("# TYPE ferrum_compression_codec_worker_failures_total counter"));

    // Check counter line
    assert!(output.contains(
        r#"ferrum_requests_total{proxy_id="render-test",method="GET",status_code="200"} 1"#
    ));

    // Check histogram has +Inf bucket
    assert!(
        output.contains(r#"ferrum_request_duration_ms_bucket{proxy_id="render-test",le="+Inf"} 1"#)
    );

    // Check rate limit counter
    assert!(output.contains("ferrum_rate_limit_exceeded_total 0"));
    // request_mirror lifecycle counters render at zero with no attacker-shaped labels.
    assert!(output.contains("# HELP ferrum_request_mirror_dispatched_total"));
    assert!(output.contains("# TYPE ferrum_request_mirror_dispatched_total counter"));
    assert!(output.contains("ferrum_request_mirror_dispatched_total 0"));
    assert!(output.contains("ferrum_request_mirror_completed_total 0"));
    assert!(output.contains("ferrum_request_mirror_request_timeouts_total 0"));
    assert!(output.contains("ferrum_request_mirror_request_failures_total 0"));
    assert!(output.contains("ferrum_request_mirror_drain_timeouts_total 0"));
    assert!(output.contains("ferrum_request_mirror_drain_failures_total 0"));
    assert!(output.contains("ferrum_request_mirror_drain_truncations_total 0"));
    assert!(output.contains("ferrum_request_mirror_cancellations_total 0"));
    assert!(output.contains("ferrum_request_mirror_concurrency_drops_total 0"));
    assert!(output.contains("ferrum_request_mirror_budget_drops_total 0"));
    assert!(!output.contains("ferrum_request_mirror_dispatched_total{"));
}

#[tokio::test]
async fn test_registry_records_hbone_relay_failure_counter() {
    let registry = MetricsRegistry::new();

    let cases = [
        (
            Direction::BackendToClient,
            ErrorClass::ConnectionReset,
            "backend_to_client",
            "connection_reset",
        ),
        (
            Direction::ClientToBackend,
            ErrorClass::ReadWriteTimeout,
            "client_to_backend",
            "read_write_timeout",
        ),
    ];

    for (direction, error_class, _, _) in cases {
        registry.record_hbone_relay_failure("mesh-hbone", direction, error_class);
    }

    for (_, _, direction_label, error_class_label) in cases {
        let key = HboneRelayFailureKey {
            proxy_id: Arc::from("mesh-hbone"),
            direction: direction_label,
            error_class: error_class_label,
        };
        assert!(registry.hbone_relay_failure_counter.contains_key(&key));
        assert_eq!(
            registry
                .hbone_relay_failure_counter
                .get(&key)
                .unwrap()
                .value
                .load(Ordering::Relaxed),
            1
        );
    }

    let output = registry.render_uncached();
    assert!(output.contains("# TYPE ferrum_mesh_hbone_relay_failures_total counter"));
    assert!(output.contains(
        r#"ferrum_mesh_hbone_relay_failures_total{proxy_id="mesh-hbone",direction="backend_to_client",error_class="connection_reset"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_mesh_hbone_relay_failures_total{proxy_id="mesh-hbone",direction="client_to_backend",error_class="read_write_timeout"} 1"#
    ));
}

#[tokio::test]
async fn test_registry_rate_limit_counter() {
    let registry = MetricsRegistry::new();
    assert_eq!(registry.rate_limit_exceeded.load(Ordering::Relaxed), 0);

    registry.record_rate_limit_exceeded();
    registry.record_rate_limit_exceeded();

    let output = registry.render_uncached();
    assert!(output.contains("ferrum_rate_limit_exceeded_total 2"));
}

#[test]
fn request_mirror_lifecycle_counters_are_monotonic_label_safe_and_rendered() {
    let registry = MetricsRegistry::new();
    registry.record_request_mirror_dispatched();
    registry.record_request_mirror_dispatched();
    registry.record_request_mirror_completed();
    registry.record_request_mirror_request_timeout();
    registry.record_request_mirror_request_failure();
    registry.record_request_mirror_drain_timeout();
    registry.record_request_mirror_drain_failure();
    registry.record_request_mirror_drain_truncation();
    registry.record_request_mirror_cancellation();
    registry.record_request_mirror_concurrency_drop();
    registry.record_request_mirror_budget_drop();

    // Second bump of completed proves monotonicity (not a gauge reset).
    registry.record_request_mirror_completed();

    let output = registry.render_uncached();
    assert!(output.contains("ferrum_request_mirror_dispatched_total 2"));
    assert!(output.contains("ferrum_request_mirror_completed_total 2"));
    assert!(output.contains("ferrum_request_mirror_request_timeouts_total 1"));
    assert!(output.contains("ferrum_request_mirror_request_failures_total 1"));
    assert!(output.contains("ferrum_request_mirror_drain_timeouts_total 1"));
    assert!(output.contains("ferrum_request_mirror_drain_failures_total 1"));
    assert!(output.contains("ferrum_request_mirror_drain_truncations_total 1"));
    assert!(output.contains("ferrum_request_mirror_cancellations_total 1"));
    assert!(output.contains("ferrum_request_mirror_concurrency_drops_total 1"));
    assert!(output.contains("ferrum_request_mirror_budget_drops_total 1"));
    // No URLs, header names, plugin IDs, or other high-cardinality labels.
    assert!(!output.contains("mirror_host="));
    assert!(!output.contains("plugin_id="));
    assert!(!output.contains("authorization"));
    assert!(!output.contains("http://"));
}

#[test]
fn request_mirror_lifecycle_counters_carry_namespace_label_when_configured() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "staging");
    registry.record_request_mirror_dispatched();
    let output = registry.render_uncached();
    assert!(output.contains(r#"ferrum_request_mirror_dispatched_total{namespace="staging"} 1"#));
}

#[test]
fn ai_federation_circuit_metrics_are_bounded_and_reload_safe() {
    let registry = MetricsRegistry::new();
    registry.record_ai_federation_circuit_opened();
    registry.record_ai_federation_half_open_probe();
    registry.record_ai_federation_open_skip();
    registry.record_ai_federation_circuit_closed();

    let output = registry.render_uncached();
    assert!(output.contains("ferrum_ai_federation_circuits_open 0"));
    assert!(output.contains("ferrum_ai_federation_circuits_opened_total 1"));
    assert!(output.contains("ferrum_ai_federation_circuits_closed_total 1"));
    assert!(output.contains("ferrum_ai_federation_circuit_half_open_probes_total 1"));
    assert!(output.contains("ferrum_ai_federation_circuit_open_skips_total 1"));
    assert!(!output.contains("provider="));

    registry.record_ai_federation_circuit_opened();
    registry.release_ai_federation_open_circuit();
    let output = registry.render_uncached();
    assert!(output.contains("ferrum_ai_federation_circuits_open 0"));
    assert!(output.contains("ferrum_ai_federation_circuits_opened_total 2"));
    assert!(output.contains("ferrum_ai_federation_circuits_closed_total 1"));
}

#[tokio::test]
async fn test_registry_records_mesh_dns_upstream_id_exhaustion() {
    let registry = MetricsRegistry::new();

    let initial_output = registry.render_uncached();
    assert!(initial_output.contains("ferrum_mesh_dns_upstream_id_exhaustions_total 0"));

    registry.record_mesh_dns_upstream_id_exhaustion();
    registry.record_mesh_dns_upstream_id_exhaustion();

    assert_eq!(
        registry
            .mesh_dns_upstream_id_exhaustions
            .load(Ordering::Relaxed),
        2
    );
    let output = registry.render_uncached();
    assert!(output.contains("# TYPE ferrum_mesh_dns_upstream_id_exhaustions_total counter"));
    assert!(output.contains("ferrum_mesh_dns_upstream_id_exhaustions_total 2"));
}

#[tokio::test]
async fn test_histogram_multiple_observations() {
    let registry = MetricsRegistry::new();

    // Record requests of varying durations
    registry.record(&make_summary("multi", "GET", 200, 3.0, 2.0)); // le=5 bucket
    registry.record(&make_summary("multi", "GET", 200, 150.0, 140.0)); // le=250 bucket
    registry.record(&make_summary("multi", "GET", 200, 3000.0, 2900.0)); // le=5000 bucket

    let hist = registry
        .request_duration_buckets
        .get(&Arc::from("multi") as &Arc<str>)
        .unwrap();
    assert_eq!(hist.count.load(Ordering::Relaxed), 3);

    // le=5: 1 (the 3.0ms request)
    assert_eq!(hist.counts[0].load(Ordering::Relaxed), 1);
    // le=250: 2 (3.0 + 150.0)
    assert_eq!(hist.counts[5].load(Ordering::Relaxed), 2);
    // le=5000: 3 (all three)
    assert_eq!(hist.counts[9].load(Ordering::Relaxed), 3);

    let sum = f64::from_bits(hist.sum.load(Ordering::Relaxed));
    assert!((sum - 3153.0).abs() < 0.01);
}

#[tokio::test]
async fn test_plugin_log_hook_records_metrics() {
    // Use a fresh registry via the plugin's log hook
    let config = json!({});
    let plugin = PrometheusMetrics::new(&config, "ferrum").unwrap();

    let summary = make_summary("log-hook-test", "DELETE", 204, 15.0, 10.0);
    plugin.log(&summary).await;

    // The global registry should have the metric
    let registry = global_registry();
    // Note: global registry is shared across tests, so we check our specific key exists
    assert!(registry.request_counter.contains_key(&CounterKey {
        proxy_id: Arc::from("log-hook-test"),
        method: "DELETE",
        status_code: 204,
        grpc_status: None,
    }));
}

#[tokio::test]
async fn test_registry_gateway_overhead_histogram() {
    let registry = MetricsRegistry::new();

    // Record a request with 3.0ms gateway overhead
    registry.record(&make_summary("proxy-overhead", "GET", 200, 50.0, 40.0));

    assert!(
        registry
            .gateway_overhead_buckets
            .contains_key(&Arc::from("proxy-overhead") as &Arc<str>)
    );
    let hist = registry
        .gateway_overhead_buckets
        .get(&Arc::from("proxy-overhead") as &Arc<str>)
        .unwrap();
    assert_eq!(hist.count.load(Ordering::Relaxed), 1);
    let sum = f64::from_bits(hist.sum.load(Ordering::Relaxed));
    // make_summary sets gateway_overhead_ms = 3.0
    assert!((sum - 3.0).abs() < 0.001);
}

#[tokio::test]
async fn test_registry_skips_streaming_unknown_gateway_overhead() {
    let registry = MetricsRegistry::new();
    let mut summary = make_summary("proxy-stream", "GET", 200, 10_000.0, -1.0);
    summary.response_streamed = true;
    summary.latency_gateway_overhead_ms = -1.0;
    registry.record(&summary);
    assert!(
        !registry
            .gateway_overhead_buckets
            .contains_key(&Arc::from("proxy-stream") as &Arc<str>),
        "unknown gateway overhead sentinel must not enter histograms"
    );
}

#[tokio::test]
async fn test_registry_render_contains_gateway_overhead() {
    let registry = MetricsRegistry::new();
    registry.record(&make_summary("overhead-render", "GET", 200, 42.0, 35.0));

    let output = registry.render_uncached();

    assert!(output.contains("# HELP ferrum_edge_overhead_ms"));
    assert!(output.contains("# TYPE ferrum_edge_overhead_ms histogram"));
    assert!(
        output
            .contains(r#"ferrum_edge_overhead_ms_bucket{proxy_id="overhead-render",le="+Inf"} 1"#)
    );
}

#[tokio::test]
async fn test_render_empty_registry() {
    let registry = MetricsRegistry::new();
    let output = registry.render_uncached();

    // Should still have HELP/TYPE headers and rate limit counter
    assert!(output.contains("# HELP ferrum_requests_total"));
    assert!(output.contains("ferrum_rate_limit_exceeded_total 0"));
    // No actual data lines for counters or histograms
    assert!(!output.contains("proxy_id="));
}

#[tokio::test]
async fn test_registry_render_escapes_prometheus_label_values() {
    let registry = MetricsRegistry::new();
    registry.record(&make_summary(
        "proxy\"line\nslash\\id",
        "PO\"ST",
        200,
        42.0,
        35.0,
    ));
    registry.record_stream(&make_stream_summary("stream\"proxy\nid", "tc\\p"));

    let output = registry.render_uncached();

    assert!(output.contains(
        "ferrum_requests_total{proxy_id=\"proxy\\\"line\\nslash\\\\id\",method=\"OTHER\",status_code=\"200\"} 1"
    ));
    assert!(!output.contains("PO\\\"ST"));
    assert!(output.contains(
        "ferrum_stream_connections_total{proxy_id=\"stream\\\"proxy\\nid\",protocol=\"tc\\\\p\"} 1"
    ));
}

#[tokio::test]
async fn test_evict_stale_removes_old_entries() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("stale-proxy", "GET", 200, 10.0, 5.0));
    registry.record_stream(&make_stream_summary("stale-stream", "tcp"));
    registry.record_ws_session(&make_ws_summary("stale-ws"));
    registry.record_tls_source_refresh("vault", "certificate", "frontend", "success");
    registry.record_mesh_outbound_registry_decision("stale-ns", "backend.test", "admit");
    registry.record_mesh_outbound_registry_stream_decision("stale-ns", "tcp", "deny");

    // All entries exist
    assert_eq!(registry.request_counter.len(), 1);
    assert_eq!(registry.stream_connection_counter.len(), 1);

    // Evict with TTL of 0 nanos — everything is stale
    let evicted = registry.evict_stale(0);
    assert!(evicted > 0);

    // All maps should be empty
    assert!(registry.request_counter.is_empty());
    assert!(registry.request_duration_buckets.is_empty());
    assert!(registry.backend_duration_buckets.is_empty());
    assert!(registry.gateway_overhead_buckets.is_empty());
    assert!(registry.stream_connection_counter.is_empty());
    assert!(registry.stream_duration_buckets.is_empty());
    assert!(registry.ws_session_counter.is_empty());
    assert!(registry.ws_session_duration_buckets.is_empty());
    assert!(registry.ws_bytes_counter.is_empty());
    assert!(registry.ws_frames_counter.is_empty());
    assert!(registry.tls_source_refresh_counter.is_empty());
    assert!(registry.mesh_outbound_registry_decisions.is_empty());
    assert!(registry.mesh_outbound_registry_stream_decisions.is_empty());
}

#[tokio::test]
async fn test_evict_stale_keeps_fresh_entries() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("fresh-proxy", "GET", 200, 10.0, 5.0));
    registry.record_tls_source_refresh("file", "certificate", "admin", "unchanged");
    registry.record_mesh_outbound_registry_decision("fresh-ns", "backend.test", "deny");
    registry.record_mesh_outbound_registry_stream_decision("fresh-ns", "udp", "admit");

    // Evict with a very large TTL — nothing should be evicted
    let evicted = registry.evict_stale(u64::MAX);
    assert_eq!(evicted, 0);

    // Entry should still exist
    assert_eq!(registry.request_counter.len(), 1);
    assert_eq!(registry.tls_source_refresh_counter.len(), 1);
    assert_eq!(registry.mesh_outbound_registry_decisions.len(), 1);
    assert_eq!(registry.mesh_outbound_registry_stream_decisions.len(), 1);
}

#[tokio::test]
async fn test_render_cache_returns_same_output() {
    let registry = MetricsRegistry::new();
    registry.record(&make_summary("cache-test", "GET", 200, 10.0, 5.0));

    let first = registry.render();
    let second = registry.render();

    // Both should be identical (second is from cache)
    assert_eq!(first, second);
    assert!(first.contains("cache-test"));
}

#[tokio::test]
async fn test_render_cache_invalidated_on_new_record() {
    let registry = MetricsRegistry::new();
    // Set min age to 0 so invalidation is immediate (test needs instant invalidation)
    registry.configure(5, 3600, 0, "ferrum");
    registry.record(&make_summary("inv-test-1", "GET", 200, 10.0, 5.0));

    let first = registry.render();
    assert!(first.contains("inv-test-1"));

    // Record new data — cache should be invalidated (min age = 0)
    registry.record(&make_summary("inv-test-2", "POST", 201, 20.0, 15.0));

    let second = registry.render();
    assert!(second.contains("inv-test-2"));
}

#[tokio::test]
async fn test_render_cache_not_invalidated_when_young() {
    let registry = MetricsRegistry::new();
    // Set min age high so cache is never invalidated by record()
    registry.configure(5, 3600, 60_000, "ferrum");
    registry.record(&make_summary("young-1", "GET", 200, 10.0, 5.0));

    let first = registry.render();
    assert!(first.contains("young-1"));

    // Record new data — cache is too young, should NOT be invalidated
    registry.record(&make_summary("young-2", "POST", 201, 20.0, 15.0));

    let second = registry.render();
    // second should still be cached (young-2 not yet visible)
    assert!(!second.contains("young-2"));
    // But render_uncached should see it
    assert!(registry.render_uncached().contains("young-2"));
}

#[tokio::test]
async fn test_plugin_config_sets_registry_tunables() {
    let config = serde_json::json!({
        "render_cache_ttl_seconds": 10,
        "stale_entry_ttl_seconds": 7200,
        "cache_invalidation_min_age_ms": 1000
    });
    let _plugin = PrometheusMetrics::new(&config, "ferrum").unwrap();

    let _registry = global_registry();
    // Can't read atomics directly from outside, but we can verify the plugin
    // didn't error on valid config
    assert_eq!(_plugin.name(), "prometheus_metrics");
}

#[tokio::test]
async fn test_plugin_config_saturates_extreme_tunables() {
    let config = serde_json::json!({
        "render_cache_ttl_seconds": u64::MAX,
        "stale_entry_ttl_seconds": u64::MAX,
        "cache_invalidation_min_age_ms": u64::MAX
    });

    let plugin = PrometheusMetrics::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "prometheus_metrics");
}

#[tokio::test]
async fn test_namespace_label_present_for_default_namespace() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "ferrum");
    registry.record(&make_summary("ns-default", "GET", 200, 10.0, 5.0));

    let output = registry.render_uncached();
    assert!(output.contains(r#"namespace="ferrum""#));
    assert!(output.contains(
        r#"ferrum_requests_total{proxy_id="ns-default",method="GET",status_code="200",namespace="ferrum"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_request_duration_ms_bucket{proxy_id="ns-default",le="+Inf",namespace="ferrum"} 1"#
    ));
}

#[tokio::test]
async fn test_namespace_label_present_for_non_default_namespace() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "staging");
    registry.record(&make_summary("ns-custom", "POST", 201, 20.0, 15.0));

    let output = registry.render_uncached();
    // Namespace labels are present on all metrics.
    assert!(output.contains(r#"namespace="staging""#));
    assert!(output.contains(
        r#"ferrum_requests_total{proxy_id="ns-custom",method="POST",status_code="201",namespace="staging"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_request_duration_ms_bucket{proxy_id="ns-custom",le="+Inf",namespace="staging"} 1"#
    ));
    // Rate limit counter should also have namespace label
    assert!(output.contains(r#"ferrum_rate_limit_exceeded_total{namespace="staging"}"#));
}

#[test]
fn test_mesh_metrics_use_distinct_gateway_namespace_label() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "staging");
    let mut summary = make_summary("mesh-namespace", "GET", 200, 10.0, 5.0);
    summary.metadata = HashMap::from([
        ("mesh.source.workload".to_string(), "frontend".to_string()),
        (
            "mesh.source.namespace".to_string(),
            "application".to_string(),
        ),
        (
            "mesh.destination.namespace".to_string(),
            "payments".to_string(),
        ),
    ]);
    registry.record(&summary);
    prometheus_helpers::set_mesh_ca_health("gateway_namespace_test", true);

    let output = registry.render_uncached();
    let red_line = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh RED counter line");
    assert!(red_line.contains(r#"source_namespace="application""#));
    assert!(red_line.contains(r#"destination_namespace="payments""#));
    assert!(red_line.contains(r#"gateway_namespace="staging""#));
    assert!(!red_line.contains(r#",namespace="staging""#));
    assert!(output.contains(
        r#"ferrum_mesh_ca_health{ca_type="gateway_namespace_test",gateway_namespace="staging"} 1"#
    ));
}

#[tokio::test]
async fn workload_metrics_response_code_override_changes_selected_metric_family() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [
                {
                    "metric": "REQUEST_COUNT",
                    "name": "response_code",
                    "operation": {"type": "set", "value": "server_error"}
                },
                {
                    "metric": "REQUEST_DURATION",
                    "name": "response_code",
                    "operation": {"type": "rename", "new_name": "response_flags"}
                }
            ]
        }
    }))
    .expect("response_code metric overrides");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    let result = workload_metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let registry = MetricsRegistry::new();
    let mut summary = make_summary("response-code-override", "GET", 503, 10.0, 5.0);
    summary.metadata = ctx.metadata;
    registry.record(&summary);
    let output = registry.render_uncached();
    let counter = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter");
    let duration = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_request_duration_ms_count{"))
        .expect("mesh request duration count");

    assert!(
        counter.contains("response_code=\"server_error\""),
        "{counter}"
    );
    assert!(!duration.contains("response_code="), "{duration}");
    assert!(duration.contains("response_flags=\"503\""), "{duration}");
}

#[tokio::test]
async fn mesh_metrics_render_valid_labels_when_all_base_labels_are_removed() {
    let removed_labels = [
        "source_workload",
        "source_namespace",
        "source_principal",
        "source_app",
        "source_service",
        "destination_workload",
        "destination_namespace",
        "destination_principal",
        "destination_app",
        "destination_service",
        "request_protocol",
        "response_code",
        "response_flags",
        "connection_security_policy",
    ];
    let tag_overrides = removed_labels
        .into_iter()
        .map(|name| {
            json!({
                "name": name,
                "operation": {"type": "remove"}
            })
        })
        .collect::<Vec<_>>();
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {"tag_overrides": tag_overrides}
    }))
    .expect("remove every request-duration label");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    let result = workload_metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut summary = make_summary("label-free-histogram", "GET", 200, 42.0, 35.0);
    summary.metadata = ctx.metadata;
    let registry = MetricsRegistry::new();
    registry.record(&summary);

    let output = registry.render_uncached();
    assert!(output.contains("ferrum_mesh_requests_total{} 1"));
    let buckets = output
        .lines()
        .filter(|line| line.starts_with("ferrum_mesh_request_duration_ms_bucket{"))
        .collect::<Vec<_>>();
    assert!(!buckets.is_empty(), "mesh histogram buckets: {output}");
    assert!(
        buckets.iter().all(|line| !line.contains("{,")),
        "label-free buckets must not start with a comma: {buckets:?}"
    );
    assert!(
        buckets.iter().any(
            |line| line.starts_with("ferrum_mesh_request_duration_ms_bucket{le=\"")
                && !line.contains("le=\"+Inf\"")
        ),
        "finite bucket must contain only a valid le label: {buckets:?}"
    );
    assert!(
        buckets.iter().any(|line| {
            line.starts_with("ferrum_mesh_request_duration_ms_bucket{le=\"+Inf\"} 1")
        }),
        "+Inf bucket must remain valid: {buckets:?}"
    );
    assert!(output.contains("ferrum_mesh_request_duration_ms_sum{} 42.00"));
    assert!(output.contains("ferrum_mesh_request_duration_ms_count{} 1"));

    registry.configure(5, 3600, 0, "mesh-system");
    let namespaced_output = registry.render_uncached();
    assert!(!namespaced_output.contains("{,"), "{namespaced_output}");
    assert!(
        namespaced_output
            .contains("ferrum_mesh_requests_total{gateway_namespace=\"mesh-system\"} 1")
    );
    assert!(namespaced_output.contains(
        "ferrum_mesh_request_duration_ms_bucket{le=\"+Inf\",gateway_namespace=\"mesh-system\"} 1"
    ));
    assert!(
        namespaced_output.contains(
            "ferrum_mesh_request_duration_ms_sum{gateway_namespace=\"mesh-system\"} 42.00"
        )
    );
    assert!(
        namespaced_output
            .contains("ferrum_mesh_request_duration_ms_count{gateway_namespace=\"mesh-system\"} 1")
    );

    let mut labeled_summary = summary.clone();
    labeled_summary
        .metadata
        .remove("mesh.metrics.request_duration.tag_overrides");
    labeled_summary
        .metadata
        .remove("mesh.metrics.request_count.tag_overrides");
    let labeled_registry = MetricsRegistry::new();
    labeled_registry.record(&labeled_summary);
    let labeled_output = labeled_registry.render_uncached();
    let labeled_bucket = labeled_output
        .lines()
        .find(|line| {
            line.starts_with("ferrum_mesh_request_duration_ms_bucket{")
                && !line.contains("le=\"+Inf\"")
        })
        .expect("normally labeled finite bucket");
    assert!(labeled_bucket.contains("source_workload=\"unknown\","));
    assert!(labeled_bucket.contains(",le=\""));
}

#[tokio::test]
async fn test_namespace_label_with_stream_metrics() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 0, "prod");

    let summary = StreamTransactionSummary {
        proxy_id: "stream-ns".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("tcp-proxy".to_string()),
        namespace: "prod".to_string(),
        protocol: "tcp".to_string(),
        listen_port: 9090,
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "backend.local:8080".to_string(),
        backend_resolved_ip: None,
        bytes_sent: 1024,
        bytes_received: 2048,
        duration_ms: 500.0,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    };
    registry.record_stream(&summary);

    let output = registry.render_uncached();
    assert!(output.contains(
        r#"ferrum_stream_connections_total{proxy_id="stream-ns",protocol="tcp",namespace="prod"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_stream_duration_ms_bucket{proxy_id="stream-ns",le="+Inf",namespace="prod"} 1"#
    ));
}

/// Finding #78: `mesh_request_key` interns label values, so two calls with the
/// same metadata return `Arc<str>` handles backed by the *same* allocation
/// rather than 11 fresh heap allocations per call. Before interning, every call
/// did `Arc::from(&str)`, so the pointers would differ.
#[test]
fn test_mesh_request_key_interns_repeated_label_values() {
    fn mesh_summary() -> TransactionSummary {
        let mut summary = make_summary("payments-proxy", "GET", 200, 42.0, 35.0);
        summary.metadata = HashMap::from([
            ("mesh.source.workload".to_string(), "frontend".to_string()),
            ("mesh.source.namespace".to_string(), "default".to_string()),
            (
                "mesh.destination.workload".to_string(),
                "payments".to_string(),
            ),
            ("mesh.request_protocol".to_string(), "grpc".to_string()),
            (
                "mesh.connection_security_policy".to_string(),
                "mutual_tls".to_string(),
            ),
        ]);
        summary
    }

    let first = prometheus_helpers::mesh_request_key(&mesh_summary())
        .expect("mesh metadata present yields a key");
    let second = prometheus_helpers::mesh_request_key(&mesh_summary())
        .expect("mesh metadata present yields a key");

    // Same interned allocation across calls (present values and defaults alike).
    assert!(
        Arc::ptr_eq(&first.source_workload, &second.source_workload),
        "present label values should be interned to one allocation"
    );
    assert!(Arc::ptr_eq(
        &first.request_protocol,
        &second.request_protocol
    ));
    assert!(Arc::ptr_eq(
        &first.connection_security_policy,
        &second.connection_security_policy
    ));
    // A default-filled field (no `mesh.source.principal` key → "unknown") is
    // also interned across calls.
    assert!(Arc::ptr_eq(
        &first.source_principal,
        &second.source_principal
    ));

    // Sanity: the key still carries the expected values.
    assert_eq!(&*first.source_workload, "frontend");
    assert_eq!(&*first.destination_workload, "payments");
    assert_eq!(&*first.request_protocol, "grpc");
    assert_eq!(&*first.source_principal, "unknown");
}

#[tokio::test]
async fn ai_token_metadata_records_and_renders_bounded_prometheus_families() {
    let plugin = AiTokenMetrics::new(&json!({
        "metadata_prefix": "llm",
        "cost_per_prompt_token": 0.1,
        "cost_per_completion_token": 0.2
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/responses".to_string(),
    );
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = serde_json::to_vec(&json!({
        "object": "response",
        "model": "must-not-be-a-label",
        "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;

    let registry = MetricsRegistry::new();
    registry.configure(0, 3600, 0, "tenant-a");
    let mut summary = make_summary("ai-proxy", "POST", 200, 10.0, 8.0);
    summary.ai_usage_export = ctx.authoritative_ai_usage_export();
    summary.metadata = ctx.metadata;
    registry.record(&summary);
    let output = registry.render_uncached();

    assert!(output.contains(
        "ferrum_ai_prompt_tokens_total{proxy_id=\"ai-proxy\",provider=\"openai\",namespace=\"tenant-a\"} 10"
    ));
    assert!(output.contains(
        "ferrum_ai_completion_tokens_total{proxy_id=\"ai-proxy\",provider=\"openai\",namespace=\"tenant-a\"} 5"
    ));
    assert!(output.contains(
        "ferrum_ai_tokens_total{proxy_id=\"ai-proxy\",provider=\"openai\",namespace=\"tenant-a\"} 15"
    ));
    assert!(output.contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"ai-proxy\",provider=\"openai\",namespace=\"tenant-a\"} 2.000000"
    ));
    assert!(!output.contains("must-not-be-a-label"));
}

#[test]
fn federation_provider_aliases_use_bounded_ai_metric_families() {
    let registry = MetricsRegistry::new();
    registry.configure(0, 3600, 0, "federation-ns");
    let aliases = [
        ("azure_openai", "openai"),
        ("xai", "openai"),
        ("deepseek", "openai"),
        ("meta_llama", "openai"),
        ("hugging_face", "openai"),
        ("google_gemini", "google"),
        ("google_vertex", "google"),
        ("aws_bedrock", "bedrock"),
    ];

    for (index, (raw_provider, _)) in aliases.iter().enumerate() {
        let mut summary = make_summary(&format!("federation-{index}"), "POST", 200, 1.0, 1.0);
        summary.ai_usage_export = Some(AiUsageExport {
            prefix: Arc::from("ai"),
            provider: raw_provider,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: Some(1),
            cost: None,
        });
        registry.record(&summary);
    }

    let output = registry.render_uncached();
    for (index, (raw_provider, metric_provider)) in aliases.iter().enumerate() {
        assert!(output.contains(&format!(
            "ferrum_ai_tokens_total{{proxy_id=\"federation-{index}\",provider=\"{metric_provider}\",namespace=\"federation-ns\"}} 1"
        )));
        assert!(!output.contains(&format!("provider=\"{raw_provider}\"")));
    }
}

#[tokio::test]
async fn multiple_ai_token_instances_preserve_one_trusted_cost_without_double_counting() {
    let priced_sparse = AiTokenMetrics::new(&json!({
        "metadata_prefix": "alpha",
        "include_token_details": false,
        "cost_per_prompt_token": 0.1,
        "cost_per_completion_token": 0.2
    }))
    .unwrap();
    let detailed = AiTokenMetrics::new(&json!({"metadata_prefix": "zeta"})).unwrap();
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let body = br#"{"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}"#;

    let registry = MetricsRegistry::new();
    for (proxy_id, priced_first) in [
        ("multi-ai-priced-first", true),
        ("multi-ai-detailed-first", false),
    ] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/chat".to_string(),
        );
        ctx.metadata
            .insert("ai_estimated_cost".to_string(), "999.000000".to_string());
        let instances = if priced_first {
            [&priced_sparse, &detailed]
        } else {
            [&detailed, &priced_sparse]
        };
        for instance in instances {
            instance
                .on_response_body(&mut ctx, 200, &mut headers, body)
                .await;
        }

        let export = ctx
            .authoritative_ai_usage_export()
            .expect("built-in instances must retain typed usage provenance");
        assert_eq!(export.prefix.as_ref(), "alpha");
        assert_eq!(export.prompt_tokens, Some(7));
        assert_eq!(export.completion_tokens, Some(3));
        assert_eq!(export.total_tokens, Some(10));
        assert_eq!(
            export.cost.as_ref().map(|cost| cost.microunits),
            Some(1_300_000)
        );

        let mut summary = make_summary(proxy_id, "POST", 200, 1.0, 1.0);
        summary.ai_usage_export = Some(export);
        summary.metadata = ctx.metadata;
        registry.record(&summary);
    }

    let output = registry.render_uncached();
    for proxy_id in ["multi-ai-priced-first", "multi-ai-detailed-first"] {
        assert!(output.contains(&format!(
            "ferrum_ai_prompt_tokens_total{{proxy_id=\"{proxy_id}\",provider=\"openai\"}} 7"
        )));
        assert!(output.contains(&format!(
            "ferrum_ai_completion_tokens_total{{proxy_id=\"{proxy_id}\",provider=\"openai\"}} 3"
        )));
        assert!(output.contains(&format!(
            "ferrum_ai_tokens_total{{proxy_id=\"{proxy_id}\",provider=\"openai\"}} 10"
        )));
        assert!(output.contains(&format!(
            "ferrum_ai_estimated_cost_currency_units_total{{proxy_id=\"{proxy_id}\",provider=\"openai\"}} 1.300000"
        )));
    }
    assert!(!output.contains(" 999.000000"));
    assert!(!output.contains(" 2.600000"));
}

#[test]
fn spoofed_backend_custom_and_malformed_ai_metadata_cannot_export_usage() {
    let registry = MetricsRegistry::new();
    let cases = [
        HashMap::from([
            ("evil_usage_export".to_string(), "v1".to_string()),
            ("evil_provider".to_string(), "attacker-model".to_string()),
            ("evil_total_tokens".to_string(), "10".to_string()),
        ]),
        HashMap::from([
            ("bad_usage_export".to_string(), "v1".to_string()),
            ("bad_provider".to_string(), "openai".to_string()),
            ("bad_prompt_tokens".to_string(), "-1".to_string()),
            ("bad_completion_tokens".to_string(), "1.5".to_string()),
            (
                "bad_total_tokens".to_string(),
                "18446744073709551616".to_string(),
            ),
            ("bad_estimated_cost".to_string(), "NaN".to_string()),
        ]),
        HashMap::from([
            ("ai_usage_export".to_string(), "v1".to_string()),
            ("ai_provider".to_string(), "openai".to_string()),
            ("ai_total_tokens".to_string(), "999".to_string()),
            ("ai_estimated_cost".to_string(), "999.000000".to_string()),
        ]),
        HashMap::from([
            ("serverless_ai_usage_export".to_string(), "v1".to_string()),
            ("serverless_ai_provider".to_string(), "openai".to_string()),
            ("serverless_ai_total_tokens".to_string(), "999".to_string()),
            (
                "serverless_ai_estimated_cost".to_string(),
                "999.000000".to_string(),
            ),
        ]),
        HashMap::from([
            ("custom.export".to_string(), "v1".to_string()),
            ("custom.provider".to_string(), "openai".to_string()),
            ("custom.total_tokens".to_string(), "999".to_string()),
            (
                "custom.estimated_cost".to_string(),
                "999.000000".to_string(),
            ),
        ]),
        HashMap::from([
            ("raw_provider".to_string(), "openai".to_string()),
            ("raw_total_tokens".to_string(), "999".to_string()),
        ]),
    ];
    for (index, metadata) in cases.into_iter().enumerate() {
        let mut summary = make_summary(&format!("malformed-{index}"), "POST", 200, 1.0, 1.0);
        summary.metadata = metadata;
        registry.record(&summary);
    }
    let output = registry.render_uncached();
    assert!(!output.contains("ferrum_ai_tokens_total"));
    assert!(!output.contains("ferrum_ai_estimated_cost_currency_units_total"));
}

#[test]
fn ai_usage_recording_is_concurrent_reload_safe_and_invalidates_render_cache() {
    let registry = Arc::new(MetricsRegistry::new());
    registry.configure(3600, 3600, 0, "before-reload");
    let metadata = HashMap::from([
        ("ai_provider".to_string(), "anthropic".to_string()),
        ("ai_prompt_tokens".to_string(), "2".to_string()),
        ("ai_completion_tokens".to_string(), "1".to_string()),
        ("ai_total_tokens".to_string(), "3".to_string()),
        ("ai_estimated_cost".to_string(), "0.000001".to_string()),
    ]);

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let registry = Arc::clone(&registry);
            let metadata = metadata.clone();
            scope.spawn(move || {
                for _ in 0..100 {
                    let mut summary = make_summary("concurrent-ai", "POST", 200, 1.0, 1.0);
                    summary.metadata = metadata.clone();
                    summary.ai_usage_export = Some(AiUsageExport {
                        prefix: Arc::from("ai"),
                        provider: "anthropic",
                        prompt_tokens: Some(2),
                        completion_tokens: Some(1),
                        total_tokens: Some(3),
                        cost: Some(AiCost {
                            microunits: 1,
                            submicrounits: 0,
                        }),
                    });
                    registry.record(&summary);
                }
            });
        }
    });

    let cached = registry.render();
    assert!(cached.contains(
        "ferrum_ai_tokens_total{proxy_id=\"concurrent-ai\",provider=\"anthropic\",namespace=\"before-reload\"} 2400"
    ));

    registry.configure(3600, 3600, 0, "after-reload");
    let reloaded = registry.render();
    assert!(reloaded.contains(
        "ferrum_ai_tokens_total{proxy_id=\"concurrent-ai\",provider=\"anthropic\",namespace=\"after-reload\"} 2400"
    ));
    assert!(!reloaded.contains("namespace=\"before-reload\""));
    assert!(reloaded.contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"concurrent-ai\",provider=\"anthropic\",namespace=\"after-reload\"} 0.000800"
    ));
}

#[tokio::test]
async fn submicro_request_costs_accumulate_before_aggregate_rounding() {
    let plugin = AiTokenMetrics::new(&json!({"cost_per_prompt_token": 0.0000004})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    plugin
        .on_response_body(
            &mut ctx,
            200,
            &mut HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            br#"{"usage":{"prompt_tokens":1,"total_tokens":1}}"#,
        )
        .await;

    // The per-request metadata contract is still six decimals, but the typed
    // export retains the 0.4 micro-unit remainder for aggregate accounting.
    assert_eq!(
        ctx.metadata.get("ai_estimated_cost").map(String::as_str),
        Some("0.000000")
    );
    let usage = ctx
        .authoritative_ai_usage_export()
        .expect("direct usage must carry typed provenance");
    assert_eq!(
        usage.cost,
        Some(AiCost {
            microunits: 0,
            submicrounits: 400_000_000_000,
        })
    );

    let registry = MetricsRegistry::new();
    let mut summary = make_summary("submicro-ai", "POST", 200, 1.0, 1.0);
    summary.ai_usage_export = Some(usage.clone());
    registry.record(&summary);
    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"submicro-ai\",provider=\"openai\"} 0.000000"
    ));

    registry.record(&summary);
    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"submicro-ai\",provider=\"openai\"} 0.000001"
    ));

    for _ in 0..8 {
        let mut summary = make_summary("submicro-ai", "POST", 200, 1.0, 1.0);
        summary.ai_usage_export = Some(usage.clone());
        registry.record(&summary);
    }
    let output = registry.render_uncached();
    assert!(output.contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"submicro-ai\",provider=\"openai\"} 0.000004"
    ));
}

#[test]
fn split_cost_carry_gap_cannot_decrease_rendered_counter() {
    let registry = MetricsRegistry::new();
    let mut summary = make_summary("carry-ai", "POST", 200, 1.0, 1.0);
    summary.ai_usage_export = Some(AiUsageExport {
        prefix: Arc::from("ai"),
        provider: "openai",
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        cost: Some(AiCost {
            microunits: 0,
            submicrounits: 800_000_000_000,
        }),
    });
    registry.record(&summary);
    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"carry-ai\",provider=\"openai\"} 0.000001"
    ));

    // Deterministically model the split update window: the remainder has
    // wrapped from 0.8 to 0.2 micro-units, but the whole-unit carry has not yet
    // landed. Scrapes must retain the last atomically published rounded value.
    {
        let counter = registry
            .ai_estimated_cost_counter
            .iter()
            .next()
            .expect("cost counter must exist");
        counter
            .submicrounits
            .store(200_000_000_000, Ordering::Relaxed);
    }
    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"carry-ai\",provider=\"openai\"} 0.000001"
    ));

    let counter = registry
        .ai_estimated_cost_counter
        .iter()
        .next()
        .expect("cost counter must exist");
    counter.microunits.store(1, Ordering::Relaxed);
    drop(counter);
    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"carry-ai\",provider=\"openai\"} 0.000001"
    ));
}

#[test]
fn ordinary_request_increment_uses_fetch_add_while_ai_tokens_saturate() {
    let registry = MetricsRegistry::new();
    let summary = make_summary("ordinary-hot-path", "GET", 200, 1.0, 1.0);
    registry.record(&summary);
    {
        let counter = registry
            .request_counter
            .iter()
            .next()
            .expect("request counter must exist");
        counter.value.store(u64::MAX, Ordering::Relaxed);
    }

    registry.record(&summary);

    let counter = registry
        .request_counter
        .iter()
        .next()
        .expect("request counter must exist");
    assert_eq!(
        counter.value.load(Ordering::Relaxed),
        0,
        "ordinary increments must keep the single fetch_add path; saturation is reserved for untrusted token additions"
    );
    drop(counter);

    for total_tokens in [u64::MAX, 1] {
        let mut summary = make_summary("untrusted-ai-total", "POST", 200, 1.0, 1.0);
        summary.ai_usage_export = Some(AiUsageExport {
            prefix: Arc::from("ai"),
            provider: "openai",
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: Some(total_tokens),
            cost: None,
        });
        registry.record(&summary);
    }
    assert!(registry.render_uncached().contains(
        "ferrum_ai_tokens_total{proxy_id=\"untrusted-ai-total\",provider=\"openai\"} 18446744073709551615"
    ));
}

#[test]
fn cumulative_ai_cost_saturates_instead_of_wrapping() {
    let registry = MetricsRegistry::new();
    for cost in [
        AiCost {
            microunits: u64::MAX,
            submicrounits: 0,
        },
        AiCost {
            microunits: 1,
            submicrounits: 999_999_999_999,
        },
    ] {
        let mut summary = make_summary("saturated-ai", "POST", 200, 1.0, 1.0);
        summary.ai_usage_export = Some(AiUsageExport {
            prefix: Arc::from("ai"),
            provider: "openai",
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            cost: Some(cost),
        });
        registry.record(&summary);
    }

    assert!(registry.render_uncached().contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"saturated-ai\",provider=\"openai\"} 18446744073709.551615"
    ));
}

// --- Cached TLS inventory snapshot freshness (issue #2410) -------------------

const SNAPSHOT_TIMESTAMP_LINE: &str =
    "ferrum_tls_inventory_snapshot_timestamp_seconds{namespace=\"ferrum\"} 1700000000";
const SNAPSHOT_REFRESHED_LINE: &str =
    "ferrum_tls_inventory_snapshot_timestamp_seconds{namespace=\"ferrum\"} 1700000060";
const SNAPSHOT_MAX_AGE_LINE: &str =
    "ferrum_tls_inventory_snapshot_max_age_seconds{namespace=\"ferrum\"} 300";

#[test]
fn tls_inventory_freshness_renders_timestamp_and_configured_bound() {
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 60_000, "ferrum");

    registry.set_tls_inventory_freshness(Some((1_700_000_000, 300)));

    let output = registry.render_uncached();
    assert!(
        output.contains(SNAPSHOT_TIMESTAMP_LINE),
        "snapshot collection timestamp must be exported:\n{output}"
    );
    assert!(
        output.contains(SNAPSHOT_MAX_AGE_LINE),
        "configured snapshot bound must be exported:\n{output}"
    );
}

#[test]
fn tls_inventory_freshness_omitted_until_a_snapshot_exists() {
    let registry = MetricsRegistry::new();
    registry.set_tls_inventory_freshness(None);

    let output = registry.render_uncached();
    assert!(
        !output.contains("ferrum_tls_inventory_snapshot_"),
        "no freshness series may be exported before the first snapshot:\n{output}"
    );
}

#[tokio::test]
async fn unchanged_tls_inventory_freshness_preserves_the_render_cache() {
    // Issue #2240 discipline: the scrape path publishes freshness on every
    // request, so an unchanged value must not evict the rendered exposition.
    // A high invalidation min-age keeps `record()` from clearing the cache, so
    // the only candidate invalidation source is the freshness publication.
    let registry = MetricsRegistry::new();
    registry.configure(5, 3600, 60_000, "ferrum");
    registry.set_tls_inventory_freshness(Some((1_700_000_000, 300)));

    let first = registry.render();
    assert!(first.contains(SNAPSHOT_TIMESTAMP_LINE));

    registry.record(&make_summary("freshness-hidden", "GET", 200, 10.0, 5.0));
    registry.set_tls_inventory_freshness(Some((1_700_000_000, 300)));
    let cached = registry.render();
    assert!(
        !cached.contains("freshness-hidden"),
        "republishing the same freshness must not evict the render cache:\n{cached}"
    );

    // A real snapshot refresh (new timestamp) does invalidate it.
    registry.set_tls_inventory_freshness(Some((1_700_000_060, 300)));
    let refreshed = registry.render();
    assert!(
        refreshed.contains(SNAPSHOT_REFRESHED_LINE),
        "a newer snapshot must be rendered:\n{refreshed}"
    );
    assert!(
        refreshed.contains("freshness-hidden"),
        "the invalidated cache must also expose the recorded series:\n{refreshed}"
    );
}

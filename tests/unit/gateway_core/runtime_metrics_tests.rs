use std::sync::atomic::Ordering;

use ferrum_edge::plugins::{StreamTransactionSummary, TransactionSummary};
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::runtime_metrics::{LogLevel, PoolKind, RuntimeMetrics};

#[test]
fn runtime_metrics_counters_increment() {
    let metrics = RuntimeMetrics::new();
    let summary = TransactionSummary {
        proxy_id: Some("proxy-a".to_string()),
        error_class: Some(ErrorClass::TlsError),
        body_error_class: Some(ErrorClass::ClientDisconnect),
        client_disconnected: true,
        ..TransactionSummary::default()
    };
    metrics.record_transaction(&summary);
    metrics.record_dns_hit();
    metrics.record_dns_miss();
    metrics.record_dns_error();
    metrics.record_pool_handshake(PoolKind::HttpReqwest);
    metrics.record_pool_failure(PoolKind::Http3);
    metrics.record_pool_eviction(PoolKind::Grpc);
    metrics.record_log(LogLevel::Warn, "proxy");

    assert_eq!(metrics.dns_lookups_total.load(Ordering::Relaxed), 3);
    assert_eq!(metrics.dns_cache_hits.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dns_cache_misses.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dns_lookup_errors.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.http_errors_by_class.len(), 1);
    assert_eq!(metrics.body_errors_by_class.len(), 1);
    assert_eq!(metrics.pool_handshakes_total.len(), 1);
    assert_eq!(metrics.pool_failures_total.len(), 1);
    assert_eq!(metrics.pool_evictions_total.len(), 1);
    assert_eq!(
        metrics.log_counts[LogLevel::Warn as usize].load(Ordering::Relaxed),
        1
    );
}

#[test]
fn runtime_metrics_stream_errors_increment() {
    let metrics = RuntimeMetrics::new();
    let summary = StreamTransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-a".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: None,
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "tcp://127.0.0.1:9001".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 9000,
        duration_ms: 1.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: Some("reset".to_string()),
        error_class: Some(ErrorClass::ConnectionReset),
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-05-14T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-05-14T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: Default::default(),
    };

    metrics.record_stream_transaction(&summary);

    assert_eq!(metrics.stream_errors_by_class.len(), 1);
}

/// Issue #7183: a raw-TCP relay that builds no stream summary (no stream
/// plugin chain) records the same stream-error and RST counters a summary
/// would.
#[test]
fn runtime_metrics_stream_end_matches_the_summary_counters() {
    use ferrum_edge::plugins::Direction;

    let metrics = RuntimeMetrics::new();
    metrics.record_stream_end("relay-a", None, Some(Direction::BackendToClient));
    assert!(metrics.stream_errors_by_class.is_empty());
    assert!(metrics.tcp_rst_observed.is_empty());

    metrics.record_stream_end("relay-a", Some(ErrorClass::ConnectionRefused), None);
    assert_eq!(metrics.stream_errors_by_class.len(), 1);
    assert!(
        metrics.tcp_rst_observed.is_empty(),
        "only a reset is an RST"
    );

    metrics.record_stream_end(
        "relay-a",
        Some(ErrorClass::ConnectionReset),
        Some(Direction::BackendToClient),
    );
    assert_eq!(metrics.stream_errors_by_class.len(), 2);
    assert_eq!(metrics.tcp_rst_observed.len(), 1);
}

#[test]
fn runtime_metrics_snapshot_serializes_expected_top_level_shape() {
    let snapshot = ferrum_edge::runtime_metrics::build_snapshot("cp", None);
    let value = serde_json::to_value(snapshot).expect("snapshot serializes");

    assert!(value.get("timestamp").is_some());
    assert_eq!(value.get("mode").and_then(|v| v.as_str()), Some("cp"));
    assert!(value.get("system").is_some());
    assert!(value.get("http").is_some());
    assert!(value.get("errors").is_some());
    assert!(value.get("dns").is_some());
    assert!(value.get("connections").is_some());
    assert!(value.get("logs").is_some());
    assert!(value.get("overload").is_some());
}

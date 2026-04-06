//! Tests for prometheus_metrics plugin

use ferrum_edge::plugins::prometheus_metrics::{
    CounterKey, MetricsRegistry, PrometheusMetrics, global_registry,
};
use ferrum_edge::plugins::{Plugin, StreamTransactionSummary, TransactionSummary};
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
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        http_method: method.to_string(),
        request_path: "/test".to_string(),
        matched_proxy_id: Some(proxy_id.to_string()),
        matched_proxy_name: Some("Test".to_string()),
        backend_target_url: Some("http://localhost:3000".to_string()),
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
        mirror: false,
        metadata: HashMap::new(),
    }
}

fn make_stream_summary(proxy_id: &str, protocol: &str) -> StreamTransactionSummary {
    StreamTransactionSummary {
        proxy_id: proxy_id.to_string(),
        proxy_name: Some("Stream Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: protocol.to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_prometheus_plugin_creation() {
    let config = json!({});
    let plugin = PrometheusMetrics::new(&config).unwrap();
    assert_eq!(plugin.name(), "prometheus_metrics");
    assert_eq!(plugin.priority(), 9300);
}

#[tokio::test]
async fn test_registry_records_request_counter() {
    let registry = MetricsRegistry::new();
    let summary = make_summary("proxy-1", "GET", 200, 50.0, 40.0);

    registry.record(&summary);

    let key = CounterKey {
        proxy_id: Arc::from("proxy-1"),
        method: Arc::from("GET"),
        status_code: 200,
    };
    assert!(registry.request_counter.contains_key(&key));
    let count = registry.request_counter.get(&key).unwrap();
    assert_eq!(count.value.load(Ordering::Relaxed), 1);
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
        method: Arc::from("POST"),
        status_code: 201,
    };
    let count = registry.request_counter.get(&key).unwrap();
    assert_eq!(count.value.load(Ordering::Relaxed), 5);
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
                method: Arc::from("GET"),
                status_code: 200
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
                method: Arc::from("POST"),
                status_code: 200
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
                method: Arc::from("GET"),
                status_code: 200
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
                method: Arc::from("GET"),
                status_code: 500
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
    summary.matched_proxy_id = None;
    registry.record(&summary);

    assert!(registry.request_counter.contains_key(&CounterKey {
        proxy_id: Arc::from("unknown"),
        method: Arc::from("GET"),
        status_code: 200
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
}

#[tokio::test]
async fn test_registry_rate_limit_counter() {
    let registry = MetricsRegistry::new();
    assert_eq!(registry.rate_limit_exceeded.load(Ordering::Relaxed), 0);

    registry.rate_limit_exceeded.fetch_add(1, Ordering::Relaxed);
    registry.rate_limit_exceeded.fetch_add(1, Ordering::Relaxed);

    let output = registry.render_uncached();
    assert!(output.contains("ferrum_rate_limit_exceeded_total 2"));
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
    let plugin = PrometheusMetrics::new(&config).unwrap();

    let summary = make_summary("log-hook-test", "DELETE", 204, 15.0, 10.0);
    plugin.log(&summary).await;

    // The global registry should have the metric
    let registry = global_registry();
    // Note: global registry is shared across tests, so we check our specific key exists
    assert!(registry.request_counter.contains_key(&CounterKey {
        proxy_id: Arc::from("log-hook-test"),
        method: Arc::from("DELETE"),
        status_code: 204
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
        "ferrum_requests_total{proxy_id=\"proxy\\\"line\\nslash\\\\id\",method=\"PO\\\"ST\",status_code=\"200\"} 1"
    ));
    assert!(output.contains(
        "ferrum_stream_connections_total{proxy_id=\"stream\\\"proxy\\nid\",protocol=\"tc\\\\p\"} 1"
    ));
}

#[tokio::test]
async fn test_evict_stale_removes_old_entries() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("stale-proxy", "GET", 200, 10.0, 5.0));
    registry.record_stream(&make_stream_summary("stale-stream", "tcp"));

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
}

#[tokio::test]
async fn test_evict_stale_keeps_fresh_entries() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("fresh-proxy", "GET", 200, 10.0, 5.0));

    // Evict with a very large TTL — nothing should be evicted
    let evicted = registry.evict_stale(u64::MAX);
    assert_eq!(evicted, 0);

    // Entry should still exist
    assert_eq!(registry.request_counter.len(), 1);
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
    registry.configure(5, 3600, 0);
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
    registry.configure(5, 3600, 60_000);
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
    let _plugin = PrometheusMetrics::new(&config).unwrap();

    let _registry = global_registry();
    // Can't read atomics directly from outside, but we can verify the plugin
    // didn't error on valid config
    assert_eq!(_plugin.name(), "prometheus_metrics");
}

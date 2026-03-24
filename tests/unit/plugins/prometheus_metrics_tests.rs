//! Tests for prometheus_metrics plugin

use ferrum_gateway::plugins::prometheus_metrics::{
    MetricsRegistry, PrometheusMetrics, global_registry,
};
use ferrum_gateway::plugins::{Plugin, TransactionSummary};
use serde_json::json;
use std::collections::HashMap;
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
        response_status_code: status,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: 5.0,
        latency_backend_ttfb_ms: total_ms - 5.0,
        latency_backend_total_ms: backend_ms,
        request_user_agent: Some("test-agent".to_string()),
        response_streamed: false,
        client_disconnected: false,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_prometheus_plugin_creation() {
    let config = json!({});
    let plugin = PrometheusMetrics::new(&config);
    assert_eq!(plugin.name(), "prometheus_metrics");
    assert_eq!(plugin.priority(), 9300);
}

#[tokio::test]
async fn test_registry_records_request_counter() {
    let registry = MetricsRegistry::new();
    let summary = make_summary("proxy-1", "GET", 200, 50.0, 40.0);

    registry.record(&summary);

    let key = "proxy-1:GET:200";
    assert!(registry.request_counter.contains_key(key));
    let count = registry.request_counter.get(key).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_registry_increments_counter_on_repeated_requests() {
    let registry = MetricsRegistry::new();

    for _ in 0..5 {
        let summary = make_summary("proxy-1", "POST", 201, 30.0, 25.0);
        registry.record(&summary);
    }

    let key = "proxy-1:POST:201";
    let count = registry.request_counter.get(key).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 5);
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
            .get("proxy-a:GET:200")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get("proxy-a:POST:200")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get("proxy-b:GET:200")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        registry
            .request_counter
            .get("proxy-a:GET:500")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_registry_request_duration_histogram() {
    let registry = MetricsRegistry::new();

    // Record a 50ms request — should fall in the <=50 bucket
    registry.record(&make_summary("proxy-hist", "GET", 200, 50.0, 40.0));

    let hist = registry.request_duration_buckets.get("proxy-hist").unwrap();
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
            .contains_key("proxy-stream")
    );
    // Backend duration should NOT be recorded
    assert!(
        !registry
            .backend_duration_buckets
            .contains_key("proxy-stream")
    );
}

#[tokio::test]
async fn test_registry_backend_duration_records_positive() {
    let registry = MetricsRegistry::new();

    registry.record(&make_summary("proxy-be", "GET", 200, 100.0, 80.0));

    assert!(registry.backend_duration_buckets.contains_key("proxy-be"));
    let hist = registry.backend_duration_buckets.get("proxy-be").unwrap();
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

    assert!(registry.request_counter.contains_key("unknown:GET:200"));
}

#[tokio::test]
async fn test_registry_render_contains_expected_metrics() {
    let registry = MetricsRegistry::new();
    registry.record(&make_summary("render-test", "GET", 200, 42.0, 35.0));

    let output = registry.render();

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

    let output = registry.render();
    assert!(output.contains("ferrum_rate_limit_exceeded_total 2"));
}

#[tokio::test]
async fn test_histogram_multiple_observations() {
    let registry = MetricsRegistry::new();

    // Record requests of varying durations
    registry.record(&make_summary("multi", "GET", 200, 3.0, 2.0)); // le=5 bucket
    registry.record(&make_summary("multi", "GET", 200, 150.0, 140.0)); // le=250 bucket
    registry.record(&make_summary("multi", "GET", 200, 3000.0, 2900.0)); // le=5000 bucket

    let hist = registry.request_duration_buckets.get("multi").unwrap();
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
    let plugin = PrometheusMetrics::new(&config);

    let summary = make_summary("log-hook-test", "DELETE", 204, 15.0, 10.0);
    plugin.log(&summary).await;

    // The global registry should have the metric
    let registry = global_registry();
    // Note: global registry is shared across tests, so we check our specific key exists
    assert!(
        registry
            .request_counter
            .contains_key("log-hook-test:DELETE:204")
    );
}

#[tokio::test]
async fn test_render_empty_registry() {
    let registry = MetricsRegistry::new();
    let output = registry.render();

    // Should still have HELP/TYPE headers and rate limit counter
    assert!(output.contains("# HELP ferrum_requests_total"));
    assert!(output.contains("ferrum_rate_limit_exceeded_total 0"));
    // No actual data lines for counters or histograms
    assert!(!output.contains("proxy_id="));
}

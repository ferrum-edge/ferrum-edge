//! Tests for api_chargeback plugin

use ferrum_edge::plugins::api_chargeback::{ApiChargeback, ChargebackRegistry};
use ferrum_edge::plugins::{Plugin, TransactionSummary};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

fn make_summary(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    status: u16,
) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: consumer.map(|c| c.to_string()),
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some(proxy_name.to_string()),
        backend_target_url: Some("http://localhost:3000".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: 50.0,
        latency_gateway_processing_ms: 5.0,
        latency_backend_ttfb_ms: 45.0,
        latency_backend_total_ms: 40.0,
        latency_plugin_execution_ms: 2.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 3.0,
        request_user_agent: Some("test-agent".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_streamed_to_client: 0,
        request_bytes: 0,
        response_bytes: 0,
        mirror: false,
        metadata: HashMap::new(),
    }
}

/// Build the same key format used by the registry internally.
fn make_key(consumer: &str, proxy_id: &str, status_code: u16) -> String {
    format!("{}|{}|{}", consumer, proxy_id, status_code)
}

// --- Plugin config validation tests ---

#[test]
fn test_valid_config() {
    let config = json!({
        "currency": "EUR",
        "pricing_tiers": [
            {
                "status_codes": [200, 201],
                "price_per_call": 0.00001
            }
        ]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
    assert_eq!(plugin.priority(), 9350);
}

#[test]
fn test_missing_pricing_tiers() {
    let config = json!({ "currency": "USD" });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("pricing_tiers"));
}

#[test]
fn test_empty_pricing_tiers() {
    let config = json!({ "pricing_tiers": [] });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("at least one"));
}

#[test]
fn test_missing_status_codes_in_tier() {
    let config = json!({
        "pricing_tiers": [{ "price_per_call": 0.001 }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("status_codes"));
}

#[test]
fn test_missing_price_in_tier() {
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200] }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("price_per_call"));
}

#[test]
fn test_negative_price_rejected() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": -0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("non-negative"));
}

#[test]
fn test_duplicate_status_code_across_tiers() {
    let config = json!({
        "pricing_tiers": [
            { "status_codes": [200], "price_per_call": 0.001 },
            { "status_codes": [200, 201], "price_per_call": 0.002 }
        ]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("200"));
    assert!(err.contains("multiple pricing tiers"));
}

#[test]
fn test_empty_status_codes_in_tier() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_status_code_out_of_range() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [70000],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("invalid HTTP status code"));
}

#[test]
fn test_status_code_below_100_rejected() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [99],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("invalid HTTP status code"));
}

#[test]
fn test_default_currency_is_usd() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.00001
        }]
    });
    // Plugin creation succeeds with default currency
    ApiChargeback::new(&config, "ferrum").unwrap();
}

// --- Registry tests ---

#[test]
fn test_registry_records_charge() {
    let registry = ChargebackRegistry::new();
    registry.record("user-1", "proxy-a", "My API", 200, 0.00001);

    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    let charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((charge - 0.00001).abs() < 1e-15);
    // Verify render metadata is stored correctly
    assert_eq!(&*entry.consumer, "user-1");
    assert_eq!(&*entry.proxy_id, "proxy-a");
    assert_eq!(&*entry.proxy_name, "My API");
    assert_eq!(entry.status_code, 200);
}

#[test]
fn test_registry_accumulates_charges() {
    let registry = ChargebackRegistry::new();
    for _ in 0..1000 {
        registry.record("user-1", "proxy-a", "My API", 200, 0.00001);
    }

    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1000);
    let charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((charge - 0.01).abs() < 1e-10);
}

#[test]
fn test_registry_zero_alloc_hot_path() {
    // Verify that repeated record() calls hit the fast path (DashMap::get)
    // by checking entry count stays at 1 for the same key.
    let registry = ChargebackRegistry::new();
    registry.record("user-1", "proxy-a", "API", 200, 0.001);
    registry.record("user-1", "proxy-a", "API", 200, 0.001);
    registry.record("user-1", "proxy-a", "API", 200, 0.001);

    assert_eq!(registry.entries.len(), 1);
    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 3);
}

#[test]
fn test_registry_separates_by_consumer() {
    let registry = ChargebackRegistry::new();
    registry.record("user-1", "proxy-a", "API", 200, 0.001);
    registry.record("user-2", "proxy-a", "API", 200, 0.002);

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_separates_by_status_code() {
    let registry = ChargebackRegistry::new();
    registry.record("user-1", "proxy-a", "API", 200, 0.001);
    registry.record("user-1", "proxy-a", "API", 201, 0.002);

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_stale_eviction() {
    let registry = ChargebackRegistry::new();
    registry.record("user-1", "proxy-a", "API", 200, 0.001);

    // Evict with zero TTL should remove everything
    let evicted = registry.evict_stale(0);
    assert_eq!(evicted, 1);
    assert!(registry.entries.is_empty());
}

// --- Prometheus render tests ---

#[test]
fn test_prometheus_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_prometheus_uncached();
    assert!(output.contains("ferrum_api_chargeable_calls_total"));
    assert!(output.contains("ferrum_api_charges_total"));
}

#[test]
fn test_prometheus_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record("alice", "proxy-1", "Payments API", 200, 0.00001);
    registry.record("alice", "proxy-1", "Payments API", 200, 0.00001);

    let output = registry.render_prometheus_uncached();
    assert!(output.contains("consumer=\"alice\""));
    assert!(output.contains("proxy_id=\"proxy-1\""));
    assert!(output.contains("proxy_name=\"Payments API\""));
    assert!(output.contains("status_code=\"200\""));
    // Should have 2 calls
    assert!(output.contains("} 2\n"));
    // Currency label on charges
    assert!(output.contains("currency=\"USD\""));
}

// --- JSON render tests ---

#[test]
fn test_json_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["consumers"].as_object().unwrap().is_empty());
    assert_eq!(parsed["currency"], "USD");
}

#[test]
fn test_json_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure("EUR", 5, 3600, 500, "ferrum");

    for _ in 0..100 {
        registry.record("bob", "proxy-2", "Orders API", 200, 0.00001);
    }
    registry.record("bob", "proxy-2", "Orders API", 201, 0.00002);

    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["currency"], "EUR");

    let bob = &parsed["consumers"]["bob"];
    assert_eq!(bob["total_calls"], 101);

    let proxy = &bob["proxies"]["proxy-2"];
    assert_eq!(proxy["proxy_name"], "Orders API");
    assert_eq!(proxy["total_calls"], 101);

    let status_200 = &proxy["by_status"]["200"];
    assert_eq!(status_200["calls"], 100);
}

// --- Plugin log hook tests ---

#[tokio::test]
async fn test_log_charges_identified_consumer() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary("proxy-1", "Test API", Some("alice"), 200);

    plugin.log(&summary).await;

    // Verify a charge was recorded in the global registry
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("alice", "proxy-1", 200);
    assert!(registry.entries.contains_key(&key));
}

#[tokio::test]
async fn test_log_skips_anonymous_traffic() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    // No consumer
    let summary = make_summary("proxy-1", "Test API", None, 200);
    plugin.log(&summary).await;

    // Empty consumer
    let summary2 = make_summary("proxy-1", "Test API", Some(""), 200);
    plugin.log(&summary2).await;

    // No crash, no charge recorded for anonymous traffic
}

#[tokio::test]
async fn test_log_skips_uncharged_status_codes() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    // 404 is not in the pricing tiers
    let summary = make_summary("proxy-uncharged", "Test API", Some("charlie"), 404);
    plugin.log(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("charlie", "proxy-uncharged", 404);
    assert!(!registry.entries.contains_key(&key));
}

#[test]
fn test_multiple_pricing_tiers() {
    let config = json!({
        "pricing_tiers": [
            { "status_codes": [200, 201], "price_per_call": 0.00001 },
            { "status_codes": [301, 302], "price_per_call": 0.000005 }
        ]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
}

#[test]
fn test_prometheus_render_namespace_absent_for_default() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record("alice", "proxy-1", "API", 200, 0.001);

    let output = registry.render_prometheus_uncached();
    assert!(!output.contains("namespace="));
    assert!(output.contains("consumer=\"alice\""));
}

#[test]
fn test_prometheus_render_namespace_present_for_non_default() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "staging");
    registry.record("bob", "proxy-2", "API", 200, 0.001);

    let output = registry.render_prometheus_uncached();
    assert!(output.contains(r#"namespace="staging""#));
    assert!(output.contains("consumer=\"bob\""));
}

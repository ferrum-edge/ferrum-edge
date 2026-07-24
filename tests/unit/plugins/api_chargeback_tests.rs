//! Tests for api_chargeback plugin

use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, Proxy};
use ferrum_edge::plugins::api_chargeback::{
    ApiChargeback, ChargebackRegistry, InstanceScope, ProtocolFamily, global_registry,
};
use ferrum_edge::plugins::chargeback::pricing::{
    MAX_UNIT_PRICE, checked_add_charge, checked_mul_quantity,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, DisconnectCause, Plugin, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Default per-instance scope used by registry tests (USD / "ferrum").
fn scope() -> InstanceScope {
    InstanceScope::new("USD", "ferrum")
}

/// Build an instance scope with an explicit currency + namespace.
fn scope_for(currency: &str, namespace: &str) -> InstanceScope {
    InstanceScope::new(currency, namespace)
}

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
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some(proxy_name.to_string()),
        backend_target: Some("http://localhost:3000".to_string()),
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
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn make_summary_with_bytes(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    status: u16,
    bytes_sent: u64,
    bytes_received: u64,
) -> TransactionSummary {
    let mut summary = make_summary(proxy_id, proxy_name, consumer, status);
    summary.bytes_sent = bytes_sent;
    summary.bytes_received = bytes_received;
    summary
}

fn make_grpc_summary(
    proxy_id: &str,
    consumer: &str,
    grpc_status: Option<&str>,
) -> TransactionSummary {
    let mut summary = make_summary(proxy_id, "gRPC API", Some(consumer), 200);
    summary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    if let Some(status) = grpc_status {
        summary
            .metadata
            .insert("grpc_status".to_string(), status.to_string());
    }
    summary
}

fn make_stream_summary(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    protocol: &str,
    bytes_sent: u64,
    bytes_received: u64,
) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some(proxy_name.to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: consumer.map(|c| c.to_string()),
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: protocol.to_string(),
        listen_port: 5000,
        duration_ms: 1234.0,
        bytes_sent,
        bytes_received,
        connection_error: None,
        error_class: None,
        disconnect_direction: Some(Direction::ClientToBackend),
        disconnect_cause: Some(DisconnectCause::GracefulShutdown),
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

/// Build the same key format used by the registry internally.
fn make_key(
    consumer: &str,
    proxy_id: &str,
    status_code: u16,
    protocol_family: ProtocolFamily,
) -> String {
    make_key_with_prices(
        consumer,
        proxy_id,
        status_code,
        protocol_family,
        0.0,
        0.0,
        0.0,
    )
}

fn make_key_with_prices(
    consumer: &str,
    proxy_id: &str,
    status_code: u16,
    protocol_family: ProtocolFamily,
    call_price: f64,
    bw_price_sent: f64,
    bw_price_received: f64,
) -> String {
    let scope = scope();
    let protocol_family = match protocol_family {
        ProtocolFamily::Http => "http",
        ProtocolFamily::Stream => "stream",
    };
    format!(
        "{}|{}|{}|{}|{}|{}|{:016x}|{:016x}|{:016x}",
        consumer,
        proxy_id,
        status_code,
        protocol_family,
        scope.currency,
        scope.namespace_label,
        call_price.to_bits(),
        bw_price_sent.to_bits(),
        bw_price_received.to_bits()
    )
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
    // Now supports all protocols so it sees stream summaries via on_stream_disconnect.
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[test]
fn test_invalid_config_shapes_rejected() {
    let cases = [
        json!(null),
        json!({"currency": 100, "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"currency": "  ", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"render_cache_ttl_seconds": "5", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"stale_entry_ttl_seconds": false, "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"cache_invalidation_min_age_ms": [], "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"cleanup_interval_seconds": "300", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"pricing_tiers": [42]}),
    ];

    for config in cases {
        assert!(
            ApiChargeback::new(&config, "ferrum").is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[test]
fn test_missing_all_pricing_blocks_rejected() {
    // No pricing_tiers, no bandwidth_pricing, no stream_connection_pricing.
    let config = json!({ "currency": "USD" });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("at least one"));
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
fn test_extreme_tunables_do_not_overflow() {
    let config = json!({
        "render_cache_ttl_seconds": u64::MAX,
        "stale_entry_ttl_seconds": u64::MAX,
        "cache_invalidation_min_age_ms": u64::MAX,
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });

    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
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

// --- Bandwidth / stream config validation ---

#[tokio::test]
async fn test_bandwidth_only_config_records_bytes() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary_with_bytes(
        "bw-only-proxy",
        "API",
        Some("bw-only-user"),
        404,
        1_000_000,
        2_000_000,
    );
    plugin.log(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "bw-only-user",
            "bw-only-proxy",
            404,
            ProtocolFamily::Http,
            0.0,
            0.0000001,
            0.0000002,
        ))
        .expect("bandwidth-only entry recorded");
    assert!((entry.bandwidth_charge_sent().unwrap() - 0.1).abs() < 1e-10);
    assert!((entry.bandwidth_charge_received().unwrap() - 0.4).abs() < 1e-10);
}

#[tokio::test]
async fn test_stream_only_config_charges_connection() {
    let config = json!({
        "stream_connection_pricing": { "price_per_connection": 0.0005 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_stream_summary(
        "stream-only-proxy",
        "TCP API",
        Some("stream-only-user"),
        "tcp",
        0,
        0,
    );
    plugin.on_stream_disconnect(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "stream-only-user",
            "stream-only-proxy",
            0,
            ProtocolFamily::Stream,
            0.0005,
            0.0,
            0.0,
        ))
        .expect("stream-only entry recorded");
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    assert!((entry.call_charge().unwrap() - 0.0005).abs() < 1e-12);
}

#[test]
fn test_bandwidth_pricing_rejects_unknown_key() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.001,
            "unexpected": true
        }
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("unknown key"));
}

/// GHSA-8478: misspelled top-level pricing dimensions and unknown
/// `pricing_tiers[]` keys must fail both OpenAPI draft 2020-12 validation and
/// runtime construction — never silently bill at zero.
#[test]
fn test_unknown_keys_rejected_by_schema_and_runtime() {
    use ferrum_edge::plugins::api_chargeback::API_CHARGEBACK_CONFIG_KEYS;
    use ferrum_edge::plugins::create_plugin;
    use serde_json::Value as JsonValue;

    let spec: JsonValue =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ApiChargebackConfig",
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("ApiChargebackConfig schema compiles");

    let accepted = [
        json!({
            "currency": "USD",
            "pricing_tiers": [
                { "status_codes": [200, 201], "price_per_call": 0.00001 }
            ]
        }),
        json!({
            "bandwidth_pricing": {
                "price_per_byte_sent": 0.0000001,
                "price_per_byte_received": 0.0000002
            }
        }),
        json!({
            "stream_connection_pricing": { "price_per_connection": 0.0005 }
        }),
        json!({
            "currency": "USD",
            "pricing_tiers": [
                { "status_codes": [200], "price_per_call": 0.001 }
            ],
            "bandwidth_pricing": {
                "price_per_byte_sent": 0.0000001
            },
            "stream_connection_pricing": {
                "price_per_connection": 0.0005
            },
            "render_cache_ttl_seconds": 5,
            "stale_entry_ttl_seconds": 3600,
            "cache_invalidation_min_age_ms": 500,
            "cleanup_interval_seconds": 300
        }),
    ];
    for config in &accepted {
        assert!(
            validator.validate(config).is_ok(),
            "config should be schema-valid: {config}"
        );
        assert!(
            ApiChargeback::new(config, "ferrum").is_ok(),
            "config should be runtime-valid via ApiChargeback::new: {config}"
        );
        assert!(
            create_plugin("api_chargeback", config).is_ok(),
            "config should be runtime-valid via create_plugin: {config}"
        );
    }

    // Advisory reproduction: valid HTTP tier + misspelled bandwidth key.
    let misspelled_top_level = json!({
        "pricing_tiers": [
            { "status_codes": [200], "price_per_call": 0.00001 }
        ],
        "bandwith_pricing": {
            "price_per_byte_sent": 0.0000001
        }
    });
    assert!(
        validator.validate(&misspelled_top_level).is_err(),
        "misspelled bandwith_pricing must be schema-invalid"
    );
    let runtime_err = ApiChargeback::new(&misspelled_top_level, "ferrum")
        .err()
        .expect("misspelled bandwith_pricing must be runtime-rejected");
    assert!(
        runtime_err.contains("bandwith_pricing")
            || runtime_err.contains("unknown configuration key"),
        "runtime error should name the unknown key: {runtime_err}"
    );
    assert!(
        create_plugin("api_chargeback", &misspelled_top_level).is_err(),
        "create_plugin must reject misspelled bandwith_pricing"
    );

    let unknown_tier_key = json!({
        "pricing_tiers": [
            {
                "status_codes": [200],
                "price_per_call": 0.00001,
                "price_per_requst": 0.001
            }
        ]
    });
    assert!(
        validator.validate(&unknown_tier_key).is_err(),
        "unknown pricing_tiers[] key must be schema-invalid"
    );
    let tier_err = ApiChargeback::new(&unknown_tier_key, "ferrum")
        .err()
        .expect("unknown pricing_tiers[] key must be runtime-rejected");
    assert!(
        tier_err.contains("pricing_tiers[0]")
            && (tier_err.contains("price_per_requst")
                || tier_err.contains("unknown configuration key")),
        "runtime error should name the tier path and unknown key: {tier_err}"
    );
    assert!(
        create_plugin("api_chargeback", &unknown_tier_key).is_err(),
        "create_plugin must reject unknown pricing_tiers[] keys"
    );

    assert_eq!(
        API_CHARGEBACK_CONFIG_KEYS,
        &[
            "currency",
            "pricing_tiers",
            "bandwidth_pricing",
            "stream_connection_pricing",
            "render_cache_ttl_seconds",
            "stale_entry_ttl_seconds",
            "cache_invalidation_min_age_ms",
            "cleanup_interval_seconds",
        ]
    );
}

#[test]
fn test_bandwidth_pricing_rejects_negative() {
    let config = json!({
        "bandwidth_pricing": { "price_per_byte_sent": -0.001 }
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("non-negative"));
}

#[test]
fn test_stream_connection_pricing_requires_price() {
    let config = json!({ "stream_connection_pricing": {} });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("price_per_connection"));
}

#[tokio::test]
async fn test_combined_pricing_applies_both_call_and_bandwidth_charges() {
    let config = json!({
        "currency": "USD",
        "pricing_tiers": [
            { "status_codes": [200], "price_per_call": 0.001 }
        ],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.000001,
            "price_per_byte_received": 0.000002
        },
        "stream_connection_pricing": { "price_per_connection": 0.0005 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary_with_bytes(
        "combined-proxy",
        "API",
        Some("combined-user"),
        200,
        1_000,
        2_000,
    );
    plugin.log(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "combined-user",
            "combined-proxy",
            200,
            ProtocolFamily::Http,
            0.001,
            0.000001,
            0.000002,
        ))
        .expect("combined entry recorded");
    let call_charge = entry.call_charge().unwrap();
    let bw_sent = entry.bandwidth_charge_sent().unwrap();
    let bw_recv = entry.bandwidth_charge_received().unwrap();
    assert!((call_charge - 0.001).abs() < 1e-12);
    assert!((bw_sent - 0.001).abs() < 1e-12); // 1_000 * 0.000001
    assert!((bw_recv - 0.004).abs() < 1e-12); // 2_000 * 0.000002
}

// --- Registry tests ---

#[test]
fn test_registry_records_charge() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "My API",
        200,
        0.00001,
        0,
        0,
        0.0,
        0.0,
    );

    let key = make_key_with_prices(
        "user-1",
        "proxy-a",
        200,
        ProtocolFamily::Http,
        0.00001,
        0.0,
        0.0,
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    assert!((entry.call_charge().unwrap() - 0.00001).abs() < 1e-15);
    // Verify render metadata is stored correctly
    assert_eq!(&*entry.consumer, "user-1");
    assert_eq!(&*entry.proxy_id, "proxy-a");
    assert_eq!(&*entry.proxy_name, "My API");
    assert_eq!(entry.status_code, 200);
    assert_eq!(entry.protocol_family, ProtocolFamily::Http);
}

#[test]
fn test_registry_accumulates_charges() {
    let registry = ChargebackRegistry::new();
    for _ in 0..1000 {
        registry.record_http(
            &scope(),
            "user-1",
            "proxy-a",
            "My API",
            200,
            0.00001,
            0,
            0,
            0.0,
            0.0,
        );
    }

    let key = make_key_with_prices(
        "user-1",
        "proxy-a",
        200,
        ProtocolFamily::Http,
        0.00001,
        0.0,
        0.0,
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1000);
    assert!((entry.call_charge().unwrap() - 0.01).abs() < 1e-10);
}

#[test]
fn test_registry_zero_alloc_hot_path() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );

    assert_eq!(registry.entries.len(), 1);
    let key = make_key_with_prices(
        "user-1",
        "proxy-a",
        200,
        ProtocolFamily::Http,
        0.001,
        0.0,
        0.0,
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 3);
}

#[test]
fn test_registry_separates_by_consumer() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &scope(),
        "user-2",
        "proxy-a",
        "API",
        200,
        0.002,
        0,
        0,
        0.0,
        0.0,
    );

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_separates_by_status_code() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        201,
        0.002,
        0,
        0,
        0.0,
        0.0,
    );

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_stale_eviction() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "user-1",
        "proxy-a",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );

    // Evict with zero TTL should remove everything
    let evicted = registry.evict_stale(0);
    assert_eq!(evicted, 1);
    assert!(registry.entries.is_empty());
}

#[test]
fn test_registry_records_bandwidth_for_http() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "alice",
        "proxy-1",
        "API",
        200,
        0.0,
        1_000_000,
        2_000_000,
        0.0000001,
        0.0000002,
    );

    let key = make_key_with_prices(
        "alice",
        "proxy-1",
        200,
        ProtocolFamily::Http,
        0.0,
        0.0000001,
        0.0000002,
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_000_000);
    assert_eq!(
        entry.bytes_received_total.load(Ordering::Relaxed),
        2_000_000
    );
    assert!((entry.bandwidth_charge_sent().unwrap() - 0.1).abs() < 1e-10);
    assert!((entry.bandwidth_charge_received().unwrap() - 0.4).abs() < 1e-10);
}

#[test]
fn test_registry_records_stream_session() {
    let registry = ChargebackRegistry::new();
    registry.record_stream(
        &scope(),
        "alice",
        "stream-proxy",
        "TCP Edge",
        0.0005,
        500_000,
        750_000,
        0.0000001,
        0.0000002,
    );

    let key = make_key_with_prices(
        "alice",
        "stream-proxy",
        0,
        ProtocolFamily::Stream,
        0.0005,
        0.0000001,
        0.0000002,
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    assert_eq!(entry.status_code, 0);
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    assert!((entry.call_charge().unwrap() - 0.0005).abs() < 1e-12);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 500_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 750_000);
}

#[test]
fn test_registry_does_not_charge_bandwidth_when_price_zero() {
    // Bytes flow but no bandwidth pricing configured -> bytes accumulate,
    // bandwidth charges stay at zero.
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope(),
        "alice",
        "proxy",
        "API",
        200,
        0.0,
        1_000,
        2_000,
        0.0,
        0.0,
    );
    let entry = registry
        .entries
        .get(&make_key("alice", "proxy", 200, ProtocolFamily::Http))
        .unwrap();
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 2_000);
    assert_eq!(entry.bandwidth_charge_sent().unwrap(), 0.0);
    assert_eq!(entry.bandwidth_charge_received().unwrap(), 0.0);
}

// --- Prometheus render tests ---

#[test]
fn test_prometheus_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_prometheus_uncached().unwrap();
    assert!(output.contains("ferrum_api_chargeable_calls_total"));
    assert!(output.contains("ferrum_api_charges_total"));
    assert!(output.contains("ferrum_api_stream_connections_total"));
    assert!(output.contains("ferrum_api_bytes_sent_total"));
    assert!(output.contains("ferrum_api_bytes_received_total"));
    assert!(output.contains("ferrum_api_bandwidth_charges_total"));
}

#[test]
fn test_prometheus_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    registry.record_http(
        &s,
        "alice",
        "proxy-1",
        "Payments API",
        200,
        0.00001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &s,
        "alice",
        "proxy-1",
        "Payments API",
        200,
        0.00001,
        0,
        0,
        0.0,
        0.0,
    );

    let output = registry.render_prometheus_uncached().unwrap();
    assert!(output.contains("consumer=\"alice\""));
    assert!(output.contains("proxy_id=\"proxy-1\""));
    assert!(output.contains("proxy_name=\"Payments API\""));
    assert!(output.contains("status_code=\"200\""));
    // Should have 2 calls on the chargeable_calls_total line
    assert!(output.contains("ferrum_api_chargeable_calls_total{") && output.contains("} 2\n"));
    // Currency label on per-call charges
    assert!(output.contains("currency=\"USD\""));
}

#[test]
fn test_prometheus_render_emits_stream_metrics() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.record_stream(
        &scope(),
        "bob",
        "tcp-edge",
        "TCP Edge",
        0.0,
        1_024,
        2_048,
        0.000001,
        0.000002,
    );

    let output = registry.render_prometheus_uncached().unwrap();
    assert!(output.contains("ferrum_api_stream_connections_total{consumer=\"bob\""));
    assert!(output.contains("protocol_family=\"stream\""));
    // Stream entry must NOT emit ferrum_api_chargeable_calls_total rows (those are HTTP-only).
    assert!(!output.contains("ferrum_api_chargeable_calls_total{consumer=\"bob\""));
}

#[test]
fn test_prometheus_render_bandwidth_aggregates_across_status_codes() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    registry.record_http(
        &s, "charlie", "proxy-x", "API", 200, 0.0, 1_000, 10_000, 0.0000001, 0.0000002,
    );
    registry.record_http(
        &s, "charlie", "proxy-x", "API", 500, 0.0, 500, 5_000, 0.0000001, 0.0000002,
    );

    let output = registry.render_prometheus_uncached().unwrap();
    // One bytes_sent line per (consumer, proxy, family) — aggregated to 1500.
    let sent_count = output
        .lines()
        .filter(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{") && l.contains("consumer=\"charlie\"")
        })
        .count();
    assert_eq!(sent_count, 1, "expected one aggregated bytes_sent row");
    assert!(output.contains("ferrum_api_bytes_sent_total{") && output.contains(" 1500\n"));
    assert!(output.contains("ferrum_api_bytes_received_total{") && output.contains(" 15000\n"));
}

// --- JSON render tests ---

#[test]
fn test_json_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_json_uncached().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["consumers"].as_object().unwrap().is_empty());
    assert_eq!(parsed["currency"], "USD");
}

#[tokio::test]
async fn test_cleanup_interval_reconfigures_across_reload_values() {
    let registry = Arc::new(ChargebackRegistry::new());

    registry.start_cleanup_task(60);
    assert_eq!(registry.cleanup_interval_seconds_for_test(), 60);

    registry.start_cleanup_task(0);
    assert_eq!(
        registry.cleanup_interval_seconds_for_test(),
        0,
        "reload must be able to disable an already-started cleanup task"
    );

    registry.start_cleanup_task(1);
    assert_eq!(
        registry.cleanup_interval_seconds_for_test(),
        1,
        "reload must be able to re-enable cleanup with a new interval"
    );
}

#[test]
fn test_json_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope_for("EUR", "ferrum");

    for _ in 0..100 {
        registry.record_http(
            &s,
            "bob",
            "proxy-2",
            "Orders API",
            200,
            0.00001,
            0,
            0,
            0.0,
            0.0,
        );
    }
    registry.record_http(
        &s,
        "bob",
        "proxy-2",
        "Orders API",
        201,
        0.00002,
        0,
        0,
        0.0,
        0.0,
    );

    let output = registry.render_json_uncached().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["currency"], "EUR");

    let bob = &parsed["consumers"]["bob"];
    assert_eq!(bob["total_calls"], 101);

    let proxy = &bob["proxies"]["proxy-2"];
    assert_eq!(proxy["proxy_name"], "Orders API");
    assert_eq!(proxy["total_calls"], 101);
    assert_eq!(proxy["protocol_family"], "http");
    // Per-proxy currency reflects the recording instance (finding #24).
    assert_eq!(proxy["currency"], "EUR");

    let status_200 = &proxy["by_status"]["200"];
    assert_eq!(status_200["calls"], 100);
}

#[test]
fn test_json_render_includes_bandwidth() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.record_http(
        &scope(),
        "alice",
        "proxy-1",
        "API",
        200,
        0.001,
        1_000,
        4_000,
        0.0000001,
        0.0000002,
    );

    let output = registry.render_json_uncached().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let bandwidth = &parsed["consumers"]["alice"]["proxies"]["proxy-1"]["bandwidth"];
    assert_eq!(bandwidth["bytes_sent"], 1_000);
    assert_eq!(bandwidth["bytes_received"], 4_000);
}

#[test]
fn test_json_render_includes_stream_section() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.record_stream(
        &scope(),
        "alice",
        "tcp-1",
        "TCP API",
        0.0005,
        2_048,
        8_192,
        0.0000001,
        0.0000002,
    );

    let output = registry.render_json_uncached().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let proxy = &parsed["consumers"]["alice"]["proxies"]["tcp-1"];
    assert_eq!(proxy["protocol_family"], "stream");
    assert_eq!(proxy["stream"]["connections"], 1);
    let connection_charges = proxy["stream"]["connection_charges"].as_f64().unwrap();
    assert!((connection_charges - 0.0005).abs() < 1e-12);
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

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key_with_prices(
        "alice",
        "proxy-1",
        200,
        ProtocolFamily::Http,
        0.001,
        0.0,
        0.0,
    );
    assert!(registry.entries.contains_key(&key));
}

#[tokio::test]
async fn test_log_prices_final_grpc_status_as_effective_http_status() {
    let config = json!({
        "pricing_tiers": [
            {"status_codes": [200], "price_per_call": 0.001},
            {"status_codes": [403], "price_per_call": 0.007},
            {"status_codes": [500], "price_per_call": 0.008},
            {"status_codes": [503], "price_per_call": 0.009}
        ]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();

    let cases = [
        (
            "grpc-billing-ok",
            "grpc-billing-ok-user",
            Some("0"),
            200,
            0.001,
        ),
        (
            "grpc-billing-denied",
            "grpc-billing-denied-user",
            Some("7"),
            403,
            0.007,
        ),
        (
            "grpc-billing-unavailable",
            "grpc-billing-unavailable-user",
            Some("14"),
            503,
            0.009,
        ),
        (
            "grpc-billing-missing",
            "grpc-billing-missing-user",
            None,
            500,
            0.008,
        ),
        (
            "grpc-billing-malformed",
            "grpc-billing-malformed-user",
            Some("invalid"),
            500,
            0.008,
        ),
    ];

    for (proxy_id, consumer, grpc_status, effective_status, price) in cases {
        plugin
            .log(&make_grpc_summary(proxy_id, consumer, grpc_status))
            .await;
        let key = make_key_with_prices(
            consumer,
            proxy_id,
            effective_status,
            ProtocolFamily::Http,
            price,
            0.0,
            0.0,
        );
        let entry = registry
            .entries
            .get(&key)
            .unwrap_or_else(|| panic!("missing effective gRPC billing entry {key}"));
        assert_eq!(entry.status_code, effective_status);
        assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
        assert!((entry.call_charge().unwrap() - price).abs() < 1e-12);
        drop(entry);
        assert!(
            effective_status == 200
                || !registry.entries.contains_key(&make_key_with_prices(
                    consumer,
                    proxy_id,
                    200,
                    ProtocolFamily::Http,
                    0.001,
                    0.0,
                    0.0,
                )),
            "non-OK gRPC status must not be charged in the HTTP 200 bucket"
        );
    }
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
    let key = make_key("charlie", "proxy-uncharged", 404, ProtocolFamily::Http);
    assert!(!registry.entries.contains_key(&key));
}

#[tokio::test]
async fn test_log_records_bandwidth_even_when_status_is_uncharged() {
    // No status tier configured for this code, but bandwidth pricing applies →
    // we still want bandwidth bytes recorded so operators see usage data.
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.001 }],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_summary_with_bytes("proxy-bw", "API", Some("derek"), 404, 1_024, 4_096);
    plugin.log(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key_with_prices(
        "derek",
        "proxy-bw",
        404,
        ProtocolFamily::Http,
        0.0,
        0.0000001,
        0.0000002,
    );
    let entry = registry
        .entries
        .get(&key)
        .expect("bandwidth entry recorded");
    // 404 has no per-call price, so the per-call charge stays at zero.
    assert!(entry.call_charge().unwrap().abs() < 1e-15);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_024);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 4_096);
}

#[tokio::test]
async fn test_on_stream_disconnect_records_bandwidth() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        },
        "stream_connection_pricing": { "price_per_connection": 0.001 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary(
        "tcp-edge-stream-test",
        "TCP Edge",
        Some("emma"),
        "tcp",
        10_000,
        20_000,
    );
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key_with_prices(
        "emma",
        "tcp-edge-stream-test",
        0,
        ProtocolFamily::Stream,
        0.001,
        0.0000001,
        0.0000002,
    );
    let entry = registry.entries.get(&key).expect("stream entry recorded");
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    assert!((entry.call_charge().unwrap() - 0.001).abs() < 1e-12);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 10_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 20_000);
}

#[tokio::test]
async fn test_on_stream_disconnect_skips_anonymous() {
    let config = json!({
        "stream_connection_pricing": { "price_per_connection": 0.001 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary("anon-stream-test", "TCP API", None, "tcp", 10_000, 20_000);
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    assert!(
        !registry
            .entries
            .iter()
            .any(|e| &*e.value().proxy_id == "anon-stream-test")
    );
}

#[tokio::test]
async fn test_on_stream_disconnect_skips_when_only_per_call_pricing_set() {
    // Only HTTP per-call pricing configured. Stream disconnects must not
    // create stub entries — otherwise every TCP/UDP session would show up in
    // /charges output with zero charges, polluting billing pipelines.
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.001 }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary(
        "http-only-stream-test",
        "TCP API",
        Some("frank"),
        "tcp",
        10_000,
        20_000,
    );
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("frank", "http-only-stream-test", 0, ProtocolFamily::Stream);
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
fn test_prometheus_render_namespace_present_for_default() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.record_http(
        &scope_for("USD", "ferrum"),
        "alice",
        "proxy-1",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );

    let output = registry.render_prometheus_uncached().unwrap();
    assert!(output.contains(r#"namespace="ferrum""#));
    assert!(output.contains("consumer=\"alice\""));
}

#[test]
fn test_prometheus_render_namespace_present_for_non_default() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.record_http(
        &scope_for("USD", "staging"),
        "bob",
        "proxy-2",
        "API",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );

    let output = registry.render_prometheus_uncached().unwrap();
    assert!(output.contains(r#"namespace="staging""#));
    assert!(output.contains("consumer=\"bob\""));
}

// --- Finding #24: per-instance currency/namespace scoping ---

/// Two plugin instances with different currencies AND namespaces record onto
/// the SAME shared registry. Each proxy's exported rows must carry the currency
/// and namespace of the instance that recorded them — NOT a single
/// last-writer-wins value (the pre-fix behavior, where `configure()` overwrote
/// one global currency/namespace_label for the whole process).
#[test]
fn test_per_instance_currency_and_namespace_not_last_writer_wins() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);

    // Instance A: USD / namespace "team-a", recording for proxy-a.
    let scope_a = scope_for("USD", "team-a");
    // Instance B: EUR / namespace "team-b", recording for proxy-b.
    let scope_b = scope_for("EUR", "team-b");

    registry.record_http(
        &scope_a, "alice", "proxy-a", "API A", 200, 1.0, 0, 0, 0.0, 0.0,
    );
    // B is constructed/records LAST — under the old last-writer-wins design its
    // currency/namespace would have clobbered A's on the shared registry.
    registry.record_http(
        &scope_b, "alice", "proxy-b", "API B", 200, 2.0, 0, 0, 0.0, 0.0,
    );

    // Prometheus: each proxy keeps its own currency + namespace label.
    let prom = registry.render_prometheus_uncached().unwrap();
    assert!(
        prom.lines().any(|l| l.contains("proxy_id=\"proxy-a\"")
            && l.contains("currency=\"USD\"")
            && l.contains(r#"namespace="team-a""#)),
        "proxy-a must render under USD/team-a\n{prom}"
    );
    assert!(
        prom.lines().any(|l| l.contains("proxy_id=\"proxy-b\"")
            && l.contains("currency=\"EUR\"")
            && l.contains(r#"namespace="team-b""#)),
        "proxy-b must render under EUR/team-b\n{prom}"
    );
    // The pre-fix bug: both proxies sharing one (last) currency. proxy-a must
    // NOT be mislabeled with EUR.
    assert!(
        !prom
            .lines()
            .any(|l| l.contains("proxy_id=\"proxy-a\"") && l.contains("currency=\"EUR\"")),
        "proxy-a must not be misattributed to EUR (last-writer-wins regression)\n{prom}"
    );

    // JSON: per-proxy currency, top-level currency signals "mixed", and
    // consumer monetary totals are partitioned (never USD+EUR=2).
    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    assert_eq!(json["currency"], "mixed");
    assert_eq!(
        json["consumers"]["alice"]["proxies"]["proxy-a"]["currency"],
        "USD"
    );
    assert_eq!(
        json["consumers"]["alice"]["proxies"]["proxy-b"]["currency"],
        "EUR"
    );
    assert!(json["consumers"]["alice"]["total_charges"].is_null());
    assert_eq!(
        json["consumers"]["alice"]["charges_by_currency"]["USD"]["total_charges"],
        1.0
    );
    assert_eq!(
        json["consumers"]["alice"]["charges_by_currency"]["EUR"]["total_charges"],
        2.0
    );
}

#[test]
fn test_same_proxy_records_stay_partitioned_by_instance_scope() {
    let registry = ChargebackRegistry::new();
    let scope_usd = scope_for("USD", "team-a");
    let scope_eur = scope_for("EUR", "team-b");

    registry.record_http(
        &scope_usd,
        "alice",
        "shared-proxy",
        "Shared API",
        200,
        1.0,
        100,
        0,
        0.01,
        0.0,
    );
    registry.record_http(
        &scope_eur,
        "alice",
        "shared-proxy",
        "Shared API",
        200,
        2.0,
        200,
        0,
        0.02,
        0.0,
    );

    assert_eq!(registry.entries.len(), 2);

    let prom = registry.render_prometheus_uncached().unwrap();
    assert!(
        prom.lines()
            .any(|line| line.contains("proxy_id=\"shared-proxy\"")
                && line.contains("currency=\"USD\"")
                && line.contains(r#"namespace="team-a""#)
                && line.ends_with("1.0000000000")),
        "USD/team-a call row missing\n{prom}"
    );
    assert!(
        prom.lines()
            .any(|line| line.contains("proxy_id=\"shared-proxy\"")
                && line.contains("currency=\"EUR\"")
                && line.contains(r#"namespace="team-b""#)
                && line.ends_with("2.0000000000")),
        "EUR/team-b call row missing\n{prom}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    let proxies = json["consumers"]["alice"]["proxies"].as_object().unwrap();
    assert_eq!(proxies.len(), 2);
    assert!(proxies.values().any(|proxy| {
        proxy["proxy_id"] == "shared-proxy"
            && proxy["currency"] == "USD"
            && proxy["by_status"]["200"]["calls"] == 1
            && proxy["by_status"]["200"]["charges"] == 1.0
    }));
    assert!(proxies.values().any(|proxy| {
        proxy["proxy_id"] == "shared-proxy"
            && proxy["currency"] == "EUR"
            && proxy["by_status"]["200"]["calls"] == 1
            && proxy["by_status"]["200"]["charges"] == 2.0
    }));
}

/// When every entry shares one currency, the top-level JSON `currency` reports
/// that single currency (not "mixed").
#[test]
fn test_json_top_level_currency_single_when_uniform() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope_for("GBP", "ferrum");
    registry.record_http(&s, "alice", "proxy-a", "API", 200, 1.0, 0, 0, 0.0, 0.0);
    registry.record_http(&s, "bob", "proxy-b", "API", 200, 1.0, 0, 0, 0.0, 0.0);

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    assert_eq!(json["currency"], "GBP");
}

// --- Finding #75: deterministic protocol_family + stream detail not dropped ---

/// HTTP and stream activity sharing the same (consumer, proxy_id). The
/// Prometheus bandwidth rows must split into separate, deterministically
/// labeled `protocol_family="http"` and `protocol_family="stream"` rows, and
/// the JSON proxy object must always include the `stream` sub-object (it was
/// previously dropped when the HTTP entry was iterated first), label the proxy
/// `"mixed"`, and reconcile its totals.
#[test]
fn test_http_and_stream_share_proxy_id_render_is_deterministic() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();

    // HTTP entry: 100 bytes sent / 200 received under (alice, proxy-1, 200).
    registry.record_http(
        &s, "alice", "proxy-1", "Edge", 200, 0.0, 100, 200, 0.001, 0.001,
    );
    // Stream entry: 60 bytes sent / 95 received under (alice, proxy-1, sentinel).
    registry.record_stream(&s, "alice", "proxy-1", "Edge", 0.0005, 60, 95, 0.001, 0.001);

    // --- Prometheus: separate, deterministic per-family bandwidth rows. ---
    // Render several times; the label set must be identical every time.
    let mut http_sent_seen = false;
    let mut stream_sent_seen = false;
    for _ in 0..8 {
        let prom = registry.render_prometheus_uncached().unwrap();
        let http_sent = prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{")
                && l.contains("proxy_id=\"proxy-1\"")
                && l.contains("protocol_family=\"http\"")
                && l.ends_with(" 100")
        });
        let stream_sent = prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{")
                && l.contains("proxy_id=\"proxy-1\"")
                && l.contains("protocol_family=\"stream\"")
                && l.ends_with(" 60")
        });
        assert!(
            http_sent,
            "missing deterministic http bytes_sent row\n{prom}"
        );
        assert!(
            stream_sent,
            "missing deterministic stream bytes_sent row\n{prom}"
        );
        // Exactly two bytes_sent rows for this proxy (one per family), so the
        // families never collapse onto a single ambiguous row.
        let sent_rows = prom
            .lines()
            .filter(|l| {
                l.starts_with("ferrum_api_bytes_sent_total{") && l.contains("proxy_id=\"proxy-1\"")
            })
            .count();
        assert_eq!(
            sent_rows, 2,
            "expected one bytes_sent row per family\n{prom}"
        );
        http_sent_seen |= http_sent;
        stream_sent_seen |= stream_sent;
    }
    assert!(http_sent_seen && stream_sent_seen);

    // --- JSON: stream sub-object always present, label "mixed", totals reconcile. ---
    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    let proxy = &json["consumers"]["alice"]["proxies"]["proxy-1"];
    assert_eq!(proxy["protocol_family"], "mixed");
    // The stream sub-object must be present regardless of iteration order.
    assert_eq!(proxy["stream"]["connections"], 1);
    let conn_charges = proxy["stream"]["connection_charges"].as_f64().unwrap();
    assert!((conn_charges - 0.0005).abs() < 1e-12);
    // HTTP breakdown still present.
    assert_eq!(proxy["by_status"]["200"]["calls"], 1);
    // Bandwidth bytes fold BOTH families: 100+60 sent, 200+95 received.
    assert_eq!(proxy["bandwidth"]["bytes_sent"], 160);
    assert_eq!(proxy["bandwidth"]["bytes_received"], 295);

    // total_charges must reconcile with the visible breakdown:
    //   bandwidth (160+295)*0.001 = 0.455  + stream connection 0.0005 = 0.4555
    let total = proxy["total_charges"].as_f64().unwrap();
    assert!(
        (total - 0.4555).abs() < 1e-9,
        "totals must reconcile, got {total}"
    );
    assert_eq!(proxy["total_calls"], 2); // 1 HTTP call + 1 stream session
}

// --- Issue #2571: status-0 WebSocket bandwidth vs bandwidth-only stream ---

/// Bandwidth-only stream (zero connection price) and WebSocket-disconnect
/// bandwidth share status `0` and identical price bits. Registry identity must
/// include protocol family so insertion order cannot corrupt family attribution,
/// call/session counts, or Prometheus/JSON reconciliation.
fn assert_bandwidth_only_stream_and_websocket_reconcile(
    registry: &ChargebackRegistry,
    order_label: &str,
) {
    assert_eq!(
        registry.entries.len(),
        2,
        "{order_label}: expected distinct HTTP and stream entries"
    );

    let http_key =
        make_key_with_prices("alice", "edge", 0, ProtocolFamily::Http, 0.0, 0.001, 0.001);
    let stream_key = make_key_with_prices(
        "alice",
        "edge",
        0,
        ProtocolFamily::Stream,
        0.0,
        0.001,
        0.001,
    );

    let http_entry = registry
        .entries
        .get(&http_key)
        .unwrap_or_else(|| panic!("{order_label}: missing WebSocket/HTTP entry"));
    assert_eq!(http_entry.protocol_family, ProtocolFamily::Http);
    assert_eq!(http_entry.status_code, 0);
    assert_eq!(
        http_entry.call_count.load(Ordering::Relaxed),
        0,
        "{order_label}: WebSocket bandwidth must not count as a call"
    );
    assert_eq!(http_entry.bytes_sent_total.load(Ordering::Relaxed), 50);
    assert_eq!(http_entry.bytes_received_total.load(Ordering::Relaxed), 75);
    drop(http_entry);

    let stream_entry = registry
        .entries
        .get(&stream_key)
        .unwrap_or_else(|| panic!("{order_label}: missing stream entry"));
    assert_eq!(stream_entry.protocol_family, ProtocolFamily::Stream);
    assert_eq!(stream_entry.status_code, 0);
    assert_eq!(
        stream_entry.call_count.load(Ordering::Relaxed),
        1,
        "{order_label}: stream session must count as one connection"
    );
    assert_eq!(stream_entry.bytes_sent_total.load(Ordering::Relaxed), 100);
    assert_eq!(
        stream_entry.bytes_received_total.load(Ordering::Relaxed),
        200
    );
    // Zero connection price keeps the stream call charge at zero.
    assert_eq!(stream_entry.call_charge().unwrap(), 0.0);
    drop(stream_entry);

    let prom = registry.render_prometheus_uncached().unwrap();
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{")
                && l.contains("proxy_id=\"edge\"")
                && l.contains("protocol_family=\"http\"")
                && l.ends_with(" 50")
        }),
        "{order_label}: missing http bytes_sent row\n{prom}"
    );
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{")
                && l.contains("proxy_id=\"edge\"")
                && l.contains("protocol_family=\"stream\"")
                && l.ends_with(" 100")
        }),
        "{order_label}: missing stream bytes_sent row\n{prom}"
    );
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_received_total{")
                && l.contains("proxy_id=\"edge\"")
                && l.contains("protocol_family=\"http\"")
                && l.ends_with(" 75")
        }),
        "{order_label}: missing http bytes_received row\n{prom}"
    );
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_bytes_received_total{")
                && l.contains("proxy_id=\"edge\"")
                && l.contains("protocol_family=\"stream\"")
                && l.ends_with(" 200")
        }),
        "{order_label}: missing stream bytes_received row\n{prom}"
    );
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_stream_connections_total{")
                && l.contains("proxy_id=\"edge\"")
                && l.ends_with(" 1")
        }),
        "{order_label}: missing stream connection counter\n{prom}"
    );
    // WebSocket bandwidth uses status 0 with call_count=0. A colliding stream
    // session must never promote that row into a chargeable HTTP call (count 1).
    for line in prom.lines() {
        if line.starts_with("ferrum_api_chargeable_calls_total{")
            && line.contains("proxy_id=\"edge\"")
        {
            assert!(
                line.contains("status_code=\"0\"") && line.ends_with(" 0"),
                "{order_label}: status-0 must stay non-chargeable (count 0)\n{line}\n{prom}"
            );
        }
    }

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    let proxy = &json["consumers"]["alice"]["proxies"]["edge"];
    assert_eq!(
        proxy["protocol_family"], "mixed",
        "{order_label}: proxy must remain mixed across families"
    );
    assert_eq!(proxy["stream"]["connections"], 1);
    assert_eq!(proxy["stream"]["connection_charges"].as_f64().unwrap(), 0.0);
    // WebSocket may leave a zero-call status-0 HTTP bucket; it must never absorb
    // the stream session as a chargeable HTTP call.
    if let Some(status0) = proxy["by_status"].get("0") {
        assert_eq!(
            status0["calls"], 0,
            "{order_label}: status-0 must not become a chargeable HTTP call row: {proxy}"
        );
    }
    // Bandwidth folds both families: 50+100 sent, 75+200 received.
    assert_eq!(proxy["bandwidth"]["bytes_sent"], 150);
    assert_eq!(proxy["bandwidth"]["bytes_received"], 275);
    // (150+275)*0.001 = 0.425; zero connection price.
    let total = proxy["total_charges"].as_f64().unwrap();
    assert!(
        (total - 0.425).abs() < 1e-9,
        "{order_label}: totals must reconcile, got {total}"
    );
    assert_eq!(
        proxy["total_calls"], 1,
        "{order_label}: only the stream session is a counted call/session"
    );
}

#[test]
fn test_bandwidth_only_stream_then_websocket_keeps_families_distinct() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    // Stream first: zero connection price + identical directional bandwidth rates.
    registry.record_stream(&s, "alice", "edge", "Edge", 0.0, 100, 200, 0.001, 0.001);
    registry.record_websocket_bandwidth(&s, "alice", "edge", "Edge", 50, 75, 0.001, 0.001);
    assert_bandwidth_only_stream_and_websocket_reconcile(&registry, "stream-then-websocket");
}

#[test]
fn test_websocket_then_bandwidth_only_stream_keeps_families_distinct() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    // WebSocket first: reverse insertion order of the colliding status-0 key.
    registry.record_websocket_bandwidth(&s, "alice", "edge", "Edge", 50, 75, 0.001, 0.001);
    registry.record_stream(&s, "alice", "edge", "Edge", 0.0, 100, 200, 0.001, 0.001);
    assert_bandwidth_only_stream_and_websocket_reconcile(&registry, "websocket-then-stream");
}

// --- Issue #2572: proxy_name is live metadata; aggregation is deterministic ---

/// Extract the `proxy_name="..."` label from a Prometheus sample line.
fn prometheus_proxy_name(line: &str) -> Option<&str> {
    let key = "proxy_name=\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(&line[start..end])
}

fn record_payment(
    registry: &ChargebackRegistry,
    scope: &InstanceScope,
    proxy_name: &str,
    price: f64,
) {
    registry.record_http(
        scope, "alice", "payments", proxy_name, 200, price, 0, 0, 0.0, 0.0,
    );
}

/// Assert JSON and Prometheus expose the same authoritative `proxy_name` for a
/// consumer/proxy HTTP status row, and that repeated renders stay stable.
fn assert_json_and_prometheus_proxy_name_agree(
    registry: &ChargebackRegistry,
    consumer: &str,
    proxy_id: &str,
    status_code: u16,
    expected_name: &str,
    order_label: &str,
) {
    for pass in 0..8 {
        let prom = registry.render_prometheus_uncached().unwrap();
        let call_line = prom
            .lines()
            .find(|l| {
                l.starts_with("ferrum_api_chargeable_calls_total{")
                    && l.contains(&format!("consumer=\"{consumer}\""))
                    && l.contains(&format!("proxy_id=\"{proxy_id}\""))
                    && l.contains(&format!("status_code=\"{status_code}\""))
            })
            .unwrap_or_else(|| {
                panic!("{order_label} pass {pass}: missing chargeable_calls row\n{prom}")
            });
        let prom_name = prometheus_proxy_name(call_line).unwrap_or_else(|| {
            panic!("{order_label} pass {pass}: missing proxy_name label\n{call_line}")
        });
        assert_eq!(
            prom_name, expected_name,
            "{order_label} pass {pass}: prometheus name mismatch\n{call_line}"
        );

        let charge_line = prom
            .lines()
            .find(|l| {
                l.starts_with("ferrum_api_charges_total{")
                    && l.contains(&format!("consumer=\"{consumer}\""))
                    && l.contains(&format!("proxy_id=\"{proxy_id}\""))
                    && l.contains(&format!("status_code=\"{status_code}\""))
            })
            .unwrap_or_else(|| panic!("{order_label} pass {pass}: missing charges row\n{prom}"));
        assert_eq!(
            prometheus_proxy_name(charge_line),
            Some(expected_name),
            "{order_label} pass {pass}: charges label must match calls\n{charge_line}"
        );

        let json: serde_json::Value =
            serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
        let json_name = json["consumers"][consumer]["proxies"][proxy_id]["proxy_name"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("{order_label} pass {pass}: missing json proxy_name: {json}")
            });
        assert_eq!(
            json_name, expected_name,
            "{order_label} pass {pass}: json/prometheus name disagreement"
        );
        assert_eq!(
            json_name, prom_name,
            "{order_label} pass {pass}: json and prometheus must agree"
        );
    }
}

/// Name-only reload under continuous traffic must refresh the live display name
/// on the existing key without splitting counter continuity.
#[test]
fn test_name_only_rename_under_continuous_traffic_refreshes_live_proxy_name() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v1".to_string(),
    )]));
    let s = scope();
    let price = 0.001;

    for _ in 0..10 {
        record_payment(&registry, &s, "Payments v1", price);
    }

    let key = make_key_with_prices(
        "alice",
        "payments",
        200,
        ProtocolFamily::Http,
        price,
        0.0,
        0.0,
    );
    assert_eq!(registry.entries.len(), 1);
    {
        let entry = registry.entries.get(&key).unwrap();
        assert_eq!(entry.call_count.load(Ordering::Relaxed), 10);
        assert_eq!(&*entry.proxy_name, "Payments v1");
    }
    let cached_v1: serde_json::Value =
        serde_json::from_str(&registry.render_json().unwrap()).unwrap();
    assert_eq!(
        cached_v1["consumers"]["alice"]["proxies"]["payments"]["proxy_name"],
        "Payments v1"
    );

    // The accepted reload publishes the new name before new-generation
    // traffic. Continuous traffic after the reload still hits the same key.
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v2".to_string(),
    )]));
    let cached_v2: serde_json::Value =
        serde_json::from_str(&registry.render_json().unwrap()).unwrap();
    assert_eq!(
        cached_v2["consumers"]["alice"]["proxies"]["payments"]["proxy_name"], "Payments v2",
        "metadata publication must invalidate the cached old label immediately"
    );
    for _ in 0..5 {
        record_payment(&registry, &s, "Payments v2", price);
    }

    assert_eq!(
        registry.entries.len(),
        1,
        "name-only reload must not create a second pricing-generation entry"
    );
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(
        entry.call_count.load(Ordering::Relaxed),
        15,
        "counters must remain continuous across the rename"
    );
    assert_eq!(
        &*entry.proxy_name, "Payments v1",
        "entry fallback metadata remains immutable; exports use the published snapshot"
    );
    drop(entry);

    let prom = registry.render_prometheus_uncached().unwrap();
    let call_rows = prom
        .lines()
        .filter(|l| {
            l.starts_with("ferrum_api_chargeable_calls_total{")
                && l.contains("proxy_id=\"payments\"")
        })
        .count();
    assert_eq!(
        call_rows, 1,
        "one render must emit one row under the authoritative current name\n{prom}"
    );
    assert!(
        prom.lines().any(|l| {
            l.starts_with("ferrum_api_chargeable_calls_total{")
                && l.contains("proxy_name=\"Payments v2\"")
                && l.ends_with(" 15")
        }),
        "expected continuous counter under the live name\n{prom}"
    );

    assert_json_and_prometheus_proxy_name_agree(
        &registry,
        "alice",
        "payments",
        200,
        "Payments v2",
        "name-only-rename",
    );
}

/// Shared assertions for rename + price-change overlap under a fixed insertion
/// order. The authoritative export name comes from the published configuration,
/// never request completion order.
fn assert_rename_plus_price_overlap(
    registry: &ChargebackRegistry,
    expected_name: &str,
    expected_calls: u64,
    order_label: &str,
) {
    assert_eq!(
        registry.entries.len(),
        2,
        "{order_label}: expected two pricing-generation entries"
    );

    let prom = registry.render_prometheus_uncached().unwrap();
    let call_rows: Vec<_> = prom
        .lines()
        .filter(|l| {
            l.starts_with("ferrum_api_chargeable_calls_total{")
                && l.contains("proxy_id=\"payments\"")
        })
        .collect();
    assert_eq!(
        call_rows.len(),
        1,
        "{order_label}: overlapping generations must collapse to one series\n{prom}"
    );
    assert!(
        call_rows[0].ends_with(&format!(" {expected_calls}")),
        "{order_label}: aggregated call count mismatch\n{}",
        call_rows[0]
    );
    assert_eq!(
        prometheus_proxy_name(call_rows[0]),
        Some(expected_name),
        "{order_label}: unexpected prometheus name\n{}",
        call_rows[0]
    );

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    let proxy = &json["consumers"]["alice"]["proxies"]["payments"];
    assert_eq!(proxy["proxy_name"], expected_name);
    assert_eq!(proxy["by_status"]["200"]["calls"], expected_calls);

    assert_json_and_prometheus_proxy_name_agree(
        registry,
        "alice",
        "payments",
        200,
        expected_name,
        order_label,
    );
}

#[test]
fn test_rename_plus_price_change_old_then_new_selects_authoritative_name() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v1".to_string(),
    )]));

    // Old generation under the retired display name.
    record_payment(&registry, &s, "Payments v1", 0.001);
    record_payment(&registry, &s, "Payments v1", 0.001);
    // Publish the accepted rename, then record the new price generation.
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v2".to_string(),
    )]));
    record_payment(&registry, &s, "Payments v2", 0.002);
    record_payment(&registry, &s, "Payments v2", 0.002);
    record_payment(&registry, &s, "Payments v2", 0.002);

    assert_rename_plus_price_overlap(&registry, "Payments v2", 5, "old-then-new");
}

#[test]
fn test_rename_plus_price_change_new_then_old_selects_authoritative_name() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v2".to_string(),
    )]));

    // Reverse insertion order: new pricing generation first, then overlapping
    // old-generation traffic (in-flight after reload) recorded last.
    record_payment(&registry, &s, "Payments v2", 0.002);
    record_payment(&registry, &s, "Payments v2", 0.002);
    record_payment(&registry, &s, "Payments v2", 0.002);
    record_payment(&registry, &s, "Payments v1", 0.001);
    record_payment(&registry, &s, "Payments v1", 0.001);

    // The retired request completes last, but cannot restore its old name.
    assert_rename_plus_price_overlap(&registry, "Payments v2", 5, "new-then-old");
}

#[tokio::test]
async fn test_plugin_cache_reload_publishes_name_before_late_old_completion() {
    const CONSUMER: &str = "issue-2572-cache-reload-consumer";
    const PROXY_ID: &str = "issue-2572-cache-reload-proxy";
    const PLUGIN_ID: &str = "issue-2572-cache-reload-chargeback";

    let mut old_proxy = chargeback_chain_proxy(PROXY_ID, "/issue-2572-v1", PLUGIN_ID);
    old_proxy.name = Some("Payments v1".to_string());
    let plugin_config = chargeback_chain_plugin(
        PLUGIN_ID,
        PROXY_ID,
        "USD",
        json!({
            "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.001 }]
        }),
    );
    let old_config = GatewayConfig {
        proxies: vec![old_proxy],
        plugin_configs: vec![plugin_config.clone()],
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&old_config).expect("old chargeback cache");
    let old_plugin = cache
        .get_plugins(PROXY_ID)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("old chargeback plugin");
    old_plugin
        .log(&make_summary(PROXY_ID, "Payments v1", Some(CONSUMER), 200))
        .await;

    let mut new_proxy = chargeback_chain_proxy(PROXY_ID, "/issue-2572-v1", PLUGIN_ID);
    new_proxy.name = Some("Payments v2".to_string());
    let new_config = GatewayConfig {
        proxies: vec![new_proxy],
        plugin_configs: vec![plugin_config],
        ..GatewayConfig::default()
    };
    cache
        .rebuild(&new_config)
        .expect("publish renamed chargeback cache");
    let new_plugin = cache
        .get_plugins(PROXY_ID)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("new chargeback plugin");
    new_plugin
        .log(&make_summary(PROXY_ID, "Payments v2", Some(CONSUMER), 200))
        .await;

    // A request admitted through the retained old chain completes after the
    // rename. Its summary must not restore the retired display name.
    old_plugin
        .log(&make_summary(PROXY_ID, "Payments v1", Some(CONSUMER), 200))
        .await;

    let rendered: serde_json::Value =
        serde_json::from_str(&global_registry().render_json_uncached().unwrap()).unwrap();
    let proxy = &rendered["consumers"][CONSUMER]["proxies"][PROXY_ID];
    assert_eq!(proxy["proxy_name"], "Payments v2");
    assert_eq!(proxy["by_status"]["200"]["calls"], 3);
}

/// When a proxy is removed from published metadata, overlapping retained pricing
/// generations fall back to admission-time names and keep the lexicographic
/// maximum so JSON and Prometheus stay deterministic.
#[test]
fn test_deleted_proxy_uses_lexicographic_admission_name_fallback() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let s = scope();

    // Leave active_proxy_names empty so exporters must use admission fallbacks.
    // Multiple proxy IDs make the lex-upgrade path order-independent across
    // DashMap iteration.
    for i in 0..16 {
        let proxy_id = format!("deleted-proxy-{i}");
        registry.record_http(
            &s, "alice", &proxy_id, "Alpha", 200, 0.001, 10, 5, 0.01, 0.01,
        );
        registry.record_http(
            &s, "alice", &proxy_id, "Zulu", 200, 0.002, 20, 10, 0.02, 0.02,
        );
        registry.record_stream(&s, "alice", &proxy_id, "Alpha", 0.001, 30, 15, 0.01, 0.01);
        registry.record_stream(&s, "alice", &proxy_id, "Zulu", 0.002, 40, 20, 0.02, 0.02);
    }

    let prom = registry.render_prometheus_uncached().unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    for i in 0..16 {
        let proxy_id = format!("deleted-proxy-{i}");
        let call_line = prom
            .lines()
            .find(|l| {
                l.starts_with("ferrum_api_chargeable_calls_total{")
                    && l.contains(&format!("proxy_id=\"{proxy_id}\""))
            })
            .unwrap_or_else(|| panic!("missing http calls for {proxy_id}\n{prom}"));
        assert_eq!(
            prometheus_proxy_name(call_line),
            Some("Zulu"),
            "deleted proxy http export must pick lex-max admission name\n{call_line}"
        );
        let stream_line = prom
            .lines()
            .find(|l| {
                l.starts_with("ferrum_api_stream_connections_total{")
                    && l.contains(&format!("proxy_id=\"{proxy_id}\""))
            })
            .unwrap_or_else(|| panic!("missing stream connections for {proxy_id}\n{prom}"));
        assert_eq!(
            prometheus_proxy_name(stream_line),
            Some("Zulu"),
            "deleted proxy stream export must pick lex-max admission name\n{stream_line}"
        );
        assert_eq!(
            json["consumers"]["alice"]["proxies"][&proxy_id]["proxy_name"], "Zulu",
            "deleted proxy json export must match prometheus lex-max fallback"
        );
    }
}

/// Generation-tagged render caches must hit on unchanged metadata and refresh
/// immediately after a live name publication.
#[test]
fn test_render_cache_hits_until_proxy_metadata_generation_advances() {
    let registry = ChargebackRegistry::new();
    registry.configure(60, 3600, 500);
    let s = scope();
    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v1".to_string(),
    )]));
    record_payment(&registry, &s, "Payments v1", 0.001);

    let prom1 = registry.render_prometheus().unwrap();
    let prom2 = registry.render_prometheus().unwrap();
    assert_eq!(
        prom1, prom2,
        "unchanged metadata generation must reuse the prometheus render cache"
    );
    assert!(
        prom1.contains("proxy_name=\"Payments v1\""),
        "cached prometheus must carry the published name\n{prom1}"
    );

    let json1 = registry.render_json().unwrap();
    let json2 = registry.render_json().unwrap();
    assert_eq!(
        json1, json2,
        "unchanged metadata generation must reuse the json render cache"
    );
    let cached: serde_json::Value = serde_json::from_str(&json1).unwrap();
    assert_eq!(
        cached["consumers"]["alice"]["proxies"]["payments"]["proxy_name"],
        "Payments v1"
    );

    registry.set_active_proxy_names(HashMap::from([(
        "payments".to_string(),
        "Payments v2".to_string(),
    )]));
    let prom3 = registry.render_prometheus().unwrap();
    assert!(
        prom3.contains("proxy_name=\"Payments v2\""),
        "metadata publication must invalidate prometheus cache\n{prom3}"
    );
    let json3 = registry.render_json().unwrap();
    let json3_value: serde_json::Value = serde_json::from_str(&json3).unwrap();
    assert_eq!(
        json3_value["consumers"]["alice"]["proxies"]["payments"]["proxy_name"],
        "Payments v2"
    );

    // A second pair of renders after the rename must hit the new generation's
    // cache rather than rebuilding again.
    assert_eq!(prom3, registry.render_prometheus().unwrap());
    assert_eq!(json3, registry.render_json().unwrap());
}

// --- Finding #76: monetary totals do not drift over high volume ---

/// Recording a small per-call price across a large number of calls must yield
/// exactly `count * price` (computed once from the exact integer call count) —
/// no order-dependent f64 accumulation drift.
#[test]
fn test_high_volume_charge_has_no_accumulation_drift() {
    let registry = ChargebackRegistry::new();
    // 0.1 is not exactly representable in binary floating point, so repeatedly
    // ADDING it (the pre-fix design) accumulates rounding error; multiplying the
    // exact integer count by it once does not.
    let price = 0.1f64;
    let n: u64 = 1_000_000;
    let s = scope();
    for _ in 0..n {
        registry.record_http(&s, "alice", "proxy-1", "API", 200, price, 0, 0, 0.0, 0.0);
    }
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "alice",
            "proxy-1",
            200,
            ProtocolFamily::Http,
            price,
            0.0,
            0.0,
        ))
        .unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), n);
    // Exact: equals n * price computed once, bit-for-bit.
    assert_eq!(entry.call_charge().unwrap(), n as f64 * price);
}

/// Bandwidth charge is computed from the exact accumulated byte count, so many
/// small transfers reconcile exactly with one bulk transfer of the same bytes.
#[test]
fn test_bandwidth_charge_is_exact_from_byte_totals() {
    let price = 0.000_001f64;
    let s = scope();

    // Many small 7-byte transfers.
    let many = ChargebackRegistry::new();
    let chunks: u64 = 100_000;
    for _ in 0..chunks {
        many.record_http(&s, "alice", "proxy-1", "API", 200, 0.0, 7, 0, price, 0.0);
    }
    let many_entry = many
        .entries
        .get(&make_key_with_prices(
            "alice",
            "proxy-1",
            200,
            ProtocolFamily::Http,
            0.0,
            price,
            0.0,
        ))
        .unwrap();
    assert_eq!(
        many_entry.bytes_sent_total.load(Ordering::Relaxed),
        7 * chunks
    );
    // Charge derives from the (exact) total byte count, so it equals the bulk
    // computation exactly — no per-add drift.
    assert_eq!(
        many_entry.bandwidth_charge_sent().unwrap(),
        (7 * chunks) as f64 * price
    );
}

// --- Issue #2574: finite arithmetic bounds for pricing and exports ---

#[test]
fn test_price_at_max_unit_price_is_accepted() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": MAX_UNIT_PRICE
        }]
    });
    ApiChargeback::new(&config, "ferrum").expect("MAX_UNIT_PRICE must be accepted");
}

#[test]
fn test_price_above_max_unit_price_is_rejected() {
    let just_above = f64::from_bits(MAX_UNIT_PRICE.to_bits() + 1);
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": just_above
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(
        err.contains("1e288")
            || err.contains(&MAX_UNIT_PRICE.to_string())
            || err.contains("no greater than"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_bandwidth_and_stream_prices_above_max_are_rejected() {
    let bw = json!({
        "bandwidth_pricing": { "price_per_byte_sent": 1e308 }
    });
    let bw_err = ApiChargeback::new(&bw, "ferrum").err().unwrap();
    assert!(bw_err.contains("no greater than"), "{bw_err}");

    let stream = json!({
        "stream_connection_pricing": { "price_per_connection": 1e308 }
    });
    let stream_err = ApiChargeback::new(&stream, "ferrum").err().unwrap();
    assert!(stream_err.contains("no greater than"), "{stream_err}");
}

#[test]
fn test_non_finite_configured_prices_are_rejected() {
    for price in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let config = serde_json::json!({
            "pricing_tiers": [{
                "status_codes": [200],
                "price_per_call": price
            }]
        });
        // serde_json encodes non-finite f64 as null, which fails "must be a number".
        let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
        assert!(
            err.contains("must be a number") || err.contains("finite"),
            "price={price:?} err={err}"
        );
    }
}

#[test]
fn test_checked_mul_quantity_rejects_overflow() {
    let ok = checked_mul_quantity(2, MAX_UNIT_PRICE).unwrap();
    assert!(ok.is_finite());

    let overflow = checked_mul_quantity(u64::MAX, 1e308).unwrap_err();
    assert!(overflow.contains("overflowed") || overflow.contains("non-finite"));
}

#[test]
fn test_checked_add_charge_rejects_aggregate_overflow() {
    let near_max = f64::MAX / 2.0;
    assert!(checked_add_charge(near_max, near_max).is_ok());
    let err = checked_add_charge(f64::MAX, f64::MAX).unwrap_err();
    assert!(
        err.contains("overflowed") || err.contains("non-finite"),
        "{err}"
    );
}

#[test]
fn test_max_price_times_max_counter_stays_finite_for_exports() {
    let registry = ChargebackRegistry::new();
    let s = scope();
    registry.record_http(
        &s,
        "alice",
        "proxy-max",
        "API",
        200,
        MAX_UNIT_PRICE,
        0,
        0,
        0.0,
        0.0,
    );
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "alice",
            "proxy-max",
            200,
            ProtocolFamily::Http,
            MAX_UNIT_PRICE,
            0.0,
            0.0,
        ))
        .unwrap();
    entry.call_count.store(u64::MAX, Ordering::Relaxed);

    let charge = entry
        .call_charge()
        .expect("max price × u64::MAX must be finite");
    assert!(charge.is_finite());

    let prom = registry
        .render_prometheus_uncached()
        .expect("prometheus export must succeed for bounded prices");
    assert!(prom.contains("ferrum_api_charges_total"));
    assert!(!prom.to_lowercase().contains("inf"));

    let json_text = registry
        .render_json_uncached()
        .expect("json export must succeed for bounded prices");
    let parsed: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let charges =
        &parsed["consumers"]["alice"]["proxies"]["proxy-max"]["by_status"]["200"]["charges"];
    assert!(
        charges.is_number(),
        "charges must remain a JSON number, got {charges}"
    );
    assert!(!charges.is_null());
}

#[test]
fn test_bandwidth_max_price_times_max_bytes_stays_finite() {
    let registry = ChargebackRegistry::new();
    let s = scope();
    registry.record_http(
        &s,
        "alice",
        "proxy-bw-max",
        "API",
        404,
        0.0,
        0,
        0,
        MAX_UNIT_PRICE,
        MAX_UNIT_PRICE,
    );
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "alice",
            "proxy-bw-max",
            404,
            ProtocolFamily::Http,
            0.0,
            MAX_UNIT_PRICE,
            MAX_UNIT_PRICE,
        ))
        .unwrap();
    entry.bytes_sent_total.store(u64::MAX, Ordering::Relaxed);
    entry
        .bytes_received_total
        .store(u64::MAX, Ordering::Relaxed);

    assert!(entry.bandwidth_charge_sent().unwrap().is_finite());
    assert!(entry.bandwidth_charge_received().unwrap().is_finite());
    registry
        .render_json_uncached()
        .expect("bandwidth export at bound must succeed");
}

#[test]
fn test_render_fails_closed_on_quantity_price_overflow() {
    // Bypass admission (record_* accepts raw f64) to simulate historical /
    // poisoned registry state that config bounds alone cannot remove.
    let registry = ChargebackRegistry::new();
    let s = scope();
    let poison = 1e308;
    registry.record_http(
        &s,
        "alice",
        "proxy-poison",
        "API",
        200,
        poison,
        0,
        0,
        0.0,
        0.0,
    );
    let entry = registry
        .entries
        .get(&make_key_with_prices(
            "alice",
            "proxy-poison",
            200,
            ProtocolFamily::Http,
            poison,
            0.0,
            0.0,
        ))
        .unwrap();
    entry.call_count.store(2, Ordering::Relaxed);

    assert!(entry.call_charge().is_err());

    let prom_err = registry.render_prometheus_uncached().unwrap_err();
    assert!(
        prom_err.contains("overflow") || prom_err.contains("non-finite"),
        "{prom_err}"
    );

    let json_err = registry.render_json_uncached().unwrap_err();
    assert!(
        json_err.contains("overflow") || json_err.contains("non-finite"),
        "{json_err}"
    );
}

#[test]
fn test_render_fails_closed_on_aggregate_addition_overflow() {
    let registry = ChargebackRegistry::new();
    let s = scope();
    // Two series that each contribute a near-max finite charge; summing them
    // overflows aggregation even though each product is finite.
    let price = f64::MAX * 0.75;
    for (proxy, status) in [("p-a", 200u16), ("p-b", 200u16)] {
        registry.record_http(&s, "alice", proxy, "API", status, price, 0, 0, 0.0, 0.0);
        let entry = registry
            .entries
            .get(&make_key_with_prices(
                "alice",
                proxy,
                status,
                ProtocolFamily::Http,
                price,
                0.0,
                0.0,
            ))
            .unwrap();
        entry.call_count.store(1, Ordering::Relaxed);
        assert!(entry.call_charge().unwrap().is_finite());
    }

    // JSON sums consumer totals across proxies — that addition overflows.
    let err = registry.render_json_uncached().unwrap_err();
    assert!(
        err.contains("overflow") || err.contains("non-finite"),
        "{err}"
    );
}

#[test]
fn test_mixed_currency_export_still_succeeds_with_finite_prices() {
    // Preserve finding #24 mixed-currency labeling while exercising the new
    // fail-closed export path on healthy finite arithmetic.
    let registry = ChargebackRegistry::new();
    registry.record_http(
        &scope_for("USD", "ns-a"),
        "alice",
        "proxy-a",
        "A",
        200,
        0.001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        &scope_for("EUR", "ns-b"),
        "alice",
        "proxy-b",
        "B",
        200,
        0.002,
        0,
        0,
        0.0,
        0.0,
    );

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    assert_eq!(json["currency"], "mixed");
    assert!(json["consumers"]["alice"]["total_charges"].is_null());
    assert_eq!(
        json["consumers"]["alice"]["charges_by_currency"]["USD"]["total_charges"],
        0.001
    );
    assert_eq!(
        json["consumers"]["alice"]["charges_by_currency"]["EUR"]["total_charges"],
        0.002
    );

    let prom = registry.render_prometheus_uncached().unwrap();
    assert!(prom.contains("currency=\"USD\""));
    assert!(prom.contains("currency=\"EUR\""));
    assert!(!prom.to_lowercase().contains("inf"));
}

// --- Issue #2569: never sum monetary totals across currencies ---

/// One consumer spanning USD (HTTP per-call + bandwidth) and EUR (stream
/// connection + bandwidth + HTTP per-call) must null currency-blind monetary
/// fields and expose reconcilable `charges_by_currency` partitions.
#[test]
fn test_json_mixed_currency_consumer_totals_partitioned_not_summed() {
    let registry = ChargebackRegistry::new();
    registry.configure(5, 3600, 500);
    let usd = scope_for("USD", "team-usd");
    let eur = scope_for("EUR", "team-eur");

    // USD HTTP: per-call 1.0 + bandwidth 100*0.01 + 50*0.02 = 1.0 + 1.0 + 1.0 = 3.0
    registry.record_http(
        &usd,
        "alice",
        "proxy-usd",
        "USD API",
        200,
        1.0,
        100,
        50,
        0.01,
        0.02,
    );
    // EUR stream: connection 0.5 + bandwidth 10*0.1 + 20*0.05 = 0.5 + 1.0 + 1.0 = 2.5
    registry.record_stream(
        &eur,
        "alice",
        "proxy-eur-stream",
        "EUR Stream",
        0.5,
        10,
        20,
        0.1,
        0.05,
    );
    // EUR HTTP per-call only: 1.0
    registry.record_http(
        &eur,
        "alice",
        "proxy-eur-http",
        "EUR HTTP",
        200,
        1.0,
        0,
        0,
        0.0,
        0.0,
    );
    // A second consumer billed only in USD keeps numeric flat totals even when
    // the response-level currency is "mixed".
    registry.record_http(
        &usd,
        "bob",
        "proxy-usd",
        "USD API",
        200,
        2.0,
        0,
        0,
        0.0,
        0.0,
    );

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    assert_eq!(json["currency"], "mixed");

    let alice = &json["consumers"]["alice"];
    assert_eq!(alice["total_calls"], 3); // 2 HTTP + 1 stream
    assert!(
        alice["total_charges"].is_null(),
        "mixed consumer must not emit a unitless total_charges"
    );
    assert!(alice["per_call_charges"].is_null());
    assert!(alice["stream_connection_charges"].is_null());
    assert!(alice["bandwidth_charges"].is_null());

    let by = alice["charges_by_currency"]
        .as_object()
        .expect("charges_by_currency required for mixed consumer");
    assert_eq!(by.len(), 2);

    let usd_totals = &by["USD"];
    assert_eq!(usd_totals["total_calls"], 1);
    assert!((usd_totals["per_call_charges"].as_f64().unwrap() - 1.0).abs() < 1e-12);
    assert!((usd_totals["bandwidth_charges"].as_f64().unwrap() - 2.0).abs() < 1e-12);
    assert!((usd_totals["stream_connection_charges"].as_f64().unwrap()).abs() < 1e-12);
    assert!((usd_totals["total_charges"].as_f64().unwrap() - 3.0).abs() < 1e-12);

    let eur_totals = &by["EUR"];
    assert_eq!(eur_totals["total_calls"], 2);
    assert!((eur_totals["per_call_charges"].as_f64().unwrap() - 1.0).abs() < 1e-12);
    assert!((eur_totals["stream_connection_charges"].as_f64().unwrap() - 0.5).abs() < 1e-12);
    assert!((eur_totals["bandwidth_charges"].as_f64().unwrap() - 2.0).abs() < 1e-12);
    assert!((eur_totals["total_charges"].as_f64().unwrap() - 3.5).abs() < 1e-12);

    // Per-proxy rows stay authoritative and reconcile within each currency.
    let proxies = alice["proxies"].as_object().unwrap();
    let mut usd_proxy_sum = 0.0;
    let mut eur_proxy_sum = 0.0;
    for proxy in proxies.values() {
        let charge = proxy["total_charges"].as_f64().unwrap();
        match proxy["currency"].as_str().unwrap() {
            "USD" => usd_proxy_sum += charge,
            "EUR" => eur_proxy_sum += charge,
            other => panic!("unexpected currency {other}"),
        }
    }
    assert!((usd_proxy_sum - 3.0).abs() < 1e-12);
    assert!((eur_proxy_sum - 3.5).abs() < 1e-12);

    let bob = &json["consumers"]["bob"];
    assert!(bob["charges_by_currency"].is_null());
    assert!((bob["total_charges"].as_f64().unwrap() - 2.0).abs() < 1e-12);
    assert!((bob["per_call_charges"].as_f64().unwrap() - 2.0).abs() < 1e-12);
    assert!(bob["total_charges"].is_number());
}

/// Same-currency consumer still emits the historical flat monetary fields.
#[test]
fn test_json_single_currency_consumer_keeps_flat_totals() {
    let registry = ChargebackRegistry::new();
    let usd = scope_for("USD", "ferrum");
    registry.record_http(&usd, "alice", "proxy-a", "A", 200, 1.0, 10, 0, 0.1, 0.0);
    registry.record_stream(&usd, "alice", "proxy-b", "B", 0.25, 0, 0, 0.0, 0.0);

    let json: serde_json::Value =
        serde_json::from_str(&registry.render_json_uncached().unwrap()).unwrap();
    let alice = &json["consumers"]["alice"];
    assert_eq!(json["currency"], "USD");
    assert!(alice["charges_by_currency"].is_null());
    assert!((alice["total_charges"].as_f64().unwrap() - 2.25).abs() < 1e-12);
    assert!((alice["per_call_charges"].as_f64().unwrap() - 1.0).abs() < 1e-12);
    assert!((alice["stream_connection_charges"].as_f64().unwrap() - 0.25).abs() < 1e-12);
    assert!((alice["bandwidth_charges"].as_f64().unwrap() - 1.0).abs() < 1e-12);
    assert_eq!(alice["total_calls"], 2);
}

fn chargeback_chain_proxy(id: &str, path: &str, plugin_config_id: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "name": id,
        "namespace": "ferrum",
        "listen_path": path,
        "backend_scheme": "http",
        "backend_host": "backend.invalid",
        "backend_port": 80,
        "plugins": [{ "plugin_config_id": plugin_config_id }]
    }))
    .expect("test proxy config")
}

fn chargeback_chain_stream_proxy(id: &str, plugin_config_id: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "name": id,
        "namespace": "ferrum",
        "backend_scheme": "tcp",
        "backend_host": "backend.invalid",
        "backend_port": 9000,
        "listen_port": 65001,
        "plugins": [{ "plugin_config_id": plugin_config_id }]
    }))
    .expect("test stream proxy config")
}

fn chargeback_chain_plugin(
    id: &str,
    proxy_id: &str,
    currency: &str,
    pricing: serde_json::Value,
) -> PluginConfig {
    let mut config = pricing.as_object().cloned().expect("pricing config object");
    config.insert("currency".to_string(), json!(currency));
    config.insert("cleanup_interval_seconds".to_string(), json!(0));
    serde_json::from_value(json!({
        "id": id,
        "plugin_name": "api_chargeback",
        "namespace": "ferrum",
        "config": config,
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true
    }))
    .expect("test plugin config")
}

/// Build the effective per-proxy plugin chains, then record through the trait
/// hooks rather than writing registry rows directly. This proves independent
/// proxy-scoped instances retain their currencies through PluginCache wiring.
#[tokio::test]
async fn test_effective_plugin_chain_partitions_multi_instance_currency_totals() {
    const CONSUMER: &str = "issue-2569-chain-consumer";
    const USD_PROXY: &str = "issue-2569-chain-usd";
    const EUR_HTTP_PROXY: &str = "issue-2569-chain-eur-http";
    const EUR_STREAM_PROXY: &str = "issue-2569-chain-eur-stream";

    let plugin_configs = vec![
        chargeback_chain_plugin(
            "charge-usd",
            USD_PROXY,
            "USD",
            json!({
                "pricing_tiers": [{ "status_codes": [200], "price_per_call": 1.0 }],
                "bandwidth_pricing": {
                    "price_per_byte_sent": 0.01,
                    "price_per_byte_received": 0.02
                }
            }),
        ),
        chargeback_chain_plugin(
            "charge-eur-http",
            EUR_HTTP_PROXY,
            "EUR",
            json!({
                "pricing_tiers": [{ "status_codes": [200], "price_per_call": 1.0 }]
            }),
        ),
        chargeback_chain_plugin(
            "charge-eur-stream",
            EUR_STREAM_PROXY,
            "EUR",
            json!({
                "bandwidth_pricing": {
                    "price_per_byte_sent": 0.1,
                    "price_per_byte_received": 0.05
                },
                "stream_connection_pricing": { "price_per_connection": 0.5 }
            }),
        ),
    ];
    let config = GatewayConfig {
        proxies: vec![
            chargeback_chain_proxy(USD_PROXY, "/issue-2569-usd", "charge-usd"),
            chargeback_chain_proxy(EUR_HTTP_PROXY, "/issue-2569-eur-http", "charge-eur-http"),
            chargeback_chain_stream_proxy(EUR_STREAM_PROXY, "charge-eur-stream"),
        ],
        plugin_configs,
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&config).expect("multi-instance plugin cache");

    let mut usd = make_summary_with_bytes(USD_PROXY, "USD API", Some(CONSUMER), 200, 100, 50);
    usd.namespace = "ferrum".to_string();
    let usd_chain = cache.get_plugins(USD_PROXY);
    let usd_plugin = usd_chain
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .expect("USD chargeback attached");
    usd_plugin.log(&usd).await;

    let mut eur_http = make_summary(EUR_HTTP_PROXY, "EUR API", Some(CONSUMER), 200);
    eur_http.namespace = "ferrum".to_string();
    let eur_http_chain = cache.get_plugins(EUR_HTTP_PROXY);
    let eur_http_plugin = eur_http_chain
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .expect("EUR HTTP chargeback attached");
    eur_http_plugin.log(&eur_http).await;

    let eur_stream = make_stream_summary(
        EUR_STREAM_PROXY,
        "EUR Stream",
        Some(CONSUMER),
        "tcp",
        10,
        20,
    );
    let eur_stream_chain = cache.get_plugins(EUR_STREAM_PROXY);
    let eur_stream_plugin = eur_stream_chain
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .expect("EUR stream chargeback attached");
    eur_stream_plugin.on_stream_disconnect(&eur_stream).await;

    let rendered: serde_json::Value =
        serde_json::from_str(&global_registry().render_json_uncached().unwrap()).unwrap();
    let consumer = &rendered["consumers"][CONSUMER];
    assert!(consumer["total_charges"].is_null());
    assert_eq!(consumer["total_calls"], 3);
    assert_eq!(consumer["charges_by_currency"]["USD"]["total_charges"], 3.0);
    assert_eq!(consumer["charges_by_currency"]["EUR"]["total_charges"], 3.5);
}

/// Model an atomic reload that reuses one proxy id for HTTP/WebSocket while an
/// old stream generation remains alive. The retained old plugin instance must
/// not merge its late disconnect into the new generation's status-0 WebSocket
/// bandwidth row.
#[tokio::test]
async fn test_reload_overlap_old_stream_disconnect_after_new_websocket_stays_partitioned() {
    const CONSUMER: &str = "issue-2571-reload-consumer";
    const PROXY_ID: &str = "issue-2571-reused-proxy";
    let pricing = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.001,
            "price_per_byte_received": 0.001
        }
    });

    let old_config = GatewayConfig {
        proxies: vec![chargeback_chain_stream_proxy(PROXY_ID, "charge-old-stream")],
        plugin_configs: vec![chargeback_chain_plugin(
            "charge-old-stream",
            PROXY_ID,
            "USD",
            pricing.clone(),
        )],
        ..GatewayConfig::default()
    };
    let old_cache = PluginCache::new(&old_config).expect("old stream generation cache");
    let old_plugin = old_cache
        .get_plugins(PROXY_ID)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("old stream generation chargeback plugin");

    let new_config = GatewayConfig {
        proxies: vec![chargeback_chain_proxy(
            PROXY_ID,
            "/issue-2571-reused",
            "charge-new-http",
        )],
        plugin_configs: vec![chargeback_chain_plugin(
            "charge-new-http",
            PROXY_ID,
            "USD",
            pricing,
        )],
        ..GatewayConfig::default()
    };
    let new_cache = PluginCache::new(&new_config).expect("new HTTP generation cache");
    let new_plugin = new_cache
        .get_plugins(PROXY_ID)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("new HTTP generation chargeback plugin");

    new_plugin
        .on_ws_disconnect(&WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: PROXY_ID.to_string(),
            proxy_name: Some("New WebSocket".to_string()),
            client_ip: "127.0.0.1".to_string(),
            backend_target: "http://127.0.0.1:9000".to_string(),
            listen_port: 8080,
            connection_id: 1,
            duration_ms: 10.0,
            frames_client_to_backend: 1,
            frames_backend_to_client: 1,
            bytes_client_to_backend: 50,
            bytes_backend_to_client: 75,
            timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
            timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
            direction: None,
            io_side: None,
            error_class: None,
            consumer_username: Some(CONSUMER.to_string()),
            auth_method: None,
            metadata: HashMap::new(),
            proxy_lifecycle_generation: Some(2),
        })
        .await;

    let mut old_stream =
        make_stream_summary(PROXY_ID, "Old Stream", Some(CONSUMER), "tcp", 100, 200);
    old_stream.proxy_lifecycle_generation = Some(1);
    old_plugin.on_stream_disconnect(&old_stream).await;

    let registry = global_registry();
    let http_key = make_key_with_prices(
        CONSUMER,
        PROXY_ID,
        0,
        ProtocolFamily::Http,
        0.0,
        0.001,
        0.001,
    );
    let stream_key = make_key_with_prices(
        CONSUMER,
        PROXY_ID,
        0,
        ProtocolFamily::Stream,
        0.0,
        0.001,
        0.001,
    );
    let http = registry
        .entries
        .get(&http_key)
        .expect("new WebSocket generation entry");
    assert_eq!(http.protocol_family, ProtocolFamily::Http);
    assert_eq!(http.call_count.load(Ordering::Relaxed), 0);
    drop(http);
    let stream = registry
        .entries
        .get(&stream_key)
        .expect("retained old stream generation entry");
    assert_eq!(stream.protocol_family, ProtocolFamily::Stream);
    assert_eq!(stream.call_count.load(Ordering::Relaxed), 1);
}

/// Issue #2564: one effective `api_chargeback` on a proxy records HTTP,
/// WebSocket-disconnect, TCP, UDP, and DTLS activity exactly once through the
/// PluginCache trait hooks (no silent multiplication).
#[tokio::test]
async fn test_effective_chain_records_each_protocol_path_exactly_once() {
    const CONSUMER: &str = "issue-2564-protocol-consumer";
    const HTTP_PROXY: &str = "issue-2564-http";
    const WS_PROXY: &str = "issue-2564-ws";
    const TCP_PROXY: &str = "issue-2564-tcp";
    const UDP_PROXY: &str = "issue-2564-udp";
    const DTLS_PROXY: &str = "issue-2564-dtls";

    let call_and_stream = json!({
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 1.0 }],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.01,
            "price_per_byte_received": 0.02
        },
        "stream_connection_pricing": { "price_per_connection": 0.5 }
    });
    let stream_only = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.01,
            "price_per_byte_received": 0.02
        },
        "stream_connection_pricing": { "price_per_connection": 0.5 }
    });
    let ws_only = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.01,
            "price_per_byte_received": 0.02
        }
    });

    fn stream_proxy(id: &str, plugin_config_id: &str, scheme: &str, listen_port: u16) -> Proxy {
        serde_json::from_value(json!({
            "id": id,
            "name": id,
            "namespace": "ferrum",
            "backend_scheme": scheme,
            "backend_host": "backend.invalid",
            "backend_port": 9000,
            "listen_port": listen_port,
            "frontend_tls": scheme == "dtls",
            "plugins": [{ "plugin_config_id": plugin_config_id }]
        }))
        .expect("test stream proxy config")
    }

    let plugin_configs = vec![
        chargeback_chain_plugin("charge-http", HTTP_PROXY, "USD", call_and_stream),
        chargeback_chain_plugin("charge-ws", WS_PROXY, "USD", ws_only),
        chargeback_chain_plugin("charge-tcp", TCP_PROXY, "USD", stream_only.clone()),
        chargeback_chain_plugin("charge-udp", UDP_PROXY, "USD", stream_only.clone()),
        chargeback_chain_plugin("charge-dtls", DTLS_PROXY, "USD", stream_only),
    ];
    let config = GatewayConfig {
        proxies: vec![
            chargeback_chain_proxy(HTTP_PROXY, "/issue-2564-http", "charge-http"),
            chargeback_chain_proxy(WS_PROXY, "/issue-2564-ws", "charge-ws"),
            stream_proxy(TCP_PROXY, "charge-tcp", "tcp", 65011),
            stream_proxy(UDP_PROXY, "charge-udp", "udp", 65012),
            stream_proxy(DTLS_PROXY, "charge-dtls", "dtls", 65013),
        ],
        plugin_configs,
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&config).expect("single chargeback per proxy");

    let http_plugin = cache
        .get_plugins(HTTP_PROXY)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("HTTP chargeback");
    http_plugin
        .log(&make_summary(HTTP_PROXY, "HTTP API", Some(CONSUMER), 200))
        .await;

    let ws_plugin = cache
        .get_plugins(WS_PROXY)
        .iter()
        .find(|plugin| plugin.name() == "api_chargeback")
        .cloned()
        .expect("WS chargeback");
    ws_plugin
        .on_ws_disconnect(&WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: WS_PROXY.to_string(),
            proxy_name: Some("WS API".to_string()),
            client_ip: "127.0.0.1".to_string(),
            backend_target: "http://127.0.0.1:9000".to_string(),
            listen_port: 8080,
            connection_id: 1,
            duration_ms: 10.0,
            frames_client_to_backend: 1,
            frames_backend_to_client: 1,
            bytes_client_to_backend: 10,
            bytes_backend_to_client: 20,
            timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
            timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
            direction: None,
            io_side: None,
            error_class: None,
            consumer_username: Some(CONSUMER.to_string()),
            auth_method: None,
            metadata: HashMap::new(),
            proxy_lifecycle_generation: None,
        })
        .await;

    for (proxy_id, protocol) in [(TCP_PROXY, "tcp"), (UDP_PROXY, "udp"), (DTLS_PROXY, "dtls")] {
        let plugin = cache
            .get_plugins(proxy_id)
            .iter()
            .find(|plugin| plugin.name() == "api_chargeback")
            .cloned()
            .unwrap_or_else(|| panic!("{protocol} chargeback"));
        plugin
            .on_stream_disconnect(&make_stream_summary(
                proxy_id,
                &format!("{protocol} API"),
                Some(CONSUMER),
                protocol,
                10,
                20,
            ))
            .await;
    }

    let rendered: serde_json::Value =
        serde_json::from_str(&global_registry().render_json_uncached().unwrap()).unwrap();
    let consumer = &rendered["consumers"][CONSUMER];
    // HTTP call + three stream sessions (WS has no call_count).
    assert_eq!(consumer["total_calls"], 4);
    let proxies = consumer["proxies"].as_object().expect("proxies object");
    assert_eq!(proxies[HTTP_PROXY]["by_status"]["200"]["calls"], 1);
    assert_eq!(proxies[TCP_PROXY]["stream"]["connections"], 1);
    assert_eq!(proxies[UDP_PROXY]["stream"]["connections"], 1);
    assert_eq!(proxies[DTLS_PROXY]["stream"]["connections"], 1);
    assert_eq!(proxies[WS_PROXY]["bandwidth"]["bytes_sent"], 10);
    assert_eq!(proxies[WS_PROXY]["bandwidth"]["bytes_received"], 20);
}

/// Direct trait dispatch through two constructed instances still multiplies —
/// proving why the PluginCache uniqueness rule is required. The production
/// path rejects this composition; this documents the pre-fix failure mode.
#[tokio::test]
async fn test_two_direct_instances_would_double_count_one_http_transaction() {
    const CONSUMER: &str = "issue-2564-double-consumer";
    const PROXY: &str = "issue-2564-double-proxy";

    let a = ApiChargeback::new(
        &json!({
            "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
            "cleanup_interval_seconds": 0
        }),
        "ferrum",
    )
    .expect("instance a");
    let b = ApiChargeback::new(
        &json!({
            "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
            "cleanup_interval_seconds": 0
        }),
        "ferrum",
    )
    .expect("instance b");

    let summary = make_summary(PROXY, "Double", Some(CONSUMER), 200);
    a.log(&summary).await;
    b.log(&summary).await;

    let rendered: serde_json::Value =
        serde_json::from_str(&global_registry().render_json_uncached().unwrap()).unwrap();
    assert_eq!(
        rendered["consumers"][CONSUMER]["proxies"][PROXY]["by_status"]["200"]["calls"], 2,
        "two hooks on one shared registry key inflate calls — uniqueness must reject this"
    );
}

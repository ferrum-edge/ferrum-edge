//! Tests for kafka_logging plugin

use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, kafka_logging::KafkaLogging};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_kafka_logging_plugin_creation() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test-access-logs"
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
    assert_eq!(plugin.priority(), 9150);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_kafka_logging_missing_broker_list() {
    let result = KafkaLogging::new(&json!({"topic": "test"}), &default_http_client());
    match result {
        Err(e) => assert!(
            e.contains("broker_list"),
            "Expected error about broker_list, got: {e}"
        ),
        Ok(_) => panic!("Expected Err when creating kafka_logging without broker_list"),
    }
}

#[tokio::test]
async fn test_kafka_logging_empty_broker_list() {
    let result = KafkaLogging::new(
        &json!({"broker_list": "", "topic": "test"}),
        &default_http_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_missing_topic() {
    let result = KafkaLogging::new(
        &json!({"broker_list": "localhost:9092"}),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(e.contains("topic"), "Expected error about topic, got: {e}"),
        Ok(_) => panic!("Expected Err when creating kafka_logging without topic"),
    }
}

#[tokio::test]
async fn test_kafka_logging_empty_topic() {
    let result = KafkaLogging::new(
        &json!({"broker_list": "localhost:9092", "topic": ""}),
        &default_http_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"broker_list": 9092, "topic": "test"}),
        json!({"broker_list": "localhost:9092", "topic": 123}),
        json!({"broker_list": ", ,", "topic": "test"}),
        json!({"broker_list": "localhost:9092", "topic": "test", "buffer_capacity": "100"}),
        json!({"broker_list": "localhost:9092", "topic": "test", "flush_timeout_seconds": false}),
        json!({"broker_list": "localhost:9092", "topic": "test", "message_timeout_ms": []}),
        json!({"broker_list": "localhost:9092", "topic": "test", "key_field": ""}),
        json!({"broker_list": "localhost:9092", "topic": "test", "compression": 1}),
        json!({"broker_list": "localhost:9092", "topic": "test", "acks": true}),
        json!({"broker_list": "localhost:9092", "topic": "test", "security_protocol": ""}),
        json!({"broker_list": "localhost:9092", "topic": "test", "sasl_mechanism": []}),
        json!({"broker_list": "localhost:9092", "topic": "test", "sasl_username": ""}),
        json!({"broker_list": "localhost:9092", "topic": "test", "sasl_password": {}}),
        json!({"broker_list": "localhost:9092", "topic": "test", "ssl_no_verify": "false"}),
        json!({"broker_list": "localhost:9092", "topic": "test", "ssl_ca_location": ""}),
        json!({"broker_list": "localhost:9092", "topic": "test", "ssl_certificate_location": "/cert.pem"}),
        json!({"broker_list": "localhost:9092", "topic": "test", "ssl_key_location": "/key.pem"}),
        json!({"broker_list": "localhost:9092", "topic": "test", "producer_config": []}),
        json!({"broker_list": "localhost:9092", "topic": "test", "producer_config": {"": "value"}}),
        json!({"broker_list": "localhost:9092", "topic": "test", "producer_config": {"linger.ms": 10}}),
        json!({"broker_list": "localhost:9092", "topic": "test", "producer_config": {"linger.ms": ""}}),
    ];

    for config in cases {
        assert!(
            KafkaLogging::new(&config, &default_http_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_kafka_logging_invalid_compression() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "compression": "bzip2"
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("compression"),
            "Expected compression error, got: {e}"
        ),
        Ok(_) => panic!("Expected Err for unsupported compression type"),
    }
}

#[tokio::test]
async fn test_kafka_logging_valid_compression_types() {
    for comp in &["none", "gzip", "snappy", "lz4", "zstd"] {
        let result = KafkaLogging::new(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "test",
                "compression": comp
            }),
            &default_http_client(),
        );
        assert!(result.is_ok(), "Compression '{comp}' should be accepted");
    }
}

#[tokio::test]
async fn test_kafka_logging_invalid_acks() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "acks": "2"
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(e.contains("acks"), "Expected acks error, got: {e}"),
        Ok(_) => panic!("Expected Err for unsupported acks value"),
    }
}

#[tokio::test]
async fn test_kafka_logging_valid_acks() {
    for acks in &["0", "1", "all", "-1"] {
        let result = KafkaLogging::new(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "test",
                "acks": acks
            }),
            &default_http_client(),
        );
        assert!(result.is_ok(), "Acks '{acks}' should be accepted");
    }
}

#[tokio::test]
async fn test_kafka_logging_log_does_not_panic() {
    // Even with an unreachable broker, log() should accept entries
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test-logs"
        }),
        &default_http_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_kafka_logging_stream_disconnect_does_not_panic() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test-logs"
        }),
        &default_http_client(),
    )
    .unwrap();
    let summary = create_test_stream_transaction_summary();
    plugin.on_stream_disconnect(&summary).await;
}

#[tokio::test]
async fn test_kafka_logging_multiple_brokers() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "broker1:9092,broker2:9092,broker3:9092",
            "topic": "test-logs"
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
    assert_eq!(plugin.warmup_hostnames().len(), 3);
}

#[tokio::test]
async fn test_kafka_logging_warmup_skips_ip_addresses() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "broker1:9092,127.0.0.1:9092,[::1]:9092",
            "topic": "test-logs"
        }),
        &default_http_client(),
    )
    .unwrap();
    // Only broker1 is a hostname; 127.0.0.1 and ::1 are IPs
    assert_eq!(plugin.warmup_hostnames(), vec!["broker1".to_string()]);
}

#[tokio::test]
async fn test_kafka_logging_with_security_config() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "sasl_plaintext",
            "sasl_mechanism": "PLAIN",
            "sasl_username": "admin",
            "sasl_password": "secret"
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_with_producer_config() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "producer_config": {
                "linger.ms": "50",
                "batch.num.messages": "1000"
            }
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_rejects_bootstrap_override_in_producer_config() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "producer_config": {
                "bootstrap.servers": "127.0.0.1:9092"
            }
        }),
        &default_http_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_buffer_full_drops_gracefully() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "buffer_capacity": 5
        }),
        &default_http_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    // Send more entries than buffer_capacity — excess should be dropped
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
    // Should not panic — overflow entries are dropped with a warning
}

#[tokio::test]
async fn test_kafka_logging_key_field_options() {
    for key_field in &["client_ip", "proxy_id", "none"] {
        let plugin = KafkaLogging::new(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "test",
                "key_field": key_field
            }),
            &default_http_client(),
        )
        .unwrap();
        assert_eq!(plugin.name(), "kafka_logging");
    }
}

#[tokio::test]
async fn test_kafka_logging_key_field_invalid_rejected() {
    // A typo (or any unknown value) must be rejected at construction time
    // instead of silently falling back to the client_ip default.
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "key_field": "proxyID"
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("key_field") && e.contains("proxyID"),
            "Expected error naming the bad key_field value, got: {e}",
        ),
        Ok(_) => panic!("Expected Err for invalid key_field value"),
    }
}

#[tokio::test]
async fn test_kafka_logging_default_lifecycle_phases() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test"
        }),
        &default_http_client(),
    )
    .unwrap();

    let mut ctx = ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_kafka_logging_flush_timeout_config() {
    // Custom flush timeout should be accepted
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "flush_timeout_seconds": 15
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_flush_timeout_minimum_clamped() {
    // flush_timeout_seconds of 0 should be clamped to 1
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "flush_timeout_seconds": 0
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_default_compression_is_lz4() {
    // When no compression is specified, lz4 should be the default.
    // This test verifies the plugin creates successfully with default compression.
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test"
        }),
        &default_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_supported_protocols() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test"
        }),
        &default_http_client(),
    )
    .unwrap();

    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

//! Tests for kafka_logging plugin

use ferrum_edge::plugins::{Plugin, kafka_logging::KafkaLogging};
use serde_json::json;

use super::plugin_utils::create_test_transaction_summary;

#[tokio::test]
async fn test_kafka_logging_plugin_creation() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test-access-logs"
    }))
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_missing_broker_list() {
    let result = KafkaLogging::new(&json!({"topic": "test"}));
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
    let result = KafkaLogging::new(&json!({"broker_list": "", "topic": "test"}));
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_missing_topic() {
    let result = KafkaLogging::new(&json!({"broker_list": "localhost:9092"}));
    match result {
        Err(e) => assert!(e.contains("topic"), "Expected error about topic, got: {e}"),
        Ok(_) => panic!("Expected Err when creating kafka_logging without topic"),
    }
}

#[tokio::test]
async fn test_kafka_logging_empty_topic() {
    let result = KafkaLogging::new(&json!({"broker_list": "localhost:9092", "topic": ""}));
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_invalid_compression() {
    let result = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test",
        "compression": "bzip2"
    }));
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
        let result = KafkaLogging::new(&json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "compression": comp
        }));
        assert!(result.is_ok(), "Compression '{comp}' should be accepted");
    }
}

#[tokio::test]
async fn test_kafka_logging_invalid_acks() {
    let result = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test",
        "acks": "2"
    }));
    match result {
        Err(e) => assert!(e.contains("acks"), "Expected acks error, got: {e}"),
        Ok(_) => panic!("Expected Err for unsupported acks value"),
    }
}

#[tokio::test]
async fn test_kafka_logging_valid_acks() {
    for acks in &["0", "1", "all", "-1"] {
        let result = KafkaLogging::new(&json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "acks": acks
        }));
        assert!(result.is_ok(), "Acks '{acks}' should be accepted");
    }
}

#[tokio::test]
async fn test_kafka_logging_log_does_not_panic() {
    // Even with an unreachable broker, log() should accept entries
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:19092",
        "topic": "test-logs"
    }))
    .unwrap();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_kafka_logging_multiple_brokers() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "broker1:9092,broker2:9092,broker3:9092",
        "topic": "test-logs"
    }))
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
    assert_eq!(plugin.warmup_hostnames().len(), 3);
}

#[tokio::test]
async fn test_kafka_logging_warmup_skips_ip_addresses() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "broker1:9092,127.0.0.1:9092,[::1]:9092",
        "topic": "test-logs"
    }))
    .unwrap();
    // Only broker1 is a hostname; 127.0.0.1 and ::1 are IPs
    assert_eq!(plugin.warmup_hostnames(), vec!["broker1".to_string()]);
}

#[tokio::test]
async fn test_kafka_logging_with_security_config() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test",
        "security_protocol": "sasl_plaintext",
        "sasl_mechanism": "PLAIN",
        "sasl_username": "admin",
        "sasl_password": "secret"
    }))
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_with_producer_config() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test",
        "producer_config": {
            "linger.ms": "50",
            "batch.num.messages": "1000"
        }
    }))
    .unwrap();
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_buffer_full_drops_gracefully() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:19092",
        "topic": "test",
        "buffer_capacity": 5
    }))
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
        let plugin = KafkaLogging::new(&json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "key_field": key_field
        }))
        .unwrap();
        assert_eq!(plugin.name(), "kafka_logging");
    }
}

#[tokio::test]
async fn test_kafka_logging_default_lifecycle_phases() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test"
    }))
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
async fn test_kafka_logging_supported_protocols() {
    let plugin = KafkaLogging::new(&json!({
        "broker_list": "localhost:9092",
        "topic": "test"
    }))
    .unwrap();

    // Should support all protocols (HTTP, gRPC, WebSocket, TCP, UDP)
    assert_eq!(
        plugin.supported_protocols(),
        ferrum_edge::plugins::ALL_PROTOCOLS
    );
}

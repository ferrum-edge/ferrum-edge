//! Tests for kafka_logging plugin

use ferrum_edge::_test_support::{
    kafka_logging_http_record_key_for_test, kafka_logging_parsed_sasl_credentials_for_test,
    kafka_logging_probe_byte_budget_before_serialize_for_test,
    kafka_logging_probe_downstream_lease_ownership_for_test,
    kafka_logging_probe_queue_full_backoff_for_test,
    kafka_logging_probe_reserve_before_serialize_for_test,
    kafka_logging_probe_terminal_loss_accounting_for_test,
    kafka_logging_probe_worker_batching_for_test,
    kafka_logging_serialize_http_with_config_for_test,
    kafka_logging_serialize_stream_with_config_for_test, kafka_logging_stream_record_key_for_test,
    kafka_logging_validate_producer_admission_for_test,
};
use ferrum_edge::plugins::kafka_logging::{
    DEFAULT_BUFFER_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES,
    HARD_MAX_ENTRY_BYTES, HARD_MAX_FLUSH_TIMEOUT_SECONDS, KAFKA_MESSAGE_FRAMING_HEADROOM_BYTES,
    KafkaLogging, MAX_KAFKA_TOPIC_NAME_LENGTH, MAX_MESSAGE_TIMEOUT_MS,
};
use ferrum_edge::plugins::utils::byte_budget::RetainedByteCeiling;
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginFailurePolicy, plugin_failure_policy};
use rdkafka::mocking::MockCluster;
use serde_json::json;
use tokio::time::{Duration, sleep};

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn start_kafka_logging(plugin: &KafkaLogging) {
    plugin
        .start_background_tasks()
        .expect("kafka_logging live tests require start_background_tasks");
    plugin.commit_background_tasks();
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
    assert_eq!(
        plugin_failure_policy("kafka_logging"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
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
async fn kafka_rejects_overrides_of_managed_delivery_reporting() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("OpenAPI parses");
    let schema = spec
        .pointer("/components/schemas/KafkaLoggingConfig/properties/producer_config")
        .expect("producer_config schema exists");
    let validator = jsonschema::draft202012::new(schema).expect("producer_config schema compiles");
    let client = default_http_client();

    for property in [
        "delivery.report.only.error",
        "DELIVERY.REPORT.ONLY.ERROR",
        "Delivery.Report.Only.Error",
    ] {
        for value in ["true", "false", "operator-supplied-value"] {
            let config = json!({
                "broker_list": "localhost:9092",
                "topic": "delivery-accounting",
                "producer_config": {property: value}
            });
            let error = KafkaLogging::new(&config, &client)
                .err()
                .expect("delivery reporting overrides must be rejected at construction");
            assert!(error.contains(&format!("`producer_config` key {property:?}")));
            assert!(error.contains("delivery reporting is managed"));
            assert!(!error.contains(value));
            assert_eq!(
                kafka_logging_validate_producer_admission_for_test(&config, &client),
                Err(error)
            );
            assert!(!validator.is_valid(&config["producer_config"]));
        }
    }
    assert!(validator.is_valid(&json!({})));
    assert!(validator.is_valid(&json!({"linger.ms": "50"})));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_successful_deliveries_release_leases_before_finalization() {
    let cluster = MockCluster::new(1).expect("create Kafka mock cluster");
    let topic = "delivery-accounting";
    cluster
        .create_topic(topic, 1, 1)
        .expect("create mock topic");
    let client = default_http_client();

    for key_field in ["client_ip", "none"] {
        for acks in ["all", "0"] {
            let plugin = KafkaLogging::new(
                &json!({
                    "broker_list": cluster.bootstrap_servers(),
                    "topic": topic,
                    "key_field": key_field,
                    "acks": acks,
                    "compression": "none",
                    "max_entry_bytes": 4096,
                    "buffer_max_bytes": 8192,
                    "message_timeout_ms": 10_000,
                    "flush_timeout_seconds": 5,
                    "producer_config": {
                        "linger.ms": "0",
                        "enabled_events": "0",
                        "produce.offset.report": "false"
                    }
                }),
                &client,
            )
            .expect("construct Kafka logger for successful delivery");
            start_kafka_logging(&plugin);
            let baseline = plugin.snapshot().retained_bytes;
            assert_eq!(baseline, 0);

            // Event selection remains owned by rust-rdkafka, and the deprecated
            // offset-report option does not change terminal delivery accounting.
            // Reuse the same budget for a second pair of HTTP/stream records.
            for expected in [2, 4] {
                plugin.log(&create_test_transaction_summary()).await;
                plugin
                    .on_stream_disconnect(&create_test_stream_transaction_summary())
                    .await;
                let delivered = tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        let snapshot = plugin.snapshot();
                        if snapshot.admitted_total == expected
                            && snapshot.delivered_total == expected
                            && snapshot.retained_bytes == baseline
                            && snapshot.in_flight == 0
                        {
                            break snapshot;
                        }
                        sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("successful delivery must return every lease before finalization");
                assert!(!delivered.finalized);
                assert_eq!(delivered.delivery_failed_total, 0);
                assert_eq!(delivered.queue_rejected_total, 0);
                assert_eq!(delivered.ferrum_dropped_total, 0);
            }

            plugin.finalize().await;
            let finalized = plugin.snapshot();
            assert!(finalized.finalized);
            assert_eq!(finalized.retained_bytes, baseline);
            assert_eq!(finalized.delivered_total, 4);
            assert_eq!(finalized.delivery_failed_total, 0);
            assert_eq!(finalized.flush_failures_total, 0);
            assert_eq!(finalized.shutdown_incomplete_total, 0);
        }
    }
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
    for key_field in &["client_ip", "proxy_id", "consumer_username", "none"] {
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
    assert_eq!(plugin.snapshot().flush_timeout_seconds, 15);
    assert_eq!(plugin.name(), "kafka_logging");
}

#[tokio::test]
async fn test_kafka_logging_rejects_zero_flush_timeout() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "flush_timeout_seconds": 0
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("flush_timeout_seconds") && e.contains(">= 1"),
            "expected zero flush_timeout rejection, got: {e}"
        ),
        Ok(_) => panic!("flush_timeout_seconds=0 must be rejected"),
    }
}

#[tokio::test]
async fn test_kafka_logging_rejects_flush_timeout_above_hard_max() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "flush_timeout_seconds": HARD_MAX_FLUSH_TIMEOUT_SECONDS + 1
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("flush_timeout_seconds")
                && e.contains(&HARD_MAX_FLUSH_TIMEOUT_SECONDS.to_string()),
            "expected flush_timeout hard-max rejection, got: {e}"
        ),
        Ok(_) => panic!("flush_timeout above hard max must be rejected"),
    }
}

#[tokio::test]
async fn test_kafka_logging_rejects_zero_buffer_capacity() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "buffer_capacity": 0
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("buffer_capacity") && e.contains(">= 1"),
            "expected zero buffer_capacity rejection, got: {e}"
        ),
        Ok(_) => panic!("buffer_capacity=0 must be rejected"),
    }
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

#[tokio::test]
async fn test_kafka_logging_rejects_unknown_root_keys() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protcol": "sasl_ssl"
        }),
        &default_http_client(),
    );
    match result {
        Err(e) => {
            assert!(
                e.contains("unknown configuration key") && e.contains("security_protcol"),
                "expected unknown-key rejection for security_protcol, got: {e}"
            );
            assert!(
                e.contains("security_protocol") || e.contains("did you mean"),
                "expected near-miss hint toward security_protocol, got: {e}"
            );
        }
        Ok(_) => panic!("misspelled security_protocol must not construct"),
    }
}

#[tokio::test]
async fn test_kafka_logging_rejects_oversized_buffer_capacity() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "buffer_capacity": 1_000_001
        }),
        &default_http_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_rejects_oversized_producer_queue_budget() {
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "producer_config": {
                "queue.buffering.max.kbytes": "1048576"
            }
        }),
        &default_http_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_kafka_logging_rejects_conflicting_crl_override() {
    let client =
        default_http_client().with_tls_crl_source(Some("/etc/ferrum/gateway.crl".to_string()));
    // Assert the pure admission boundary (same path construction uses) so
    // CRL conflict coverage does not depend on librdkafka/OpenSSL.
    let result = kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "producer_config": {
                "ssl.crl.location": "/tmp/other.crl"
            }
        }),
        &client,
    );
    match result {
        Err(e) => assert!(
            e.contains("ssl.crl.location") && e.contains("conflicts"),
            "expected CRL conflict error, got: {e}"
        ),
        Ok(()) => panic!("conflicting CRL override must be rejected"),
    }
}

#[tokio::test]
async fn test_kafka_logging_allows_matching_crl_override() {
    let client =
        default_http_client().with_tls_crl_source(Some("/etc/ferrum/gateway.crl".to_string()));
    // Pure admission checks matching overrides without requiring a producer
    // or an actual CRL file at the fixture path.
    kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "producer_config": {
                "ssl.crl.location": "/etc/ferrum/gateway.crl"
            }
        }),
        &client,
    )
    .expect("matching gateway CRL override must be admitted");
}

#[tokio::test]
async fn test_kafka_logging_normalizes_file_uri_gateway_crl_source() {
    let client = default_http_client()
        .with_tls_crl_source(Some("file:///etc/ferrum/gateway.crl".to_string()));
    assert_eq!(client.tls_crl_file_path(), Some("/etc/ferrum/gateway.crl"));
    kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "producer_config": {
                "ssl.crl.location": "/etc/ferrum/gateway.crl"
            }
        }),
        &client,
    )
    .expect("file URI CRL source must normalize to librdkafka's filesystem path");
}

#[tokio::test]
async fn test_kafka_logging_rejects_non_file_gateway_crl_source_for_verified_tls() {
    let source_reference = "vault://secret/data/kafka-crl";
    let client = default_http_client().with_tls_crl_source(Some(source_reference.to_string()));
    let error = kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl"
        }),
        &client,
    )
    .err()
    .unwrap_or_else(|| {
        panic!("non-file CRL sources cannot be silently omitted for verified Kafka TLS")
    });
    assert!(error.contains("file-backed gateway CRL source"));
    assert!(
        !error.contains(source_reference),
        "CRL provider identity must not be echoed"
    );
}

#[tokio::test]
async fn test_kafka_logging_no_verify_skips_crl_conflict() {
    let client =
        default_http_client().with_tls_crl_source(Some("/etc/ferrum/gateway.crl".to_string()));
    // ssl_no_verify disables verification, so a divergent CRL path is not a
    // conflict; assert via pure admission (no producer / OpenSSL required).
    kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "ssl_no_verify": true,
            "producer_config": {
                "ssl.crl.location": "/tmp/other.crl"
            }
        }),
        &client,
    )
    .expect("ssl_no_verify must skip CRL conflict admission");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_finalize_is_exact_once() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);
    let before = plugin.snapshot();
    assert!(before.accepting);
    assert!(!before.finalized);
    plugin.log(&create_test_transaction_summary()).await;
    let ((), ()) = tokio::join!(plugin.finalize(), plugin.finalize());
    let after = plugin.snapshot();
    assert!(after.finalized);
    assert!(!after.accepting);
    // Every subsequent finalize is a no-op and must not panic.
    plugin.finalize().await;
    assert!(plugin.snapshot().finalized);
}

#[test]
fn test_kafka_logging_finalize_budget_includes_blocking_pool_queue() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build constrained Kafka finalize test runtime");
    runtime.block_on(async {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx
                .send(())
                .expect("announce occupied blocking slot");
            release_rx.recv().expect("release occupied blocking slot");
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("blocking-pool fixture must start");

        let plugin = KafkaLogging::new(
            &json!({
                "broker_list": "localhost:19092",
                "topic": "test",
                "flush_timeout_seconds": 1
            }),
            &default_http_client(),
        )
        .expect("construct Kafka logger for blocking-pool budget test");
        start_kafka_logging(&plugin);
        plugin.log(&create_test_transaction_summary()).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while plugin.snapshot().admitted_total == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("record must reach librdkafka before finalize");

        let started = std::time::Instant::now();
        plugin.finalize().await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "finalize must not wait indefinitely for a saturated blocking pool"
        );
        let snapshot = plugin.snapshot();
        assert!(snapshot.finalized);
        assert_eq!(snapshot.flush_timeouts_total, 1);
        assert_eq!(snapshot.flush_failures_total, 1);
        assert_eq!(
            snapshot
                .last_failure
                .as_ref()
                .map(|failure| failure.error_kind.as_str()),
            Some("flush_task_timed_out")
        );

        release_tx.send(()).expect("release blocking-pool fixture");
        blocker.await.expect("blocking-pool fixture joins");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_snapshot_counters_start_at_zero() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);
    let snap = plugin.snapshot();
    assert_eq!(snap.admitted_total, 0);
    assert_eq!(snap.delivered_total, 0);
    assert_eq!(snap.delivery_failed_total, 0);
    assert_eq!(snap.queue_rejected_total, 0);
    plugin.finalize().await;
}

#[test]
fn docs_do_not_require_undeclared_kafka_cargo_feature() {
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let docs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/plugins.md"));
    let features_idx = cargo
        .find("[features]")
        .expect("Cargo.toml must declare [features]");
    let features = &cargo[features_idx..];
    assert!(
        !features
            .lines()
            .any(|line| line.trim_start().starts_with("kafka")),
        "Cargo.toml must not declare a kafka feature while docs claim unconditional availability"
    );
    assert!(
        !docs.contains("--features kafka"),
        "docs/plugins.md must not instruct operators to pass --features kafka"
    );
    assert!(
        docs.contains("unconditional dependency")
            || docs.contains("Built into every default Ferrum Edge binary"),
        "docs/plugins.md must describe the unconditional Kafka build contract"
    );
}

#[tokio::test]
async fn test_kafka_logging_byte_budget_defaults_and_validation() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test"
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);
    let snap = plugin.snapshot();
    assert_eq!(snap.max_entry_bytes, DEFAULT_MAX_ENTRY_BYTES as u64);
    assert_eq!(snap.buffer_max_bytes, DEFAULT_BUFFER_MAX_BYTES as u64);
    plugin.finalize().await;

    let oversize_entry = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "max_entry_bytes": HARD_MAX_ENTRY_BYTES + 1
        }),
        &default_http_client(),
    );
    assert!(oversize_entry.is_err());

    let oversize_buffer = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "buffer_max_bytes": HARD_MAX_BUFFER_MAX_BYTES + 1
        }),
        &default_http_client(),
    );
    assert!(oversize_buffer.is_err());

    let inverted = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "max_entry_bytes": 4096,
            "buffer_max_bytes": 1024
        }),
        &default_http_client(),
    );
    match inverted {
        Err(e) => assert!(
            e.contains("buffer_max_bytes") && e.contains("max_entry_bytes"),
            "expected buffer_max_bytes >= max_entry_bytes, got: {e}"
        ),
        Ok(_) => panic!("buffer_max_bytes < max_entry_bytes must be rejected"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_reserves_channel_before_oversize_serialization() {
    let mut oversized = create_test_transaction_summary();
    oversized.request_path = format!("/{}", "a".repeat(4096));
    let (dropped, oversize) =
        kafka_logging_probe_reserve_before_serialize_for_test(&oversized).await;
    assert!(
        dropped > 0,
        "expected channel drops when capacity is saturated, got dropped={dropped}"
    );
    assert_eq!(
        oversize, 0,
        "oversize counter must stay zero when channel reservation fails first"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_reserves_byte_budget_before_oversize_serialization() {
    let mut oversized = create_test_transaction_summary();
    oversized.request_path = format!("/{}", "b".repeat(4096));
    let (exhausted, oversize) =
        kafka_logging_probe_byte_budget_before_serialize_for_test(&oversized).await;
    assert_eq!(
        exhausted, 1,
        "expected aggregate byte-budget rejection before serialization"
    );
    assert_eq!(
        oversize, 0,
        "oversize counter must stay zero when byte-budget reservation fails first"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_rejects_oversize_entry_when_channel_has_capacity() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "buffer_capacity": 16,
            "max_entry_bytes": 64,
            "buffer_max_bytes": 1024,
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);

    let mut huge = create_test_transaction_summary();
    huge.request_path = format!("/{}", "b".repeat(4096));
    plugin.log(&huge).await;

    let snap = plugin.snapshot();
    assert!(
        snap.entry_oversize_total >= 1,
        "expected oversize rejection, got {snap:?}"
    );
    assert!(snap.ferrum_dropped_total >= 1);
    plugin.finalize().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_byte_budget_saturation_and_release() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "buffer_capacity": 32,
            "max_entry_bytes": 512,
            "buffer_max_bytes": 512,
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);

    let summary = create_test_transaction_summary();
    for _ in 0..8 {
        plugin.log(&summary).await;
    }
    // Allow the worker to attempt librdkafka admission; leases stay charged
    // through terminal delivery.
    sleep(Duration::from_millis(200)).await;
    let mid = plugin.snapshot();
    assert!(
        mid.byte_budget_exhausted_total > 0 || mid.retained_bytes <= mid.buffer_max_bytes,
        "byte budget must either saturate or stay within the configured ceiling: {mid:?}"
    );

    plugin.finalize().await;
    let after = plugin.snapshot();
    assert_eq!(
        after.retained_bytes, 0,
        "finalize must drain Ferrum retained bytes"
    );
}

#[test]
fn test_kafka_logging_schema_only_applies_to_matching_summary_type() {
    let http = create_test_transaction_summary();
    let stream = create_test_stream_transaction_summary();

    let stream_only_schema = json!({
        "schema": {
            "summary_type": "stream",
            "omit": ["protocol"]
        }
    });
    let http_value = kafka_logging_serialize_http_with_config_for_test(&stream_only_schema, &http)
        .expect("HTTP serialization should succeed with a stream-only schema");
    assert!(
        http_value.get("http_method").is_some(),
        "stream-only schemas must not remove native HTTP audit fields: {http_value}"
    );
    assert!(
        http_value.get("request_path").is_some(),
        "stream-only schemas must not remove native HTTP path fields: {http_value}"
    );

    let http_only_schema = json!({
        "schema": {
            "summary_type": "http",
            "omit": ["request_path"]
        }
    });
    let stream_value =
        kafka_logging_serialize_stream_with_config_for_test(&http_only_schema, &stream)
            .expect("stream serialization should succeed with an HTTP-only schema");
    assert!(
        stream_value.get("protocol").is_some(),
        "HTTP-only schemas must not remove native stream connection fields: {stream_value}"
    );
    assert!(
        stream_value.get("listen_port").is_some(),
        "HTTP-only schemas must not remove native stream listener fields: {stream_value}"
    );

    let matching_http = kafka_logging_serialize_http_with_config_for_test(&http_only_schema, &http)
        .expect("matching HTTP schema should serialize");
    assert!(
        matching_http.get("request_path").is_none(),
        "matching HTTP schema should still be applied: {matching_http}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_http_and_stream_schema_key_behavior() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "key_field": "proxy_id",
            "schema": {
                "summary_type": "both",
                "omit": ["request_user_agent"],
                "rename": { "proxy_id": "route_id" }
            },
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);

    let mut http = create_test_transaction_summary();
    http.proxy_id = Some("http-proxy".to_string());
    plugin.log(&http).await;

    let mut stream = create_test_stream_transaction_summary();
    stream.proxy_id = "stream-proxy".to_string();
    plugin.on_stream_disconnect(&stream).await;

    // Admission must remain non-blocking and must not panic with schema/key.
    let snap = plugin.snapshot();
    assert!(snap.accepting);
    assert_eq!(snap.entry_oversize_total, 0);
    plugin.finalize().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kafka_logging_diagnostics_omit_secrets() {
    let password = "super-secret-kafka-password-value";
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:19092",
            "topic": "test",
            "security_protocol": "sasl_plaintext",
            "sasl_mechanism": "PLAIN",
            "sasl_username": "alice",
            "sasl_password": password,
            "flush_timeout_seconds": 1
        }),
        &default_http_client(),
    )
    .unwrap();
    start_kafka_logging(&plugin);
    plugin.log(&create_test_transaction_summary()).await;
    let snap = serde_json::to_string(&plugin.snapshot()).unwrap();
    let prom = ferrum_edge::plugins::kafka_logging::render_prometheus();
    assert!(
        !snap.contains(password),
        "snapshot must not echo SASL password"
    );
    assert!(
        !prom.contains(password),
        "prometheus exposition must not echo SASL password"
    );
    assert!(
        !prom.contains("alice"),
        "prometheus exposition must not echo SASL username"
    );
    plugin.finalize().await;
}

#[tokio::test]
async fn test_kafka_logging_constructor_error_omits_rejected_property_value() {
    let secret = "super-secret-kafka-client-config-value";
    let result = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "producer_config": {
                "ferrum.unknown.sensitive.option": secret
            }
        }),
        &default_http_client(),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unknown librdkafka property must fail construction"),
    };
    assert!(
        error.contains("client_config_error"),
        "constructor should retain only the safe failure class: {error}"
    );
    assert!(
        !error.contains(secret),
        "constructor error must not echo the rejected property value"
    );
}

/// GHSA-4988-2wph-67g2: `producer_config` is an open escape hatch forwarded to
/// librdkafka. Inline private-key material must be refused by *shape*, not only
/// under the one property name librdkafka happens to call `ssl.key.pem` today,
/// and the rejection must never echo the key back into an error, an audit
/// record, or a log line.
#[tokio::test]
async fn test_kafka_logging_rejects_inline_private_key_material_in_producer_config() {
    const PEM_CANARY: &str = "kafka-inline-pem-canary";
    let pems = [
        format!("-----BEGIN PRIVATE KEY-----\n{PEM_CANARY}\n-----END PRIVATE KEY-----"),
        format!("-----BEGIN RSA PRIVATE KEY-----\n{PEM_CANARY}\n-----END RSA PRIVATE KEY-----"),
        format!("-----BEGIN EC PRIVATE KEY-----\n{PEM_CANARY}\n-----END EC PRIVATE KEY-----"),
        format!(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n{PEM_CANARY}\n-----END ENCRYPTED PRIVATE KEY-----"
        ),
        format!("-----begin private key-----\n{PEM_CANARY}\n-----end private key-----"),
    ];
    // A property name that is on no deny-list at all, to prove the check is by
    // value shape rather than by property name.
    for property in ["ssl.key.pem", "some.future.inline.material"] {
        for pem in &pems {
            let result = kafka_logging_validate_producer_admission_for_test(
                &json!({
                    "broker_list": "localhost:9092",
                    "topic": "test",
                    "security_protocol": "ssl",
                    "producer_config": { property: pem }
                }),
                &default_http_client(),
            );
            match result {
                Err(e) => assert!(
                    !e.contains(PEM_CANARY) && !e.contains("BEGIN"),
                    "rejection echoed private-key material: {e}"
                ),
                Ok(()) => panic!("producer_config.{property} inline PEM must be rejected"),
            }
        }
    }
}

/// Safe-value control for the check above: certificates and public keys are not
/// credentials and must still be admissible.
#[tokio::test]
async fn test_kafka_logging_admits_non_private_key_pem_material() {
    let result = kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "producer_config": {
                "some.future.public.material":
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            }
        }),
        &default_http_client(),
    );
    assert!(
        result.is_ok(),
        "certificate material must not be refused as a private key: {result:?}"
    );
}

#[tokio::test]
async fn test_kafka_logging_rejects_producer_config_security_aliases_case_insensitive() {
    let cases = [
        ("security.protocol", "security_protocol"),
        ("SECURITY.PROTOCOL", "security_protocol"),
        ("enable.ssl.certificate.verification", "ssl_no_verify"),
        ("Enable.SSL.Certificate.Verification", "ssl_no_verify"),
        ("ssl.endpoint.identification.algorithm", "ssl_no_verify"),
        ("ssl.ca.location", "ssl_ca_location"),
        ("SSL.CA.LOCATION", "ssl_ca_location"),
        ("ssl.ca.pem", "ssl_ca_location"),
        ("ssl.ca.certificate.stores", "ssl_ca_location"),
        ("ssl.certificate.location", "ssl_certificate_location"),
        ("ssl.certificate.pem", "ssl_certificate_location"),
        ("ssl.key.location", "ssl_key_location"),
        ("ssl.key.pem", "ssl_key_location"),
        (
            "ssl.keystore.location",
            "ssl_certificate_location and ssl_key_location",
        ),
        ("sasl.mechanism", "sasl_mechanism"),
        ("sasl.mechanisms", "sasl_mechanism"),
        ("sasl.username", "sasl_username"),
        ("sasl.password", "sasl_password"),
        ("SASL.PASSWORD", "sasl_password"),
    ];
    for (producer_key, authoritative) in cases {
        let result = kafka_logging_validate_producer_admission_for_test(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "test",
                "producer_config": {
                    producer_key: "should-not-be-echoed-secret"
                }
            }),
            &default_http_client(),
        );
        match result {
            Err(e) => {
                assert!(
                    e.contains(authoritative),
                    "expected error pointing to {authoritative}, got: {e}"
                );
                assert!(
                    !e.contains("should-not-be-echoed-secret"),
                    "error must not echo producer_config values: {e}"
                );
            }
            Ok(()) => panic!("producer_config.{producer_key} must be rejected"),
        }
    }
}

#[tokio::test]
async fn test_kafka_logging_ssl_no_verify_skips_gateway_crl_path_requirement() {
    // Verification disabled: gateway CRL filesystem identity is not required.
    let client = default_http_client()
        .with_tls_crl_source(Some("vault://secret/data/kafka-crl".to_string()));
    kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "ssl_no_verify": true
        }),
        &client,
    )
    .expect("ssl_no_verify must skip gateway CRL path resolution");
}

#[tokio::test]
async fn test_kafka_logging_rejects_incoherent_tls_and_sasl_controls() {
    let cases = [
        json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "ssl_no_verify": false
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "sasl_plaintext",
            "ssl_ca_location": "/etc/ferrum/ca.pem"
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "ssl",
            "sasl_mechanism": "PLAIN"
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "security_protocol": "sasl_ssl",
            "sasl_username": "alice"
        }),
    ];
    for config in cases {
        let result =
            kafka_logging_validate_producer_admission_for_test(&config, &default_http_client());
        assert!(
            result.is_err(),
            "incoherent Kafka security controls must fail admission: {config}"
        );
    }
}

#[tokio::test]
async fn test_kafka_logging_rejects_security_namespaces_on_plaintext_escape_hatch() {
    for producer_key in [
        "ssl.crl.location",
        "ssl.cipher.suites",
        "sasl.oauthbearer.config",
        "https.ca.location",
    ] {
        let result = kafka_logging_validate_producer_admission_for_test(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "test",
                "producer_config": {
                    producer_key: "must-not-be-applied"
                }
            }),
            &default_http_client(),
        );
        assert!(
            result.is_err(),
            "producer_config.{producer_key} must not be ignored on plaintext transport"
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap-server grammar parity with the pinned librdkafka, and the
// fail-closed gate for destinations librdkafka dials without Ferrum ever
// seeing them (GHSA-mp2j-gjfp-2vm8).
// ---------------------------------------------------------------------------

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::plugins::kafka_logging::{
    KAFKA_DEFAULT_PORT, KafkaBootstrapEntry, parse_kafka_bootstrap_servers,
    screen_kafka_broker_list_egress,
};

fn entry(host: &str, port: u16) -> KafkaBootstrapEntry {
    KafkaBootstrapEntry {
        host: host.to_string(),
        port,
    }
}

fn parse_ok(broker_list: &str) -> Vec<KafkaBootstrapEntry> {
    parse_kafka_bootstrap_servers(broker_list, None).expect("broker list must parse")
}

fn default_production_policy() -> BackendEgressPolicy {
    BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid policy")
}

#[test]
fn kafka_bootstrap_grammar_matches_librdkafka_host_port_forms() {
    assert_eq!(parse_ok("broker:9092"), vec![entry("broker", 9092)]);
    // No port -> librdkafka's RD_KAFKA_PORT default.
    assert_eq!(
        parse_ok("broker"),
        vec![entry("broker", KAFKA_DEFAULT_PORT)]
    );
    assert_eq!(parse_ok("10.0.0.5:9093"), vec![entry("10.0.0.5", 9093)]);
    // Multiple entries, with the separator whitespace librdkafka skips.
    assert_eq!(
        parse_ok("a:1, b:2 ,c"),
        vec![entry("a", 1), entry("b", 2), entry("c", KAFKA_DEFAULT_PORT)]
    );
}

#[test]
fn kafka_bootstrap_grammar_matches_librdkafka_ipv6_forms() {
    // Bracketed IPv6 with a port: the byte before the last ':' is ']', so the
    // port is split off and the host keeps its brackets.
    assert_eq!(parse_ok("[::1]:9092"), vec![entry("[::1]", 9092)]);
    // Bracketed IPv6 without a port: last ':' is inside the brackets and is not
    // preceded by ']', so no port is split.
    assert_eq!(
        parse_ok("[fd00:ec2::254]"),
        vec![entry("[fd00:ec2::254]", KAFKA_DEFAULT_PORT)]
    );
    // Bare IPv6 without brackets: more than one ':' and no ']' -> whole string
    // is the host.
    assert_eq!(parse_ok("::1"), vec![entry("::1", KAFKA_DEFAULT_PORT)]);
    assert_eq!(parse_ok("[::1]:9092")[0].unbracketed_host(), "::1");
    assert_eq!(
        parse_ok("[fd00:ec2::254]")[0].literal_ip(),
        Some("fd00:ec2::254".parse().unwrap())
    );
}

#[test]
fn kafka_bootstrap_grammar_accepts_protocol_prefixes_and_strips_url_paths() {
    // This is the parser differential the advisory describes: a
    // protocol-prefixed literal that a `host:port`-only reading misses.
    assert_eq!(
        parse_ok("PLAINTEXT://169.254.169.254:9092"),
        vec![entry("169.254.169.254", 9092)]
    );
    assert_eq!(
        parse_ok("sasl_ssl://broker.example.com"),
        vec![entry("broker.example.com", KAFKA_DEFAULT_PORT)]
    );
    // "Ignore anything that looks like the path part of an URL".
    assert_eq!(
        parse_ok("ssl://10.0.0.5:9093/ignored/path"),
        vec![entry("10.0.0.5", 9093)]
    );
    // Empty host after the scheme becomes localhost.
    assert_eq!(
        parse_ok("plaintext://:9092"),
        vec![entry("localhost", 9092)]
    );
}

#[test]
fn kafka_bootstrap_grammar_rejects_entries_librdkafka_would_refuse() {
    for broker_list in ["://host:9092", "https://host:9092", "ftp://host"] {
        let error = parse_kafka_bootstrap_servers(broker_list, None)
            .err()
            .unwrap_or_else(|| {
                panic!("librdkafka would refuse this entry and stop parsing the list")
            });
        assert!(
            error.contains("protocol"),
            "unexpected error for {broker_list}: {error}"
        );
    }
    // A protocol prefix that disagrees with security.protocol makes librdkafka
    // drop the entry (and the rest of the list) — reject instead.
    let error = parse_kafka_bootstrap_servers("ssl://broker:9093", Some("plaintext"))
        .err()
        .unwrap_or_else(|| panic!("protocol mismatch must be rejected"));
    assert!(
        error.contains("does not match `security_protocol`"),
        "{error}"
    );
    assert!(parse_kafka_bootstrap_servers("ssl://broker:9093", Some("ssl")).is_ok());
    // Case-insensitive, matching librdkafka's uppercase-then-compare.
    assert!(parse_kafka_bootstrap_servers("SASL_SSL://broker", Some("sasl_ssl")).is_ok());
}

#[test]
fn kafka_protocol_prefixed_denied_literal_is_rejected_under_restrictive_policy() {
    // The screen must see the metadata address through the protocol prefix.
    let error = screen_kafka_broker_list_egress(
        &json!({ "broker_list": "PLAINTEXT://169.254.169.254:9092", "topic": "logs" }),
        &default_production_policy(),
    )
    .err()
    .unwrap_or_else(|| panic!("protocol-prefixed denied literal must be rejected"));
    assert!(
        error.contains("169.254.169.254") && error.contains("denied by backend egress policy"),
        "{error}"
    );
}

#[test]
fn kafka_bracketed_ipv6_denied_literal_is_rejected() {
    let error = screen_kafka_broker_list_egress(
        &json!({ "broker_list": "ssl://[fd00:ec2::254]:9093", "security_protocol": "ssl" }),
        &default_production_policy(),
    )
    .err()
    .unwrap_or_else(|| panic!("denied IPv6 literal must be rejected"));
    assert!(error.contains("denied by backend egress policy"), "{error}");
}

#[test]
fn kafka_logging_fails_closed_under_any_restrictive_egress_policy() {
    // librdkafka resolves bootstrap hostnames itself and dials brokers learned
    // from cluster metadata; rdkafka 0.39 exposes no connect/resolve callback,
    // so those addresses cannot be screened. Rather than leave an unenforced
    // egress path, the plugin is refused.
    for policy in [
        default_production_policy(),
        BackendEgressPolicy::from_env(BackendAllowIps::Public, "", "", false).expect("policy"),
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", false)
            .expect("policy"),
    ] {
        let error = screen_kafka_broker_list_egress(
            &json!({ "broker_list": "broker.example.com:9092", "topic": "logs" }),
            &policy,
        )
        .err()
        .unwrap_or_else(|| panic!("kafka_logging must fail closed under a restrictive policy"));
        assert!(
            error.contains("cannot be admitted"),
            "unexpected error: {error}"
        );
        // The message must not leak credentials or endpoint userinfo.
        assert!(
            !error.contains("password") && !error.contains('@'),
            "{error}"
        );
    }
}

#[test]
fn kafka_logging_is_admitted_only_when_the_policy_denies_nothing() {
    screen_kafka_broker_list_egress(
        &json!({ "broker_list": "PLAINTEXT://broker.example.com:9092" }),
        &BackendEgressPolicy::unrestricted(),
    )
    .expect("a fully-open policy has no boundary to bypass");
}

#[tokio::test]
async fn kafka_logging_registry_admission_fails_closed_under_default_policy() {
    let error = ferrum_edge::plugins::validate_plugin_config_with_policy(
        "kafka_logging",
        &json!({ "broker_list": "broker.example.com:9092", "topic": "logs" }),
        &default_production_policy(),
    )
    .err()
    .unwrap_or_else(|| panic!("registry admission must apply the same gate"));
    assert!(error.contains("cannot be admitted"), "{error}");
}

#[tokio::test]
async fn kafka_logging_warmup_hostnames_use_the_librdkafka_grammar() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "PLAINTEXT://broker-one:9092,[fd00::1]:9093,10.0.0.5:9094,broker-two",
            "topic": "logs"
        }),
        &default_http_client(),
    )
    .expect("build plugin");
    let mut hostnames = plugin.warmup_hostnames();
    hostnames.sort();
    assert_eq!(
        hostnames,
        vec!["broker-one".to_string(), "broker-two".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Downstream (librdkafka) retained-byte ownership — GHSA-83h5-52mw-f33p.
//
// `ThreadedProducer::send` success only means librdkafka copied the record into
// its own queue. Releasing the lease at that handoff would leave a stalled
// broker's pinned queue outside both the per-instance budget and the process
// ceiling, and multiple instances would multiply it.
// ---------------------------------------------------------------------------

fn leaked_test_ceiling(max_bytes: usize) -> &'static RetainedByteCeiling {
    let ceiling: &'static RetainedByteCeiling =
        Box::leak(Box::new(RetainedByteCeiling::new(max_bytes)));
    ceiling.set_max_unclamped_for_test(max_bytes);
    ceiling
}

#[test]
fn kafka_lease_is_held_while_librdkafka_retains_the_record_and_released_on_destroy() {
    let ceiling = leaked_test_ceiling(8 * 1024 * 1024);
    // librdkafka is an unconditional dependency and the probe's broker is a
    // local unreachable port, so producer creation failing is evidence of a
    // defect, not an optional environment capability. Fail, never skip.
    let (instance_after_send, ceiling_after_send, instance_after_destroy, ceiling_after_destroy) =
        kafka_logging_probe_downstream_lease_ownership_for_test(ceiling, 4)
            .expect("librdkafka downstream-ownership probe must run");

    assert!(
        instance_after_send > 0,
        "the per-instance budget must still charge the record librdkafka retains"
    );
    assert!(
        ceiling_after_send > 0,
        "the process ceiling must still charge the record librdkafka retains"
    );
    assert_eq!(
        instance_after_send, ceiling_after_send,
        "the per-instance and ceiling charges stay in lockstep"
    );
    assert_eq!(
        instance_after_destroy, 0,
        "producer destruction purges the queue and releases every lease exactly once"
    );
    assert_eq!(
        ceiling_after_destroy, 0,
        "no ceiling reservation leaks or underflows across delivery callbacks"
    );
}

#[test]
fn kafka_downstream_leases_of_multiple_instances_share_one_ceiling() {
    let ceiling = leaked_test_ceiling(8 * 1024 * 1024);
    let (_, first_ceiling_used, _, first_after_destroy) =
        kafka_logging_probe_downstream_lease_ownership_for_test(ceiling, 2)
            .expect("librdkafka downstream-ownership probe must run");
    assert!(first_ceiling_used > 0);
    assert_eq!(first_after_destroy, 0);

    // Saturate the shared ceiling from outside any `kafka_logging` instance. The
    // next instance's own 1 MiB per-instance budget is entirely free, so only an
    // *aggregate* bound can refuse its record leases — a private per-instance
    // allowance would admit them. Running the probes sequentially would not
    // distinguish the two, because each one fully drains before the next starts.
    let hold = ceiling
        .try_acquire(8 * 1024 * 1024)
        .expect("the shared ceiling can be saturated");
    let refused = kafka_logging_probe_downstream_lease_ownership_for_test(ceiling, 2);
    assert!(
        refused.is_err(),
        "a second instance must be refused by the shared ceiling while it is saturated"
    );
    assert_eq!(
        ceiling.used(),
        8 * 1024 * 1024,
        "a refused instance must leave only the pre-existing hold charged"
    );

    // Capacity recovers for the next instance once the hold releases.
    drop(hold);
    assert_eq!(ceiling.used(), 0);
    let (_, second_ceiling_used, _, second_after_destroy) =
        kafka_logging_probe_downstream_lease_ownership_for_test(ceiling, 2)
            .expect("librdkafka downstream-ownership probe must run");
    assert_eq!(
        second_ceiling_used, first_ceiling_used,
        "both instances reserve against the same ceiling"
    );
    assert_eq!(second_after_destroy, 0);
    assert_eq!(ceiling.used(), 0);
}

// ── #5213: Kafka topic-name syntax is admitted, not discovered at runtime ────

#[tokio::test]
async fn kafka_rejects_topic_names_kafka_can_never_create() {
    let too_long = "a".repeat(MAX_KAFKA_TOPIC_NAME_LENGTH + 1);
    for topic in [
        ".",
        "..",
        "bad/name",
        "bad name",
        "bad:name",
        "bad,name",
        "café-logs",
        "logs\n",
        too_long.as_str(),
    ] {
        let error = KafkaLogging::new(
            &json!({"broker_list": "localhost:9092", "topic": topic}),
            &default_http_client(),
        )
        .err()
        .unwrap_or_else(|| panic!("an invalid Kafka topic name must be refused at admission"));
        assert!(
            error.contains("topic"),
            "topic rejection must name the field, got: {error}"
        );
    }
}

#[tokio::test]
async fn kafka_admits_every_legal_topic_name_shape() {
    let at_limit = "a".repeat(MAX_KAFKA_TOPIC_NAME_LENGTH);
    for topic in [
        "a",
        "access-logs",
        "access_logs",
        "access.logs",
        "...",
        "0",
        at_limit.as_str(),
    ] {
        KafkaLogging::new(
            &json!({"broker_list": "localhost:9092", "topic": topic}),
            &default_http_client(),
        )
        .unwrap_or_else(|error| panic!("legal Kafka topic '{topic}' must be admitted: {error}"));
    }
}

// ── #5215: a transactional producer can never deliver from this sink ─────────

#[tokio::test]
async fn kafka_rejects_transactional_producer_configuration() {
    // Both spellings: the constructor matches producer_config keys
    // case-insensitively, so a re-cased property cannot slip past the refusal.
    for config in [
        json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "producer_config": {"transactional.id": "audit-transaction"}
        }),
        json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "producer_config": {"TRANSACTIONAL.ID": "audit-transaction"}
        }),
    ] {
        let error = KafkaLogging::new(&config, &default_http_client())
            .err()
            .unwrap_or_else(|| {
                panic!("transactional.id must be refused before a generation is published")
            });
        assert!(
            error.contains("transactional.id") || error.contains("TRANSACTIONAL.ID"),
            "rejection must name the property, got: {error}"
        );
        assert!(
            !error.contains("audit-transaction"),
            "rejection must not echo the configured value, got: {error}"
        );
        // The pure admission boundary refuses it too, so a reload candidate
        // never reaches producer construction.
        assert!(
            kafka_logging_validate_producer_admission_for_test(&config, &default_http_client())
                .is_err(),
            "producer admission must refuse transactional.id"
        );
    }
}

// ── #5216: SASL credential bytes reach the broker unchanged ──────────────────

#[tokio::test]
async fn kafka_preserves_sasl_credential_bytes_verbatim() {
    let config = json!({
        "broker_list": "localhost:9092",
        "topic": "audit-logs",
        "security_protocol": "sasl_plaintext",
        "sasl_mechanism": "PLAIN",
        "sasl_username": " test ",
        "sasl_password": "  pa ss  "
    });
    let (username, password) =
        kafka_logging_parsed_sasl_credentials_for_test(&config, &default_http_client())
            .expect("padded SASL credentials must be admitted");
    assert_eq!(username.as_deref(), Some(" test "));
    assert_eq!(password.as_deref(), Some("  pa ss  "));
    KafkaLogging::new(&config, &default_http_client())
        .expect("padded SASL credentials must construct");
}

#[tokio::test]
async fn kafka_rejects_unsupported_sasl_credential_shapes_without_rewriting_them() {
    for (username, password) in [
        (json!("   "), json!("secret")),
        (json!("alice"), json!(" \t ")),
        (json!("al\u{0}ice"), json!("secret")),
        (json!("alice"), json!("sec\u{0}ret")),
    ] {
        let config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "security_protocol": "sasl_plaintext",
            "sasl_username": username,
            "sasl_password": password
        });
        let error = KafkaLogging::new(&config, &default_http_client())
            .err()
            .unwrap_or_else(|| {
                panic!("an unsupported credential shape must be rejected, not rewritten")
            });
        assert!(
            error.contains("sasl_username") || error.contains("sasl_password"),
            "rejection must name the credential field, got: {error}"
        );
        assert!(
            !error.contains("secret") && !error.contains("alice"),
            "rejection must not echo credential material, got: {error}"
        );
    }
}

// ── #5214: terminal Kafka losses reach the process-cumulative loss family ────

#[test]
fn kafka_terminal_delivery_failures_charge_the_shared_loss_family() {
    let (sink_error_delta, _queue_full_delta, delivery_failed, queue_rejected) =
        kafka_logging_probe_terminal_loss_accounting_for_test(4, None)
            .expect("librdkafka terminal-loss probe must run");

    assert_eq!(
        queue_rejected, 0,
        "an uncapped producer queue must accept every probe record locally"
    );
    assert_eq!(
        delivery_failed, 4,
        "producer destruction must resolve every queued record terminally"
    );
    // The shared family is process-wide, so a concurrently running test can
    // only add to it; the probe's own contribution is the lower bound.
    assert!(
        sink_error_delta >= 4,
        "every terminal delivery failure must charge the shared loss family, saw {sink_error_delta}"
    );
}

#[test]
fn kafka_immediate_producer_rejections_charge_the_shared_loss_family() {
    let (sink_error_delta, _queue_full_delta, delivery_failed, queue_rejected) =
        kafka_logging_probe_terminal_loss_accounting_for_test(8, Some(1))
            .expect("librdkafka terminal-loss probe must run");

    assert!(
        queue_rejected >= 1,
        "a one-record librdkafka queue must reject the rest immediately"
    );
    assert_eq!(
        queue_rejected + delivery_failed,
        8,
        "every record must be accounted for exactly once, as an immediate \
         rejection or a terminal delivery outcome"
    );
    // Only 8 records exist and fewer than 8 of them reached the delivery
    // callback, so 8 sink_error charges can only be met if the immediate
    // rejections were charged too. `sink_error` — not the admission-time
    // `queue_full` reason — is the correct label: these records were already
    // counted as accepted when they entered Ferrum's channel, and the
    // published accounting identity pairs `accepted` with admission-time
    // refusals only.
    assert!(
        sink_error_delta >= 8,
        "immediate rejections and purged records alike must charge the shared \
         loss family as sink_error, saw {sink_error_delta}"
    );
}

// ── #5217: the constructor and the OpenAPI component admit the same documents ─

#[tokio::test]
async fn kafka_enum_fields_accept_only_their_canonical_spelling() {
    for (field, value) in [
        ("security_protocol", "PLAINTEXT"),
        ("security_protocol", "Ssl"),
        ("security_protocol", " ssl "),
        ("key_field", " none "),
        ("key_field", "None"),
        ("acks", " 1 "),
        ("compression", " gzip "),
        ("compression", "GZIP"),
    ] {
        let mut config = json!({"broker_list": "localhost:9092", "topic": "audit-logs"});
        config[field] = json!(value);
        assert!(
            KafkaLogging::new(&config, &default_http_client()).is_err(),
            "'{field}: {value}' must be rejected: the OpenAPI enum admits only the \
             canonical lowercase spelling"
        );
    }

    for (field, value) in [
        ("security_protocol", "plaintext"),
        ("security_protocol", "ssl"),
        ("key_field", "none"),
        ("key_field", "proxy_id"),
        ("acks", "all"),
        ("acks", "-1"),
        ("compression", "zstd"),
    ] {
        let mut config = json!({"broker_list": "localhost:9092", "topic": "audit-logs"});
        config[field] = json!(value);
        KafkaLogging::new(&config, &default_http_client())
            .unwrap_or_else(|error| panic!("'{field}: {value}' must be admitted: {error}"));
    }
}

/// Native TLS/SCRAM are required in the default artifact (#5212). Validate
/// through the real constructor, which calls librdkafka's native config API;
/// a feature-list assertion or a capability skip would miss a broken build.
#[tokio::test]
async fn kafka_tls_protocols_pass_offline_native_validation() {
    let native = rdkafka::ClientConfig::new()
        .set("builtin.features", "ssl,sasl_scram")
        .create_native_config();
    assert!(
        native.is_ok(),
        "TLS and SCRAM must be compiled into librdkafka"
    );
    for mechanism in [
        None,
        Some("PLAIN"),
        Some("SCRAM-SHA-256"),
        Some("SCRAM-SHA-512"),
    ] {
        let mut config = json!({
            "broker_list": "127.0.0.1:9092",
            "topic": "audit-logs",
            "security_protocol": "ssl"
        });
        if let Some(mechanism) = mechanism {
            config["security_protocol"] = json!("sasl_ssl");
            config["sasl_mechanism"] = json!(mechanism);
            config["sasl_username"] = json!("ferrum-test");
            config["sasl_password"] = json!("fixture-password");
        }
        let plugin = KafkaLogging::new(&config, &default_http_client())
            .unwrap_or_else(|error| panic!("TLS/{mechanism:?} must validate offline: {error}"));
        assert_eq!(plugin.snapshot().admitted_total, 0);

        let restricted =
            PluginHttpClient::default_with_backend_allow_ips(default_production_policy());
        let error = KafkaLogging::new(&config, &restricted)
            .err()
            .expect("TLS support must not bypass restrictive egress policy");
        assert!(
            error.contains("denied by backend egress policy")
                || error.contains("cannot be admitted"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn kafka_message_timeout_ms_is_bounded_by_the_documented_range() {
    KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "message_timeout_ms": MAX_MESSAGE_TIMEOUT_MS
        }),
        &default_http_client(),
    )
    .expect("librdkafka's own maximum must be admitted");

    let error = KafkaLogging::new(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "message_timeout_ms": MAX_MESSAGE_TIMEOUT_MS + 1
        }),
        &default_http_client(),
    )
    .err()
    .unwrap_or_else(|| panic!("a message_timeout_ms above librdkafka's range must be rejected"));
    assert!(
        error.contains("message_timeout_ms"),
        "the diagnostic must name the field rather than report an opaque client \
         config error, got: {error}"
    );
}

#[test]
fn startup_diagnostics_withhold_kafka_enums_and_producer_keys() {
    let secret = "'diagnostic-secret-5594`\"\\\n";
    for (field, value) in [
        ("security_protocol", json!(secret)),
        ("key_field", json!(secret)),
        ("compression", json!(secret)),
        ("acks", json!(secret)),
        (
            "producer_config",
            json!({"'diagnostic-secret-5594": 987654321}),
        ),
    ] {
        let mut config = json!({"broker_list": "localhost:9092", "topic": "logs"});
        config[field] = value;
        let error = KafkaLogging::new(&config, &default_http_client())
            .err()
            .expect("invalid Kafka configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(!rendered.contains("diagnostic-secret-5594"), "{rendered}");
        assert!(!rendered.contains("987654321"), "{rendered}");
    }

    let error = ferrum_edge::plugins::kafka_logging::parse_kafka_bootstrap_servers(
        "'diagnostic-secret-5594://localhost:9092",
        None,
    )
    .unwrap_err();
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    assert!(rendered.contains("unsupported protocol"), "{rendered}");
    assert!(!rendered.contains("diagnostic-secret-5594"), "{rendered}");
}

// ---------------------------------------------------------------------------
// librdkafka native-loader, command and gateway-file keys (issue #6539).
// ---------------------------------------------------------------------------

/// Every `producer_config` key the plugin material registry lists as native:
/// it loads native code, runs a host command, or reads a gateway file.
const NATIVE_PRODUCER_KEYS: &[&str] = &[
    "plugin.library.paths",
    "ssl.engine.location",
    "ssl.engine.id",
    "ssl.providers",
    "sasl.kerberos.kinit.cmd",
    "sasl.kerberos.keytab",
    "sasl.oauthbearer.assertion.private.key.file",
    "sasl.oauthbearer.assertion.file",
    "sasl.oauthbearer.assertion.jwt.template.file",
    "https.ca.location",
    "offset.store.path",
];

/// `sasl_ssl` satisfies both the `ssl.*` and the `sasl.*`/`https.*` transport
/// requirements, so only the native-key rule can refuse these configs.
fn native_key_config(key: &str) -> serde_json::Value {
    json!({
        "broker_list": "localhost:9093",
        "topic": "test",
        "security_protocol": "sasl_ssl",
        "sasl_mechanism": "PLAIN",
        "sasl_username": "alice",
        "sasl_password": "alice-secret",
        "ssl_no_verify": true,
        "producer_config": { key: "/opt/attacker/payload" }
    })
}

#[test]
fn native_producer_keys_are_refused_for_every_token_by_default() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let mut keys: Vec<String> = NATIVE_PRODUCER_KEYS.iter().map(|k| k.to_string()).collect();
    // librdkafka matches names exactly; the refusal must not depend on case.
    keys.push("Plugin.Library.Paths".to_string());
    keys.push("SASL.KERBEROS.KINIT.CMD".to_string());
    // librdkafka strips a `topic.` prefix from global-level topic properties.
    keys.push("topic.offset.store.path".to_string());
    keys.push("Topic.plugin.library.paths".to_string());
    for key in keys {
        let error = kafka_logging_validate_producer_admission_for_test(
            &native_key_config(&key),
            &default_http_client(),
        )
        .expect_err("a native producer_config key must be refused without the opt-in");
        assert!(
            error.contains(&format!("{key:?}"))
                && error.contains("FERRUM_KAFKA_ALLOW_NATIVE_CONFIG"),
            "{key}: the refusal must name the key and the opt-in: {error}"
        );
        assert!(
            !error.contains("/opt/attacker/payload"),
            "{key}: the refusal must not echo the configured value: {error}"
        );
        // Construction applies the same admission, so a stored config with a
        // native key cannot start a producer either.
        assert!(
            KafkaLogging::new(&native_key_config(&key), &default_http_client()).is_err(),
            "{key}: plugin construction must refuse a native key"
        );
    }
}

#[test]
fn native_producer_keys_are_admitted_only_with_the_operator_opt_in() {
    let env = crate::unit::env_lock::EnvGuard::new(&[]);
    for value in ["true", "TRUE", "1", "yes"] {
        env.set("FERRUM_KAFKA_ALLOW_NATIVE_CONFIG", value);
        for key in NATIVE_PRODUCER_KEYS {
            kafka_logging_validate_producer_admission_for_test(
                &native_key_config(key),
                &default_http_client(),
            )
            .unwrap_or_else(|error| panic!("{key} with opt-in {value:?}: {error}"));
        }
    }
    for value in ["false", "0", "no", "", "maybe"] {
        env.set("FERRUM_KAFKA_ALLOW_NATIVE_CONFIG", value);
        assert!(
            kafka_logging_validate_producer_admission_for_test(
                &native_key_config("plugin.library.paths"),
                &default_http_client(),
            )
            .is_err(),
            "opt-in value {value:?} must not allow native keys"
        );
    }
}

#[test]
fn native_producer_key_list_matches_the_plugin_material_registry() {
    let registered = ferrum_edge::_test_support::kafka_native_producer_keys_for_test();
    let mut registered: Vec<&str> = registered.iter().map(|(key, _)| *key).collect();
    registered.sort_unstable();
    let mut expected = NATIVE_PRODUCER_KEYS.to_vec();
    expected.sort_unstable();
    assert_eq!(registered, expected);
}

#[test]
fn ordinary_tuning_keys_do_not_need_the_opt_in() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    kafka_logging_validate_producer_admission_for_test(
        &json!({
            "broker_list": "localhost:9092",
            "topic": "test",
            "producer_config": {"linger.ms": "5", "batch.num.messages": "1000", "client.id": "edge"}
        }),
        &default_http_client(),
    )
    .expect("tuning keys stay admitted without the opt-in");
}

/// The shared publication validator (full snapshots and incremental updates on
/// every node, including a data plane fed by an opted-in control plane) refuses
/// a disabled row carrying a native key under this node's own opt-in.
#[test]
fn snapshot_validator_refuses_disabled_native_rows_under_the_local_opt_in() {
    let env = crate::unit::env_lock::EnvGuard::new(&[]);
    let now = chrono::Utc::now();
    let row =
        |id: &str, producer_config: serde_json::Value| ferrum_edge::config::types::PluginConfig {
            labels: Default::default(),
            id: id.to_string(),
            plugin_name: "kafka_logging".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            config: json!({
                "broker_list": "localhost:9092",
                "topic": "logs",
                "producer_config": producer_config
            }),
            scope: ferrum_edge::config::types::PluginScope::Global,
            proxy_id: None,
            enabled: false,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
    let rows = vec![
        row("tuning", json!({"linger.ms": "5"})),
        row(
            "native",
            json!({"ssl.engine.location": "/opt/attacker/engine.so"}),
        ),
    ];
    let refusals = ferrum_edge::_test_support::kafka_snapshot_native_key_refusals_for_test(&rows);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("\"native\"") && refusals[0].contains("ssl.engine.location"));
    assert!(!refusals[0].contains("/opt/attacker"));

    env.set("FERRUM_KAFKA_ALLOW_NATIVE_CONFIG", "true");
    assert!(
        ferrum_edge::_test_support::kafka_snapshot_native_key_refusals_for_test(&rows).is_empty()
    );
}

// ---------------------------------------------------------------------------
// Production-launch review fixes (kafka_logging-SOL-1/2, kafka_logging-CLAUDE-1..8).
// ---------------------------------------------------------------------------

use ferrum_edge::config::env_config::{KafkaBrokerAllowance, parse_kafka_allowed_brokers};
use ferrum_edge::plugins::kafka_logging::screen_kafka_broker_list_egress_with_allowance;

fn broker_allowance(raw: &str) -> KafkaBrokerAllowance {
    parse_kafka_allowed_brokers(Some(raw)).expect("valid broker allowance")
}

fn literal(ip: &str) -> Option<std::net::IpAddr> {
    Some(ip.parse().expect("test IP literal"))
}

// ── kafka_logging-SOL-2 / CLAUDE-7: operator-attested brokers ────────────────

#[test]
fn kafka_broker_allowance_parses_endpoints_and_cidrs_strictly() {
    assert!(parse_kafka_allowed_brokers(None).expect("unset").is_empty());
    assert!(
        parse_kafka_allowed_brokers(Some("  "))
            .expect("blank")
            .is_empty()
    );

    let allowance =
        broker_allowance("Kafka-0.Internal:9093, 10.20.0.0/24, [fd00::5]:9094, 192.0.2.7:9092");
    assert!(allowance.covers("kafka-0.internal", None, 9093));
    assert!(
        !allowance.covers("kafka-0.internal", None, 9092),
        "the port is part of a host:port attestation"
    );
    assert!(!allowance.covers("kafka-1.internal", None, 9093));
    assert!(
        allowance.covers("10.20.0.9", literal("10.20.0.9"), 1234),
        "a listed CIDR covers its addresses on any port"
    );
    assert!(!allowance.covers("10.21.0.9", literal("10.21.0.9"), 9093));
    assert!(allowance.covers("fd00::5", literal("fd00::5"), 9094));
    assert!(!allowance.covers("fd00::5", literal("fd00::5"), 9095));
    assert!(allowance.covers("192.0.2.7", literal("192.0.2.7"), 9092));
    assert!(!allowance.covers("192.0.2.8", literal("192.0.2.8"), 9092));

    for invalid in [
        "kafka-0:9092,,kafka-1:9092",
        "kafka-0:9092,",
        "kafka-0",
        "kafka-0:0",
        "kafka-0:70000",
        "[kafka-0]:9092",
        "[fd00::1]",
        "kafka 0:9092",
        "10.0.0.0/33",
        "0.0.0.0/0",
        "::/0",
        "0.0.0.0/1,128.0.0.0/1",
    ] {
        assert!(
            parse_kafka_allowed_brokers(Some(invalid)).is_err(),
            "{invalid:?} must fail closed instead of widening or dropping the attestation"
        );
    }
}

#[test]
fn kafka_logging_is_admitted_under_a_restrictive_policy_only_for_attested_brokers() {
    let policy = default_production_policy();
    let config = json!({
        "broker_list": "kafka-0.internal:9093,10.20.0.9:9093",
        "topic": "logs"
    });

    let error = screen_kafka_broker_list_egress_with_allowance(
        &config,
        &policy,
        &KafkaBrokerAllowance::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("without an attestation the default posture stays closed"));
    assert!(
        error.contains("cannot be admitted") && error.contains("FERRUM_KAFKA_ALLOWED_BROKERS"),
        "{error}"
    );

    screen_kafka_broker_list_egress_with_allowance(
        &config,
        &policy,
        &broker_allowance("kafka-0.internal:9093,10.20.0.0/24"),
    )
    .expect("every attested bootstrap broker is admitted under the default posture");

    let error = screen_kafka_broker_list_egress_with_allowance(
        &config,
        &policy,
        &broker_allowance("kafka-0.internal:9093"),
    )
    .err()
    .unwrap_or_else(|| panic!("an unlisted bootstrap broker must refuse the config"));
    assert!(
        error.contains("10.20.0.9:9093") && error.contains("not listed"),
        "{error}"
    );

    // A fully-open policy needs no attestation.
    screen_kafka_broker_list_egress_with_allowance(
        &config,
        &BackendEgressPolicy::unrestricted(),
        &KafkaBrokerAllowance::default(),
    )
    .expect("a fully-open policy has no boundary to bypass");
}

#[test]
fn kafka_attested_literal_brokers_pass_deny_lists_but_never_the_dangerous_baseline() {
    let config = json!({ "broker_list": "10.1.2.3:9092", "topic": "logs" });

    let deny = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", true)
        .expect("policy");
    let error = screen_kafka_broker_list_egress_with_allowance(
        &config,
        &deny,
        &KafkaBrokerAllowance::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("an unattested denied literal must be refused"));
    assert!(error.contains("FERRUM_BACKEND_DENY_CIDRS"), "{error}");
    screen_kafka_broker_list_egress_with_allowance(
        &config,
        &deny,
        &broker_allowance("10.1.2.3:9092"),
    )
    .expect("an attested broker may pass FERRUM_BACKEND_DENY_CIDRS");

    let public =
        BackendEgressPolicy::from_env(BackendAllowIps::Public, "", "", true).expect("policy");
    screen_kafka_broker_list_egress_with_allowance(
        &config,
        &public,
        &broker_allowance("10.1.2.0/24"),
    )
    .expect("an attested broker may pass the FERRUM_BACKEND_ALLOW_IPS mode");

    let metadata = json!({ "broker_list": "PLAINTEXT://169.254.169.254:9092", "topic": "logs" });
    for allowance in ["169.254.169.254:9092", "169.254.0.0/16"] {
        let error = screen_kafka_broker_list_egress_with_allowance(
            &metadata,
            &default_production_policy(),
            &broker_allowance(allowance),
        )
        .err()
        .unwrap_or_else(|| panic!("{allowance}: the attestation must not waive the baseline"));
        assert!(
            error.contains("169.254.169.254") && error.contains("denied by backend egress policy"),
            "{error}"
        );
    }
    let escape_hatch =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "169.254.169.254/32", "", true)
            .expect("policy");
    screen_kafka_broker_list_egress_with_allowance(
        &metadata,
        &escape_hatch,
        &broker_allowance("169.254.169.254:9092"),
    )
    .expect("FERRUM_BACKEND_ALLOW_CIDRS stays the explicit override for the baseline");
}

#[tokio::test]
async fn kafka_logging_admission_reads_the_node_broker_attestation() {
    let env = crate::unit::env_lock::EnvGuard::new(&[]);
    let restricted = PluginHttpClient::default_with_backend_allow_ips(default_production_policy());
    let config = json!({ "broker_list": "kafka-0.internal:9093", "topic": "logs" });

    assert!(
        KafkaLogging::new(&config, &restricted).is_err(),
        "the default posture stays closed without an attestation"
    );

    env.set("FERRUM_KAFKA_ALLOWED_BROKERS", "kafka-0.internal:9093");
    KafkaLogging::new(&config, &restricted)
        .unwrap_or_else(|error| panic!("an attested broker must be admitted: {error}"));
    ferrum_edge::plugins::validate_plugin_config_with_policy(
        "kafka_logging",
        &config,
        &default_production_policy(),
    )
    .unwrap_or_else(|error| panic!("registry admission must honour the attestation: {error}"));

    env.set("FERRUM_KAFKA_ALLOWED_BROKERS", "kafka-1.internal:9093");
    assert!(
        KafkaLogging::new(&config, &restricted).is_err(),
        "a broker outside the attestation must stay refused"
    );

    // A malformed attestation never widens admission.
    env.set("FERRUM_KAFKA_ALLOWED_BROKERS", "kafka-0.internal:9093,,");
    assert!(KafkaLogging::new(&config, &restricted).is_err());
}

// ── kafka_logging-SOL-1: reload disposal must not wait in the dropping owner ──

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_drop_returns_before_a_stalled_flush_and_retires_in_background() {
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": "127.0.0.1:1",
            "topic": "ferrum-retire",
            "message_timeout_ms": 300_000,
            "flush_timeout_seconds": 3
        }),
        &default_http_client(),
    )
    .expect("construct Kafka logger for retirement test");
    start_kafka_logging(&plugin);
    let generation_id = plugin.snapshot().generation_id;
    plugin.log(&create_test_transaction_summary()).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while plugin.snapshot().admitted_total == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the record must reach librdkafka so the flush has work that cannot finish");

    let started = std::time::Instant::now();
    drop(plugin);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "dropping the last handle must not wait for the producer flush budget, took {elapsed:?}"
    );
    let retiring = ferrum_edge::plugins::kafka_logging::snapshots()
        .into_iter()
        .find(|snapshot| snapshot.generation_id == generation_id)
        .expect("a retiring generation stays visible until its finalize completes");
    assert!(
        !retiring.accepting,
        "drop must close admission synchronously"
    );
    assert!(
        !retiring.finalized,
        "the stalled flush must still be running in the background"
    );

    tokio::time::timeout(Duration::from_secs(15), async {
        while ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snapshot| snapshot.generation_id == generation_id)
        {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the tracked retirement must finalize and unregister the generation");
}

// ── kafka_logging-CLAUDE-1: aliases and duplicates of managed properties ─────

#[tokio::test]
async fn kafka_refuses_every_spelling_of_properties_top_level_fields_own() {
    let client = default_http_client();
    for (key, field) in [
        ("acks", "acks"),
        ("request.required.acks", "acks"),
        ("Request.Required.Acks", "acks"),
        ("topic.acks", "acks"),
        ("topic.request.required.acks", "acks"),
        ("message.timeout.ms", "message_timeout_ms"),
        ("delivery.timeout.ms", "message_timeout_ms"),
        ("topic.delivery.timeout.ms", "message_timeout_ms"),
        ("compression.type", "compression"),
        ("compression.codec", "compression"),
        ("topic.compression.codec", "compression"),
    ] {
        let config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "acks": "all",
            "producer_config": { key: "0" }
        });
        let error = KafkaLogging::new(&config, &client)
            .err()
            .unwrap_or_else(|| panic!("producer_config.{key} must be refused"));
        assert!(
            error.contains(&format!("{key:?}")) && error.contains(&format!("top-level `{field}`")),
            "{key}: {error}"
        );
        assert_eq!(
            kafka_logging_validate_producer_admission_for_test(&config, &client),
            Err(error)
        );
    }
}

#[tokio::test]
async fn kafka_refuses_two_spellings_of_one_librdkafka_property() {
    let client = default_http_client();
    for (first, second) in [
        ("linger.ms", "queue.buffering.max.ms"),
        ("retries", "message.send.max.retries"),
        ("max.in.flight", "max.in.flight.requests.per.connection"),
        ("batch.num.messages", "Batch.Num.Messages"),
    ] {
        let config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "producer_config": { first: "5", second: "50" }
        });
        let error = KafkaLogging::new(&config, &client)
            .err()
            .unwrap_or_else(|| panic!("{first} and {second} together must be refused"));
        assert!(
            error.contains(&format!("{first:?}")) && error.contains(&format!("{second:?}")),
            "{error}"
        );
        assert!(
            !error.contains("\"50\"") && !error.contains("\"5\""),
            "{error}"
        );
    }
    for single in ["linger.ms", "queue.buffering.max.ms", "retries"] {
        KafkaLogging::new(
            &json!({
                "broker_list": "localhost:9092",
                "topic": "audit-logs",
                "producer_config": { single: "5" }
            }),
            &client,
        )
        .unwrap_or_else(|error| panic!("one spelling of {single} must be admitted: {error}"));
    }
}

// ── kafka_logging-CLAUDE-2: message ceiling and idempotence coherence ────────

#[tokio::test]
async fn kafka_message_max_bytes_must_fit_the_largest_admitted_entry() {
    let client = default_http_client();
    let config = |max_entry_bytes: usize, message_max_bytes: Option<usize>| {
        let mut config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "max_entry_bytes": max_entry_bytes,
        });
        if let Some(message_max_bytes) = message_max_bytes {
            config["producer_config"] =
                json!({ "message.max.bytes": message_max_bytes.to_string() });
        }
        config
    };

    let error = KafkaLogging::new(&config(DEFAULT_MAX_ENTRY_BYTES, Some(1024)), &client)
        .err()
        .unwrap_or_else(|| panic!("a message ceiling below max_entry_bytes must be refused"));
    assert!(
        error.contains("message.max.bytes") && error.contains("max_entry_bytes"),
        "{error}"
    );

    let floor = 4096 + KAFKA_MESSAGE_FRAMING_HEADROOM_BYTES;
    KafkaLogging::new(&config(4096, Some(floor)), &client)
        .unwrap_or_else(|error| panic!("exactly the framing floor must be admitted: {error}"));
    assert!(KafkaLogging::new(&config(4096, Some(floor - 1)), &client).is_err());

    // Without an explicit ceiling the default grows to fit the largest entry.
    KafkaLogging::new(&config(HARD_MAX_ENTRY_BYTES, None), &client).unwrap_or_else(|error| {
        panic!("the default message ceiling must fit a hard-maximum entry: {error}")
    });
}

#[tokio::test]
async fn kafka_idempotence_requires_acks_all_at_admission() {
    let client = default_http_client();
    let config = |acks: Option<&str>, idempotence: &str| {
        let mut config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "producer_config": { "enable.idempotence": idempotence }
        });
        if let Some(acks) = acks {
            config["acks"] = json!(acks);
        }
        config
    };
    for acks in ["0", "1"] {
        for idempotence in ["true", "TRUE", "t", "1"] {
            let error = KafkaLogging::new(&config(Some(acks), idempotence), &client)
                .err()
                .unwrap_or_else(|| panic!("idempotence {idempotence} with acks {acks} must fail"));
            assert!(
                error.contains("enable.idempotence") && error.contains("acks"),
                "{error}"
            );
        }
    }
    for acks in [None, Some("all"), Some("-1")] {
        KafkaLogging::new(&config(acks, "true"), &client)
            .unwrap_or_else(|error| panic!("idempotence with acks {acks:?} is valid: {error}"));
    }
    KafkaLogging::new(&config(Some("1"), "false"), &client)
        .unwrap_or_else(|error| panic!("acks 1 without idempotence is valid: {error}"));
}

// ── kafka_logging-CLAUDE-3: SASL mechanism and credential coherence ─────────

#[tokio::test]
async fn kafka_sasl_mechanism_is_reconciled_with_its_credentials() {
    let client = default_http_client();
    let sasl = |extra: serde_json::Value| {
        let mut config = json!({
            "broker_list": "localhost:9092",
            "topic": "audit-logs",
            "security_protocol": "sasl_plaintext"
        });
        for (key, value) in extra.as_object().expect("overrides are an object") {
            config[key] = value.clone();
        }
        config
    };
    let credentials = json!({"sasl_username": "ferrum", "sasl_password": "fixture-password"});
    let with_credentials = |mechanism: &str| {
        let mut extra = credentials.clone();
        extra["sasl_mechanism"] = json!(mechanism);
        sasl(extra)
    };

    for (config, expected) in [
        (sasl(credentials.clone()), "GSSAPI"),
        (sasl(json!({})), "sasl_mechanism"),
        (
            sasl(json!({"sasl_mechanism": "PLAIN"})),
            "requires `sasl_username`",
        ),
        (
            sasl(json!({"sasl_mechanism": "SCRAM-SHA-256"})),
            "requires `sasl_username`",
        ),
        (with_credentials("OAUTHBEARER"), "used only by"),
        (with_credentials("plain"), "unsupported `sasl_mechanism`"),
        (
            with_credentials("SCRAM-SHA-265"),
            "unsupported `sasl_mechanism`",
        ),
    ] {
        let error = KafkaLogging::new(&config, &client)
            .err()
            .unwrap_or_else(|| panic!("incoherent SASL config must be refused: {config}"));
        assert!(error.contains(expected), "expected {expected:?}: {error}");
        assert!(!error.contains("fixture-password"), "{error}");
    }

    for mechanism in ["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"] {
        KafkaLogging::new(&with_credentials(mechanism), &client)
            .unwrap_or_else(|error| panic!("{mechanism} with credentials is valid: {error}"));
    }
    KafkaLogging::new(&sasl(json!({"sasl_mechanism": "OAUTHBEARER"})), &client)
        .unwrap_or_else(|error| panic!("OAUTHBEARER without credentials is valid: {error}"));

    let gssapi = KafkaLogging::new(&sasl(json!({"sasl_mechanism": "GSSAPI"})), &client);
    if cfg!(windows) {
        gssapi.unwrap_or_else(|error| panic!("GSSAPI uses SSPI on Windows: {error}"));
    } else {
        let error = gssapi
            .err()
            .unwrap_or_else(|| panic!("GSSAPI must be refused without Cyrus SASL"));
        assert!(error.contains("GSSAPI"), "{error}");
    }
}

// ── kafka_logging-CLAUDE-4: QueueFull waits for queue space, bounded ────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_queue_full_waits_for_librdkafka_space_instead_of_dropping() {
    let outcome = kafka_logging_probe_queue_full_backoff_for_test(
        Some(Duration::from_millis(100)),
        Duration::from_secs(5),
    )
    .await
    .expect("librdkafka queue-full probe must run");
    assert_eq!(
        outcome.queue_rejected, 0,
        "a record refused while the queue was momentarily full must be retried: {outcome:?}"
    );
    assert_eq!(outcome.admitted, 2, "{outcome:?}");
    assert!(outcome.first_batch_waits >= 1, "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_queue_full_backoff_is_bounded_and_not_repeated_while_saturated() {
    let started = std::time::Instant::now();
    let outcome = kafka_logging_probe_queue_full_backoff_for_test(None, Duration::from_millis(200))
        .await
        .expect("librdkafka queue-full probe must run");
    assert_eq!(outcome.admitted, 1, "{outcome:?}");
    assert_eq!(outcome.queue_rejected, 2, "{outcome:?}");
    assert!(
        outcome.first_batch_waits >= 1,
        "the first QueueFull must back off before dropping: {outcome:?}"
    );
    assert_eq!(
        outcome.follow_up_waits, 0,
        "a saturated producer must drop further QueueFull records without waiting again: \
         {outcome:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the backoff must stay inside its budget"
    );
}

// ── kafka_logging-CLAUDE-5: the worker batches records per turn ─────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_worker_hands_librdkafka_batches_not_single_records() {
    let records = 1_000;
    let (flushes, flushed) = kafka_logging_probe_worker_batching_for_test(records)
        .await
        .expect("worker batching probe must run");
    assert_eq!(flushed, records, "close must still drain every record");
    assert!(
        flushes * 10 <= records,
        "expected batched worker turns, saw {flushes} flushes for {records} records"
    );
}

// ── kafka_logging-CLAUDE-6: saturation drops clear the healthy signal ───────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_admission_saturation_clears_healthy_until_delivery_recovers() {
    let cluster = MockCluster::new(1).expect("create Kafka mock cluster");
    let topic = "saturation-health";
    cluster
        .create_topic(topic, 1, 1)
        .expect("create mock topic");
    let plugin = KafkaLogging::new(
        &json!({
            "broker_list": cluster.bootstrap_servers(),
            "topic": topic,
            "compression": "none",
            "max_entry_bytes": 4096,
            "buffer_max_bytes": 4096,
            "message_timeout_ms": 10_000,
            "flush_timeout_seconds": 5,
            "producer_config": { "linger.ms": "0" }
        }),
        &default_http_client(),
    )
    .expect("construct Kafka logger for saturation health");
    start_kafka_logging(&plugin);
    assert!(plugin.snapshot().healthy);

    // The first record holds its lease until delivery, so the second one is
    // refused by the retained-byte budget.
    plugin.log(&create_test_transaction_summary()).await;
    plugin.log(&create_test_transaction_summary()).await;
    let saturated = plugin.snapshot();
    assert_eq!(saturated.byte_budget_exhausted_total, 1, "{saturated:?}");
    assert!(
        !saturated.healthy,
        "a generation shedding records must not report healthy: {saturated:?}"
    );
    let failure = saturated
        .last_failure
        .as_ref()
        .expect("saturation records the latest failure");
    assert_eq!(failure.operation, "admission");
    assert_eq!(failure.error_kind, "byte_budget_exhausted");

    let recovered = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let snapshot = plugin.snapshot();
            if snapshot.delivered_total >= 1 && snapshot.healthy {
                break snapshot;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the next terminal delivery must restore healthy");
    assert_eq!(recovered.delivery_failed_total, 0);
    plugin.finalize().await;
}

// ── kafka_logging-CLAUDE-8: partition key by effective identity ─────────────

#[test]
fn kafka_key_field_consumer_username_keys_by_effective_identity() {
    let config = json!({
        "broker_list": "localhost:9092",
        "topic": "audit-logs",
        "key_field": "consumer_username"
    });

    let mut http = create_test_transaction_summary();
    http.consumer_username = Some("tenant-a".to_string());
    assert_eq!(
        kafka_logging_http_record_key_for_test(&config, &http),
        Ok(Some("tenant-a".to_string()))
    );
    http.consumer_username = Some(String::new());
    assert_eq!(
        kafka_logging_http_record_key_for_test(&config, &http),
        Ok(None)
    );
    http.consumer_username = None;
    assert_eq!(
        kafka_logging_http_record_key_for_test(&config, &http),
        Ok(None)
    );

    let mut stream = create_test_stream_transaction_summary();
    stream.consumer_username = Some("svc-b".to_string());
    assert_eq!(
        kafka_logging_stream_record_key_for_test(&config, &stream),
        Ok(Some("svc-b".to_string()))
    );
    stream.consumer_username = None;
    assert_eq!(
        kafka_logging_stream_record_key_for_test(&config, &stream),
        Ok(None)
    );

    // The existing options keep their keys.
    let client_ip =
        json!({"broker_list": "localhost:9092", "topic": "t", "key_field": "client_ip"});
    assert_eq!(
        kafka_logging_http_record_key_for_test(&client_ip, &http),
        Ok(Some(http.client_ip.clone()))
    );
    let invalid = json!({"broker_list": "localhost:9092", "topic": "t", "key_field": "consumer"});
    assert!(kafka_logging_http_record_key_for_test(&invalid, &http).is_err());
}

//! Tests for kafka_logging plugin

use ferrum_edge::_test_support::{
    kafka_logging_probe_byte_budget_before_serialize_for_test,
    kafka_logging_probe_reserve_before_serialize_for_test,
    kafka_logging_validate_producer_admission_for_test,
};
use ferrum_edge::plugins::kafka_logging::{
    DEFAULT_BUFFER_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES, HARD_MAX_BUFFER_MAX_BYTES,
    HARD_MAX_ENTRY_BYTES, HARD_MAX_FLUSH_TIMEOUT_SECONDS, KafkaLogging,
};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginFailurePolicy, plugin_failure_policy};
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
    // Matching CRL overrides are admitted without constructing a producer
    // (CI librdkafka builds may lack OpenSSL).
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
    .expect_err("non-file CRL sources cannot be silently omitted for verified Kafka TLS");
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
    start_kafka_logging(&plugin);

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
    start_kafka_logging(&plugin);
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
    // Allow the worker to attempt librdkafka admission (releases leases).
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

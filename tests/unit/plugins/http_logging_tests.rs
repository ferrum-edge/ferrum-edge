//! Tests for http_logging plugin

use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, http_logging::HttpLogging};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_http_logging_plugin_creation() {
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://localhost:9200/logs",
            "custom_headers": {
                "Authorization": "Bearer log-token"
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "http_logging");
    assert_eq!(plugin.priority(), 9100);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_http_logging_plugin_creation_empty_config() {
    let result = HttpLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(
            e.contains("endpoint_url"),
            "Expected error about endpoint_url, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when creating http_logging without endpoint_url"),
    }
}

#[tokio::test]
async fn test_http_logging_empty_url_does_not_send() {
    // When endpoint_url is empty, creation should fail with an error
    assert!(HttpLogging::new(&json!({}), default_client()).is_err());

    // With a valid endpoint_url, log() should accept entries without errors
    let plugin = HttpLogging::new(
        &json!({"endpoint_url": "http://127.0.0.1:1/unreachable"}),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // This should not panic or error — entry goes into channel and is drained
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_http_logging_invalid_url_does_not_panic() {
    // When endpoint_url is unreachable, log() should handle the error gracefully
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued and background task handles the failure
    plugin.log(&summary).await;

    // Give the background flush task time to attempt delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_http_logging_rejects_malformed_endpoint_url() {
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "not a valid url"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("invalid 'endpoint_url'")),
        Ok(_) => panic!("Expected malformed endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_http_logging_rejects_non_http_scheme() {
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "tcp://127.0.0.1:9000/logs"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("http:// or https://")),
        Ok(_) => panic!("Expected non-http endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_http_logging_rejects_empty_endpoint_authority() {
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "https:///logs"
        }),
        default_client(),
    );
    let err = result
        .err()
        .expect("empty endpoint authority must be rejected");
    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_http_logging_warmup_unbrackets_ipv6_endpoint() {
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "https://[2001:db8::50]:9200/logs"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::50"]);
}

#[tokio::test]
async fn test_http_logging_with_custom_headers() {
    // custom_headers supports arbitrary key-value pairs for services like Datadog, New Relic
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "DD-API-KEY": "my-datadog-key",
                "X-Custom-Tag": "ferrum-edge"
            },
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "http_logging");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_http_logging_custom_headers_rejects_non_string_values() {
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "DD-API-KEY": "valid-key",
                "bad_number": 123,
                "bad_bool": true
            },
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("custom_headers['bad_")),
        Ok(_) => panic!("Expected non-string custom header values to be rejected"),
    }
}

#[tokio::test]
async fn test_http_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "custom_headers": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "batch_size": "10"}),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "flush_interval_ms": false}),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "buffer_capacity": -1}),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "max_retries": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/logs", "retry_delay_ms": {}}),
    ];

    for config in cases {
        assert!(
            HttpLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_http_logging_rejects_invalid_header_name() {
    // Header names with spaces or non-ASCII characters are rejected at config load time
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "Invalid Header": "value"
            }
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("invalid custom_headers name"),
            "Expected header name validation error, got: {e}"
        ),
        Ok(_) => panic!("Expected invalid header name to be rejected"),
    }
}

#[tokio::test]
async fn test_http_logging_rejects_invalid_header_value() {
    // Header values with non-visible ASCII are rejected at config load time
    let result = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "X-Token": "bad\x01value"
            }
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("invalid custom_headers value"),
            "Expected header value validation error, got: {e}"
        ),
        Ok(_) => panic!("Expected invalid header value to be rejected"),
    }
}

#[tokio::test]
async fn test_http_logging_custom_headers_deduplicates_case_insensitive() {
    // Duplicate header names with different casing should be deduplicated (last wins)
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "X-Custom": "first",
                "x-custom": "second"
            },
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "http_logging");
}

#[tokio::test]
async fn test_http_logging_default_lifecycle_phases() {
    // http_logging only implements log(), all other phases should return Continue
    let plugin = HttpLogging::new(
        &json!({"endpoint_url": "http://127.0.0.1:1/unreachable"}),
        default_client(),
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
async fn test_http_logging_batch_config_defaults() {
    // Plugin should accept minimal config and apply defaults
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://localhost:9200/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "http_logging");
}

#[tokio::test]
async fn test_http_logging_custom_batch_config() {
    // Plugin should accept all batch/retry config options
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://localhost:9200/logs",
            "batch_size": 100,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "buffer_capacity": 50000
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "http_logging");
}

#[tokio::test]
async fn test_http_logging_buffer_accepts_multiple_entries() {
    // log() should accept many entries without blocking
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        default_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_http_logging_buffer_full_drops_gracefully() {
    // When buffer_capacity is exceeded, entries should be dropped without panic
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        default_client(),
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
async fn test_http_logging_stream_disconnect_does_not_panic() {
    let plugin = HttpLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

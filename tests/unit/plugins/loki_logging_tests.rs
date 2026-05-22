//! Tests for loki_logging plugin

use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, loki_logging::LokiLogging};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_loki_logging_plugin_creation() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
    assert_eq!(plugin.priority(), 9155);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert_eq!(plugin.warmup_hostnames(), vec!["localhost".to_string()]);
}

#[tokio::test]
async fn test_loki_logging_plugin_creation_empty_config() {
    let result = LokiLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(
            e.contains("endpoint_url"),
            "Expected error about endpoint_url, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when creating loki_logging without endpoint_url"),
    }
}

#[tokio::test]
async fn test_loki_logging_rejects_malformed_endpoint_url() {
    let result = LokiLogging::new(
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
async fn test_loki_logging_rejects_non_http_scheme() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "tcp://127.0.0.1:3100/loki"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("http:// or https://")),
        Ok(_) => panic!("Expected non-http endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_loki_logging_rejects_empty_endpoint_authority() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "https:///loki/api/v1/push"
        }),
        default_client(),
    );
    let err = result
        .err()
        .expect("empty endpoint authority must be rejected");
    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_loki_logging_warmup_unbrackets_ipv6_endpoint() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "https://[2001:db8::51]:3100/loki/api/v1/push"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::51"]);
}

#[tokio::test]
async fn test_loki_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "gzip": "true"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": {"bad-label": "value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "labels": {"env": 1}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_proxy_id_label": "false"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_listen_path_label": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "include_status_class_label": 1}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"X-Scope-OrgID": 1}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"Bad Header": "value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "custom_headers": {"X-Bad": "bad\u{0001}value"}}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": ""}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": 123}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "authorization_header": "bad\u{0001}value"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "batch_size": "100"}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "flush_interval_ms": false}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "buffer_capacity": -1}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "max_retries": []}),
        json!({"endpoint_url": "http://127.0.0.1:1/loki", "retry_delay_ms": {}}),
    ];

    for config in cases {
        assert!(
            LokiLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_loki_logging_with_authorization_header() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "authorization_header": "Bearer my-loki-token",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_loki_logging_with_custom_headers() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "custom_headers": {
                "X-Scope-OrgID": "tenant-1"
            },
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_with_custom_labels() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "labels": {
                "service": "my-gateway",
                "env": "staging",
                "region": "us-east-1"
            },
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_loki_logging_gzip_disabled() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "gzip": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_default_lifecycle_phases() {
    let plugin = LokiLogging::new(
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
async fn test_loki_logging_batch_config_defaults() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_custom_batch_config() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://localhost:3100/loki/api/v1/push",
            "batch_size": 200,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "buffer_capacity": 50000,
            "gzip": true
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "loki_logging");
}

#[tokio::test]
async fn test_loki_logging_buffer_accepts_multiple_entries() {
    let plugin = LokiLogging::new(
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
}

#[tokio::test]
async fn test_loki_logging_buffer_full_drops_gracefully() {
    let plugin = LokiLogging::new(
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
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
}

#[tokio::test]
async fn test_loki_logging_unreachable_endpoint_graceful() {
    let plugin = LokiLogging::new(
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
    plugin.log(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_loki_logging_stream_disconnect_does_not_panic() {
    let plugin = LokiLogging::new(
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

#[tokio::test]
async fn test_loki_logging_label_options_disabled() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_proxy_id_label": false,
            "include_status_class_label": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_loki_logging_include_proxy_id_label_new_key() {
    let plugin = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_proxy_id_label": false,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    // No panic, and the plugin accepts the new key. Full label-output
    // coverage lives in the build_http_labels tests below.
}

#[tokio::test]
async fn test_loki_logging_removed_listen_path_key_rejected() {
    let result = LokiLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:1/unreachable",
            "include_listen_path_label": false,
            "max_retries": 0
        }),
        default_client(),
    );
    let err = result.err().expect("removed key should be rejected");
    assert!(err.contains("include_listen_path_label"), "got: {err}");
}

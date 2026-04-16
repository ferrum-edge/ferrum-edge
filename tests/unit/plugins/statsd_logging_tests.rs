//! Tests for statsd_logging plugin

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, StreamTransactionSummary, statsd_logging::StatsdLogging,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn make_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
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
async fn test_statsd_logging_plugin_creation() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 8125
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_missing_host() {
    let result = StatsdLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {e}"),
        Ok(_) => panic!("Expected Err when creating statsd_logging without host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_empty_host() {
    let result = StatsdLogging::new(&json!({"host": ""}), default_client());
    match result {
        Err(e) => assert!(e.contains("host")),
        Ok(_) => panic!("Expected Err for empty host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_zero() {
    let result = StatsdLogging::new(&json!({"host": "127.0.0.1", "port": 0}), default_client());
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_too_high() {
    let result = StatsdLogging::new(
        &json!({"host": "127.0.0.1", "port": 99999}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port > 65535"),
    }
}

#[tokio::test]
async fn test_statsd_logging_default_port() {
    // port defaults to 8125 when not specified
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_custom_prefix() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "prefix": "myapp.gateway"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_with_global_tags() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "global_tags": {
                "env": "prod",
                "region": "us-east-1"
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_log_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued and background task handles UDP send
    plugin.log(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_stream_disconnect_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = make_stream_summary();

    // Should not panic
    plugin.on_stream_disconnect(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_default_lifecycle_phases() {
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();

    let mut ctx = create_test_context();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_statsd_logging_buffer_full_drops_gracefully() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "buffer_capacity": 5,
            "max_batch_lines": 1000,
            "flush_interval_ms": 60000
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
async fn test_statsd_logging_accepts_all_config_options() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9125,
            "prefix": "gateway.edge",
            "global_tags": {"env": "staging", "dc": "us-west-2"},
            "flush_interval_ms": 1000,
            "buffer_capacity": 50000,
            "max_batch_lines": 100
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_warmup_hostnames() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "statsd.internal.example.com"
        }),
        default_client(),
    )
    .unwrap();
    let hosts = plugin.warmup_hostnames();
    assert_eq!(hosts, vec!["statsd.internal.example.com".to_string()]);
}

//! Tests for ws_logging plugin

use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, ws_logging::WsLogging};
use serde_json::json;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_ws_logging_plugin_creation() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_plugin_creation_wss() {
    // wss:// triggers rustls ClientConfig construction, which requires
    // a crypto provider to be installed (normally done in main.rs).
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::ring::default_provider(),
    );
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "wss://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_plugin_creation_empty_config() {
    let result = WsLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(
            e.contains("endpoint_url"),
            "Expected error about endpoint_url, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when creating ws_logging without endpoint_url"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_malformed_endpoint_url() {
    let result = WsLogging::new(
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
async fn test_ws_logging_rejects_non_ws_scheme() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:9000/logs"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("ws:// or wss://")),
        Ok(_) => panic!("Expected non-ws endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_tcp_scheme() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "tcp://127.0.0.1:9000/logs"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("ws:// or wss://")),
        Ok(_) => panic!("Expected tcp scheme to be rejected"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_missing_hostname() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "ws://"
        }),
        default_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ws_logging_log_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry goes into channel and is drained
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_ws_logging_unreachable_endpoint_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    plugin.log(&summary).await;

    // Give the background flush task time to attempt delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
}

#[tokio::test]
async fn test_ws_logging_default_lifecycle_phases() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable"
        }),
        default_client(),
    )
    .unwrap();

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
async fn test_ws_logging_batch_config_defaults() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_custom_batch_config() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs",
            "batch_size": 100,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "reconnect_delay_ms": 10000,
            "buffer_capacity": 50000
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_buffer_accepts_multiple_entries() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
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
async fn test_ws_logging_buffer_full_drops_gracefully() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
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

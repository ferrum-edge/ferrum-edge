//! Tests for tcp_logging plugin

use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, tcp_logging::TcpLogging};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
    assert_eq!(plugin.priority(), 9125);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_with_tls() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5141,
            "tls": true,
            "tls_server_name": "logstash.example.com"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_missing_host() {
    let result = TcpLogging::new(&json!({"port": 5140}), default_client());
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging without host"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_missing_port() {
    let result = TcpLogging::new(&json!({"host": "localhost"}), default_client());
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging without port"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_invalid_port_zero() {
    let result = TcpLogging::new(&json!({"host": "localhost", "port": 0}), default_client());
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging with port 0"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_invalid_port_too_large() {
    let result = TcpLogging::new(
        &json!({"host": "localhost", "port": 70000}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating tcp_logging with port > 65535"),
    }
}

#[tokio::test]
async fn test_tcp_logging_plugin_creation_empty_host() {
    let result = TcpLogging::new(&json!({"host": "", "port": 5140}), default_client());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tcp_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "tcp://logs.example.com",
        "user@logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "logs.example.com:5140",
        "bad host",
    ] {
        let result = TcpLogging::new(&json!({"host": host, "port": 5140}), default_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_tcp_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"host": 123, "port": 5140}),
        json!({"host": "localhost", "port": "5140"}),
        json!({"host": "localhost", "port": 5140, "tls": "true"}),
        json!({"host": "localhost", "port": 5140, "tls_server_name": ""}),
        json!({"host": "localhost", "port": 5140, "connect_timeout_ms": false}),
        json!({"host": "localhost", "port": 5140, "batch_size": []}),
        json!({"host": "localhost", "port": 5140, "max_retries": -1}),
    ];

    for config in cases {
        assert!(
            TcpLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_tcp_logging_log_does_not_panic() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
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
async fn test_tcp_logging_stream_disconnect_does_not_panic() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
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
async fn test_tcp_logging_default_lifecycle_phases() {
    let plugin =
        TcpLogging::new(&json!({"host": "127.0.0.1", "port": 1}), default_client()).unwrap();

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
async fn test_tcp_logging_batch_config_defaults() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_custom_batch_config() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "localhost",
            "port": 5140,
            "batch_size": 100,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "buffer_capacity": 50000,
            "connect_timeout_ms": 10000
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "tcp_logging");
}

#[tokio::test]
async fn test_tcp_logging_buffer_accepts_multiple_entries() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
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
async fn test_tcp_logging_buffer_full_drops_gracefully() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
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
async fn test_tcp_logging_warmup_hostnames() {
    let plugin = TcpLogging::new(
        &json!({
            "host": "logstash.example.com",
            "port": 5140
        }),
        default_client(),
    )
    .unwrap();

    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["logstash.example.com"]);
}

#[tokio::test]
async fn test_tcp_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin =
            TcpLogging::new(&json!({"host": host, "port": 5140}), default_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

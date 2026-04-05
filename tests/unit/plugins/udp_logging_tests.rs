//! Tests for udp_logging plugin

use ferrum_edge::plugins::{Plugin, udp_logging::UdpLogging};
use serde_json::json;

use super::plugin_utils::create_test_transaction_summary;

#[tokio::test]
async fn test_udp_logging_plugin_creation() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514
    }))
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_missing_host() {
    let result = UdpLogging::new(&json!({
        "port": 9514
    }));
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without host"),
    }
}

#[tokio::test]
async fn test_udp_logging_missing_port() {
    let result = UdpLogging::new(&json!({
        "host": "127.0.0.1"
    }));
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without port"),
    }
}

#[tokio::test]
async fn test_udp_logging_empty_host() {
    let result = UdpLogging::new(&json!({
        "host": "",
        "port": 9514
    }));
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_logging_invalid_port_zero() {
    let result = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 0
    }));
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_too_large() {
    let result = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 70000
    }));
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 70000"),
    }
}

#[tokio::test]
async fn test_udp_logging_log_does_not_panic() {
    // When the endpoint is unreachable, log() should still accept entries
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 1,
        "max_retries": 0
    }))
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued in the channel
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_udp_logging_buffer_accepts_multiple_entries() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 1,
        "batch_size": 50,
        "flush_interval_ms": 10000,
        "max_retries": 0,
        "buffer_capacity": 1000
    }))
    .unwrap();

    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_udp_logging_buffer_full_drops_gracefully() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 1,
        "batch_size": 1000,
        "flush_interval_ms": 60000,
        "max_retries": 0,
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
async fn test_udp_logging_default_lifecycle_phases() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514
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
async fn test_udp_logging_batch_config_defaults() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514
    }))
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_custom_batch_config() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514,
        "batch_size": 5,
        "flush_interval_ms": 2000,
        "max_retries": 3,
        "retry_delay_ms": 1000,
        "buffer_capacity": 50000
    }))
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_dtls_cert_key_pairing_required() {
    // cert without key should fail
    let result = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514,
        "dtls": true,
        "dtls_cert_path": "/some/cert.pem"
    }));
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when cert is provided without key"),
    }

    // key without cert should fail
    let result = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514,
        "dtls": true,
        "dtls_key_path": "/some/key.pem"
    }));
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when key is provided without cert"),
    }
}

#[tokio::test]
async fn test_udp_logging_dtls_config_accepted() {
    // DTLS config without certs (ephemeral cert will be used) should be accepted
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514,
        "dtls": true,
        "dtls_no_verify": true
    }))
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_warmup_hostnames() {
    let plugin = UdpLogging::new(&json!({
        "host": "syslog.example.com",
        "port": 9514
    }))
    .unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["syslog.example.com".to_string()]);
}

#[tokio::test]
async fn test_udp_logging_supported_protocols() {
    let plugin = UdpLogging::new(&json!({
        "host": "127.0.0.1",
        "port": 9514
    }))
    .unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 5); // Http, Grpc, WebSocket, Tcp, Udp
}

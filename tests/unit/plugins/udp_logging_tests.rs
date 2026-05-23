//! Tests for udp_logging plugin

use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, udp_logging::UdpLogging};
use serde_json::json;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn test_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

#[tokio::test]
async fn test_udp_logging_plugin_creation() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
    assert_eq!(plugin.priority(), 9160);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_udp_logging_missing_host() {
    let result = UdpLogging::new(
        &json!({
            "port": 9514
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without host"),
    }
}

#[tokio::test]
async fn test_udp_logging_missing_port() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without port"),
    }
}

#[tokio::test]
async fn test_udp_logging_empty_host() {
    let result = UdpLogging::new(
        &json!({
            "host": "",
            "port": 9514
        }),
        test_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "udp://logs.example.com",
        "user@logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "logs.example.com:9514",
        "bad host",
    ] {
        let result = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_zero() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 0
        }),
        test_client(),
    );
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
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 70000
        }),
        test_client(),
    );
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
async fn test_udp_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"host": 123, "port": 9514}),
        json!({"host": "127.0.0.1", "port": "9514"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": "true"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_no_verify": 1}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_cert_path": ""}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_key_path": false}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_ca_cert_path": []}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": {}}),
        json!({"host": "127.0.0.1", "port": 9514, "retry_delay_ms": "500"}),
    ];

    for config in cases {
        assert!(
            UdpLogging::new(&config, test_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_log_does_not_panic() {
    // When the endpoint is unreachable, log() should still accept entries
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued in the channel
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_udp_logging_stream_disconnect_does_not_panic() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_udp_logging_buffer_accepts_multiple_entries() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        test_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_udp_logging_buffer_full_drops_gracefully() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        test_client(),
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
async fn test_udp_logging_default_lifecycle_phases() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
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
async fn test_udp_logging_batch_config_defaults() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_custom_batch_config() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "batch_size": 5,
            "flush_interval_ms": 2000,
            "max_retries": 3,
            "retry_delay_ms": 1000,
            "buffer_capacity": 50000
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_dtls_cert_key_pairing_required() {
    // cert without key should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/some/cert.pem"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when cert is provided without key"),
    }

    // key without cert should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_key_path": "/some/key.pem"
        }),
        test_client(),
    );
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
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_warmup_hostnames() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "syslog.example.com",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["syslog.example.com".to_string()]);
}

#[tokio::test]
async fn test_udp_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_supported_protocols() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, ALL_PROTOCOLS);
}

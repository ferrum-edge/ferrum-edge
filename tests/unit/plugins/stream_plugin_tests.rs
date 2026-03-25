//! Tests for stream proxy plugin compatibility.
//!
//! Verifies that the correct plugins opt into stream proxy support
//! and that stream-specific plugin hooks work correctly.

use ferrum_gateway::plugins::{Plugin, create_plugin};
use serde_json::json;
use std::sync::Arc;

/// Helper to create a plugin by name with minimal config.
fn make_plugin(name: &str, config: serde_json::Value) -> Option<Arc<dyn Plugin>> {
    create_plugin(name, &config).ok().flatten()
}

#[test]
fn test_stream_compatible_plugins() {
    // Plugins that SHOULD support stream proxy
    let stream_plugins = vec![
        ("ip_restriction", json!({"allow": ["10.0.0.0/8"]})),
        ("rate_limiting", json!({"per_second": 100})),
        ("stdout_logging", json!({})),
        ("prometheus_metrics", json!({})),
        ("correlation_id", json!({})),
    ];

    for (name, config) in stream_plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        assert!(
            plugin.unwrap().supports_stream_proxy(),
            "Plugin {} should support stream proxy",
            name
        );
    }
}

#[test]
fn test_http_only_plugins() {
    // Plugins that should NOT support stream proxy
    let http_only_plugins = vec![
        ("cors", json!({"origins": ["*"]})),
        ("key_auth", json!({})),
        ("basic_auth", json!({})),
        ("request_transformer", json!({})),
        ("response_transformer", json!({})),
        ("body_validator", json!({"schema": {}})),
        ("request_termination", json!({"status_code": 503})),
        ("access_control", json!({"allowed_consumers": ["admin"]})),
        ("bot_detection", json!({})),
    ];

    for (name, config) in http_only_plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        assert!(
            !plugin.unwrap().supports_stream_proxy(),
            "Plugin {} should NOT support stream proxy",
            name
        );
    }
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_allowed() {
    use ferrum_gateway::config::types::BackendProtocol;
    use ferrum_gateway::plugins::{PluginResult, StreamConnectionContext};
    use std::collections::HashMap;

    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let ctx = StreamConnectionContext {
        client_ip: "10.1.2.3".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        metadata: HashMap::new(),
    };

    let result = plugin.on_stream_connect(&ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_denied() {
    use ferrum_gateway::config::types::BackendProtocol;
    use ferrum_gateway::plugins::{PluginResult, StreamConnectionContext};
    use std::collections::HashMap;

    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let ctx = StreamConnectionContext {
        client_ip: "192.168.1.1".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        metadata: HashMap::new(),
    };

    let result = plugin.on_stream_connect(&ctx).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

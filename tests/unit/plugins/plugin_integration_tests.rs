//! Integration tests for the plugin system
//! Tests plugin creation, scope configuration, and error handling

use ferrum_gateway::config::types::{PluginConfig, PluginScope};
use ferrum_gateway::plugins::{available_plugins, create_plugin};
use serde_json::json;

use super::plugin_utils::{create_test_consumer, create_test_context};

#[tokio::test]
async fn test_all_plugins_available() {
    let plugins = available_plugins();

    // 20 built-in + custom plugins from custom_plugins/mod.rs
    let expected_builtins = vec![
        "stdout_logging",
        "http_logging",
        "transaction_debugger",
        "oauth2_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "hmac_auth",
        "cors",
        "access_control",
        "ip_restriction",
        "bot_detection",
        "correlation_id",
        "request_transformer",
        "response_transformer",
        "rate_limiting",
        "body_validator",
        "request_termination",
        "prometheus_metrics",
        "otel_tracing",
    ];

    // Verify all built-in plugins are present
    assert!(
        plugins.len() >= expected_builtins.len(),
        "Expected at least {} plugins, got {}",
        expected_builtins.len(),
        plugins.len()
    );

    let expected_plugins = expected_builtins;

    for expected in expected_plugins {
        assert!(plugins.contains(&expected), "Missing plugin: {}", expected);
    }
}

#[tokio::test]
async fn test_plugin_creation_all_plugins() {
    for plugin_name in available_plugins() {
        // Some plugins now require specific config fields
        let config = match plugin_name {
            "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
            "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
            "oauth2_auth" => json!({"jwks_uri": "https://example.com/.well-known/jwks.json"}),
            "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
            "access_control" => json!({"allowed_ips": ["0.0.0.0/0"]}),
            _ => json!({}),
        };
        let plugin = create_plugin(plugin_name, &config);
        let plugin = plugin
            .unwrap_or_else(|e| panic!("create_plugin returned Err for {}: {}", plugin_name, e));
        assert!(plugin.is_some(), "Failed to create plugin: {}", plugin_name);
        assert_eq!(plugin.unwrap().name(), plugin_name);
    }
}

#[tokio::test]
async fn test_plugin_scope_configuration() {
    // Test global plugin config
    let global_config = PluginConfig {
        id: "global-plugin".to_string(),
        plugin_name: "stdout_logging".to_string(),
        config: json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(global_config.scope, PluginScope::Global);
    assert!(global_config.proxy_id.is_none());

    // Test proxy plugin config
    let proxy_config = PluginConfig {
        id: "proxy-plugin".to_string(),
        plugin_name: "jwt_auth".to_string(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("test-proxy".to_string()),
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(proxy_config.scope, PluginScope::Proxy);
    assert_eq!(proxy_config.proxy_id, Some("test-proxy".to_string()));
}

#[tokio::test]
async fn test_plugin_error_handling() {
    // Test creating plugin with invalid name
    let config = json!({});
    let plugin = create_plugin("nonexistent_plugin", &config);
    assert!(matches!(plugin, Ok(None)));

    // Test creating plugin with invalid config
    let plugin = create_plugin("jwt_auth", &json!({"invalid": "config"}));
    assert!(plugin.unwrap().is_some()); // Should still create, but may fail during execution
}

#[tokio::test]
async fn test_plugin_configuration_validation() {
    // Test that plugins handle missing config gracefully
    let empty_config = json!({});

    // Note: access_control and ip_restriction are excluded because they now
    // require at least one rule in config and intentionally reject empty config.
    let plugin_names = vec![
        "stdout_logging",
        "transaction_debugger",
        "key_auth",
        "basic_auth",
        "rate_limiting",
        "request_transformer",
        "response_transformer",
    ];

    for plugin_name in plugin_names {
        let plugin = create_plugin(plugin_name, &empty_config);
        let plugin = plugin
            .unwrap_or_else(|e| panic!("create_plugin returned Err for {}: {}", plugin_name, e));
        assert!(plugin.is_some(), "Failed to create plugin: {}", plugin_name);

        let plugin = plugin.unwrap();
        assert_eq!(plugin.name(), plugin_name);

        // Test basic operations don't panic
        let mut ctx = create_test_context();
        let consumer_index = ferrum_gateway::ConsumerIndex::new(&[create_test_consumer()]);

        // These should not panic even with empty config
        let _ = plugin.on_request_received(&mut ctx).await;
        let _ = plugin.authorize(&mut ctx).await;
        let _ = plugin.authenticate(&mut ctx, &consumer_index).await;

        let mut headers = std::collections::HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        let _ = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    }
}

#[tokio::test]
async fn test_plugin_complex_configurations() {
    let complex_configs = vec![
        (
            "rate_limiting",
            json!({
                "window_seconds": 3600,
                "max_requests": 1000,
                "limit_by": "consumer",
                "skip_successful_requests": false,
                "skip_failed_requests": true
            }),
        ),
        (
            "access_control",
            json!({
                "allowed_ips": ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"],
                "blocked_ips": ["172.16.0.0/12"],
                "default_action": "allow"
            }),
        ),
        (
            "request_transformer",
            json!({
                "add_headers": {
                    "X-Request-ID": "{{request_id}}",
                    "X-Timestamp": "{{timestamp}}",
                    "X-Forwarded-For": "{{client_ip}}"
                },
                "remove_headers": ["X-Internal", "X-Debug"],
                "set_query_params": {
                    "version": "v2",
                    "format": "json"
                }
            }),
        ),
    ];

    for (plugin_name, config) in complex_configs {
        let plugin = create_plugin(plugin_name, &config);
        let plugin = plugin
            .unwrap_or_else(|e| panic!("create_plugin returned Err for {}: {}", plugin_name, e));
        assert!(
            plugin.is_some(),
            "Failed to create plugin: {} with complex config",
            plugin_name
        );
        assert_eq!(plugin.unwrap().name(), plugin_name);
    }
}

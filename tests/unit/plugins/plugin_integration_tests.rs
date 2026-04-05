//! Integration tests for the plugin system
//! Tests plugin creation, scope configuration, and error handling

use ferrum_edge::config::types::{PluginConfig, PluginScope};
use ferrum_edge::plugins::{
    Plugin, PluginResult, RequestContext, available_plugins, create_plugin,
};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use super::plugin_utils::{create_test_consumer, create_test_context, create_test_proxy};

fn create_response_context(path: &str) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.path = path.to_string();
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx
}

fn sort_plugins(mut plugins: Vec<Arc<dyn Plugin>>) -> Vec<Arc<dyn Plugin>> {
    plugins.sort_by_key(|plugin| plugin.priority());
    plugins
}

fn reject_parts(result: PluginResult) -> Option<(u16, Vec<u8>, HashMap<String, String>)> {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => Some((status_code, body.into_bytes(), headers)),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => Some((status_code, body.to_vec(), headers)),
        PluginResult::Continue => None,
    }
}

async fn run_buffered_response_lifecycle(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    mut response_status: u16,
    mut response_headers: HashMap<String, String>,
    mut response_body: Vec<u8>,
) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut proxy_headers = HashMap::new();
    for plugin in plugins {
        if let Some((status_code, body, headers)) =
            reject_parts(plugin.before_proxy(ctx, &mut proxy_headers).await)
        {
            return (status_code, headers, body);
        }
    }

    for plugin in plugins {
        if let Some((status_code, body, headers)) = reject_parts(
            plugin
                .after_proxy(ctx, response_status, &mut response_headers)
                .await,
        ) {
            response_status = status_code;
            response_headers = headers;
            response_headers
                .entry("content-type".to_string())
                .or_insert_with(|| "application/json".to_string());
            response_body = body;
            return (response_status, response_headers, response_body);
        }
    }

    for plugin in plugins {
        match plugin
            .on_response_body(ctx, response_status, &response_headers, &response_body)
            .await
        {
            PluginResult::Continue => {}
            reject => {
                let (status_code, body, headers) =
                    reject_parts(reject).expect("expected rejection");
                response_status = status_code;
                response_headers.clear();
                response_headers.insert("content-type".to_string(), "application/json".to_string());
                for (key, value) in headers {
                    response_headers.insert(key, value);
                }
                response_body = body;
                break;
            }
        }
    }

    let content_type = response_headers.get("content-type").cloned();
    let content_type = content_type.as_deref();
    for plugin in plugins {
        if let Some(transformed) = plugin
            .transform_response_body(&response_body, content_type, &response_headers)
            .await
        {
            response_headers.insert("content-length".to_string(), transformed.len().to_string());
            response_body = transformed;
        }
    }

    for plugin in plugins {
        match plugin
            .on_final_response_body(ctx, response_status, &response_headers, &response_body)
            .await
        {
            PluginResult::Continue => {}
            reject => {
                let (status_code, body, headers) =
                    reject_parts(reject).expect("expected rejection");
                response_status = status_code;
                response_headers.clear();
                response_headers.insert("content-type".to_string(), "application/json".to_string());
                for (key, value) in headers {
                    response_headers.insert(key, value);
                }
                response_body = body;
                break;
            }
        }
    }

    (response_status, response_headers, response_body)
}

async fn run_buffered_request_lifecycle(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    mut request_headers: HashMap<String, String>,
    mut request_body: Vec<u8>,
) -> PluginResult {
    for plugin in plugins {
        match plugin.before_proxy(ctx, &mut request_headers).await {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                return reject;
            }
        }
    }

    let content_type = request_headers.get("content-type").cloned();
    let content_type = content_type.as_deref();
    for plugin in plugins {
        if let Some(transformed) = plugin
            .transform_request_body(&request_body, content_type, &request_headers)
            .await
        {
            request_headers.insert("content-length".to_string(), transformed.len().to_string());
            request_body = transformed;
        }
    }

    for plugin in plugins {
        match plugin
            .on_final_request_body(&request_headers, &request_body)
            .await
        {
            PluginResult::Continue => {}
            reject @ PluginResult::Reject { .. } | reject @ PluginResult::RejectBinary { .. } => {
                return reject;
            }
        }
    }

    PluginResult::Continue
}

#[tokio::test]
async fn test_all_plugins_available() {
    let plugins = available_plugins();
    let custom_plugins: BTreeSet<_> = ferrum_edge::custom_plugins::custom_plugin_names()
        .into_iter()
        .collect();
    let builtins: BTreeSet<_> = plugins
        .iter()
        .copied()
        .filter(|name| !custom_plugins.contains(name))
        .collect();

    let expected_builtins: BTreeSet<_> = [
        "stdout_logging",
        "http_logging",
        "transaction_debugger",
        "jwks_auth",
        "jwt_auth",
        "key_auth",
        "basic_auth",
        "hmac_auth",
        "mtls_auth",
        "cors",
        "access_control",
        "tcp_connection_throttle",
        "ip_restriction",
        "bot_detection",
        "correlation_id",
        "request_transformer",
        "response_transformer",
        "graphql",
        "grpc_method_router",
        "grpc_deadline",
        "grpc_web",
        "rate_limiting",
        "request_size_limiting",
        "response_size_limiting",
        "body_validator",
        "request_termination",
        "response_caching",
        "prometheus_metrics",
        "otel_tracing",
        "ai_token_metrics",
        "ai_request_guard",
        "ai_rate_limiter",
        "ai_prompt_shield",
        "ws_message_size_limiting",
        "ws_frame_logging",
        "ws_logging",
        "ws_rate_limiting",
        "udp_rate_limiting",
        "serverless_function",
        "request_mirror",
    ]
    .into_iter()
    .collect();

    assert_eq!(
        builtins, expected_builtins,
        "built-in plugin registry drifted"
    );
    assert_eq!(
        plugins.len(),
        expected_builtins.len() + custom_plugins.len(),
        "available_plugins() should be built-ins plus discovered custom plugins"
    );
}

#[tokio::test]
async fn test_plugin_creation_all_plugins() {
    for plugin_name in available_plugins() {
        // Some plugins now require specific config fields
        let config = match plugin_name {
            "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
            "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
            "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
            "jwks_auth" => {
                json!({"providers": [{"jwks_uri": "https://example.com/.well-known/jwks.json"}]})
            }
            "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
            "access_control" => json!({"allowed_consumers": ["testuser"]}),
            "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
            "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
            "serverless_function" => {
                json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
            }
            "request_mirror" => json!({"mirror_host": "mirror.local"}),
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
        let consumer_index = ferrum_edge::ConsumerIndex::new(&[create_test_consumer()]);

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
                "allowed_consumers": ["alice", "bob", "service-account"],
                "disallowed_consumers": ["blocked-user"]
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

#[tokio::test]
async fn test_response_caching_stores_transformed_body() {
    let plugins = sort_plugins(vec![
        create_plugin(
            "response_caching",
            &json!({"ttl_seconds": 60, "add_cache_status_header": true}),
        )
        .unwrap()
        .unwrap(),
        create_plugin(
            "response_transformer",
            &json!({
                "rules": [
                    {
                        "operation": "update",
                        "target": "body",
                        "key": "message",
                        "value": "gateway"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
    ]);

    let mut ctx = create_response_context("/cache-transform");
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let (status, _, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut ctx,
        200,
        response_headers,
        br#"{"message":"backend"}"#.to_vec(),
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(String::from_utf8(body).unwrap(), r#"{"message":"gateway"}"#);

    let mut hit_ctx = create_response_context("/cache-transform");
    let mut proxy_headers = HashMap::new();
    let mut cache_hit = None;
    for plugin in &plugins {
        match plugin.before_proxy(&mut hit_ctx, &mut proxy_headers).await {
            PluginResult::Continue => {}
            result @ PluginResult::Reject { .. } | result @ PluginResult::RejectBinary { .. } => {
                cache_hit = Some(result);
                break;
            }
        }
    }

    let (status_code, body, headers) =
        reject_parts(cache_hit.expect("expected response_caching cache HIT"))
            .expect("expected rejection");
    assert_eq!(status_code, 200);
    assert_eq!(String::from_utf8(body).unwrap(), r#"{"message":"gateway"}"#);
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));
}

#[tokio::test]
async fn test_response_size_limiting_checks_transformed_body() {
    let plugins = sort_plugins(vec![
        create_plugin(
            "response_size_limiting",
            &json!({"max_bytes": 20, "require_buffered_check": true}),
        )
        .unwrap()
        .unwrap(),
        create_plugin(
            "response_transformer",
            &json!({
                "rules": [
                    {
                        "operation": "add",
                        "target": "body",
                        "key": "padding",
                        "value": "abcdefghijklmnopqrstuvwxyz"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
    ]);

    let mut ctx = create_response_context("/transform-limit");
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let (status, _, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut ctx,
        200,
        response_headers,
        br#"{"ok":true}"#.to_vec(),
    )
    .await;

    assert_eq!(status, 502);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "Response body too large");
    assert_eq!(parsed["limit"], 20);
}

#[tokio::test]
async fn test_request_size_limiting_checks_transformed_body() {
    let plugins = sort_plugins(vec![
        create_plugin("request_size_limiting", &json!({"max_bytes": 20}))
            .unwrap()
            .unwrap(),
        create_plugin(
            "request_transformer",
            &json!({
                "rules": [
                    {
                        "operation": "add",
                        "target": "body",
                        "key": "padding",
                        "value": "abcdefghijklmnopqrstuvwxyz"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
    ]);

    let mut ctx = create_test_context();
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let result =
        run_buffered_request_lifecycle(&plugins, &mut ctx, headers, br#"{"ok":true}"#.to_vec())
            .await;

    let (status_code, body, _) =
        reject_parts(result).expect("expected transformed request body to be rejected");
    assert_eq!(status_code, 413);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "Request body too large");
    assert_eq!(parsed["limit"], 20);
}

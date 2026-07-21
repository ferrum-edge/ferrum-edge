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

    // Authority is `BUILTIN_PLUGIN_REGISTRATIONS` — do not maintain a second inventory.
    let expected_builtins: BTreeSet<_> = ferrum_edge::plugins::BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|registration| registration.name)
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
            "geo_restriction" => json!({
                "db_path": "/nonexistent/GeoIP2-Country.mmdb",
                "allow_countries": ["US"]
            }),
            "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
            "tcp_logging" => json!({"host": "localhost", "port": 5140}),
            "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
            "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
            "jwks_auth" => {
                json!({"providers": [{"jwks_uri": "http://127.0.0.1:9/.well-known/jwks.json"}]})
            }
            "oauth2_introspection" => json!({
                "providers": [{
                    // Loopback endpoint so client_auth "none" is accepted.
                    "introspection_endpoint": "http://127.0.0.1:9/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            "oidc_relying_party" => json!({
                "providers": [{
                    "issuer": "https://issuer.example.com",
                    "authorization_endpoint": "https://issuer.example.com/authorize",
                    "token_endpoint": "https://issuer.example.com/token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                    "client_id": "ferrum-gateway",
                    "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
                    "scopes": ["openid", "profile"],
                    "redirect_uri": "https://app.example.com/oauth/callback",
                    "callback_path": "/oauth/callback",
                    "logout_path": "/oauth/logout"
                }],
                "session": {
                    "store": "cookie",
                    "encryption_secret": "01234567890123456789012345678901"
                },
                "behavior": {"trusted_redirect_hosts": ["app.example.com"]}
            }),
            "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
            "access_control" => json!({"allowed_consumers": ["testuser"]}),
            "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
            "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
            "serverless_function" => {
                json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
            }
            "request_mirror" => json!({"mirror_host": "mirror.local"}),
            "load_testing" => {
                json!({
                    "key": "test-load-key-0123456789abcdef!!",
                    "concurrent_clients": 5,
                    "duration_seconds": 10,
                    "gateway_port": 8000
                })
            }
            "response_mock" => json!({"rules": [{"path": "/test", "body": "mock"}]}),
            "udp_logging" => json!({"host": "127.0.0.1", "port": 9514}),
            "statsd_logging" => json!({"host": "127.0.0.1", "port": 8125}),
            "loki_logging" => json!({"endpoint_url": "http://localhost:3100/loki/api/v1/push"}),
            "sse" => json!({}),
            "kafka_logging" => {
                json!({"broker_list": "localhost:9092", "topic": "test-logs"})
            }
            "rate_limiting" => json!({
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
            }),
            "request_transformer" => {
                json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
            }
            "response_transformer" => {
                json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
            }
            "adaptive_concurrency" => json!({}),
            "request_size_limiting" => json!({"max_bytes": 1048576}),
            "response_size_limiting" => json!({"max_bytes": 1048576}),
            "ws_message_size_limiting" => json!({"max_frame_bytes": 65536}),
            "ws_rate_limiting" => json!({"frames_per_second": 100}),
            "body_validator" => json!({"required_fields": ["name"]}),
            "openapi_validator" => json!({
                "operations": [{
                    "method": "GET",
                    "path_template": "/health",
                    "path_regex": "^/health$",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "type": "object"
                                }
                            }
                        }
                    }
                }]
            }),
            "graphql" => json!({"max_depth": 100}),
            "grpc_method_router" => json!({"allow_methods": ["test.Svc/Method"]}),
            "grpc_deadline" => json!({"max_deadline_ms": 30000}),
            "ai_rate_limiter" => json!({"token_limit": 100000}),
            "ai_federation" => {
                json!({"providers": [{"name": "test", "provider_type": "openai", "api_key": "sk-test"}]})
            }
            "ai_stream_router" => json!({
                "providers": [{
                    "name": "test",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"]
                }]
            }),
            "mcp_gateway" => json!({
                "mode": "transparent_proxy",
                "endpoint": {"path": "/mcp"},
                "servers": {
                    "tools": {
                        "upstream_url": "http://mcp-gateway.example/mcp",
                        "namespace": "tools"
                    }
                }
            }),
            "a2a_gateway" => json!({
                "mode": "transparent_proxy",
                "endpoint": {
                    "path": "/a2a",
                    "agent_card_path": "/.well-known/agent-card.json",
                    "grpc_services": ["lf.a2a.v1.A2AService"]
                }
            }),
            "ai_semantic_firewall" => json!({
                "provider": {
                    "type": "openai_compatible_embeddings",
                    "endpoint": "http://127.0.0.1:9/v1/embeddings",
                    "request_timeout_ms": 100
                }
            }),
            "ai_tool_governor" => json!({
                "tools": { "github.create_pr": { "action": "allow" } }
            }),
            // ai_transcript_audit requires an HTTP sink endpoint.
            "ai_transcript_audit" => json!({
                "sink": {"endpoint_url": "http://localhost:9200/audit"}
            }),
            "ldap_auth" => json!({
                "ldap_url": "ldaps://ldap.example.com:636",
                "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
            }),
            "cors" => json!({"allowed_origins": ["*"]}),
            "response_caching" => json!({"ttl_seconds": 60}),
            "spec_expose" => json!({"spec_url": "https://example.com/openapi.yaml"}),
            "spiffe_identity" => json!({}),
            "api_chargeback" => {
                json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]})
            }
            "api_chargeback_sink" => {
                json!({
                    "clickhouse": {
                        "url": "http://127.0.0.1:8123",
                        "database": "default",
                        "table": "ferrum_charge_events"
                    },
                    "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}],
                    "spool": {"enabled": false}
                })
            }
            "ai_response_guard" => json!({"pii_patterns": ["ssn"], "action": "reject"}),
            // ai_request_guard rejects no-op configs — supply at least one policy.
            "ai_request_guard" => json!({"max_messages": 100}),
            "request_deduplication" => json!({}),
            "fault_injection" => {
                json!({"abort": {"status_code": 503, "percentage": 50.0}})
            }
            "transaction_log_schema" => {
                json!({"schemas": {"default": {"summary_type": "both"}}})
            }
            "mesh_route_dispatch" => {
                json!({
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {"upstream_id": "canary"}
                    }]
                })
            }
            "mesh_outbound_registry" => {
                json!({"registry": ["reviews.default.svc.cluster.local"]})
            }
            "opa" => {
                json!({
                    "opa_host": "http://127.0.0.1:8181",
                    "policy_path": "ferrum/authz/allow"
                })
            }
            "proxy_alerts" => json!({
                "channels": {
                    "ops": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
                },
                "rules": [{
                    "name": "r", "type": "error_rate",
                    "status_codes": [500], "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
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
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "stdout_logging".to_string(),
        config: json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(global_config.scope, PluginScope::Global);
    assert!(global_config.proxy_id.is_none());

    // Test proxy plugin config
    let proxy_config = PluginConfig {
        id: "proxy-plugin".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "jwt_auth".to_string(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("test-proxy".to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
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
    let error = create_plugin("jwt_auth", &json!({"invalid": "config"}))
        .err()
        .expect("jwt_auth must reject unknown config keys");
    assert_eq!(error, "jwt_auth: unknown config key 'invalid'");
}

#[tokio::test]
async fn test_plugin_configuration_validation() {
    // Test that plugins handle missing config gracefully
    let empty_config = json!({});

    // Note: access_control, ip_restriction, rate_limiting, request_transformer,
    // and response_transformer are excluded because they now require specific
    // config fields and intentionally reject empty config.
    let plugin_names = vec![
        "stdout_logging",
        "transaction_debugger",
        "key_auth",
        "basic_auth",
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
                "limit_by": "consumer",
                "limits": [{"scope": "default", "window_seconds": 3600, "max_requests": 1000}],
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
                "rules": [
                    {"operation": "add", "target": "header", "key": "X-Request-ID", "value": "{{request_id}}"},
                    {"operation": "add", "target": "header", "key": "X-Timestamp", "value": "{{timestamp}}"},
                    {"operation": "add", "target": "header", "key": "X-Forwarded-For", "value": "{{client_ip}}"},
                    {"operation": "remove", "target": "header", "key": "X-Internal"},
                    {"operation": "remove", "target": "header", "key": "X-Debug"}
                ]
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
    // `create_test_context` populates an authenticated consumer. After the
    // PR d34d3508 fix (shared cache leak across authenticated users), the
    // plugin refuses to store cache entries for authenticated requests
    // unless the cache key includes the consumer identity OR the response
    // explicitly opts in via `Cache-Control: public/must-revalidate/
    // s-maxage`. Enable `cache_key_include_consumer` so the test exercises
    // the storage+lookup symmetry while staying compatible with the
    // post-fix shared-cache policy.
    let plugins = sort_plugins(vec![
        create_plugin(
            "response_caching",
            &json!({
                "ttl_seconds": 60,
                "add_cache_status_header": true,
                "cache_key_include_consumer": true,
            }),
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
    // Mirror the production hot path: `before_proxy` receives a cloned (or
    // moved) copy of `ctx.headers`, never an empty map. After PR #863's
    // header-snapshot fix and PR d34d3508's auto-merge of `authorization`
    // into the cache vary list, the storage cache key is keyed by the
    // authorization value seen in `ctx.headers`; the lookup MUST be done
    // against the same view or it lands on a different `authorization=`
    // shard and misses. See `src/proxy/mod.rs` `before_proxy` dispatch.
    let mut proxy_headers = hit_ctx.headers.clone();
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

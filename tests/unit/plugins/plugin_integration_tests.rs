//! Integration tests for the plugin system
//! Tests plugin creation, scope configuration, and error handling

// Cache replay tests intentionally serialize complete async lifecycles against
// process-global RTDS publications. The guard is test-only and no task in the
// guarded lifecycle reacquires it.
#![allow(clippy::await_holding_lock)]

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
    // Stand in for the proxy's transport-owned empty-request-body proof, which
    // `response_caching` requires before it may look up or store. These hook
    // chains are driven directly rather than through a proxy body-drain path.
    ferrum_edge::_test_support::set_replay_request_body_empty_proven_for_test(&mut ctx, true);
    ferrum_edge::_test_support::set_response_presentation_policy_digest_for_test(
        &mut ctx,
        Some([0x51; 32]),
    );
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
    // Production `before_proxy` receives the live request header map (or a
    // moved copy of `ctx.headers`), never an empty map. Cache key construction
    // / Vary snapshots must see the same credentials as a later HIT lookup.
    let mut proxy_headers = ctx.headers.clone();
    for (index, plugin) in plugins.iter().enumerate() {
        if let Some((status_code, body, headers)) =
            reject_parts(plugin.before_proxy(ctx, &mut proxy_headers).await)
        {
            return (status_code, headers, body);
        }
        if plugin.participates_in_route_request_header_finalization()
            && !plugins[index + 1..]
                .iter()
                .any(|later| later.participates_in_route_request_header_finalization())
        {
            ferrum_edge::plugins::utils::route_header_transform::finalize_route_override_request_headers(
                ctx,
                &mut proxy_headers,
            );
        }
    }

    for (index, plugin) in plugins.iter().enumerate() {
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
        if plugin.participates_in_route_response_header_finalization()
            && !plugins[index + 1..]
                .iter()
                .any(|later| later.participates_in_route_response_header_finalization())
        {
            ferrum_edge::plugins::utils::route_header_transform::finalize_route_override_response_headers(
                ctx,
                &mut response_headers,
            );
        }
    }

    for plugin in plugins {
        match plugin
            .on_response_body(ctx, response_status, &mut response_headers, &response_body)
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

/// Serialize against RTDS runtime-overlay publications.
///
/// `response_caching` stamps every stored entry with the live response-side
/// runtime-overlay gate publication and retires entries whose stamp no longer
/// matches, so an overlay publication in a concurrently running test would
/// legitimately turn a HIT into a MISS. Every test that stores an entry and
/// then asserts a HIT/REVALIDATED replay takes this process-wide lock, which
/// is the same lock every overlay publisher holds.
fn response_cache_replay_policy_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
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
                "sink": {"endpoint_url": "https://localhost:9200/audit"}
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
                "limits": [{"scope": "default", "window_seconds": 3600, "max_requests": 1000}]
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
    let _policy_guard = response_cache_replay_policy_guard();
    // `create_test_context` authenticates a consumer and sends Authorization.
    // RFC 9111 §3.5 / GHSA-7f28 require an explicit shared-cache opt-in
    // (`public` / `must-revalidate` / `s-maxage`) before storage; consumer
    // key partitioning alone cannot authorize retention.
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
    response_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

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
    assert!(
        ferrum_edge::_test_support::finalized_response_replay_for_test(&hit_ctx),
        "HIT must mark the private finalized-replay capability"
    );
}

/// Shared harness for the runtime-overlay cache-provenance tests.
///
/// `response_caching` stamps every stored entry with the response-side gate
/// map that produced it, so these tests drive real overlay publications rather
/// than poking at plugin internals.
mod runtime_overlay_cache_provenance {
    use super::*;
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_for_test, finalized_response_replay_for_test,
    };
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay as response_gate;

    /// Publish one `response_transformer` scope gate through the real RTDS
    /// overlay entry point.
    ///
    /// Since GHSA-83rc-23c9-3g9x this publication is PROVENANCE ONLY: it moves
    /// the response-side publication identity that `response_caching` binds its
    /// stored entries to, but it does not (and must not) change what an
    /// already-constructed `response_transformer` does. Use
    /// [`apply_gate_generation`] to model a real accepted RTDS update.
    pub(super) fn publish_gate(scope: &str, enabled: bool) {
        let mut fields = HashMap::new();
        fields.insert(
            format!("ferrum.response_transformer.{scope}.enabled"),
            RuntimeValue::Bool(enabled),
        );
        response_gate::apply_overlay(&MeshRuntimeOverlay { fields });
    }

    pub(super) fn reset_gates() {
        response_gate::reset_for_test();
    }

    fn response_caching_plugin() -> Arc<dyn Plugin> {
        create_plugin(
            "response_caching",
            &json!({
                "ttl_seconds": 60,
                "add_cache_status_header": true,
                // Partitioning only: authenticated fixtures still need
                // `Cache-Control: public` (see `origin_headers`) under
                // RFC 9111 §3.5 / GHSA-7f28.
                "cache_key_include_consumer": true,
            }),
        )
        .unwrap()
        .unwrap()
    }

    /// One `response_transformer` instance as a mesh generation would build it:
    /// the operator's static config plus the gate that generation resolved.
    /// `resolved` of `None` models a generation whose overlay named no gate for
    /// the scope, so `default_enabled: false` governs.
    fn gated_transformer(
        scope: &str,
        rules: &serde_json::Value,
        resolved: Option<bool>,
    ) -> Arc<dyn Plugin> {
        let mut config = json!({
            "runtime_overlay_scope": scope,
            "default_enabled": false,
            "rules": rules.clone(),
        });
        if let Some(resolved) = resolved {
            config.as_object_mut().expect("object").insert(
                "runtime_overlay_resolved_enabled".to_string(),
                json!(resolved),
            );
        }
        create_plugin("response_transformer", &config)
            .unwrap()
            .unwrap()
    }

    /// `response_caching` + one overlay-gated `response_transformer`, in
    /// priority order.
    pub(super) fn plugins_with_gated_transformer(
        scope: &str,
        rules: serde_json::Value,
    ) -> Vec<Arc<dyn Plugin>> {
        sort_plugins(vec![
            response_caching_plugin(),
            gated_transformer(scope, &rules, None),
        ])
    }

    /// Model a real accepted RTDS-only update.
    ///
    /// Production does exactly two things for an overlay-only gate change:
    /// `reconcile_runtime_overlay_plugin_generations` stamps the transformer so
    /// `ConfigDelta` rebuilds THAT instance from its newly materialized effective
    /// config, while `response_caching` — whose own config did not change —
    /// retains its instance and therefore its stored entries. The post-accept
    /// consumer fanout then publishes the gate map, moving the provenance
    /// identity those stored entries are bound to.
    ///
    /// This helper reproduces both halves: the same `response_caching` Arc is
    /// carried over (so the cache under test still holds the entry stored by the
    /// previous generation) while the transformer is replaced with a freshly
    /// constructed instance carrying the new gate.
    pub(super) fn apply_gate_generation(
        previous: &[Arc<dyn Plugin>],
        scope: &str,
        rules: serde_json::Value,
        enabled: bool,
    ) -> Vec<Arc<dyn Plugin>> {
        let caching = previous
            .iter()
            .find(|plugin| plugin.name() == "response_caching")
            .cloned()
            .expect("harness always configures response_caching");
        publish_gate(scope, enabled);
        sort_plugins(vec![
            caching,
            gated_transformer(scope, &rules, Some(enabled)),
        ])
    }

    /// Run only the `before_proxy` lookup phase and return the short-circuit,
    /// if any. Mirrors the production dispatch, which hands `before_proxy` a
    /// copy of the live request header map.
    pub(super) async fn lookup(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut RequestContext,
    ) -> Option<PluginResult> {
        let mut proxy_headers = ctx.headers.clone();
        for plugin in plugins {
            match plugin.before_proxy(ctx, &mut proxy_headers).await {
                PluginResult::Continue => {}
                result @ PluginResult::Reject { .. }
                | result @ PluginResult::RejectBinary { .. } => {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Serve a HIT through the production synthetic-rejection finalizer
    /// (inspection + transform gate + final hooks + reject-path `after_proxy`).
    pub(super) async fn finalize_hit(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut RequestContext,
        hit: PluginResult,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        assert!(
            finalized_response_replay_for_test(ctx),
            "a cache HIT must mark the private finalized-replay capability"
        );
        reject_parts(finalize_plugin_rejection_for_test(plugins, ctx, hit).await)
            .map(|(status, body, headers)| (status, headers, body))
            .expect("expected a finalized rejection")
    }

    /// Complete the buffered response phases after [`lookup`] already ran.
    ///
    /// Used to place a real RTDS publication between request-side cache lookup
    /// and response-side transforms/store without invoking `before_proxy`
    /// twice.
    pub(super) async fn finish_origin_after_lookup(
        plugins: &[Arc<dyn Plugin>],
        ctx: &mut RequestContext,
        response_status: u16,
        mut response_headers: HashMap<String, String>,
        mut response_body: Vec<u8>,
    ) -> (HashMap<String, String>, Vec<u8>) {
        for plugin in plugins {
            assert!(matches!(
                plugin
                    .after_proxy(ctx, response_status, &mut response_headers)
                    .await,
                PluginResult::Continue
            ));
        }
        for plugin in plugins {
            assert!(matches!(
                plugin
                    .on_response_body(ctx, response_status, &mut response_headers, &response_body,)
                    .await,
                PluginResult::Continue
            ));
        }
        let content_type = response_headers.get("content-type").cloned();
        for plugin in plugins {
            if let Some(transformed) = plugin
                .transform_response_body_with_context(
                    ctx,
                    &response_body,
                    content_type.as_deref(),
                    &response_headers,
                )
                .await
            {
                response_headers
                    .insert("content-length".to_string(), transformed.len().to_string());
                response_body = transformed;
            }
        }
        for plugin in plugins {
            assert!(matches!(
                plugin
                    .on_final_response_body(
                        ctx,
                        response_status,
                        &response_headers,
                        &response_body,
                    )
                    .await,
                PluginResult::Continue
            ));
        }
        (response_headers, response_body)
    }

    pub(super) fn origin_headers(extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        // Authenticated test contexts require an explicit shared-cache opt-in.
        headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        for (key, value) in extra {
            headers.insert(key.to_string(), value.to_string());
        }
        headers
    }
}

/// A cache entry stored while the runtime-overlay gate was disabled must not be
/// replayed after an operator enables redaction: the entry's policy stamp no
/// longer matches, so the gateway refetches and the newly enabled header/body
/// rules apply — exactly once — before delivery.
#[tokio::test]
async fn test_response_cache_applies_response_transformer_enabled_after_store() {
    use self::runtime_overlay_cache_provenance as harness;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_enable";
    let rules = json!([
        {"target": "body", "operation": "update", "key": "secret", "value": "[redacted]"},
        {"target": "header", "operation": "update", "key": "x-secret", "value": "[redacted]"}
    ]);
    let plugins = harness::plugins_with_gated_transformer(scope, rules.clone());
    let path = "/cache-provenance-enable";

    // 1. Gate disabled (no publication, `default_enabled: false`): the origin
    //    representation is stored verbatim.
    let mut miss_ctx = create_response_context(path);
    let (status, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET")]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("TOPSECRET")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"TOPSECRET"}"#
    );

    // 2. Operator tightens policy at runtime. A gate change is an accepted RTDS
    //    generation: the transformer is rebuilt with the new gate while the
    //    unchanged `response_caching` instance keeps the entry stored above.
    let plugins = harness::apply_gate_generation(&plugins, scope, rules, true);

    // 3. The stored representation predates the live policy, so it is retired
    //    rather than replayed: a fresh origin fetch is redacted once.
    let mut tightened_ctx = create_response_context(path);
    let (status, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut tightened_ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET")]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS"),
        "an entry stored under a superseded policy must not be served"
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("[redacted]")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"[redacted]"}"#
    );

    // 4. With policy unchanged, the redacted representation is now replayable.
    let mut hit_ctx = create_response_context(path);
    let hit = harness::lookup(&plugins, &mut hit_ctx)
        .await
        .expect("expected a response_caching HIT under the unchanged policy");
    let (status, headers, body) = harness::finalize_hit(&plugins, &mut hit_ctx, hit).await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("[redacted]")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"[redacted]"}"#
    );

    harness::reset_gates();
}

/// The other half of the contract: while the gate map is unchanged, a HIT
/// replays the stored representation untouched. Non-idempotent `rename` + `add`
/// sequences (header and body) would be visible if the replay re-ran them.
#[tokio::test]
async fn test_response_cache_hit_under_unchanged_gate_skips_non_idempotent_transforms() {
    use self::runtime_overlay_cache_provenance as harness;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_stable";
    let rules = json!([
        {"target": "body", "operation": "rename", "key": "a", "new_key": "b"},
        {"target": "body", "operation": "add", "key": "a", "value": "second"},
        {"target": "header", "operation": "rename", "key": "x-a", "new_key": "x-b"},
        {"target": "header", "operation": "add", "key": "x-a", "value": "second"}
    ]);
    let plugins = harness::plugins_with_gated_transformer(scope, rules.clone());
    let path = "/cache-provenance-stable";

    // The generation serving this test has the gate enabled.
    let plugins = harness::apply_gate_generation(&plugins, scope, rules, true);

    let mut miss_ctx = create_response_context(path);
    let (status, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        harness::origin_headers(&[("x-a", "origin")]),
        br#"{"a":"origin"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );
    assert_eq!(headers.get("x-b").map(String::as_str), Some("origin"));
    assert_eq!(headers.get("x-a").map(String::as_str), Some("second"));
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"b":"origin","a":"second"}"#
    );

    // Reapplying the identical live map is a publication no-op: the gated rules
    // must NOT run a second time over the finalized representation.
    harness::publish_gate(scope, true);
    let mut hit_ctx = create_response_context(path);
    let hit = harness::lookup(&plugins, &mut hit_ctx)
        .await
        .expect("expected a response_caching HIT");
    let (status, headers, body) = harness::finalize_hit(&plugins, &mut hit_ctx, hit).await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"b":"origin","a":"second"}"#,
        "an enabled gate must not re-apply rename+add over the stored body"
    );
    assert_eq!(
        headers.get("x-b").map(String::as_str),
        Some("origin"),
        "a second rename pass would have moved `x-b` to `x-a`"
    );
    assert_eq!(
        headers.get("x-a").map(String::as_str),
        Some("second"),
        "a second `add` pass would have appended another `x-a` value"
    );

    harness::reset_gates();
}

/// A request that crosses a real gate publication keeps the generation it pinned
/// (GHSA-83rc-23c9-3g9x), and the bytes it produced still have no stable replay
/// provenance — the identity `response_caching` pinned at lookup has moved — so
/// they must not be inserted into the cache.
///
/// This test previously asserted the opposite for the body: that an in-flight
/// response "should still obey the newly live gate". That WAS the vulnerability.
/// A mid-flight gate change reaching an already-admitted request is exactly how a
/// marker header and its paired body redaction came apart, so the in-flight
/// request must now stay wholly on its own generation.
#[tokio::test]
async fn test_response_cache_drops_store_when_gate_changes_mid_request() {
    use self::runtime_overlay_cache_provenance as harness;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_mid_request";
    let rules = json!([
        {"target": "body", "operation": "update", "key": "secret", "value": "[redacted]"}
    ]);
    let plugins = harness::plugins_with_gated_transformer(scope, rules.clone());
    let path = "/cache-provenance-mid-request";

    let mut request_ctx = create_response_context(path);
    assert!(
        harness::lookup(&plugins, &mut request_ctx).await.is_none(),
        "initial request must miss and pin the disabled gate publication"
    );

    // A new accepted generation lands while the request above is mid-flight. It
    // rebuilds the transformer and moves the provenance identity, but the
    // in-flight request keeps running the plugin handles it already holds.
    let next_generation = harness::apply_gate_generation(&plugins, scope, rules, true);
    let (_, body) = harness::finish_origin_after_lookup(
        &plugins,
        &mut request_ctx,
        200,
        harness::origin_headers(&[]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"TOPSECRET"}"#,
        "an in-flight response must stay on the generation it pinned, not adopt \
         a gate published after it was admitted"
    );

    // Still uncacheable: the pinned publication identity moved during the
    // request, so those bytes have no stable replay provenance.
    let mut next_ctx = create_response_context(path);
    assert!(
        harness::lookup(&plugins, &mut next_ctx).await.is_none(),
        "a response that straddled a gate publication must not be cached"
    );

    // And the new generation does apply the redaction, so the tightened policy is
    // genuinely live for requests admitted after it was published.
    let mut after_ctx = create_response_context(path);
    let (_, _, body) = run_buffered_response_lifecycle(
        &next_generation,
        &mut after_ctx,
        200,
        harness::origin_headers(&[]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"[redacted]"}"#,
        "the newly published generation must apply the tightened policy"
    );

    harness::reset_gates();
}

/// Gate cycling is deterministic in both directions. An entry transformed while
/// the gate was enabled is retired when the gate is disabled (no stale
/// gateway-authored representation under a relaxed policy), and re-enabling
/// retires the untransformed entry stored in between.
#[tokio::test]
async fn test_response_cache_provenance_survives_gate_cycles() {
    use self::runtime_overlay_cache_provenance as harness;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_cycle";
    let rules = json!([
        {"target": "body", "operation": "update", "key": "secret", "value": "[redacted]"},
        {"target": "header", "operation": "update", "key": "x-secret", "value": "[redacted]"}
    ]);
    let plugins = harness::plugins_with_gated_transformer(scope, rules.clone());
    let path = "/cache-provenance-cycle";

    let origin_body = br#"{"secret":"TOPSECRET"}"#.to_vec();

    // Enabled: store a redacted representation. Each cycle step is a full
    // accepted generation (rebuilt transformer + republished provenance).
    let plugins = harness::apply_gate_generation(&plugins, scope, rules.clone(), true);
    let mut ctx = create_response_context(path);
    let (_, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET")]),
        origin_body.clone(),
    )
    .await;
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"[redacted]"}"#
    );

    // Disabled: the redacted entry belongs to a policy that is no longer live,
    // so it is refetched instead of replayed.
    let plugins = harness::apply_gate_generation(&plugins, scope, rules.clone(), false);
    let mut ctx = create_response_context(path);
    let (_, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET")]),
        origin_body.clone(),
    )
    .await;
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS"),
        "a transformed entry must not survive into a different policy"
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("TOPSECRET")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"TOPSECRET"}"#
    );

    // Enabled again: the untransformed entry stored under the disabled gate is
    // retired in turn, and redaction applies once to the refetched response.
    let plugins = harness::apply_gate_generation(&plugins, scope, rules, true);
    let mut ctx = create_response_context(path);
    let (_, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET")]),
        origin_body,
    )
    .await;
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS"),
        "an unredacted entry must not survive re-enabling the gate"
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("[redacted]")
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"secret":"[redacted]"}"#
    );

    harness::reset_gates();
}

/// REVALIDATED parity: conditional requests take the same provenance gate as
/// HIT, so a `304` can never certify a representation produced under a
/// superseded policy. Header-only rules keep the origin `ETag` intact (a body
/// rewrite deliberately drops content-bound validators).
#[tokio::test]
async fn test_response_cache_revalidation_respects_gate_change() {
    use self::runtime_overlay_cache_provenance as harness;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_revalidate";
    let rules = json!([
        {"target": "header", "operation": "update", "key": "x-secret", "value": "[redacted]"}
    ]);
    let plugins = harness::plugins_with_gated_transformer(scope, rules.clone());
    let path = "/cache-provenance-revalidate";

    let mut miss_ctx = create_response_context(path);
    let (status, headers, _) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET"), ("etag", "\"v1\"")]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("TOPSECRET")
    );

    // Unchanged policy: the conditional request revalidates against the stored
    // entry.
    let mut revalidate_ctx = create_response_context(path);
    revalidate_ctx
        .headers
        .insert("if-none-match".to_string(), "\"v1\"".to_string());
    let revalidated = harness::lookup(&plugins, &mut revalidate_ctx)
        .await
        .expect("expected a response_caching REVALIDATED short-circuit");
    let (status, _, headers) = reject_parts(revalidated).expect("expected a rejection");
    assert_eq!(status, 304);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("REVALIDATED")
    );

    // Policy tightens as a new accepted generation: the same conditional request
    // must not be answered from the superseded entry.
    let plugins = harness::apply_gate_generation(&plugins, scope, rules, true);
    let mut tightened_ctx = create_response_context(path);
    tightened_ctx
        .headers
        .insert("if-none-match".to_string(), "\"v1\"".to_string());
    let (status, headers, _) = run_buffered_response_lifecycle(
        &plugins,
        &mut tightened_ctx,
        200,
        harness::origin_headers(&[("x-secret", "TOPSECRET"), ("etag", "\"v1\"")]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(
        status, 200,
        "a superseded entry must not certify a 304 revalidation"
    );
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );
    assert_eq!(
        headers.get("x-secret").map(String::as_str),
        Some("[redacted]")
    );

    harness::reset_gates();
}

/// The published gate identity alone is not a sufficient provenance witness
/// (GHSA-83rc-23c9-3g9x).
///
/// Mesh publishes the gate map from `record_applied_slice`, i.e. AFTER
/// `ProxyState::update_config` has published the new `RequestEpoch`. A request
/// that pinned the previous plugin generation can therefore still pin the NEW
/// publication identity — its authenticate/authorize phase runs before
/// `response_caching::before_proxy` and can span an entire mesh apply — and its
/// response is shaped by the OLD generation's transformer instances, because a
/// request now stays wholly on the generation it pinned. A `response_caching`
/// instance that survives the apply (a global instance is not rebuilt when only
/// a proxy-scoped transformer changes) would otherwise keep replaying those
/// bytes as if the current policy had produced them.
///
/// The entry is therefore also bound to its own generation's effective
/// presentation-policy digest, which since the gate is materialized into the
/// transformer's configuration covers the gate as well as the static rules.
/// This test holds the gate publication IDENTICAL throughout, so only the
/// generation digest can retire the entry.
#[tokio::test]
async fn test_response_cache_retires_entry_from_a_superseded_plugin_generation() {
    use self::runtime_overlay_cache_provenance as harness;
    use ferrum_edge::_test_support::set_response_presentation_policy_digest_for_test;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_generation";
    let rules = json!([
        {"target": "body", "operation": "update", "key": "secret", "value": "[redacted]"}
    ]);
    // One accepted generation, published once. `apply_gate_generation` moves the
    // publication identity exactly once here and is never called again, so every
    // lookup below pins the same stamp.
    let plugins = harness::apply_gate_generation(
        &harness::plugins_with_gated_transformer(scope, rules.clone()),
        scope,
        rules,
        true,
    );
    let path = "/cache-provenance-generation";

    let generation_a = [0xA1u8; 32];
    let generation_b = [0xB2u8; 32];

    let mut miss_ctx = create_response_context(path);
    set_response_presentation_policy_digest_for_test(&mut miss_ctx, Some(generation_a));
    let (status, headers, _) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        harness::origin_headers(&[]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS"),
        "the first request must reach the origin and store under generation A"
    );

    // Same generation, same publication identity: the entry is replayable.
    let mut same_generation_ctx = create_response_context(path);
    set_response_presentation_policy_digest_for_test(&mut same_generation_ctx, Some(generation_a));
    let hit = harness::lookup(&plugins, &mut same_generation_ctx)
        .await
        .expect("an entry from the live generation must still HIT");
    let (status, _, headers) = reject_parts(hit).expect("expected a rejection");
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );

    // A later generation whose effective presentation policy differs, with the
    // gate publication identity unchanged. The stored representation was shaped
    // by generation A's rules/gate, so it must be retired rather than replayed.
    let mut next_generation_ctx = create_response_context(path);
    set_response_presentation_policy_digest_for_test(&mut next_generation_ctx, Some(generation_b));
    assert!(
        harness::lookup(&plugins, &mut next_generation_ctx)
            .await
            .is_none(),
        "an entry from a superseded plugin generation must not be replayed even \
         while the published gate identity is unchanged"
    );

    harness::reset_gates();
}

/// Unknown presentation policy must never match another unknown policy.
///
/// `ResponsePresentationPolicy::Dynamic` collapses the request digest to
/// `None`. The shared response cache must fail closed exactly like
/// `request_deduplication`: it cannot claim that two requests were shaped by
/// the same policy merely because neither policy was provable.
#[tokio::test]
async fn test_response_cache_retains_nothing_under_unprovable_policy() {
    use self::runtime_overlay_cache_provenance as harness;
    use ferrum_edge::_test_support::set_response_presentation_policy_digest_for_test;

    let _policy_guard = response_cache_replay_policy_guard();
    harness::reset_gates();

    let scope = "cache_provenance_unprovable";
    let rules = json!([
        {"target": "body", "operation": "update", "key": "secret", "value": "[redacted]"}
    ]);
    let plugins = harness::apply_gate_generation(
        &harness::plugins_with_gated_transformer(scope, rules.clone()),
        scope,
        rules,
        true,
    );
    let path = "/cache-provenance-unprovable";

    let mut miss_ctx = create_response_context(path);
    set_response_presentation_policy_digest_for_test(&mut miss_ctx, None);
    let (status, headers, _) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        harness::origin_headers(&[]),
        br#"{"secret":"TOPSECRET"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("MISS")
    );

    let mut next_ctx = create_response_context(path);
    set_response_presentation_policy_digest_for_test(&mut next_ctx, None);
    assert!(
        harness::lookup(&plugins, &mut next_ctx).await.is_none(),
        "unknown presentation policy must not retain or replay a representation"
    );

    harness::reset_gates();
}

/// #2381: store final post-transform representation; full synthetic HIT
/// finalizer must not re-apply non-idempotent body or header sequences.
#[tokio::test]
async fn test_response_cache_hit_lifecycle_skips_non_idempotent_transforms() {
    let _policy_guard = response_cache_replay_policy_guard();
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_for_test, finalized_response_replay_for_test,
    };
    use ferrum_edge::plugins::utils::route_header_transform::{
        RawRouteHeaderTransformRule, parse_route_header_transforms,
    };

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
                "apply_route_overrides": true,
                "rules": [
                    {
                        "target": "body",
                        "operation": "rename",
                        "key": "a",
                        "new_key": "b"
                    },
                    {
                        "target": "body",
                        "operation": "add",
                        "key": "a",
                        "value": "second"
                    },
                    {
                        "target": "header",
                        "operation": "rename",
                        "key": "x-a",
                        "new_key": "x-b"
                    },
                    {
                        "target": "header",
                        "operation": "add",
                        "key": "x-a",
                        "value": "second"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
        create_plugin(
            "response_transformer",
            &json!({
                "rules": [
                    {
                        "target": "header",
                        "operation": "add",
                        "key": "x-second-transformer",
                        "value": "sibling"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
    ]);

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "add", "target": "header", "key": "x-route-add", "value": "route"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "test.route").unwrap());

    // Miss: transform once and store the final representation.
    let mut miss_ctx = create_response_context("/cache-non-idempotent");
    miss_ctx.route_override_response_transform = Some(route_rules.clone());
    let mut miss_headers = HashMap::new();
    miss_headers.insert("content-type".to_string(), "application/json".to_string());
    miss_headers.insert("x-a".to_string(), "origin".to_string());
    miss_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let (status, headers, body) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        miss_headers,
        br#"{"a":"origin"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    let miss_body = String::from_utf8(body).unwrap();
    assert_eq!(miss_body, r#"{"b":"origin","a":"second"}"#);
    assert_eq!(headers.get("x-b").map(String::as_str), Some("origin"));
    assert_eq!(headers.get("x-a").map(String::as_str), Some("second"));
    assert_eq!(
        headers.get("x-second-transformer").map(String::as_str),
        Some("sibling")
    );
    assert_eq!(
        headers.get("x-route-add").map(String::as_str),
        Some("route")
    );

    // HIT: run the production synthetic rejection finalizer (inspect +
    // transform gate + final hooks + reject-path after_proxy).
    let mut hit_ctx = create_response_context("/cache-non-idempotent");
    hit_ctx.route_override_response_transform = Some(route_rules);
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
    let hit = cache_hit.expect("expected response_caching HIT");
    assert!(finalized_response_replay_for_test(&hit_ctx));

    match finalize_plugin_rejection_for_test(&plugins, &mut hit_ctx, hit).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                String::from_utf8(body.to_vec()).unwrap(),
                r#"{"b":"origin","a":"second"}"#,
                "HIT must replay the stored miss body, not re-apply rename+add"
            );
            assert_eq!(
                headers.get("x-b").map(String::as_str),
                Some("origin"),
                "static header rename+add must not overwrite x-b on HIT"
            );
            assert_eq!(
                headers.get("x-a").map(String::as_str),
                Some("second"),
                "static header rename+add must not reshape x-a on HIT"
            );
            assert_eq!(
                headers.get("x-second-transformer").map(String::as_str),
                Some("sibling"),
                "second transformer instance must not re-mutate HIT headers"
            );
            assert_eq!(
                headers.get("x-route-add").map(String::as_str),
                Some("route"),
                "route-level header add must not append again on HIT"
            );
            assert_eq!(
                headers.get("x-cache-status").map(String::as_str),
                Some("HIT")
            );
        }
        other => panic!("expected finalized HIT RejectBinary, got {other:?}"),
    }
    assert!(
        hit_ctx.route_override_response_transform.is_none(),
        "finalized replay must consume unused route overrides without applying them"
    );
}

/// #2381: REVALIDATED keeps validators-only headers and skips representation
/// transforms (body rewrite would have stripped ETag, so this path is
/// header-focused).
#[tokio::test]
async fn test_response_cache_revalidated_lifecycle_skips_header_transforms() {
    let _policy_guard = response_cache_replay_policy_guard();
    use ferrum_edge::_test_support::{
        finalize_plugin_rejection_for_test, finalized_response_replay_for_test,
    };
    use ferrum_edge::plugins::utils::route_header_transform::{
        RawRouteHeaderTransformRule, parse_route_header_transforms,
    };

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
                "apply_route_overrides": true,
                "rules": [
                    {
                        "target": "header",
                        "operation": "rename",
                        "key": "x-a",
                        "new_key": "x-b"
                    },
                    {
                        "target": "header",
                        "operation": "add",
                        "key": "x-a",
                        "value": "second"
                    }
                ]
            }),
        )
        .unwrap()
        .unwrap(),
    ]);

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "add", "target": "header", "key": "x-route-add", "value": "route"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "test.route").unwrap());

    let mut miss_ctx = create_response_context("/cache-revalidated");
    miss_ctx.route_override_response_transform = Some(route_rules.clone());
    let mut miss_headers = HashMap::new();
    miss_headers.insert("content-type".to_string(), "application/json".to_string());
    miss_headers.insert("etag".to_string(), "\"v1\"".to_string());
    miss_headers.insert("x-a".to_string(), "origin".to_string());
    miss_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );

    let (status, headers, _) = run_buffered_response_lifecycle(
        &plugins,
        &mut miss_ctx,
        200,
        miss_headers,
        br#"{"ok":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("etag").map(String::as_str), Some("\"v1\""));
    assert_eq!(headers.get("x-b").map(String::as_str), Some("origin"));
    assert_eq!(headers.get("x-a").map(String::as_str), Some("second"));
    assert_eq!(
        headers.get("x-route-add").map(String::as_str),
        Some("route")
    );

    let mut reval_ctx = create_response_context("/cache-revalidated");
    reval_ctx.route_override_response_transform = Some(route_rules);
    let mut reval_headers = reval_ctx.headers.clone();
    reval_headers.insert("if-none-match".to_string(), "\"v1\"".to_string());
    let mut revalidated = None;
    for plugin in &plugins {
        match plugin
            .before_proxy(&mut reval_ctx, &mut reval_headers)
            .await
        {
            PluginResult::Continue => {}
            result @ PluginResult::Reject { .. } | result @ PluginResult::RejectBinary { .. } => {
                revalidated = Some(result);
                break;
            }
        }
    }
    let revalidated = revalidated.expect("expected response_caching REVALIDATED");
    assert!(finalized_response_replay_for_test(&reval_ctx));

    match finalize_plugin_rejection_for_test(&plugins, &mut reval_ctx, revalidated).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 304);
            assert!(body.is_empty());
            assert_eq!(headers.get("etag").map(String::as_str), Some("\"v1\""));
            assert!(
                !headers.contains_key("x-a")
                    && !headers.contains_key("x-b")
                    && !headers.contains_key("x-route-add"),
                "REVALIDATED must keep not-modified validators only; got {headers:?}"
            );
            assert_eq!(
                headers.get("x-cache-status").map(String::as_str),
                Some("REVALIDATED")
            );
        }
        other => panic!("expected finalized REVALIDATED RejectBinary, got {other:?}"),
    }
}

#[tokio::test]
async fn test_finalized_response_replay_is_not_spoofable_via_metadata() {
    use ferrum_edge::_test_support::finalize_plugin_rejection_for_test;

    let transformer = create_plugin(
        "response_transformer",
        &json!({
            "rules": [
                {
                    "target": "body",
                    "operation": "rename",
                    "key": "a",
                    "new_key": "b"
                },
                {
                    "target": "body",
                    "operation": "add",
                    "key": "a",
                    "value": "second"
                },
                {
                    "target": "header",
                    "operation": "rename",
                    "key": "x-a",
                    "new_key": "x-b"
                },
                {
                    "target": "header",
                    "operation": "add",
                    "key": "x-a",
                    "value": "second"
                }
            ]
        }),
    )
    .unwrap()
    .unwrap();
    let plugins = sort_plugins(vec![transformer]);

    // Unrelated synthetic short-circuit without the private capability must
    // still run ordinary presentation transforms. Spoofed public metadata
    // must not suppress them.
    let mut ctx = create_response_context("/spoof-check");
    ctx.metadata.insert(
        "ferrum:synthetic_short_circuit".to_string(),
        "true".to_string(),
    );
    ctx.metadata
        .insert("finalized_response_replay".to_string(), "true".to_string());
    ctx.metadata.insert(
        "ferrum:finalized_response_replay".to_string(),
        "true".to_string(),
    );
    assert!(!ferrum_edge::_test_support::finalized_response_replay_for_test(&ctx));

    let ordinary = PluginResult::RejectBinary {
        status_code: 200,
        body: bytes::Bytes::from_static(br#"{"a":"origin"}"#),
        headers: HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("x-a".to_string(), "origin".to_string()),
        ]),
    };
    match finalize_plugin_rejection_for_test(&plugins, &mut ctx, ordinary).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                String::from_utf8(body.to_vec()).unwrap(),
                r#"{"b":"origin","a":"second"}"#,
                "metadata spoofing must not suppress body transforms"
            );
            assert_eq!(
                headers.get("x-b").map(String::as_str),
                Some("origin"),
                "metadata spoofing must not suppress header rename"
            );
            assert_eq!(
                headers.get("x-a").map(String::as_str),
                Some("second"),
                "metadata spoofing must not suppress header add after rename"
            );
        }
        other => panic!("expected transformed synthetic response, got {other:?}"),
    }
}

#[test]
fn test_h1_h2_and_h3_early_reject_paths_share_finalized_replay_chokepoint() {
    let _policy_guard = response_cache_replay_policy_guard();
    // Behavioral coverage above exercises
    // `apply_reject_after_proxy_and_synthetic_body_hooks`. Pin that every
    // frontend's early plugin-reject surface reaches that shared helper so
    // cache HIT/REVALIDATED and dedup replay skipping stays protocol-parity.
    // H3 performs these hooks in `server.rs` before selecting its native or
    // cross-protocol backend dispatch; `cross_protocol.rs` therefore does not
    // own this early synthetic-replay chokepoint.
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");

    assert!(
        h1_h2.contains("apply_reject_after_proxy_and_synthetic_body_hooks(")
            && h1_h2.contains("ctx.finalized_response_replay"),
        "H1/H2 reject finalizer must gate presentation transforms on finalized_response_replay"
    );
    assert!(
        h3.contains("apply_reject_after_proxy_and_synthetic_body_hooks("),
        "H3 early reject path must use the shared synthetic finalizer before backend dispatch"
    );
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
